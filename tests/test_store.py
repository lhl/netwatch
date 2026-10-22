"""Isolated SQLite persistence tests; no application/host state is used."""

import copy
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from autoprotect.core import AutoprotectError, PolicyError, ValidationError, digest
from autoprotect.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "store.db"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)

    def test_idempotent_schema_foreign_keys_timeout_and_context_manager(self):
        with Store(self.path) as other:
            self.assertEqual(other.connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(other.connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(other.connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
            self.assertEqual(other.connection.execute("PRAGMA synchronous").fetchone()[0], 2)
            with self.assertRaises(sqlite3.IntegrityError), other.transaction():
                other.connection.execute("INSERT INTO inventory_heads(asset_id,inventory_id) VALUES ('asset',?)", ("a" * 64,))
        with self.assertRaises(sqlite3.ProgrammingError):
            other.audit()

    def test_schema_version_and_unknown_existing_schema_are_rejected_without_deletion(self):
        self.store.connection.execute("PRAGMA user_version=3")
        with self.assertRaisesRegex(ValidationError, "schema version"):
            Store(self.path)
        self.store.connection.execute("PRAGMA user_version=0")
        with self.assertRaises(ValidationError):
            Store(self.path)
        self.assertTrue(self.store.connection.execute("SELECT name FROM sqlite_master WHERE name='objects'").fetchone())

    def test_unknown_tables_under_current_version_are_rejected(self):
        self.store.connection.execute("CREATE TABLE surprise(value)")
        with self.assertRaisesRegex(ValidationError, "schema"):
            Store(self.path)

    def test_explicit_transactions_rollback_including_interrupts_and_forbid_nesting(self):
        with self.assertRaisesRegex(AutoprotectError, "explicit"):
            self.store.put("source", {"value": 1})
        with self.assertRaises(KeyboardInterrupt), self.store.transaction():
            self.store.put("source", {"value": 1})
            raise KeyboardInterrupt
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0], 0)
        with self.store.transaction():
            with self.assertRaisesRegex(AutoprotectError, "Nested"), self.store.transaction():
                pass
        self.assertFalse(self.store.connection.in_transaction)

    def test_content_dedup_roundtrip_kind_and_detached_values(self):
        body = {"test": ["untrusted\x1b[31m", 1]}
        with self.store.transaction():
            key = self.store.put("source", body)
            self.assertEqual(key, self.store.put("source", copy.deepcopy(body)))
        self.assertEqual(key, digest(body))
        actual = self.store.get("source", key)
        actual["test"].append("changed")
        self.assertEqual(self.store.get("source", key), body)
        with self.assertRaises(ValidationError):
            self.store.get("inventory", key)
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0], 1)

    def test_immutable_objects_and_audit_reject_update_delete_and_detect_corruption(self):
        with self.store.transaction():
            key = self.store.put("source", {"value": 1})
            self.store.event(100, "source-import", {"snapshot_id": key})
        for table in ("objects", "audit"):
            for statement in (f"DELETE FROM {table}", f"UPDATE {table} SET rowid=rowid"):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.store.connection.execute(statement)
        self.store.connection.execute("DROP TRIGGER immutable_objects_update")
        self.store.connection.execute("UPDATE objects SET body='{}' WHERE id=?", (key,))
        with self.assertRaisesRegex(ValidationError, "hash"):
            self.store.get("source", key)
        with self.assertRaises(ValidationError), self.store.transaction():
            self.store.put("source", {"value": 1})

    def test_source_errors_preserve_last_good_and_snapshots(self):
        body = {"source": "debian", "acquisition": "https", "endpoint": "fixed", "records": []}
        with self.store.transaction():
            good = self.store.record_source("debian", 100, body=body, etag='"a"')
            bad = self.store.record_source("debian", 200, error="Fetch failed")
        self.assertEqual(bad["last_attempt"], 200)
        self.assertEqual(bad["last_success"], 100)
        self.assertEqual(bad["snapshot_id"], good["snapshot_id"])
        self.assertEqual(bad["etag"], '"a"')
        self.assertEqual(self.store.get("source", good["snapshot_id"]), body)
        self.assertEqual(bad["revision"], 2)

    def test_atomic_conditional_competing_claims_have_one_start_event(self):
        with self.store.transaction():
            plan_id = self.store.save_plan({"test": "claim"})["id"]
        barrier = threading.Barrier(2)
        outcomes = []
        def attempt():
            with Store(self.path) as store:
                barrier.wait(timeout=5)
                try:
                    with store.transaction():
                        store.claim(plan_id, 100, expected=("pending",))
                    outcomes.append("claimed")
                except PolicyError:
                    outcomes.append("denied")
        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(outcomes, ["claimed", "denied"])
        self.assertEqual(self.store.plan(plan_id)["status"], "executing")
        self.assertEqual([e["event"] for e in self.store.audit()], ["execution-start"])

    def test_claim_audit_is_atomic_on_transaction_failure(self):
        with self.store.transaction():
            plan_id = self.store.save_plan({"test": "rollback-claim"})["id"]
        with self.assertRaises(RuntimeError), self.store.transaction():
            self.store.claim(plan_id, 100, expected=("pending",))
            raise RuntimeError
        self.assertEqual(self.store.plan(plan_id)["status"], "pending")
        self.assertEqual(self.store.audit(), [])

    def test_findings_and_outcome_bodies_checked_and_outcomes_immutable(self):
        finding = {"asset_id": "asset", "status": "unknown"}
        finding = {"id": digest(finding), **finding}
        with self.store.transaction():
            key = self.store.save_findings({"findings": [finding]})
            plan_id = self.store.save_plan({"test": "outcome"})["id"]
            self.store.claim(plan_id, 100, expected=("pending",))
            outcome = self.store.save_outcome(plan_id, "failed", {"reason": "No mutation"}, None, 101)
        self.assertEqual(self.store.finding(finding["id"]), finding)
        self.assertEqual(self.store.outcome(plan_id), outcome)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("DELETE FROM outcomes")
        self.store.connection.execute("DROP TRIGGER immutable_objects_update")
        self.store.connection.execute("UPDATE objects SET body='{}' WHERE id=?", (key,))
        with self.assertRaises(ValidationError):
            self.store.finding(finding["id"])
        self.store.connection.execute("DROP TRIGGER immutable_outcomes_update")
        self.store.connection.execute("UPDATE outcomes SET body='{}'")
        with self.assertRaisesRegex(ValidationError, "hash"):
            self.store.outcome(plan_id)

    def test_approvals_bind_immutable_content_and_current_head(self):
        with self.store.transaction():
            plan_id = self.store.save_plan({"test": "approval"})["id"]
            original = {"plan_id": plan_id, "policy_digest": "a" * 64, "actor": "operator", "created_at": 100, "expires_at": 200}
            first = self.store.approve(original)
            revised = {**original, "actor": "second"}
            self.store.approve(revised)
        self.assertEqual(self.store.plan(plan_id)["status"], "approved")
        self.assertEqual(self.store.approval(plan_id), revised)
        self.assertEqual(self.store.get("approval", first), original)

    def test_review_collection_context_is_separate_and_same_second_recollection_updates_it(self):
        body = {"asset_id": "asset", "observed_at": 100, "collector": "simulator"}
        with self.store.transaction():
            first = self.store.save_inventory(body, backend="simulator", target_generation="0" * 64)
        self.assertEqual(self.store.inventory_context("asset"), {
            "inventory_id": first["id"], "backend": "simulator", "target_generation": "0" * 64})
        with self.store.transaction():
            second = self.store.save_inventory(body, backend="simulator", target_generation="a" * 64)
        self.assertEqual(first, second)
        self.assertEqual(set(self.store.inventory_head("asset")), {"id", "body"})
        self.assertEqual(self.store.inventory_context("asset")["target_generation"], "a" * 64)
        self.assertEqual(self.store.get("inventory", first["id"]), body)
        with self.store.transaction():
            self.store.save_inventory(body)
        self.assertEqual(self.store.inventory_context("asset"), {
            "inventory_id": first["id"], "backend": None, "target_generation": None})

    def test_review_collection_context_requires_exact_paired_backend_and_generation(self):
        for context in ({"backend": "simulator"}, {"target_generation": "0" * 64},
                        {"backend": "imported", "target_generation": "0" * 64},
                        {"backend": "simulator", "target_generation": "bad"}):
            with self.subTest(context=context), self.assertRaises(ValidationError), self.store.transaction():
                self.store.save_inventory({"asset_id": "asset"}, **context)

    def test_review_previous_schema_is_rejected_without_silent_migration(self):
        with self.store.transaction():
            key = self.store.put("source", {"test": "preserved across unsupported schema"})
        self.store.connection.execute("PRAGMA user_version=1")
        with self.assertRaisesRegex(ValidationError, "schema version"):
            Store(self.path)
        self.assertEqual(self.store.get("source", key), {"test": "preserved across unsupported schema"})

    def test_audit_order_and_bounds(self):
        with self.store.transaction():
            self.store.event(100, "first", {"value": "untrusted\ntext"})
            self.store.event(99, "second", {})
            with self.assertRaises(ValidationError):
                self.store.event(100, "third", {"value": "x" * 16384})
        self.assertEqual([e["event"] for e in self.store.audit()], ["first", "second"])


if __name__ == "__main__":
    unittest.main()
