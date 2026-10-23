"""Public source-to-execution integration on disposable simulator state only."""

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from autoprotect.backends import Simulator
from autoprotect.core import AutoprotectError, IndeterminateError, digest, now
from autoprotect.engine import Engine
from autoprotect.local_files import prepare_database
from autoprotect.store import Store


FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


def inputs():
    """Complete synthetic inputs, with an unrelated package for delta checks."""
    inventory = {
        "schema_version": 1, "asset_id": "integration-host", "observed_at": now(),
        "os": "ubuntu", "release": "noble", "architecture": "amd64",
        "collector": "imported", "complete": True,
        "packages": [
            {"ecosystem": "deb", "name": "libexample1", "version": "1:1.0-1+b8",
             "source_name": "example-source", "source_version": "1:1.0-1",
             "architecture": "amd64", "status": "installed", "held": False},
            {"ecosystem": "deb", "name": "unrelated-example", "version": "1.0-1",
             "source_name": "unrelated-example", "source_version": "1.0-1",
             "architecture": "all", "status": "installed", "held": False},
        ],
    }
    origin = {"origin": "Autoprotect-Synthetic", "label": "Autoprotect-Synthetic",
              "archive": "noble-security", "codename": "noble",
              "component": "main", "site": "example.invalid"}
    target = {
        "name": "libexample1", "architecture": "amd64", "from_version": "1:1.0-1+b8",
        "to_version": "1:1.0-1+ubuntu0.24.04.2+b1", "source_name": "example-source",
        "source_version": "1:1.0-1+ubuntu0.24.04.2", "sha256": digest({"synthetic_artifact": 1}),
        "size": 1024, "origins": [origin], "config_digest": digest({"synthetic_config": 1}),
        "metadata_digest": digest({"synthetic_metadata": 1}),
    }
    policy = {
        "schema_version": 1, "mode": "manual", "backend": "simulator",
        "allowed_assets": ["integration-host"], "allowed_packages": ["libexample1"],
        "allowed_origins": [], "approved_config_digest": None,
        "max_inventory_age": 300, "max_feed_age": 300, "max_repository_age": 300,
        "plan_ttl": 300, "approval_ttl": 300, "allow_maintainer_scripts": False,
        "recovery_confirmed": False, "trusted_installed_lineage": False,
    }
    return inventory, [target], policy


class RuntimePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        inventory, catalog, self.policy = inputs()
        self.simulator = Simulator.initialize(self.root / "simulator.json", inventory, catalog)
        self.store = Store(prepare_database(self.root / "database"))
        self.addCleanup(self.store.close)
        self.engine = Engine(self.store, lambda: copy.deepcopy(self.policy), self.simulator)
        self.seed(self.engine)

    def seed(self, engine):
        for source in ("pwn", "ubuntu"):
            engine.ingest(source, (FIXTURES / (source + ".json")).read_bytes())
        engine.inventory()
        return engine.triage("integration-host")

    def plan(self, engine=None):
        engine = engine or self.engine
        findings = engine.triage("integration-host")
        row = next(item for item in findings if "USN-10001-1" in item["advisory_ids"])
        self.assertEqual(row["status"], "affected")
        return engine.plan(row["id"])

    def queued(self, plan_id, engine=None):
        return next(row for row in (engine or self.engine).queue() if row["id"] == plan_id)

    def test_manual_public_pipeline_changes_only_planned_package_and_retriages(self):
        before = self.simulator.inspect()
        plan = self.plan()
        self.assertEqual(plan["status"], "pending")
        self.assertNotIn("never-execute", str(plan))
        with self.assertRaises(AutoprotectError):
            self.engine.execute(plan["id"])
        self.assertEqual(self.simulator.inspect()["packages"], before["packages"])
        self.engine.approve(plan["id"], "fixture-operator")
        result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertIsNotNone(result["inventory_id"])
        after = self.simulator.inspect()
        expected = copy.deepcopy(before["packages"])
        package = next(row for row in expected if row["name"] == "libexample1")
        package.update(version="1:1.0-1+ubuntu0.24.04.2+b1", source_version="1:1.0-1+ubuntu0.24.04.2")
        self.assertEqual(after["packages"], expected)
        rows = self.engine.triage("integration-host")
        self.assertEqual(next(row for row in rows if "USN-10001-1" in row["advisory_ids"])["status"], "not_affected")
        self.assertTrue(any(row["status"] == "unknown" for row in rows))
        with self.assertRaises(AutoprotectError):
            self.engine.execute(plan["id"])
        self.assertEqual(self.queued(plan["id"])["status"], "succeeded")
        self.assertTrue(self.engine.audit())

    def test_automatic_policy_executes_without_manual_approval(self):
        self.policy["mode"] = "auto"
        plan = self.plan()
        result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(self.queued(plan["id"])["status"], "succeeded")

    def test_changed_policy_cannot_reuse_approval(self):
        before = self.simulator.inspect()["packages"]
        plan = self.plan()
        self.engine.approve(plan["id"], "fixture-operator")
        self.policy["allowed_packages"] = ["different-package"]
        with self.assertRaises(AutoprotectError):
            self.engine.execute(plan["id"])
        self.assertEqual(self.simulator.inspect()["packages"], before)
        self.assertNotEqual(self.queued(plan["id"])["status"], "succeeded")

    def test_before_write_failure_is_final_without_retained_gate(self):
        before = self.simulator.inspect()["packages"]
        self.simulator.set_failure("before_write")
        plan = self.plan()
        self.engine.approve(plan["id"], "fixture-operator")
        try:
            self.engine.execute(plan["id"])
        except AutoprotectError:
            pass  # Failure may be returned or raised; durable outcome is required.
        self.assertEqual(self.queued(plan["id"])["status"], "failed")
        self.assertEqual(self.simulator.inspect()["packages"], before)
        with self.simulator.lock("integration-host"):
            pass
        with self.assertRaises(AutoprotectError):
            self.engine.execute(plan["id"])

    def test_recovery_invalidates_preexisting_collection_and_plans_across_databases(self):
        at = now()
        self.engine.clock = lambda: at
        with patch("autoprotect.backends.now", return_value=at):
            self.engine.inventory()
            first = self.plan()
            self.engine.approve(first["id"], "fixture-operator")
            second_policy = dict(self.policy, plan_ttl=self.policy["plan_ttl"] + 1)
            with Store(prepare_database(self.root / "second-database")) as store:
                second_backend = Simulator(self.root / "simulator.json")
                second = Engine(store, lambda: copy.deepcopy(second_policy), second_backend, clock=lambda: at)
                self.seed(second)
                old = self.plan(second)
                self.assertNotEqual(first["id"], old["id"])
                second.approve(old["id"], "fixture-operator")
                with patch.object(self.simulator, "apply", side_effect=IndeterminateError("Synthetic uncertain no-write outcome")):
                    result = self.engine.execute(first["id"])
                self.assertEqual(result["status"], "needs_attention")
                with self.assertRaises(AutoprotectError):
                    second.execute(old["id"])
                self.engine.resolve_recovery(first["id"], "fixture-operator", "Synthetic uncertainty inspected")
                with self.assertRaises(AutoprotectError):
                    second.execute(old["id"])
                # A new plan alone is not sufficient: collection must be new too.
                with self.assertRaises(AutoprotectError):
                    self.plan(second)
                second.inventory()
                fresh = self.plan(second)
                self.assertNotEqual(fresh["id"], old["id"])
                self.assertNotEqual(fresh["body"]["target_generation"], old["body"]["target_generation"])
                second.approve(fresh["id"], "fixture-operator")
                self.assertEqual(second.execute(fresh["id"])["status"], "succeeded")

    def test_wrong_recovery_id_does_not_consume_an_approved_plan(self):
        first = self.plan()
        self.engine.approve(first["id"], "fixture-operator")
        with self.simulator.lock("integration-host"):
            self.simulator.begin(first["id"])
        self.policy["plan_ttl"] += 1
        other = self.plan()
        self.assertNotEqual(other["id"], first["id"])
        self.engine.approve(other["id"], "fixture-operator")
        with self.assertRaises(AutoprotectError):
            self.engine.resolve_recovery(other["id"], "fixture-operator", "Wrong gate ID must be rejected")
        self.assertEqual(self.queued(other["id"])["status"], "approved")
        self.assertIsNone(self.store.outcome(other["id"]))
        with self.simulator.lock("integration-host", recovery=True) as gate:
            self.assertEqual(gate, {"plan_id": first["id"]})

    def test_malformed_gate_needs_explicit_digest_attestation_without_false_identity(self):
        plan = self.plan()
        self.engine.approve(plan["id"], "fixture-operator")
        raw = b'{"plan_id":'
        self.simulator._gate_path.write_bytes(raw)
        self.simulator._gate_path.chmod(0o600)
        expected_digest = hashlib.sha256(raw).hexdigest()
        state = self.engine.recovery_status(plan["id"])
        self.assertEqual(state["gate"], {"malformed": True, "digest": expected_digest})
        before = self.simulator.generation()
        for supplied in (None, "f" * 64):
            with self.subTest(digest=supplied), self.assertRaises(AutoprotectError):
                self.engine.resolve_recovery(plan["id"], "fixture-operator", "Fixture inspected", malformed_digest=supplied)
            self.assertEqual(self.queued(plan["id"])["status"], "approved")
            self.assertEqual(self.simulator._gate_path.read_bytes(), raw)
        result = self.engine.resolve_recovery(plan["id"], "fixture-operator", "Malformed fixture gate inspected; prior identity unknown",
                                              malformed_digest=expected_digest)
        self.assertTrue(result["gate_cleared"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["status"], "approved")  # Never executing; rotation makes it stale.
        self.assertNotEqual(before, self.simulator.generation())
        self.assertFalse(self.simulator._gate_path.exists())

    def test_after_write_failure_retains_gate_across_stores_until_explicit_resolution(self):
        self.simulator.set_failure("after_write")
        plan = self.plan()
        self.engine.approve(plan["id"], "fixture-operator")
        try:
            self.engine.execute(plan["id"])
        except AutoprotectError:
            pass
        self.assertEqual(self.queued(plan["id"])["status"], "needs_attention")
        with self.assertRaises(AutoprotectError):
            with Simulator(self.root / "simulator.json").lock("integration-host"):
                self.fail("retained gate was bypassed")
        with Store(prepare_database(self.root / "another-database")) as other_store:
            other_backend = Simulator(self.root / "simulator.json")
            other = Engine(other_store, lambda: copy.deepcopy(self.policy), other_backend)
            self.seed(other)
            self.assertEqual(other.queue(), [])
            with self.assertRaises(AutoprotectError):
                with other_backend.lock("integration-host"):
                    self.fail("changing SQLite state bypassed the target gate")
        self.engine.resolve_recovery(plan["id"], "fixture-operator", "Synthetic state inspected; no scripts ran")
        with self.simulator.lock("integration-host"):
            pass
        self.assertEqual(self.queued(plan["id"])["status"], "needs_attention")
        with self.assertRaises(AutoprotectError):
            self.engine.execute(plan["id"])


if __name__ == "__main__":
    unittest.main()
