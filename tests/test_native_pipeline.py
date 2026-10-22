"""Actual DebianApt/Engine integration; every native operation is replaced.

The fake command runner, synthetic native observations, clock, root permission
check and fixed lock paths are test-only substitutions. No real package command,
host inventory, privilege change or network request is performed.
"""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from autoprotect import backends, engine as engine_module
from autoprotect.backends import DebianApt
from autoprotect.core import AutoprotectError, BackendError, canonical
from autoprotect.engine import Engine
from autoprotect.local_files import prepare_database
from autoprotect.store import Store
from test_backends import CLOCK, FakeNativeRunner, policy


class NativePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = FakeNativeRunner()
        self.timestamp = CLOCK
        self.target_state = self.root / "native" / "targets"
        database_lock = self.root / "database-lock"
        database_lock.touch(mode=0o600)
        for patcher in (
            patch.object(backends, "_NATIVE_STATE", self.target_state),
            patch.object(backends, "_DATABASE_LOCK", database_lock),
            patch.object(backends, "now", side_effect=lambda: self.timestamp),
            patch.object(backends, "collect_local", side_effect=lambda runner: copy.deepcopy(runner.inventory)),
            patch.object(DebianApt, "_live", autospec=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.backend = DebianApt(self.runner, live=True)
        self.policy = dict(policy("debian-apt"), schema_version=1, max_inventory_age=300,
                           max_feed_age=300, plan_ttl=300, approval_ttl=10)
        self.raw = canonical({"widget-src": {"CVE-2026-10001": {
            "description": "Untrusted text: $(never-execute)",
            "releases": {"trixie": {"status": "resolved", "fixed_version": "1.0-1+deb13u1", "urgency": "high"}},
        }}}).encode("ascii")
        self.store = Store(prepare_database(self.root / "database"))
        self.addCleanup(self.store.close)
        self.engine = Engine(self.store, lambda: copy.deepcopy(self.policy), self.backend,
                             clock=lambda: self.timestamp,
                             fetcher=lambda source, etag=None: {"not_modified": False, "raw": self.raw, "etag": '"fixture"'})
        self.engine.poll("debian")
        self.engine.inventory()
        rows = self.engine.triage("synthetic-host")
        finding = next(row for row in rows if row["advisory_id"] == "CVE-2026-10001")
        self.plan = self.engine.plan(finding["id"])
        self.runner.commands.clear()
        self.runner.events.clear()

    def approve(self):
        return self.engine.approve(self.plan["id"], "synthetic-operator")

    def test_manual_execution_uses_native_protocol_and_independent_verified_outcome(self):
        before = self.backend.inspect()
        with self.assertRaises(AutoprotectError):
            self.engine.execute(self.plan["id"])
        self.assertEqual(self.runner.events, ["lock", "unlock"])
        self.assertEqual(before, self.backend.inspect())
        self.approve()
        result = self.engine.execute(self.plan["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["result"]["verified"])
        self.assertEqual(self.runner.events.count("install"), 1)
        self.assertFalse(self.backend._gate_path.exists())
        self.assertTrue(all(locked for _, _, _, locked in self.runner.commands))
        installed = self.store.get("inventory", result["inventory_id"])
        self.assertEqual(installed, self.backend.inspect())
        self.assertEqual(installed["packages"][0], before["packages"][0])
        self.assertEqual(installed["packages"][1]["version"], self.runner.target["to_version"])
        with self.assertRaises(AutoprotectError):
            self.engine.execute(self.plan["id"])
        self.assertEqual(self.runner.events.count("install"), 1)
        starts = [event for event in self.engine.audit() if event["event"] == "execution-start"]
        self.assertEqual(len(starts), 1)

    def test_corrupt_download_is_confirmed_failure_without_installation(self):
        self.approve()
        self.runner.download_bytes = b"different synthetic bytes"
        result = self.engine.execute(self.plan["id"])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["result"]["verified"])
        self.assertNotIn("install", self.runner.events)
        self.assertFalse(self.backend._gate_path.exists())
        self.assertEqual(self.backend.inspect()["packages"][1]["version"], "1.0-1")

    def test_unrelated_package_drift_retains_gate_and_requires_explicit_resolution(self):
        self.approve()
        self.runner.post_mutation = lambda observed: observed["packages"][0].update(version="9.9-1")
        result = self.engine.execute(self.plan["id"])
        self.assertEqual(result["status"], "needs_attention")
        self.assertFalse(result["result"]["verified"])
        self.assertEqual(self.runner.events.count("install"), 1)
        with self.assertRaises(BackendError), DebianApt(self.runner, live=True).lock("synthetic-host"):
            self.fail("new backend bypassed retained native gate")
        outcome = self.engine.resolve_recovery(self.plan["id"], "synthetic-operator", "Fixture-only unrelated drift inspected")
        self.assertTrue(outcome["gate_cleared"])
        self.assertEqual(outcome["status"], "needs_attention")
        self.assertFalse(outcome["verified"])
        self.assertFalse(self.backend._gate_path.exists())
        with self.assertRaises(AutoprotectError):
            self.engine.execute(self.plan["id"])
        self.assertEqual(self.runner.events.count("install"), 1)

    def test_callback_expiry_after_download_blocks_actual_native_install_path(self):
        self.approve()
        self.runner.after_download = lambda: setattr(self, "timestamp", CLOCK + 11)
        result = self.engine.execute(self.plan["id"])
        self.assertEqual(result["status"], "failed")
        self.assertIn("download", self.runner.events)
        self.assertNotIn("install", self.runner.events)
        self.assertFalse(self.backend._gate_path.exists())

    def test_repository_expiry_during_final_engine_matching_blocks_install(self):
        # Keep all Engine deadlines valid while the original repository expiry
        # crosses during the last matching pass inside the actual callback.
        for field in ("max_inventory_age", "max_feed_age", "plan_ttl", "approval_ttl"):
            self.policy[field] = 172800
        self.plan = self.engine.plan(self.plan["body"]["finding_id"])
        self.approve()
        original_apply = self.backend.apply
        original_match = engine_module.match
        matches = []

        def slow_match(*args, **kwargs):
            result = original_match(*args, **kwargs)
            matches.append(True)
            if len(matches) == 2:
                self.timestamp = CLOCK + 1001
            return result

        def apply(target, policy, *, before_mutation):
            def callback():
                with patch.object(engine_module, "match", side_effect=slow_match):
                    before_mutation()
            return original_apply(target, policy, before_mutation=callback)

        with patch.object(self.backend, "apply", side_effect=apply):
            result = self.engine.execute(self.plan["id"])
        self.assertEqual(len(matches), 2)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["result"]["verified"])
        self.assertIn("download", self.runner.events)
        self.assertNotIn("install", self.runner.events)
        self.assertFalse(self.backend._gate_path.exists())

    def test_import_after_poll_cannot_retain_native_execution_authority(self):
        self.approve()
        self.engine.ingest("debian", self.raw)
        with self.assertRaises(AutoprotectError):
            self.engine.execute(self.plan["id"])
        self.assertNotIn("download", self.runner.events)
        self.assertNotIn("install", self.runner.events)
        self.assertFalse(self.backend._gate_path.exists())
        self.assertEqual(self.engine.queue()[0]["status"], "stale")


if __name__ == "__main__":
    unittest.main()
