"""Offline command-boundary tests. Native operations and network are never run."""

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from autoprotect import __version__, cli
from autoprotect.backends import Simulator
from autoprotect.core import BackendError, PolicyError, ValidationError, digest, now
from autoprotect.store import Store


ROOT = Path(__file__).resolve().parents[1]
ASSET = "cli-fixture"
CVE = "CVE-2026-10001"
HOSTILE = "Untrusted \x1b[31m text\n$(never-execute); 日本語\u202e"


def fixtures():
    inventory = {
        "schema_version": 1, "asset_id": ASSET, "observed_at": now(),
        "os": "debian", "release": "trixie", "architecture": "amd64",
        "collector": "native", "complete": True,
        "packages": [{"ecosystem": "deb", "name": "example-package", "version": "1.0-1",
                      "source_name": "example-source", "source_version": "1.0-1",
                      "architecture": "amd64", "status": "installed", "held": False}],
    }
    origin = {"origin": "Synthetic", "label": "Synthetic", "archive": "stable-security",
              "codename": "trixie-security", "component": "main", "site": "example.invalid"}
    catalog = [{"name": "example-package", "architecture": "amd64", "from_version": "1.0-1",
                "to_version": "1.0-2", "source_name": "example-source", "source_version": "1.0-2",
                "sha256": digest("synthetic artifact"), "size": 123, "origins": [origin],
                "config_digest": digest("synthetic config"), "metadata_digest": digest("synthetic metadata")}]
    policy = {"schema_version": 1, "mode": "manual", "backend": "simulator",
              "allowed_assets": [ASSET], "allowed_packages": ["example-package"],
              "allowed_origins": [], "approved_config_digest": None,
              "max_inventory_age": 300, "max_feed_age": 300, "max_repository_age": 300,
              "plan_ttl": 300, "approval_ttl": 300, "allow_maintainer_scripts": False,
              "recovery_confirmed": False, "trusted_installed_lineage": False}
    debian = {"example-source": {CVE: {"description": HOSTILE,
              "releases": {"trixie": {"status": "resolved", "fixed_version": "1.0-2", "urgency": "high"}}}}}
    pwn = {"incidents": [{"slug": "cli-incident", "title": HOSTILE, "summary": HOSTILE,
                         "cveIds": [CVE], "severity": "high", "isExample": False}]}
    return inventory, catalog, policy, debian, pwn


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.inventory, self.catalog, self.policy, self.debian, self.pwn = fixtures()
        self.policy_path = self.save("policy.json", self.policy, private=True)
        self.inventory_path = self.save("inventory.json", self.inventory)
        self.catalog_path = self.save("catalog.json", self.catalog)
        self.debian_path = self.save("debian.json", self.debian)
        self.pwn_path = self.save("pwn.json", self.pwn)
        # Every in-process test fails closed if dispatch accidentally reaches a
        # real native constructor, collector, runner or network fetcher.
        for target in ("autoprotect.cli.DebianApt", "autoprotect.backends.collect_local",
                       "autoprotect.runner.Runner.run", "autoprotect.feeds.fetch_source"):
            mock = patch(target, side_effect=AssertionError("unexpected native or network operation"))
            mock.start()
            self.addCleanup(mock.stop)

    def save(self, name, value, *, private=False):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        if private:
            path.chmod(0o600)
        return path

    def write_policy(self, **changes):
        self.policy.update(changes)
        self.save("policy.json", self.policy, private=True)

    def globals(self):
        return ["--state-dir", str(self.state), "--policy", str(self.policy_path)]

    def invoke(self, *arguments, expected=0, operational=True):
        args = (self.globals() if operational else []) + list(map(str, arguments))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = cli.main(args)
        self.assertEqual(status, expected, (args, out.getvalue(), err.getvalue()))
        output = err.getvalue() if expected in (1, 2, 130) and err.getvalue() else out.getvalue()
        self.assertTrue(output.endswith("\n"), (args, output))
        self.assertEqual(output.count("\n"), 1, output)
        self.assertTrue(output.isascii(), output)
        self.assertFalse(any(ord(c) < 32 for c in output[:-1]), output)
        self.assertNotIn("Traceback", output)
        result = json.loads(output)
        if err.getvalue():
            self.assertEqual(out.getvalue(), "")
            self.assertIn("error", result)
        return result

    def initialize(self):
        return self.invoke("init-simulator", "--inventory", self.inventory_path, "--catalog", self.catalog_path)

    def seed(self):
        self.initialize()
        for source in ("pwn", "debian"):
            self.invoke("import-feed", source, self.root / (source + ".json"))
        self.invoke("inventory")

    def plan(self):
        rows = self.invoke("triage", ASSET)
        finding = next(row for row in rows if CVE in row["advisory_ids"])
        self.assertEqual(finding["status"], "affected")
        return self.invoke("plan", finding["id"])

    def approved(self):
        self.seed()
        plan = self.plan()
        self.invoke("approve", plan["id"], "--actor", "fixture-operator")
        return plan

    def test_init_returns_inventory_evidence_and_never_replaces_existing_state(self):
        result = self.initialize()
        self.assertEqual(result["status"], "initialized")
        self.assertTrue(result["simulation_only"])
        self.assertEqual(result["backend"], "simulator")
        self.assertEqual(result["inventory"]["body"]["collector"], "simulator")
        self.assertEqual(Path(result["simulator_path"]), self.state / "simulator.json")
        before = (self.state / "simulator.json").read_bytes()
        self.invoke("init-simulator", "--inventory", self.inventory_path, "--catalog", self.catalog_path, expected=1)
        self.assertEqual((self.state / "simulator.json").read_bytes(), before)
        self.assertEqual(self.invoke("inventory")["body"]["packages"], self.inventory["packages"])

    def test_manual_workflow_denies_unapproved_then_changes_only_fixture_state(self):
        self.seed()
        plan = self.plan()
        self.assertEqual(plan["status"], "pending")
        self.invoke("execute", plan["id"], expected=1)
        self.assertEqual(self.invoke("inventory")["body"]["packages"][0]["version"], "1.0-1")
        approved = self.invoke("approve", plan["id"], "--actor", "fixture-operator")
        self.assertEqual(approved["status"], "approved")
        result = self.invoke("execute", plan["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["result"]["verified"])
        self.assertEqual(self.invoke("inventory")["body"]["packages"][0]["version"], "1.0-2")
        self.invoke("execute", plan["id"], expected=1)
        self.assertEqual(self.invoke("queue")[0]["status"], "succeeded")
        audit = self.invoke("audit")
        self.assertTrue(any(row["event"] == "plan-approved" for row in audit))
        findings = self.invoke("triage", ASSET)
        self.assertEqual(next(row for row in findings if CVE in row["advisory_ids"])["status"], "not_affected")

    def test_auto_workflow_changes_state_without_approval(self):
        self.write_policy(mode="auto")
        self.seed()
        plan = self.plan()
        self.assertEqual(self.invoke("execute", plan["id"])["status"], "succeeded")
        self.assertFalse(any(row["event"] == "plan-approved" for row in self.invoke("audit")))
        self.assertEqual(self.invoke("inventory")["body"]["packages"][0]["version"], "1.0-2")

    def test_observe_policy_denies_approval_and_execution(self):
        self.write_policy(mode="observe")
        self.seed()
        plan = self.plan()
        self.invoke("approve", plan["id"], "--actor", "observer", expected=1)
        self.invoke("execute", plan["id"], expected=1)
        self.assertEqual(self.invoke("inventory")["body"]["packages"][0]["version"], "1.0-1")

    def test_auto_allowlist_denial(self):
        self.write_policy(mode="auto", allowed_packages=["another-package"])
        self.seed()
        finding = next(row for row in self.invoke("triage", ASSET) if CVE in row["advisory_ids"])
        self.invoke("plan", finding["id"], expected=1)
        self.assertEqual(self.invoke("queue"), [])
        self.assertEqual(self.invoke("inventory")["body"]["packages"][0]["version"], "1.0-1")

    def test_import_deduplication_provenance_and_export_escaping(self):
        self.seed()
        first = self.invoke("import-feed", "debian", self.debian_path)
        second = self.invoke("import-feed", "debian", self.debian_path)
        self.assertEqual(first["snapshot_id"], second["snapshot_id"])
        self.assertEqual(second["acquisition"], "import")
        self.assertIsNone(second["endpoint"])
        exported = self.invoke("export", ASSET)
        self.assertFalse(exported["trusted"])
        self.assertEqual(exported["kind"], "untrusted-advisory-data")
        self.assertIn("not instructions", exported["warning"])
        self.assertEqual(exported["advisories"][0]["description"], HOSTILE)
        self.assertEqual(exported["incidents"][0]["title"], HOSTILE)
        self.assertTrue(all(row["acquisition"] == "import" for row in exported["sources"]))
        imported = self.invoke("inventory", "--import", self.inventory_path)
        self.assertEqual(imported["body"]["collector"], "imported")
        with Store(self.state / "state.sqlite3") as store:
            context = store.inventory_context(ASSET)
            self.assertIsNone(context["backend"])
            self.assertIsNone(context["target_generation"])
        finding = next(row for row in self.invoke("triage", ASSET) if CVE in row["advisory_ids"])
        self.invoke("plan", finding["id"], expected=1)

    def test_feed_cannot_supply_provenance_even_when_policy_is_native(self):
        self.native_policy()
        for source in ("pwn", "debian"):
            for field in ("acquisition", "provenance"):
                path = self.save("spoof.json", {field: "https"})
                result = self.invoke("import-feed", source, path, expected=1)
                self.assertIn("provenance", result["error"]["message"])
        self.assertEqual(self.invoke("queue"), [])

    def test_poll_success_and_failure_use_runtime_health_and_exit_codes(self):
        with patch("autoprotect.feeds.fetch_source", return_value={"not_modified": False,
                   "raw": self.debian_path.read_bytes(), "etag": '"fixture"'}) as fetch:
            result = self.invoke("poll", "debian")
            self.assertEqual(result["acquisition"], "https")
            fetch.assert_called_once_with("debian", etag=None)
        with patch("autoprotect.feeds.fetch_source", side_effect=OSError("raw secret \x1b")):
            failed = self.invoke("poll", "debian", expected=1)
        self.assertEqual(failed["snapshot_id"], result["snapshot_id"])
        self.assertTrue(failed["error"])
        self.assertNotIn("raw secret", str(failed))

    def test_changed_policy_rejects_previous_approval(self):
        plan = self.approved()
        self.write_policy(mode="observe")
        self.invoke("execute", plan["id"], expected=1)
        self.assertEqual(self.invoke("inventory")["body"]["packages"][0]["version"], "1.0-1")

    def test_changed_feed_rejects_previous_approval(self):
        plan = self.approved()
        self.debian["example-source"][CVE]["description"] = "Corrected evidence"
        self.save("debian.json", self.debian)
        self.invoke("import-feed", "debian", self.debian_path)
        self.invoke("execute", plan["id"], expected=1)
        self.assertEqual(self.invoke("queue")[0]["status"], "stale")

    def test_changed_inventory_rejects_previous_approval(self):
        plan = self.approved()
        self.inventory["packages"][0]["version"] = "1.0-1+b1"
        self.save("inventory.json", self.inventory)
        self.invoke("inventory", "--import", self.inventory_path)
        self.invoke("execute", plan["id"], expected=1)
        self.assertEqual(self.invoke("queue")[0]["status"], "stale")

    def test_policy_reloaded_with_protected_loader_at_every_engine_request(self):
        self.seed()
        finding = next(row for row in self.invoke("triage", ASSET) if CVE in row["advisory_ids"])
        original = Simulator.resolve
        def change_policy(backend, *args):
            target = original(backend, *args)
            self.write_policy(mode="observe")
            return target
        with patch.object(cli.local_files, "read_bytes", wraps=cli.local_files.read_bytes) as read, \
                patch.object(Simulator, "resolve", change_policy):
            self.invoke("plan", finding["id"], expected=1)
        policy_calls = [call for call in read.call_args_list if str(call.args[0]) == str(self.policy_path)]
        self.assertGreaterEqual(len(policy_calls), 3)
        self.assertTrue(all(call.kwargs == {"max_bytes": 1024 * 1024, "private": True, "live": False}
                            for call in policy_calls))
        self.assertEqual(self.invoke("queue"), [])

    def test_policy_backend_cannot_change_under_constructed_backend(self):
        self.seed()
        finding = next(row for row in self.invoke("triage", ASSET) if CVE in row["advisory_ids"])
        original = Simulator.resolve
        def change_backend(backend, *args):
            target = original(backend, *args)
            self.native_policy()
            return target
        with patch.object(Simulator, "resolve", change_backend):
            result = self.invoke("plan", finding["id"], expected=1)
        self.assertIn("backend", result["error"]["message"].lower())
        self.assertEqual(self.invoke("queue"), [])

    def test_failed_and_uncertain_execution_exit_one_and_recovery_exit_zero(self):
        for failure, status in (("before_write", "failed"), ("after_write", "needs_attention")):
            with self.subTest(failure=failure):
                self.state = self.root / failure
                plan = self.approved()
                Simulator(self.state / "simulator.json").set_failure(failure)
                result = self.invoke("execute", plan["id"], expected=1)
                self.assertEqual(result["status"], status)
                self.assertFalse(result["result"]["verified"])
                recovery = self.invoke("recovery-status", plan["id"])
                if failure == "before_write":
                    self.assertIsNone(recovery["gate"])
                    self.invoke("recover", plan["id"], expected=1)
                else:
                    self.assertEqual(recovery["gate"], {"plan_id": plan["id"]})
                    result = self.invoke("resolve-recovery", plan["id"], "--actor", "operator",
                                         "--reason", "Synthetic state inspected")
                    self.assertEqual(result["status"], "needs_attention")
                    self.assertFalse(result["verified"])
                    self.assertTrue(result["gate_cleared"])
                    self.assertIsNone(self.invoke("recovery-status", plan["id"])["gate"])

    def test_recover_abandoned_execution_does_not_claim_verified_success(self):
        plan = self.approved()
        backend = Simulator(self.state / "simulator.json")
        with backend.lock(ASSET):
            backend.begin(plan["id"])
            with Store(self.state / "state.sqlite3") as store, store.transaction():
                store.claim(plan["id"], now(), expected=("approved",))
        result = self.invoke("recover", plan["id"])
        self.assertEqual(result["status"], "needs_attention")
        self.assertFalse(result["result"]["verified"])
        self.assertEqual(self.invoke("recovery-status", plan["id"])["gate"], {"plan_id": plan["id"]})

    def test_malformed_gate_requires_exact_explicit_digest(self):
        plan = self.approved()
        gate = self.state / "simulator.json.gate"
        raw = b'{"plan_id":'
        gate.write_bytes(raw)
        gate.chmod(0o600)
        result = self.invoke("recovery-status", plan["id"])
        expected = hashlib.sha256(raw).hexdigest()
        self.assertEqual(result["gate"], {"malformed": True, "digest": expected})
        args = ["resolve-recovery", plan["id"], "--actor", "operator", "--reason", "Inspected fixture"]
        self.invoke(*args, expected=1)
        self.invoke(*args, "--malformed-digest", "f" * 64, expected=1)
        result = self.invoke(*args, "--malformed-digest", expected)
        self.assertFalse(result["verified"])
        self.assertFalse(result["prior_plan_identity_verified"])
        self.assertFalse(gate.exists())

    def native_policy(self):
        self.write_policy(backend="debian-apt", allowed_origins=self.catalog[0]["origins"],
                          approved_config_digest=self.catalog[0]["config_digest"])

    def test_native_investigation_never_constructs_or_observes_backend(self):
        self.native_policy()
        self.invoke("import-feed", "debian", self.debian_path)
        imported = self.invoke("inventory", "--import", self.inventory_path)
        self.assertEqual(imported["body"]["collector"], "imported")
        self.invoke("triage", ASSET)
        self.invoke("export", ASSET)
        self.invoke("audit")
        self.assertEqual(self.invoke("queue"), [])
        with patch("autoprotect.feeds.fetch_source", return_value={"not_modified": False,
                   "raw": self.pwn_path.read_bytes(), "etag": None}):
            self.invoke("poll", "pwn")

    def test_native_mutation_and_recovery_require_explicit_live_and_root(self):
        self.native_policy()
        for command in ("execute", "recovery-status", "recover", "resolve-recovery"):
            args = [command, "a" * 64]
            if command == "resolve-recovery":
                args += ["--actor", "operator", "--reason", "Fixture inspected"]
            with self.subTest(command=command):
                result = self.invoke(*args, expected=1)
                self.assertIn("--live", result["error"]["message"])
                with patch("autoprotect.cli.os.geteuid", return_value=1001):
                    result = self.invoke("--live", *args, expected=1)
                self.assertIn("root", result["error"]["message"])
        self.assertFalse(self.state.exists())

    def test_simulator_rejects_live_and_native_rejects_simulator_initialization(self):
        self.invoke("--live", "queue", expected=1)
        self.assertFalse(self.state.exists())
        self.native_policy()
        self.invoke("init-simulator", "--inventory", self.inventory_path, "--catalog", self.catalog_path, expected=1)
        self.assertFalse(self.state.exists())

    def test_all_argument_errors_are_json_exit_two(self):
        cases = [[], ["queue"], ["--state-dir", str(self.state), "queue"],
                 ["--policy", str(self.policy_path), "queue"], ["unknown\x1b日本語"],
                 self.globals() + ["inventory", "--state-dir", str(self.state)],
                 self.globals() + ["--backend", "debian-apt", "queue"],
                 self.globals() + ["--pol", str(self.policy_path), "queue"],
                 self.globals() + ["import-feed", "https://example.invalid", str(self.pwn_path)],
                 self.globals() + ["approve", "a" * 64],
                 self.globals() + ["resolve-recovery", "a" * 64, "--actor", "operator"],
                 self.globals() + ["init-simulator", "--inventory", str(self.inventory_path)],
                 self.globals() + ["demo"], ["--live", "demo"]]
        for flag in ("--runner", "--clock", "--fetcher", "--endpoint", "--trust", "--failure-mode"):
            cases.append(self.globals() + [flag, "injected", "queue"])
        for args in cases:
            with self.subTest(args=args):
                self.invoke(*args, operational=False, expected=2)
        self.assertFalse(self.state.exists())

    def test_bad_policy_and_input_paths_fail_safely_without_repair(self):
        self.invoke("import-feed", "pwn", self.root / "missing\x1b日本語", expected=1)
        self.invoke("inventory", "--import", self.root, expected=1)
        link = self.root / "link.json"
        link.symlink_to(self.inventory_path)
        self.invoke("inventory", "--import", link, expected=1)
        hardlink = self.root / "hardlink.json"
        os.link(self.inventory_path, hardlink)
        self.invoke("inventory", "--import", hardlink, expected=1)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.invoke("inventory", "--import", fifo, expected=1)
        self.policy_path.chmod(0o644)
        self.invoke("queue", expected=1)
        self.assertEqual(self.policy_path.stat().st_mode & 0o777, 0o644)

    def test_symlinked_and_public_state_are_rejected(self):
        real = self.root / "real-state"
        real.mkdir(mode=0o700)
        self.state.symlink_to(real, target_is_directory=True)
        self.invoke("queue", expected=1)
        self.assertEqual(list(real.iterdir()), [])
        self.state = self.root / "public-state"
        self.state.mkdir(mode=0o755)
        self.state.chmod(0o755)  # Do not let the invoking umask make this private.
        self.invoke("queue", expected=1)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_input_byte_caps_are_enforced(self):
        cases = [("huge-policy", 1024 * 1024, "policy"), ("huge-pwn", 8 * 1024 * 1024, "pwn"),
                 ("huge-debian", 128 * 1024 * 1024, "debian"),
                 ("huge-inventory", 64 * 1024 * 1024, "inventory"),
                 ("huge-catalog", 64 * 1024 * 1024, "catalog")]
        for name, cap, kind in cases:
            with self.subTest(kind=kind):
                path = self.root / name
                with path.open("wb") as stream:
                    stream.truncate(cap + 1)  # Sparse fixture; no large allocation.
                path.chmod(0o600)
                if kind == "policy":
                    original = self.policy_path
                    self.policy_path = path
                    self.invoke("queue", expected=1)
                    self.policy_path = original
                elif kind in ("pwn", "debian"):
                    self.invoke("import-feed", kind, path, expected=1)
                elif kind == "inventory":
                    self.invoke("inventory", "--import", path, expected=1)
                else:
                    self.invoke("init-simulator", "--inventory", self.inventory_path, "--catalog", path, expected=1)

    def test_duplicate_keys_and_malformed_json_are_application_errors(self):
        malformed = self.root / "malformed.json"
        for raw in (b'{"schema_version":1,"schema_version":1}', b'NaN', b'\xff', b'{'):
            malformed.write_bytes(raw)
            self.invoke("inventory", "--import", malformed, expected=1)

    def test_json_error_messages_are_bounded_and_escape_application_text(self):
        with patch.object(cli.Engine, "queue", side_effect=ValidationError(HOSTILE * 1000)):
            result = self.invoke("queue", expected=1)
        self.assertLessEqual(len(result["error"]["message"]), 2048)
        self.assertIn("Untrusted", result["error"]["message"])
        for failure in (OSError("secret OS detail\x1b"), sqlite3.DatabaseError("secret database detail"),
                        RuntimeError("secret programming detail")):
            with self.subTest(failure=type(failure).__name__), patch.object(cli.Engine, "queue", side_effect=failure):
                result = self.invoke("queue", expected=1)
            self.assertNotIn("secret", str(result))

    def test_interruption_is_json_exit_130_with_recovery_instruction(self):
        with patch.object(cli.Engine, "queue", side_effect=KeyboardInterrupt):
            result = self.invoke("queue", expected=130)
        self.assertIn("queue", result["error"]["message"])
        self.assertIn("recovery", result["error"]["message"])

    def test_demo_dispatch_is_lazy_and_mocked(self):
        demo = types.ModuleType("autoprotect.demo")
        demo.run_demo = Mock(return_value={"simulation_only": True, "note": HOSTILE})
        with patch.dict(sys.modules, {"autoprotect.demo": demo}), \
                patch.object(cli.local_files, "read_bytes", side_effect=AssertionError("policy opened")), \
                patch.object(cli.local_files, "prepare_database", side_effect=AssertionError("state opened")):
            result = self.invoke("demo", operational=False)
        self.assertTrue(result["simulation_only"])
        self.assertEqual(result["note"], HOSTILE)
        demo.run_demo.assert_called_once_with()

    def test_native_config_reports_observation_without_state_policy_or_approval(self):
        report = {"config_digest": "c" * 64, "sources": [{"uri": "http://deb.debian.org/debian/", "suite": "trixie",
                  "components": ["main"], "key": "/usr/share/keyrings/debian-archive-keyring.pgp",
                  "key_sha256": "e" * 64, "release": "missing" + HOSTILE}], "origins": []}
        native = Mock()
        native.return_value.configuration_report.return_value = report
        observed = native.return_value.configuration_report
        with patch.object(cli, "DebianApt", native), \
                patch.object(cli.local_files, "read_bytes", side_effect=AssertionError("policy opened")), \
                patch.object(cli.local_files, "prepare_database", side_effect=AssertionError("state opened")):
            result = self.invoke("native-config", operational=False)
        observed.assert_called_once_with()
        native.assert_called_once_with()  # Never live: this command cannot mutate.
        self.assertEqual(result["kind"], "native-configuration-observation")
        self.assertIs(result["approved"], False)
        self.assertEqual(result["config_digest"], "c" * 64)
        self.assertFalse(self.state.exists())
        for args in (self.globals() + ["native-config"], ["--live", "native-config"]):
            with self.subTest(args=args):
                self.invoke(*args, operational=False, expected=2)
        native.return_value.configuration_report.side_effect = cli.core.BackendError("APT probe failed")
        with patch.object(cli, "DebianApt", native):
            self.assertEqual(self.invoke("native-config", operational=False, expected=1)["error"]["code"], "backend_error")

    def test_native_root_live_dispatch_uses_protected_loaders_without_real_operations(self):
        self.native_policy()
        for command in ("execute", "recovery-status", "recover", "resolve-recovery"):
            result = {"status": "succeeded"} if command == "execute" else {"status": "needs_attention", "verified": False}
            native = Mock(name="fake-native")
            engine = Mock()
            getattr(engine, command.replace("-", "_")).return_value = result
            def create_engine(store, provider, backend):
                self.assertEqual(provider(), cli.validate_policy(self.policy))
                backend.lock(ASSET, recovery=command != "execute")  # Mock only, never native locks.
                return engine
            args = ["--live", command, "a" * 64]
            if command == "resolve-recovery":
                args += ["--actor", "operator", "--reason", "Fixture inspected"]
            with self.subTest(command=command), \
                    patch("autoprotect.cli.os.geteuid", return_value=0), \
                    patch.object(cli.local_files, "require_trusted_code") as trusted, \
                    patch.object(cli.local_files, "read_bytes", return_value=json.dumps(self.policy).encode()) as read, \
                    patch.object(cli.local_files, "prepare_database", return_value=self.root / "mock.sqlite3") as prepare, \
                    patch.object(cli, "Store"), patch.object(cli, "Engine", side_effect=create_engine), \
                    patch.object(cli, "DebianApt", return_value=native) as constructor:
                self.assertEqual(self.invoke(*args), result)
                constructor.assert_called_once_with(live=True)
                prepare.assert_called_once_with(str(self.state), live=True)
                self.assertEqual(read.call_count, 2)
                for call in read.call_args_list:
                    self.assertEqual(call.kwargs, {"max_bytes": 1024 * 1024, "private": True, "live": True})
                native.lock.assert_called_once_with(ASSET, recovery=command != "execute")
                package_dir, search_path = trusted.call_args.args
                self.assertEqual(Path(package_dir), Path(cli.__file__).resolve().parent)
                self.assertIs(search_path, sys.path)

    def test_any_root_invocation_refuses_user_modifiable_code(self):
        native = Mock(side_effect=AssertionError("native backend constructed"))
        for args, operational in ((["queue"], True), (["native-config"], False), (["inventory"], True)):
            with self.subTest(args=args), patch("autoprotect.cli.os.geteuid", return_value=0), \
                    patch.object(cli, "DebianApt", native), \
                    patch.object(cli.local_files, "read_bytes", side_effect=AssertionError("policy opened")):
                result = self.invoke(*args, operational=operational, expected=1)
                self.assertEqual(result["error"]["code"], "policy_error")
                self.assertIn("root-owned installation", result["error"]["message"])
        self.assertFalse(self.state.exists())

    def test_live_refuses_code_that_another_user_could_modify_before_reading_policy(self):
        self.native_policy()
        # This checkout and its tests are owned by the invoking user, not root.
        with patch("autoprotect.cli.os.geteuid", return_value=0), \
                patch.object(cli.local_files, "read_bytes", side_effect=AssertionError("policy opened")), \
                patch.object(cli.local_files, "prepare_database", side_effect=AssertionError("state opened")):
            result = self.invoke("--live", "execute", "a" * 64, expected=1)
        self.assertEqual(result["error"]["code"], "policy_error")
        self.assertIn("root-owned installation", result["error"]["message"])
        self.assertFalse(self.state.exists())

    def test_native_collection_is_explicit_without_implicit_live_permission(self):
        self.native_policy()
        native = Mock()
        native.generation.return_value = "0" * 64
        native.inspect.return_value = copy.deepcopy(self.inventory)
        with patch.object(cli, "DebianApt", return_value=native) as constructor:
            result = self.invoke("inventory")
        constructor.assert_called_once_with(live=False)
        native.inspect.assert_called_once_with()
        native.lock.assert_not_called()
        self.assertEqual(result["body"]["collector"], "native")

    def test_null_inventory_import_never_becomes_native_collection(self):
        self.native_policy()
        for value in (None, [], "native", 0, False):
            path = self.save("not-inventory.json", value)
            with self.subTest(value=value):
                result = self.invoke("inventory", "--import", path, expected=1)
                self.assertIn("JSON object", result["error"]["message"])
        self.assertFalse(self.state.exists())

    def test_changed_repository_target_rejects_approved_plan(self):
        plan = self.approved()
        original = Simulator.resolve
        def changed(backend, *args):
            target = original(backend, *args)
            target["sha256"] = "f" * 64
            return target
        with patch.object(Simulator, "resolve", changed):
            self.invoke("execute", plan["id"], expected=1)
        self.assertEqual(self.invoke("queue")[0]["status"], "stale")
        self.assertEqual(self.invoke("inventory")["body"]["packages"][0]["version"], "1.0-1")

    def test_execution_reloads_policy_at_final_callback(self):
        plan = self.approved()
        original = Simulator.apply
        def change_policy(backend, *args, **kwargs):
            self.write_policy(mode="observe")
            return original(backend, *args, **kwargs)
        with patch.object(Simulator, "apply", change_policy):
            result = self.invoke("execute", plan["id"], expected=1)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["result"]["verified"])
        self.assertEqual(self.invoke("inventory")["body"]["packages"][0]["version"], "1.0-1")

    def test_policy_reload_does_not_reuse_file_after_permissions_change(self):
        self.seed()
        finding = next(row for row in self.invoke("triage", ASSET) if CVE in row["advisory_ids"])
        original = Simulator.resolve
        def change_mode(backend, *args):
            result = original(backend, *args)
            self.policy_path.chmod(0o644)
            return result
        with patch.object(Simulator, "resolve", change_mode):
            result = self.invoke("plan", finding["id"], expected=1)
        self.assertIn("private", result["error"]["message"])
        self.assertEqual(self.policy_path.stat().st_mode & 0o777, 0o644)

    def test_init_preserves_colliding_policy_and_input_files(self):
        original_policy = self.policy_path
        for name in ("state.sqlite3", "simulator.json", "simulator.json.gate", "state.sqlite3-wal"):
            for kind in ("policy", "inventory", "catalog"):
                with self.subTest(name=name, kind=kind):
                    self.state = self.root / (name + "-" + kind)
                    self.state.mkdir(mode=0o700)
                    path = self.state / name
                    value = {"policy": self.policy, "inventory": self.inventory, "catalog": self.catalog}[kind]
                    path.write_text(json.dumps(value), encoding="ascii")
                    path.chmod(0o600)
                    before = path.read_bytes()
                    self.policy_path = path if kind == "policy" else original_policy
                    inventory = path if kind == "inventory" else self.inventory_path
                    catalog = path if kind == "catalog" else self.catalog_path
                    result = self.invoke("init-simulator", "--inventory", inventory, "--catalog", catalog, expected=1)
                    self.assertIn("separate", result["error"]["message"])
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual(list(self.state.iterdir()), [path])
        self.policy_path = original_policy

    def test_init_preserves_existing_database_and_orphaned_coordination(self):
        for name in ("state.sqlite3", "simulator.json.lock", "simulator.json.gate", "simulator.json.generation"):
            with self.subTest(name=name):
                self.state = self.root / (name + "-state")
                self.state.mkdir(mode=0o700)
                path = self.state / name
                path.write_bytes(b"existing operator state")
                path.chmod(0o600)
                self.invoke("init-simulator", "--inventory", self.inventory_path, "--catalog", self.catalog_path, expected=1)
                self.assertEqual(path.read_bytes(), b"existing operator state")
                self.assertEqual(list(self.state.iterdir()), [path])

    def test_init_can_use_noncolliding_policy_and_inputs_in_private_state_directory(self):
        self.state.mkdir(mode=0o700)
        for source in (self.policy_path, self.inventory_path, self.catalog_path):
            (self.state / source.name).write_bytes(source.read_bytes())
        self.policy_path = self.state / self.policy_path.name
        self.policy_path.chmod(0o600)
        result = self.invoke("init-simulator", "--inventory", self.state / self.inventory_path.name,
                             "--catalog", self.state / self.catalog_path.name)
        self.assertEqual(result["status"], "initialized")

    def test_init_protects_publication_aliases_from_policy_or_input_use(self):
        self.state.mkdir(mode=0o700)
        alias = self.state / (".publish-" + hashlib.sha256(b"simulator.json.gate").hexdigest())
        alias.write_text(json.dumps(self.policy), encoding="ascii")
        alias.chmod(0o600)
        self.policy_path = alias
        before = alias.read_bytes()
        self.invoke("init-simulator", "--inventory", self.inventory_path, "--catalog", self.catalog_path, expected=1)
        self.assertEqual(alias.read_bytes(), before)
        self.assertEqual(list(self.state.iterdir()), [alias])

    def test_native_coordination_paths_cannot_be_policy_or_import_files(self):
        self.native_policy()
        original_policy = self.policy_path
        native = self.root / "native-target"
        native.mkdir(mode=0o700)
        names = ("local.lock", "local.gate", "local.generation",
                 ".publish-" + hashlib.sha256(b"local.gate").hexdigest())
        with patch.object(cli, "_NATIVE_STATE", native):
            for name in names:
                for kind in ("policy", "inventory", "feed"):
                    with self.subTest(name=name, kind=kind):
                        path = native / name
                        value = {"policy": self.policy, "inventory": self.inventory, "feed": self.debian}[kind]
                        path.write_text(json.dumps(value), encoding="ascii")
                        path.chmod(0o600)
                        before = path.read_bytes()
                        self.policy_path = path if kind == "policy" else original_policy
                        # Valid parent traversal must not defeat collision detection.
                        alias = native / ".." / native.name / name
                        args = {"policy": ("queue",), "inventory": ("inventory", "--import", alias),
                                "feed": ("import-feed", "debian", alias)}[kind]
                        result = self.invoke(*args, expected=1)
                        self.assertIn("separate", result["error"]["message"])
                        self.assertEqual(path.read_bytes(), before)
                        self.assertFalse(self.state.exists())
                        path.unlink()
        self.policy_path = original_policy

    def test_review_double_slash_simulator_recovery_preserves_colliding_policy(self):
        original_policy = self.policy_path
        for double_state in (True, False):
            with self.subTest(double_state=double_state):
                self.policy_path = original_policy
                self.state = self.root / ("double-state" if double_state else "double-policy")
                plan = self.approved()
                state = self.state
                alias = state / (".publish-" + hashlib.sha256(b"simulator.json.gate").hexdigest())
                alias.write_bytes(original_policy.read_bytes())
                alias.chmod(0o600)
                before = alias.read_bytes()
                self.state = Path("/" + str(state)) if double_state else state
                self.policy_path = alias if double_state else Path("/" + str(alias))
                result = self.invoke("recovery-status", plan["id"], expected=1)
                self.assertTrue(alias.exists(), "Recovery deleted the policy through an equivalent path")
                self.assertEqual(alias.read_bytes(), before)
                self.assertIn("separate", result["error"]["message"])
        self.policy_path = original_policy

    def test_review_double_slash_simulator_import_collisions(self):
        self.state.mkdir(mode=0o700)
        state = self.state
        alias = state / (".publish-" + hashlib.sha256(b"simulator.json.gate").hexdigest())
        for double_state in (True, False):
            for kind in ("inventory", "feed"):
                with self.subTest(double_state=double_state, kind=kind):
                    alias.write_text(json.dumps(self.inventory if kind == "inventory" else self.debian))
                    alias.chmod(0o600)
                    before = alias.read_bytes()
                    self.state = Path("/" + str(state)) if double_state else state
                    input_path = alias if double_state else Path("/" + str(alias))
                    args = ("inventory", "--import", input_path) if kind == "inventory" else (
                        "import-feed", "debian", input_path)
                    result = self.invoke(*args, expected=1)
                    self.assertIn("separate", result["error"]["message"])
                    self.assertEqual(alias.read_bytes(), before)
                    self.assertFalse((state / "state.sqlite3").exists())

    def test_review_double_slash_native_reservations_preserve_inputs(self):
        self.native_policy()
        original_policy = self.policy_path
        native = self.root / "native-target"
        native.mkdir(mode=0o700)
        names = ("local.lock", "local.gate", "local.generation",
                 ".publish-" + hashlib.sha256(b"local.gate").hexdigest())
        for double_native in (True, False):
            reserved = Path("/" + str(native)) if double_native else native
            with patch.object(cli, "_NATIVE_STATE", reserved):
                for name in names:
                    for kind in ("policy", "inventory", "feed"):
                        with self.subTest(double_native=double_native, name=name, kind=kind):
                            path = native / name
                            value = {"policy": self.policy, "inventory": self.inventory, "feed": self.debian}[kind]
                            path.write_text(json.dumps(value), encoding="ascii")
                            path.chmod(0o600)
                            before = path.read_bytes()
                            input_path = path if double_native else Path("/" + str(path))
                            self.policy_path = input_path if kind == "policy" else original_policy
                            args = {"policy": ("queue",), "inventory": ("inventory", "--import", input_path),
                                    "feed": ("import-feed", "debian", input_path)}[kind]
                            result = self.invoke(*args, expected=1)
                            self.assertIn("separate", result["error"]["message"])
                            self.assertEqual(path.read_bytes(), before)
                            self.assertFalse(self.state.exists())
        self.policy_path = original_policy

    def test_review_comparison_does_not_erase_unsafe_original_ancestors(self):
        good = self.root / "good"
        good.mkdir(mode=0o700)
        (self.root / "symlink").symlink_to(good, target_is_directory=True)
        (self.root / "not-directory").write_text("not a directory")
        public = self.root / "public"
        public.mkdir(mode=0o700)
        public.chmod(0o777)
        state = self.state
        policy = self.policy_path
        for prefix in ("/", "//"):
            for component in ("symlink", "missing", "not-directory", "public"):
                with self.subTest(prefix=prefix, component=component):
                    base = prefix + str(self.root).lstrip("/") + "/" + component + "/../"
                    self.state = base + state.name
                    self.policy_path = policy
                    self.invoke("queue", expected=1)
                    self.assertFalse(state.exists())
                    self.state = state
                    self.policy_path = base + policy.name
                    self.invoke("queue", expected=1)
                    self.assertEqual(policy.read_bytes(), json.dumps(self.policy).encode())
                    self.assertFalse(state.exists())
        self.state = state
        self.policy_path = policy
        # Valid parent traversal remains usable in both spellings.
        for prefix in ("/", "//"):
            self.state = prefix + str(self.root).lstrip("/") + "/good/../state"
            self.assertEqual(self.invoke("queue"), [])

    def test_policy_symlink_and_hardlink_rejected_without_state_creation(self):
        original = self.policy_path
        link = self.root / "linked-policy"
        link.symlink_to(original)
        self.policy_path = link
        self.invoke("queue", expected=1)
        hardlink = self.root / "hardlinked-policy"
        os.link(original, hardlink)
        self.policy_path = hardlink
        self.invoke("queue", expected=1)
        self.assertFalse(self.state.exists())

    def test_unsafe_database_sidecar_and_missing_parent_do_not_modify_files(self):
        self.state.mkdir(mode=0o700)
        sidecar = self.state / "state.sqlite3-wal"
        sidecar.symlink_to(self.inventory_path)
        before = self.inventory_path.read_bytes()
        self.invoke("queue", expected=1)
        self.assertEqual(self.inventory_path.read_bytes(), before)
        self.assertFalse((self.state / "state.sqlite3").exists())
        self.state = self.root / "absent" / "child"
        self.invoke("queue", expected=1)
        self.assertFalse(self.state.parent.exists())

    def _closed_reader_process(self, entry, args, *, closed_stderr=False):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)  # Deterministic: no reader exists even before child spawn.
        try:
            return subprocess.run(["python3", *entry, *map(str, args)], cwd=ROOT, timeout=20,
                                  stdout=subprocess.PIPE if closed_stderr else write_fd,
                                  stderr=write_fd if closed_stderr else subprocess.PIPE,
                                  text=True, check=False)
        finally:
            os.close(write_fd)

    def test_review_closed_stdout_has_json_error_and_exact_exit(self):
        entries = [("-m", "autoprotect"),
                   ("-c", "from autoprotect.cli import main; raise SystemExit(main())")]
        for entry in entries:
            for args in (self.globals() + ["queue"], ["--help"], ["--version"]):
                with self.subTest(entry=entry, args=args):
                    result = self._closed_reader_process(entry, args)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stderr.count("\n"), 1, result.stderr)
                    error = json.loads(result.stderr)
                    self.assertEqual(error["error"]["code"], "io_error")
                    self.assertNotIn("BrokenPipe", result.stderr)
                    self.assertNotIn("Exception ignored", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
        # Output failure must happen after normal Store context cleanup, and a
        # later ordinary command remains usable against the persisted state.
        self.assertEqual(self.invoke("queue"), [])

    def test_review_closed_stderr_retains_original_error_exit_without_stdout_fallback(self):
        entries = [("-m", "autoprotect"),
                   ("-c", "from autoprotect.cli import main; raise SystemExit(main())")]
        for entry in entries:
            for args, expected in ((["not-a-command"], 2),
                                   (self.globals() + ["inventory", "--import", self.root / "missing"], 1)):
                with self.subTest(entry=entry, expected=expected):
                    result = self._closed_reader_process(entry, args, closed_stderr=True)
                    self.assertEqual(result.returncode, expected)
                    self.assertEqual(result.stdout, "")

    def test_review_output_failure_does_not_close_or_replace_caller_streams(self):
        class FailedStream(io.StringIO):
            def write(self, value):
                raise BrokenPipeError("private caller stream diagnostic")
        out, err = FailedStream(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(self.globals() + ["queue"]), 1)
            self.assertIs(sys.stdout, out)
            self.assertIs(sys.stderr, err)
        self.assertFalse(out.closed)
        self.assertFalse(err.closed)
        self.assertEqual(json.loads(err.getvalue())["error"]["code"], "io_error")
        out, err = io.StringIO(), FailedStream()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["not-a-command"]), 2)
            self.assertIs(sys.stdout, out)
            self.assertIs(sys.stderr, err)
        self.assertFalse(out.closed)
        self.assertFalse(err.closed)
        self.assertEqual(out.getvalue(), "")

    def test_module_guard_does_not_dispatch_in_multiprocessing_import(self):
        import runpy
        with patch.object(cli, "main") as entry:
            runpy.run_module("autoprotect.__main__", run_name="__mp_main__")
        entry.assert_not_called()

    def test_module_help_version_and_ordinary_subprocess_manual_workflow(self):
        def run(*args, expected=0):
            result = subprocess.run(["python3", "-m", "autoprotect", *map(str, args)], cwd=ROOT,
                                    capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(result.returncode, expected, (args, result.stdout, result.stderr))
            return result
        self.assertIn("init-simulator", run("--help").stdout)
        self.assertIn(__version__, run("--version").stdout)
        self.assertFalse(self.state.exists())
        def command(*args, expected=0):
            result = run(*self.globals(), *args, expected=expected)
            self.assertNotIn("Traceback", result.stderr)
            return json.loads(result.stdout or result.stderr)
        command("init-simulator", "--inventory", self.inventory_path, "--catalog", self.catalog_path)
        command("import-feed", "debian", self.debian_path)
        command("inventory")
        finding = next(row for row in command("triage", ASSET) if CVE in row["advisory_ids"])
        plan = command("plan", finding["id"])
        command("execute", plan["id"], expected=1)
        command("approve", plan["id"], "--actor", "subprocess-operator")
        self.assertEqual(command("execute", plan["id"])["status"], "succeeded")
        self.assertEqual(command("inventory")["body"]["packages"][0]["version"], "1.0-2")
        self.assertEqual(command("queue")[0]["status"], "succeeded")


if __name__ == "__main__":
    unittest.main()
