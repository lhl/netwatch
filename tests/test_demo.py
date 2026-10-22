"""Unit tests use fake children; two separate selections run real CLI processes.

Fake-child and runtime API checks:
    python3 -B -m unittest discover -s tests -p 'test_demo.py' -k Unit -v

Cold-package bytecode regression (initialization and inventory only):
    python3 -B -m unittest discover -s tests -p 'test_demo.py' -k DemoColdPackage -v

Full demo, after the parent supplies the stable CLI handoff:
    python3 -B -m unittest discover -s tests -p 'test_demo.py' -k DemoCLIIntegration -v
"""

from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from autoprotect import core, demo, feeds
from autoprotect.backends import Simulator
from autoprotect.engine import Engine, validate_policy
from autoprotect.inventory import normalize_inventory
from autoprotect.runner import CommandResult
from autoprotect.store import Store


def _invocation(argv):
    """Parse the fixed operational options independently of interpreter flags."""
    state = Path(argv[argv.index("--state-dir") + 1])
    policy_index = argv.index("--policy")
    return state, Path(argv[policy_index + 1]), argv[policy_index + 2:]


class _InProcessCLI:
    """Test-only fake child results, backed by actual disposable runtime APIs.

    This does not validate argparse, CLI dispatch/protected-file loading, module
    startup or packaging. No HTTPS provenance, clock or native runner is injected.
    Each fake command opens a fresh Store/Simulator, matching process boundaries
    only at the runtime API level. Real CLI coverage is explicitly separate.
    """

    def __init__(self, transform=None):
        self.calls = []
        self.transform = transform

    def run(self, argv, *, timeout, cwd):
        self.calls.append((list(argv), timeout, cwd))
        state, policy_path, arguments = _invocation(argv)
        command, *args = arguments
        try:
            if command == "init-simulator":
                Simulator.initialize(state / "simulator.json", core.load_json(Path(args[1]).read_bytes()),
                                     core.load_json(Path(args[3]).read_bytes()))
                result = {"initialized": True}
            else:
                with Store(state / "state.sqlite3") as store:
                    engine = Engine(store, lambda: core.load_json(policy_path.read_bytes()),
                                    Simulator(state / "simulator.json"))
                    if command == "import-feed":
                        result = engine.ingest(args[0], Path(args[1]).read_bytes())
                    elif command == "inventory":
                        result = engine.inventory()
                    elif command == "triage":
                        result = engine.triage(args[0])
                    elif command == "plan":
                        result = engine.plan(args[0])
                    elif command == "approve":
                        result = engine.approve(args[0], args[2])
                    elif command == "execute":
                        result = engine.execute(args[0])
                    elif command == "queue":
                        result = engine.queue()
                    elif command == "audit":
                        result = engine.audit()
                    elif command == "export":
                        result = engine.export(args[0])
                    elif command == "recovery-status":
                        result = engine.recovery_status(args[0])
                    elif command == "resolve-recovery":
                        result = engine.resolve_recovery(args[0], args[2], args[4])
                    else:
                        raise AssertionError("Unexpected fake command")
            code = 1 if command == "execute" and result["status"] != "succeeded" else 0
            child = CommandResult(code, core.canonical(result), "")
        except core.AutoprotectError as exc:
            # Match cli.main's public error schema and category precedence.
            if isinstance(exc, core.IndeterminateError):
                code = "indeterminate_error"
            elif isinstance(exc, core.PolicyError):
                code = "policy_error"
            elif isinstance(exc, core.ValidationError):
                code = "validation_error"
            elif isinstance(exc, core.BackendError):
                code = "backend_error"
            else:
                code = "application_error"
            child = CommandResult(1, "", core.canonical({"error": {"code": code, "message": str(exc)[:2048]}}))
        return self.transform(argv, child) if self.transform else child


class DemoFixtureUnitTests(unittest.TestCase):
    def test_fixtures_are_strict_synthetic_inputs(self):
        data = demo._fixture_data()
        self.assertEqual(set(data), {"inventory", "catalog", "debian", "pwn", "manual", "auto"})
        self.assertEqual(normalize_inventory(data["inventory"]), data["inventory"])
        for mode in ("manual", "auto"):
            policy = validate_policy(data[mode])
            self.assertEqual(policy["backend"], "simulator")
            self.assertEqual(policy["mode"], mode)
            self.assertEqual(policy["allowed_assets"], [demo._ASSET])
            self.assertEqual(policy["allowed_packages"], list(demo._PACKAGES))
            self.assertFalse(policy["allow_maintainer_scripts"])
            self.assertFalse(policy["trusted_installed_lineage"])
        assertions = feeds.parse_debian(data["debian"])
        self.assertEqual(len(assertions), 2)
        self.assertTrue(all(row["fixed_version"] == demo._NEW for row in assertions))
        self.assertTrue(feeds.parse_pwn(data["pwn"])[0]["is_example"])
        with tempfile.TemporaryDirectory() as temporary:
            simulator = Simulator.initialize(Path(temporary) / "fixture.json", data["inventory"], data["catalog"])
            observed = simulator.inspect()
            self.assertEqual(observed["collector"], "simulator")
            for target in data["catalog"]:
                self.assertEqual(target["origins"][0]["site"], "synthetic.invalid")
                self.assertEqual(target["from_version"], demo._OLD)
                self.assertEqual(target["to_version"], demo._NEW)

    def test_fixtures_are_detached_and_clock_is_the_only_observation(self):
        with patch.object(demo.core, "now", return_value=100):
            first, second = demo._fixture_data(), demo._fixture_data()
        self.assertEqual(first, second)
        self.assertEqual(first["inventory"]["observed_at"], 100)
        first["manual"]["allowed_packages"].clear()
        first["catalog"][0]["origins"][0]["origin"] = "changed"
        self.assertEqual(second["manual"]["allowed_packages"], list(demo._PACKAGES))
        self.assertEqual(first["auto"]["allowed_packages"], list(demo._PACKAGES))
        self.assertEqual(first["catalog"][1]["origins"][0]["origin"], "Synthetic")

    def test_files_are_private_exclusive_and_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = demo._write_fixtures(root)
            before = {name: path.read_bytes() for name, path in paths.items()}
            for name, path in paths.items():
                self.assertEqual(path.parent, root)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertLess(len(before[name]), 8192)
                core.load_json(before[name])
            with self.assertRaises(FileExistsError):
                demo._write_fixtures(root)
            self.assertEqual(before, {name: path.read_bytes() for name, path in paths.items()})

    def test_public_api_has_no_paths_or_runtime_test_imports(self):
        self.assertEqual(str(inspect.signature(demo.run_demo)), "() -> 'dict'")
        source = inspect.getsource(demo)
        self.assertNotIn("from tests", source)
        self.assertNotIn("import tests", source)
        self.assertNotIn("tests/fixtures", source)


class DemoProcessUnitTests(unittest.TestCase):
    def setUp(self):
        self.runner = Mock()
        self.runner.run.return_value = CommandResult(0, '{"ok":true}', "")
        self.factory = patch.object(demo, "Runner", return_value=self.runner)
        self.constructor = self.factory.start()
        self.addCleanup(self.factory.stop)
        self.commands = demo._Commands()
        self.state = Path("/private synthetic/state")
        self.policy = Path("/private synthetic/policy.json")

    def call(self, **kwargs):
        return self.commands.call(self.state, self.policy, "queue", **kwargs)

    def test_fixed_module_arguments_deadline_and_output_cap(self):
        self.assertEqual(self.call(), {"ok": True})
        self.constructor.assert_called_once_with(max_output_bytes=demo._MAX_OUTPUT)
        args, kwargs = self.runner.run.call_args
        self.assertEqual(args, ([sys.executable, "-B", "-m", "autoprotect", "--state-dir", str(self.state),
                                 "--policy", str(self.policy), "queue"],))
        self.assertEqual(kwargs["cwd"], str(Path(demo.__file__).absolute().parent.parent))
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], demo._COMMAND_TIMEOUT)
        self.assertEqual(self.commands.count, 1)

    def test_arguments_remain_individual_data_not_shell_syntax(self):
        self.commands.call(self.state, self.policy, "approve", "a" * 64, "--actor", "literal; $(not-a-command)")
        self.assertEqual(self.runner.run.call_args.args[0][-1], "literal; $(not-a-command)")
        # Runner is the reviewed shell=False implementation, not subprocess.run
        # with unbounded capture_output or a second demo-specific process loop.
        with patch("autoprotect.runner._CommandProcess") as process:
            from autoprotect.runner import Runner
            process.return_value.start.side_effect = OSError("synthetic-start-failure")
            with self.assertRaises(core.IndeterminateError):
                Runner(max_output_bytes=64).run([sys.executable, "-m", "autoprotect"], timeout=1)
            self.assertIs(process.return_value.start.call_args.kwargs["shell"], False)
            self.assertIs(process.return_value.start.call_args.kwargs["start_new_session"], True)
            process.return_value.stop.assert_called_once()

    def test_exit_one_requires_the_right_structured_channel(self):
        self.runner.run.return_value = CommandResult(1, '{"status":"failed"}', "")
        self.assertEqual(self.call(expect="outcome"), {"status": "failed"})
        error = {"error": {"code": "policy_error",
                           "message": "Manual execution requires explicit approval of this immutable plan"}}
        self.runner.run.return_value = CommandResult(1, "", core.canonical(error))
        self.assertEqual(self.call(expect="denied", denial="unapproved"), error)
        for child, expectation in (
            (CommandResult(0, "{}", ""), "denied"),
            (CommandResult(1, "{}", ""), "ok"),
            (CommandResult(1, "{}", ""), "denied"),
            (CommandResult(1, "", '{"error":"denied"}'), "outcome"),
            (CommandResult(1, "", "{}"), "denied"),
            (CommandResult(1, "", "[]"), "denied"),
            (CommandResult(130, "", '{"error":"interrupted"}'), "denied"),
        ):
            with self.subTest(child=child, expectation=expectation):
                self.runner.run.return_value = child
                with self.assertRaisesRegex(core.AutoprotectError, "Disposable demo failed"):
                    self.call(expect=expectation, denial="unapproved" if expectation == "denied" else None)

    def test_denial_requires_exact_schema_category_and_semantic_reason(self):
        message = "Manual execution requires explicit approval of this immutable plan"
        for value in (
            {"error": "policy_error", "message": message},
            {"error": {"code": "io_error", "message": message}},
            {"error": {"code": "internal_error", "message": message}},
            {"error": {"code": "backend_error", "message": message}},
            {"error": {"code": "policy_error", "message": "Unrelated policy failure"}},
            {"error": {"code": "policy_error", "message": message, "extra": True}},
            {"error": {"code": "policy_error", "message": message}, "extra": True},
            {"error": {"code": "policy_error"}},
        ):
            with self.subTest(value=value):
                self.runner.run.return_value = CommandResult(1, "", core.canonical(value))
                with self.assertRaises(core.AutoprotectError):
                    self.call(expect="denied", denial="unapproved")
        for reason, (code, expected) in demo._DENIALS.items():
            value = {"error": {"code": code, "message": expected}}
            self.runner.run.return_value = CommandResult(1, "", core.canonical(value))
            self.assertEqual(self.call(expect="denied", denial=reason), value)

    def test_denial_without_a_known_reason_never_spawns(self):
        for kwargs in ({"expect": "denied"}, {"expect": "denied", "denial": "unknown"},
                       {"expect": "ok", "denial": "unapproved"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(core.AutoprotectError):
                self.call(**kwargs)
        self.runner.run.assert_not_called()

    def test_json_and_combined_output_bounds_reject_bad_children(self):
        for child in (
            CommandResult(0, '{"x":1,"x":2}', ""),
            CommandResult(0, '{"x":NaN}', ""),
            CommandResult(0, '"scalar"', ""),
            CommandResult(0, "{} trailing", ""),
            CommandResult(0, "{}", "unexpected diagnostic"),
            CommandResult(0, '{"secret":"' + "x" * demo._MAX_OUTPUT + '"}', ""),
            CommandResult(0, "{}", "x" * demo._MAX_OUTPUT),
            CommandResult(0, "[" * 34 + "0" + "]" * 34, ""),
            CommandResult(0, "[" + ",".join("0" for _ in range(20001)) + "]", ""),
            CommandResult(0, "\ud800", ""),
        ):
            with self.subTest(length=len(child.stdout) + len(child.stderr)):
                self.runner.run.return_value = child
                with self.assertRaises(core.AutoprotectError) as caught:
                    self.call()
                self.assertEqual(str(caught.exception), demo._ERROR)
                self.assertTrue(caught.exception.__suppress_context__)

    def test_failure_messages_do_not_include_child_or_os_details(self):
        for failure in (core.IndeterminateError("SECRET child output"), OSError("SECRET path"),
                        RuntimeError("SECRET unexpected")):
            with self.subTest(failure=type(failure).__name__):
                self.runner.run.side_effect = failure
                with self.assertRaises(core.AutoprotectError) as caught:
                    self.call()
                self.assertNotIn("SECRET", str(caught.exception))
                self.assertLess(len(str(caught.exception)), 256)
                self.assertTrue(caught.exception.__suppress_context__)

    def test_interrupt_is_not_converted_into_success_or_application_failure(self):
        self.runner.run.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.call()

    def test_disallowed_commands_and_live_opt_in_never_spawn(self):
        for arguments in (("poll", "debian"), ("demo",), ("inventory", "--live"), ("/bin/sh",), ()):
            with self.subTest(arguments=arguments):
                with self.assertRaises(core.AutoprotectError):
                    self.commands.call(self.state, self.policy, *arguments)
        self.runner.run.assert_not_called()

    def test_whole_demo_deadline_and_command_count_prevent_spawn(self):
        self.commands.deadline = 20
        with patch.object(demo.time, "monotonic", return_value=20):
            with self.assertRaises(core.AutoprotectError):
                self.call()
        self.runner.run.assert_not_called()
        with patch.object(demo.time, "monotonic", return_value=18):
            self.call()
            self.assertEqual(self.runner.run.call_args.kwargs["timeout"], 2)
        self.commands.count = demo._MAX_COMMANDS
        with patch.object(demo.time, "monotonic", return_value=18):
            with self.assertRaises(core.AutoprotectError):
                self.call()
        self.assertEqual(self.runner.run.call_count, 1)


class DemoOrchestrationUnitTests(unittest.TestCase):
    def setUp(self):
        self.outer = tempfile.TemporaryDirectory(prefix="demo-unit-")
        self.addCleanup(self.outer.cleanup)
        self.parent = Path(self.outer.name)
        self.sentinel = self.parent / "caller-policy.json"
        self.sentinel.write_bytes(b"caller-owned content must not be read or changed")
        real_temporary = tempfile.TemporaryDirectory
        self.roots = []

        def temporary(**kwargs):
            created = real_temporary(dir=self.parent, **kwargs)
            self.roots.append(Path(created.name))
            return created

        self.temp_patch = patch.object(demo.tempfile, "TemporaryDirectory", side_effect=temporary)
        self.temp_patch.start()
        self.addCleanup(self.temp_patch.stop)

    def assert_clean(self):
        self.assertTrue(self.roots)
        self.assertTrue(all(not root.exists() for root in self.roots))
        self.assertEqual(self.sentinel.read_bytes(), b"caller-owned content must not be read or changed")
        self.assertEqual(set(self.parent.iterdir()), {self.sentinel})

    def run_fake(self, transform=None):
        fake = _InProcessCLI(transform)
        with patch.object(demo, "Runner", return_value=fake):
            result = demo.run_demo()
        self.assert_clean()
        return result, fake

    def test_complete_matrix_with_fake_child_results_and_real_disposable_apis(self):
        with patch("autoprotect.inventory.collect_local", side_effect=AssertionError("No host inventory")), \
             patch("autoprotect.feeds.fetch_source", side_effect=AssertionError("No network")), \
             patch("autoprotect.backends.DebianApt", side_effect=AssertionError("No native backend")):
            result, fake = self.run_fake()
        self.assertTrue(result["synthetic"])
        self.assertEqual(result["backend"], "simulator")
        self.assertEqual(result["commands_run"], len(fake.calls))
        self.assertEqual(result["commands_run"], 101)
        self.assertLessEqual(result["commands_run"], demo._MAX_COMMANDS)
        scenarios = result["scenarios"]
        self.assertEqual(set(scenarios), {"manual", "automatic", "before_write", "after_write"})
        self.assertEqual(scenarios["manual"]["status"], "succeeded")
        self.assertTrue(scenarios["manual"]["manual_approval"])
        self.assertFalse(scenarios["automatic"]["manual_approval"])
        self.assertTrue(scenarios["before_write"]["package_state_unchanged"])
        self.assertFalse(scenarios["before_write"]["gate_retained"])
        self.assertTrue(scenarios["after_write"]["gate_retained_before_resolution"])
        self.assertEqual(scenarios["after_write"]["recovery"]["old_approved_plan"], "stale")
        self.assertEqual(scenarios["after_write"]["recovery"]["new_approved_plan"], "succeeded")
        self.assertEqual(result["cleanup"], {"temporary_state_removed": True, "caller_state_used": False})
        self.assertEqual({_invocation(argv)[2][0] for argv, _, _ in fake.calls}, demo._COMMANDS)
        self.assertFalse(any(_invocation(argv)[2][0] == "approve" for argv, _, _ in fake.calls
                             if _invocation(argv)[0].name == "auto"))
        for argv, timeout, cwd in fake.calls:
            self.assertEqual(argv[:5], [sys.executable, "-B", "-m", "autoprotect", "--state-dir"])
            self.assertEqual(argv[6], "--policy")
            self.assertNotIn("--live", argv)
            state, policy, _ = _invocation(argv)
            self.assertTrue(state.is_relative_to(self.roots[0]))
            self.assertTrue(policy.is_relative_to(self.roots[0]))
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, demo._COMMAND_TIMEOUT)
            self.assertEqual(cwd, str(Path(demo.__file__).absolute().parent.parent))

    def test_summary_is_bounded_and_does_not_claim_live_patch_or_rollback(self):
        result, _ = self.run_fake()
        encoded = core.canonical(result)
        self.assertLessEqual(len(encoded), demo._MAX_SUMMARY)
        self.assertNotIn(str(self.parent), encoded)
        self.assertNotIn("stdout", encoded)
        self.assertNotIn("stderr", encoded)
        self.assertNotIn("CVE-", encoded)
        self.assertIn("not runtime health", encoded)
        self.assertIn("not rollback", encoded)
        self.assertIn("not authenticated", encoded)
        self.assertIn("forced process or host death", encoded)
        self.assertFalse(result["scenarios"]["before_write"]["verified"])
        self.assertFalse(result["scenarios"]["after_write"]["verified"])
        self.assertFalse(result["scenarios"]["after_write"]["recovery"]["verified"])
        self.assertEqual(result["scenarios"]["after_write"]["recovery"]["original_status"], "needs_attention")

    def test_state_claims_require_evidence_not_only_exit_codes(self):
        mutations = (
            ("import-feed", lambda value: value.update(acquisition="https")),
            ("inventory", lambda value: value["body"].update(collector="native")),
            ("plan", lambda value: value.update(status="approved")),
            ("execute", lambda value: value["result"].update(verified=False)),
            ("queue", lambda value: value[0].update(status="succeeded") if value else None),
            ("audit", lambda value: value.clear()),
            ("export", lambda value: value.update(trusted=True)),
        )
        for command, mutate in mutations:
            with self.subTest(command=command):
                changed = []

                def transform(argv, result):
                    if _invocation(argv)[2][0] == command and result.returncode == 0 and not changed:
                        value = json.loads(result.stdout)
                        mutate(value)
                        changed.append(True)
                        return CommandResult(result.returncode, core.canonical(value), "")
                    return result

                with self.assertRaisesRegex(core.AutoprotectError, "Disposable demo failed"):
                    self.run_fake(transform)
                self.assertTrue(changed)
                self.assert_clean()

    def test_full_post_inventory_delta_is_checked(self):
        executed = False
        changed = False

        def transform(argv, result):
            nonlocal executed, changed
            command = _invocation(argv)[2][0]
            if command == "execute" and result.returncode == 0:
                executed = True
            if executed and command == "inventory" and not changed:
                value = json.loads(result.stdout)
                # A valid content digest must not hide an unrelated upgrade.
                value["body"]["packages"][1]["version"] = demo._NEW
                value["id"] = core.digest(value["body"])
                changed = True
                return CommandResult(0, core.canonical(value), "")
            return result

        with self.assertRaises(core.AutoprotectError):
            self.run_fake(transform)
        self.assertTrue(changed)
        self.assert_clean()

    def test_failed_execution_exit_alone_cannot_establish_outcome(self):
        for name, field, wrong in (("before-write", "status", "succeeded"),
                                   ("after-write", "verified", True)):
            with self.subTest(name=name):
                changed = []

                def transform(argv, result):
                    state, _, arguments = _invocation(argv)
                    if state.name == name and arguments[0] == "execute" and result.stdout:
                        value = json.loads(result.stdout)
                        if field == "verified":
                            value["result"][field] = wrong
                        else:
                            value[field] = wrong
                        changed.append(True)
                        return CommandResult(1, core.canonical(value), "")
                    return result

                with self.assertRaises(core.AutoprotectError):
                    self.run_fake(transform)
                self.assertTrue(changed)
                self.assert_clean()

    def test_duplicate_snapshot_mismatch_fails(self):
        imports = 0

        def transform(argv, result):
            nonlocal imports
            if _invocation(argv)[2][0] == "import-feed":
                imports += 1
                if imports == 2:
                    value = json.loads(result.stdout)
                    value["snapshot_id"] = "f" * 64
                    return CommandResult(0, core.canonical(value), "")
            return result

        with self.assertRaises(core.AutoprotectError):
            self.run_fake(transform)
        self.assert_clean()

    def test_retained_gate_and_generation_resolution_claims_are_checked(self):
        for field, wrong in (("gate", None), ("verified", True), ("target_generation", "0" * 64)):
            with self.subTest(field=field):
                changed = []

                def transform(argv, result):
                    state, _, arguments = _invocation(argv)
                    selected = ((field == "gate" and arguments[0] == "recovery-status")
                                or (field != "gate" and arguments[0] == "resolve-recovery"))
                    if selected and state.name == "after-write" and result.returncode == 0:
                        value = json.loads(result.stdout)
                        value[field] = wrong
                        changed.append(True)
                        return CommandResult(0, core.canonical(value), "")
                    return result

                with self.assertRaises(core.AutoprotectError):
                    self.run_fake(transform)
                self.assertTrue(changed)
                self.assert_clean()

    def test_review_predispatch_unrelated_errors_fail_each_denial(self):
        cases = (("manual", "execute", 1), ("manual", "execute", 3),
                 ("auto", "execute", 2), ("after-write", "execute", 2),
                 ("after-write", "plan", 3), ("after-write", "execute", 3))
        for case in cases:
            for code in ("io_error", "internal_error"):
                with self.subTest(case=case, code=code):
                    fake = _InProcessCLI()
                    dispatch = fake.run
                    counts = {}
                    intercepted = []

                    def run(argv, **kwargs):
                        state, _, arguments = _invocation(argv)
                        key = (state.name, arguments[0])
                        counts[key] = counts.get(key, 0) + 1
                        if (*key, counts[key]) == case:
                            # Deliberately do not call dispatch or Engine. The
                            # intended policy/gate check never ran in this case.
                            intercepted.append(True)
                            return CommandResult(1, "", core.canonical({"error": {
                                "code": code, "message": "Synthetic unrelated failure before dispatch"}}))
                        return dispatch(argv, **kwargs)

                    fake.run = run
                    with patch.object(demo, "Runner", return_value=fake):
                        with self.assertRaises(core.AutoprotectError):
                            demo.run_demo()
                    self.assertEqual(intercepted, [True])
                    self.assert_clean()

    def test_review_matching_error_before_dispatch_requires_new_audit(self):
        # Actual Engine reasons, not plausible-looking error text. The retained
        # gate path is excluded: it fails before Engine's audit transaction.
        cases = (("manual", "execute", 1,
                  "Manual execution requires explicit approval of this immutable plan"),
                 ("manual", "execute", 3,
                  "Plan is final or already claimed; collect and create a new plan"),
                 ("auto", "execute", 2,
                  "Plan is final or already claimed; collect and create a new plan"),
                 ("after-write", "plan", 3,
                  "Collection context or recovery generation changed; collect fresh backend inventory before planning"),
                 ("after-write", "execute", 3,
                  "Plan recovery generation changed; collect, create a new plan, and renew authorization"))
        for scenario, command, occurrence, reason in cases:
            with self.subTest(scenario=scenario, command=command, occurrence=occurrence):
                fake = _InProcessCLI()
                dispatch = fake.run
                counts = {}
                intercepted = []

                def run(argv, **kwargs):
                    state, _, arguments = _invocation(argv)
                    key = (state.name, arguments[0])
                    counts[key] = counts.get(key, 0) + 1
                    if (*key, counts[key]) == (scenario, command, occurrence):
                        intercepted.append(True)
                        return CommandResult(1, "", core.canonical({"error": {
                            "code": "policy_error", "message": reason}}))
                    return dispatch(argv, **kwargs)

                fake.run = run
                with patch.object(demo, "Runner", return_value=fake):
                    with self.assertRaises(core.AutoprotectError):
                        demo.run_demo()
                self.assertEqual(intercepted, [True])
                self.assert_clean()

    def test_denial_requires_a_new_matching_audit_event_not_old_evidence(self):
        reason = "Manual execution requires explicit approval of this immutable plan"
        details = {"action": "execute", "plan_id": "a" * 64, "reason": reason}
        previous = {"id": 1, "at": 100, "event": "action-denied", "details": details}
        fresh = {**previous, "id": 2}
        scenario = demo._Scenario.__new__(demo._Scenario)
        scenario.state, scenario.policy = self.parent / "unused", self.sentinel
        scenario.commands = Mock()
        error = {"error": {"code": "policy_error", "message": reason}}
        invalid = (
            [previous],  # The matching denial existed before this action.
            [previous, previous],  # An appended copy of the old ID is not new.
            [previous, {**fresh, "details": {**details, "plan_id": "b" * 64}}],
            [previous, {**fresh, "details": {**details, "reason": "Unrelated denial"}}],
            [previous, {**fresh, "details": {**details, "action": "approve"}}],
            [previous, {**fresh, "event": "execution-start"}],
            [previous, fresh, {**fresh, "id": 3}],
            [{**previous, "at": 101}, fresh],  # Earlier evidence was rewritten.
        )
        for after in invalid:
            with self.subTest(after=after):
                scenario.commands.call.side_effect = [[previous], error, after]
                with self.assertRaises(core.AutoprotectError):
                    scenario.denied("execute", "a" * 64, reason="unapproved")
        scenario.commands.call.side_effect = [[previous], error, [previous, fresh]]
        scenario.denied("execute", "a" * 64, reason="unapproved")

    def test_retained_gate_denial_does_not_require_nonexistent_engine_audit(self):
        scenario = demo._Scenario.__new__(demo._Scenario)
        scenario.state, scenario.policy = self.parent / "unused", self.sentinel
        scenario.commands = Mock()
        scenario.denied("execute", "a" * 64, reason="gate")
        scenario.commands.call.assert_called_once_with(
            scenario.state, scenario.policy, "execute", "a" * 64, expect="denied", denial="gate")

    def test_cleanup_and_bounded_error_after_command_failure(self):
        runner = Mock()
        runner.run.side_effect = OSError("SECRET child path and raw stderr")
        with patch.object(demo, "Runner", return_value=runner):
            with self.assertRaises(core.AutoprotectError) as caught:
                demo.run_demo()
        self.assertEqual(str(caught.exception), demo._ERROR)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assert_clean()

    def test_cleanup_after_interrupt(self):
        runner = Mock()
        runner.run.side_effect = KeyboardInterrupt
        with patch.object(demo, "Runner", return_value=runner):
            with self.assertRaises(KeyboardInterrupt):
                demo.run_demo()
        self.assert_clean()

    def test_late_failure_and_interrupt_remove_retained_temporary_gate(self):
        for failure in (OSError("SECRET late failure"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                reached = []
                fake = _InProcessCLI()
                dispatch = fake.run

                def run(argv, **kwargs):
                    state, _, arguments = _invocation(argv)
                    if arguments[0] == "resolve-recovery":
                        gate = state / "simulator.json.gate"
                        self.assertTrue(gate.is_file())
                        reached.append(True)
                        raise failure
                    return dispatch(argv, **kwargs)

                fake.run = run
                with patch.object(demo, "Runner", return_value=fake):
                    with self.assertRaises(KeyboardInterrupt if isinstance(failure, KeyboardInterrupt)
                                           else core.AutoprotectError):
                        demo.run_demo()
                self.assertTrue(reached)
                self.assert_clean()

    def test_summary_overflow_fails_after_cleanup(self):
        with patch.object(demo, "_MAX_SUMMARY", 1):
            with self.assertRaises(core.AutoprotectError):
                self.run_fake()
        self.assert_clean()

    def test_cleanup_after_fixture_setup_error(self):
        write = demo._write_fixtures

        def fail(root):
            write(root)
            raise OSError("SECRET fixture setup failure")

        with patch.object(demo, "_write_fixtures", side_effect=fail), patch.object(demo, "Runner") as runner:
            with self.assertRaises(core.AutoprotectError) as caught:
                demo.run_demo()
        self.assertEqual(str(caught.exception), demo._ERROR)
        runner.assert_not_called()
        self.assert_clean()

    def test_cleanup_failure_does_not_report_success(self):
        # A fake context avoids leaking real fixture state while exercising the
        # cleanup-error path. No summary may claim that removal succeeded.
        manager = Mock()
        manager.__enter__ = Mock(return_value=str(self.parent / "not-created"))
        manager.__exit__ = Mock(side_effect=OSError("SECRET cleanup failure"))
        with patch.object(demo.tempfile, "TemporaryDirectory", return_value=manager), \
             patch.object(demo, "_write_fixtures", return_value={}), \
             patch.object(demo, "_Commands"), patch.object(demo, "_success"), \
             patch.object(demo, "_before_write"), patch.object(demo, "_after_write"):
            with self.assertRaises(core.AutoprotectError) as caught:
                demo.run_demo()
        self.assertEqual(str(caught.exception), demo._ERROR)


class DemoColdPackageTests(unittest.TestCase):
    """Real bounded child commands against a writable, cache-free package copy."""

    def test_review_cold_package_child_creates_no_bytecode(self):
        with tempfile.TemporaryDirectory(prefix="demo-cold-package-") as temporary:
            root = Path(temporary)
            source = root / "source"
            package = source / "autoprotect"
            shutil.copytree(Path(demo.__file__).parent, package,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            before = {path.relative_to(source): path.read_bytes()
                      for path in source.rglob("*") if path.is_file()}
            self.assertFalse(list(package.rglob("__pycache__")))
            with tempfile.TemporaryDirectory(prefix="generated-demo-", dir=root) as generated:
                owned = Path(generated)
                fixtures = demo._write_fixtures(owned)
                state = owned / "manual"
                state.mkdir(mode=0o700)
                # The reviewed Runner intentionally drops this inherited env
                # flag. Only the demo's child interpreter argv can prevent pyc.
                with patch.dict(os.environ, {"PYTHONDONTWRITEBYTECODE": "1"}), \
                     patch.object(demo, "__file__", str(package / "demo.py")):
                    commands = demo._Commands()
                    initialized = commands.call(state, fixtures["manual"], "init-simulator",
                                                "--inventory", str(fixtures["inventory"]),
                                                "--catalog", str(fixtures["catalog"]))
                    observed = commands.call(state, fixtures["manual"], "inventory")
                self.assertEqual(initialized["status"], "initialized")
                self.assertEqual(observed["body"]["collector"], "simulator")
                self.assertEqual(observed["body"]["asset_id"], demo._ASSET)
            self.assertFalse(owned.exists())
            self.assertFalse(list(package.rglob("__pycache__")))
            self.assertFalse(list(package.rglob("*.pyc")))
            self.assertEqual(before, {path.relative_to(source): path.read_bytes()
                                      for path in source.rglob("*") if path.is_file()})


class DemoCLIIntegrationTests(unittest.TestCase):
    """Full command matrix; run after the explicitly stable CLI handoff.

    Not part of the Unit selection. This deliberately runs actual separate CLI
    processes and fails rather than skipping if packaging or dispatch is absent.
    """

    def test_real_cli_disposable_demo(self):
        result = demo.run_demo()
        self.assertEqual(result["commands_run"], 101)
        self.assertTrue(result["synthetic"])
        self.assertTrue(result["cleanup"]["temporary_state_removed"])
        self.assertFalse(result["cleanup"]["caller_state_used"])
        self.assertEqual(result["scenarios"]["manual"]["status"], "succeeded")
        self.assertEqual(result["scenarios"]["automatic"]["status"], "succeeded")
        self.assertEqual(result["scenarios"]["before_write"]["status"], "failed")
        self.assertEqual(result["scenarios"]["after_write"]["status"], "needs_attention")
        self.assertEqual(result["scenarios"]["after_write"]["recovery"]["old_approved_plan"], "stale")
        self.assertLessEqual(len(core.canonical(result)), demo._MAX_SUMMARY)


if __name__ == "__main__":
    unittest.main()
