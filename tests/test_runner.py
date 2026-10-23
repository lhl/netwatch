from contextlib import ExitStack
import errno
import json
import math
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from autoprotect.core import BackendError, IndeterminateError, ValidationError
from autoprotect.runner import CommandResult, Runner


PYTHON = os.path.abspath(sys.executable)


class RunnerTests(unittest.TestCase):
    def test_result_and_safe_decoding(self):
        result = Runner().run([PYTHON, "-c", "import os; os.write(1, b'out\\xff'); os.write(2, b'err\\xfe'); raise SystemExit(7)"])
        self.assertEqual(result, CommandResult(7, "out\ufffd", "err\ufffd"))

    def test_minimal_environment_and_controlled_process_options(self):
        poisoned = {"APT_CONFIG": "/bad", "LD_PRELOAD": "/bad", "PYTHONPATH": "/bad",
                    "BASH_ENV": "/bad", "DPKG_FRONTEND_LOCKED": "true", "SECRET": "private"}
        with patch.dict(os.environ, poisoned), patch("autoprotect.runner.subprocess.Popen.__init__", autospec=True, side_effect=subprocess.Popen.__init__) as popen:
            result = Runner().run([PYTHON, "-c", "import os,json; print(json.dumps(dict(os.environ))); print(os.getcwd()); print(input() if False else '')"])
        lines = result.stdout.splitlines()
        environment = json.loads(lines[0])
        self.assertFalse(set(poisoned) & set(environment))
        self.assertEqual(environment["LC_ALL"], "C.UTF-8")
        self.assertEqual(environment["DEBIAN_FRONTEND"], "noninteractive")
        self.assertEqual(environment["HOME"], "/nonexistent")
        self.assertEqual(lines[1], "/")
        options = popen.call_args.kwargs
        self.assertIs(options["shell"], False)
        self.assertIs(options["start_new_session"], True)
        self.assertIs(options["close_fds"], True)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)

    def test_sigint_handler_and_child_signal_mask_are_preserved(self):
        handler = signal.getsignal(signal.SIGINT)
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        result = Runner().run([
            PYTHON, "-c",
            "import signal; print(signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, []))",
        ])
        self.assertEqual(result.stdout, str(signal.SIGINT in blocked) + "\n")
        self.assertIs(signal.getsignal(signal.SIGINT), handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), blocked)

    def test_runner_can_start_from_non_main_thread(self):
        results = []
        errors = []

        def run():
            try:
                results.append(Runner().run([PYTHON, "-c", "print('worker')"], timeout=2))
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, [CommandResult(0, "worker\n", "")])

    def test_explicit_absolute_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Runner().run([PYTHON, "-c", "import os; print(os.getcwd())"], cwd=directory)
            self.assertEqual(result.stdout.strip(), directory)

    def test_shell_metacharacters_remain_a_single_argument(self):
        payload = "$(echo injected); `id` && --option='quoted'"
        result = Runner().run([PYTHON, "-c", "import sys; print(sys.argv[1])", payload])
        self.assertEqual(result.stdout, payload + "\n")

    def test_stdin_is_closed(self):
        result = Runner().run([PYTHON, "-c", "import sys; print(repr(sys.stdin.read()))"])
        self.assertEqual(result.stdout, "''\n")

    def test_argument_and_timeout_validation_occurs_before_start(self):
        invalid = [
            ([], {}), ("/bin/true", {}), (["relative"], {}), (["/bin/true", None], {}),
            (["/bad\x00"], {}), (["/bin/true", "bad\x00"], {}),
            (["/bin/true"] * 257, {}), (["/bin/true", "x" * 32769], {}),
            (["/bin/true"] + ["x" * 32768] * 5, {}),
            (["/bin/true"], {"cwd": "."}), (["/bin/true"], {"cwd": "/bad\x00"}),
            (["/bin/true", "\ud800"], {}), (["/bin/true"], {"cwd": "/\ud800"}),
        ]
        invalid.extend((["/bin/true"], {"timeout": t}) for t in (0, -1, True, "1", math.nan, math.inf, 3601, 10**1000))
        with patch("autoprotect.runner.subprocess.Popen.__init__", autospec=True) as popen:
            for argv, kwargs in invalid:
                with self.subTest(argv=str(argv)[:40], kwargs=kwargs), self.assertRaises(ValidationError):
                    Runner().run(argv, **kwargs)
            popen.assert_not_called()
        for limit in (0, -1, True, 1.0, 64 * 1024 * 1024 + 1):
            with self.subTest(limit=limit), self.assertRaises(ValidationError):
                Runner(max_output_bytes=limit)

    def test_unconfirmed_start_failure_is_bounded_indeterminate_error(self):
        with self.assertRaises(IndeterminateError) as caught:
            Runner().run(["/autoprotect-nonexistent/secret\x1b"])
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("\x1b", str(caught.exception))
        with self.assertRaises(IndeterminateError):
            Runner().run([PYTHON, "-c", "pass"], cwd="/autoprotect-nonexistent")

    def test_combined_output_limit_is_bytes_and_is_inclusive(self):
        result = Runner(max_output_bytes=10).run([PYTHON, "-c", "import os; os.write(1,b'a'*5); os.write(2,b'b'*5)"])
        self.assertEqual(result, CommandResult(0, "a" * 5, "b" * 5))
        for script in ("os.write(1,b'a'*11)", "os.write(2,b'b'*11)",
                       "os.write(1,b'a'*6); os.write(2,b'b'*5)", "os.write(1, ('\u00e9'*6).encode())"):
            with self.subTest(script=script), self.assertRaisesRegex(IndeterminateError, "output"):
                Runner(max_output_bytes=10).run([PYTHON, "-c", "import os; " + script])

    def test_large_both_streams_do_not_deadlock(self):
        result = Runner(max_output_bytes=400_000).run([
            PYTHON, "-c", "import os; os.write(1,b'a'*100000); os.write(2,b'b'*100000); os.write(1,b'c'*100000)"
        ], timeout=3)
        self.assertEqual(len(result.stdout), 200_000)
        self.assertEqual(len(result.stderr), 100_000)

    def test_deadline_applies_even_when_both_pipes_close(self):
        started = time.monotonic()
        with self.assertRaisesRegex(IndeterminateError, "deadline"):
            Runner().run([PYTHON, "-c", "import os,signal; os.close(1); os.close(2); signal.pause()"], timeout=0.2)
        self.assertLess(time.monotonic() - started, 2)

    def test_continuous_output_does_not_refresh_deadline(self):
        started = time.monotonic()
        with self.assertRaisesRegex(IndeterminateError, "deadline"):
            Runner().run([PYTHON, "-c", "import os,select\nwhile True:\n os.write(1,b'x'); select.select([],[],[],0.01)"], timeout=0.2)
        self.assertLess(time.monotonic() - started, 2)

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX fork is needed for the descendant test")
    def test_finished_leader_completes_but_descendant_is_still_killed(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
            socket_path = str(Path(directory) / "child.sock")
            pidfile = Path(directory) / "child.pid"
            listener.bind(socket_path)
            listener.listen(1)
            listener.settimeout(2)
            script = (
                "import os,signal,socket,sys\n"
                "pid=os.fork()\n"
                "if pid:\n os._exit(0)\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])\n"
                "with open(sys.argv[2],'w') as f: f.write(str(os.getpid()))\n"
                "signal.pause()\n"
            )
            try:
                # The leader exited inside its deadline, so the command is
                # complete; its pipe-holding descendant is still killed.
                result = Runner().run([PYTHON, "-c", script, socket_path, str(pidfile)], timeout=0.3)
                self.assertEqual(result.returncode, 0)
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    self.assertEqual(connection.recv(1), b"", "runner left a live descendant")
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX fork is needed for the descendant test")
    def test_descendant_holding_pipes_after_success_is_bounded_and_optionally_kept(self):
        # A daemon started by the command inherits its stdout and keeps running.
        script = ("import os,signal,sys\n"
                  "pid=os.fork()\n"
                  "if pid:\n open(sys.argv[1],'w').write(str(pid)); print('done', flush=True); os._exit(0)\n"
                  "signal.pause()\n")
        for keep in (False, True):
            with self.subTest(keep=keep), tempfile.TemporaryDirectory() as directory:
                pidfile = Path(directory) / "daemon.pid"
                started = time.monotonic()
                try:
                    result = Runner().run([PYTHON, "-c", script, str(pidfile)], timeout=30, keep_descendants=keep)
                    self.assertEqual(result, CommandResult(0, "done\n", ""))
                    self.assertLess(time.monotonic() - started, 5)
                    daemon = int(pidfile.read_text())
                    deadline = time.monotonic() + 2
                    alive = True
                    while alive and time.monotonic() < deadline:
                        try:
                            os.kill(daemon, 0)
                            if keep:
                                break
                            time.sleep(0.02)
                        except ProcessLookupError:
                            alive = False
                    self.assertEqual(alive, keep)
                finally:
                    if pidfile.exists():
                        try:
                            os.kill(int(pidfile.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_nonzero_exit_kills_descendants_even_when_keeping_was_requested(self):
        script = ("import os,signal,sys\n"
                  "pid=os.fork()\n"
                  "if pid:\n open(sys.argv[1],'w').write(str(pid)); os._exit(3)\n"
                  "os.close(1); os.close(2); signal.pause()\n")
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "daemon.pid"
            try:
                result = Runner().run([PYTHON, "-c", script, str(pidfile)], timeout=10, keep_descendants=True)
                self.assertEqual(result.returncode, 3)
                daemon = int(pidfile.read_text())
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        os.kill(daemon, 0)
                        time.sleep(0.02)
                    except ProcessLookupError:
                        break
                else:
                    self.fail("descendant of a failed command survived")
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_failures_kill_descendants_even_when_keeping_was_requested(self):
        with patch("autoprotect.runner.os.killpg", wraps=os.killpg) as killpg:
            with self.assertRaises(IndeterminateError):
                Runner(max_output_bytes=10).run([PYTHON, "-c", "import os,signal; os.write(1,b'x'*100); signal.pause()"],
                                                keep_descendants=True)
            self.assertTrue(killpg.called)
        with self.assertRaises(ValidationError):
            Runner().run([PYTHON, "-c", "pass"], keep_descendants="yes")

    def test_output_limit_kills_the_process_group(self):
        with patch("autoprotect.runner.os.killpg", wraps=os.killpg) as killpg:
            with self.assertRaises(IndeterminateError):
                Runner(max_output_bytes=10).run([PYTHON, "-c", "import os,signal; os.write(1,b'x'*100); signal.pause()"])
            self.assertTrue(killpg.called)
            self.assertEqual(killpg.call_args.args[1], signal.SIGKILL)

    def test_interrupt_kills_and_reaps_started_process(self):
        with patch("autoprotect.runner.selectors.DefaultSelector.select", side_effect=KeyboardInterrupt), \
             patch("autoprotect.runner.os.killpg", wraps=os.killpg) as killpg, \
             patch("autoprotect.runner.subprocess.Popen.__init__", autospec=True, side_effect=subprocess.Popen.__init__) as popen:
            with self.assertRaises(KeyboardInterrupt):
                Runner().run([PYTHON, "-c", "import signal; signal.pause()"])
            self.assertTrue(killpg.called)
            self.assertTrue(popen.called)


class FrontendLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "lock-frontend"
        self.path.touch(mode=0o600)
        self.patcher = patch("autoprotect.runner._FRONTEND_LOCK_PATH", str(self.path))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_environment_exists_only_while_real_posix_lock_is_held(self):
        runner = Runner()
        code = "import os; print(os.environ.get('DPKG_FRONTEND_LOCKED', 'absent'))"
        contender = (
            "import fcntl,sys\nf=open(sys.argv[1], 'r+')\n"
            "try: fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "except BlockingIOError: raise SystemExit(42)\n"
        )
        self.assertEqual(runner.run([PYTHON, "-c", code]).stdout, "absent\n")
        with runner.dpkg_frontend_lock() as locked:
            self.assertIs(locked, runner)
            self.assertEqual(runner.run([PYTHON, "-c", code]).stdout, "true\n")
            self.assertEqual(runner.run([PYTHON, "-c", contender, str(self.path)]).returncode, 42)
            # A different runner cannot claim the other instance's lock.
            self.assertEqual(Runner().run([PYTHON, "-c", code]).stdout, "absent\n")
        self.assertEqual(runner.run([PYTHON, "-c", code]).stdout, "absent\n")
        self.assertEqual(runner.run([PYTHON, "-c", contender, str(self.path)]).returncode, 0)
        self.assertNotIn("DPKG_FRONTEND_LOCKED", os.environ)

    def test_existing_external_frontend_lock_is_not_bypassed(self):
        script = (
            "import fcntl,sys\nf=open(sys.argv[1],'r+')\n"
            "fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
            "print('locked',flush=True)\nsys.stdin.read()\n"
        )
        process = subprocess.Popen([PYTHON, "-c", script, str(self.path)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline(), "locked\n")
            with self.assertRaisesRegex(BackendError, "frontend lock"):
                with Runner().dpkg_frontend_lock():
                    self.fail("entered without acquiring the frontend lock")
        finally:
            process.communicate(timeout=2)
        with Runner().dpkg_frontend_lock():
            pass

    def test_nested_or_competing_same_process_context_cannot_drop_lock(self):
        runner = Runner()
        with runner.dpkg_frontend_lock():
            for other in (runner, Runner()):
                with self.assertRaises(BackendError):
                    with other.dpkg_frontend_lock():
                        self.fail("nested POSIX lock context was permitted")
            self.assertEqual(runner._environment()["DPKG_FRONTEND_LOCKED"], "true")

    def test_lock_released_after_exception_and_wrong_owner_cannot_use_it(self):
        runner = Runner()
        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            with runner.dpkg_frontend_lock():
                with patch("autoprotect.runner.os.getpid", return_value=-1):
                    with self.assertRaises(BackendError):
                        runner._environment()
                errors = []
                def other_thread():
                    try:
                        runner._environment()
                    except BackendError as exc:
                        errors.append(exc)
                thread = threading.Thread(target=other_thread)
                thread.start()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(errors), 1)
                raise RuntimeError("synthetic body failure")
        self.assertNotIn("DPKG_FRONTEND_LOCKED", runner._environment())
        with runner.dpkg_frontend_lock():
            pass

    def _assert_startup_cleanup(self, fault, expected_exception):
        """Inject once around real spawn; even red tests reap their children."""
        runner = Runner()
        processes = []
        spawned_pids = []
        lock_fd = [None]
        release_observations = []
        connections = []
        injected = []
        group_lookup_missed = []
        real_init = subprocess.Popen.__init__
        real_read = os.read
        real_close = os.close
        real_fork_exec = subprocess._fork_exec
        real_killpg = os.killpg
        real_select = selectors.DefaultSelector.select
        real_wait = subprocess.Popen.wait
        handler = signal.getsignal(signal.SIGINT)
        previous_trace = sys.gettrace()
        socket_path = str(Path(self.temporary.name) / "startup.sock")
        script = (
            "import os,signal,socket,sys\n"
            + ("if os.fork(): signal.pause(); os._exit(0)\n" if fault == "group-created-during-cleanup" else "")
            + "s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])\n"
            + ("os.close(1); os.close(2)\n" if fault == "sigint-during-exit-wait" else "")
            + "signal.pause()\n"
        )
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(socket_path)
            listener.listen(1)
            listener.settimeout(2)

            def ready():
                if not connections:
                    connection, _ = listener.accept()
                    connection.settimeout(2)
                    connections.append(connection)

            def record_init(process, *args, **kwargs):
                processes.append(process)
                return real_init(process, *args, **kwargs)

            def trace(frame, event, arg):
                if injected:
                    return trace
                process = frame.f_locals.get("process") if frame.f_code is Runner.run.__code__ else frame.f_locals.get("self")
                if not processes or process is not processes[0] or not getattr(process, "pid", None):
                    return trace
                hit = (
                    fault in ("runner-registration", "group-created-during-cleanup") and frame.f_code is Runner.run.__code__ and event == "line"
                    or fault == "popen-return" and frame.f_code is real_init.__code__ and event == "return"
                    or fault == "pid-registration" and frame.f_code is subprocess.Popen._execute_child.__code__ and event == "line"
                )
                if hit:
                    ready()
                    injected.append(fault)
                    raise KeyboardInterrupt("synthetic startup interruption")
                return trace

            def handshake_read(fd, count):
                frame = sys._getframe(1)
                if (fault == "handshake" and not injected
                        and frame.f_code is subprocess.Popen._execute_child.__code__
                        and fd == frame.f_locals.get("errpipe_read")):
                    ready()
                    injected.append(fault)
                    raise OSError(errno.EIO, "synthetic startup secret\x1b")
                return real_read(fd, count)

            def fork_exec(*args, **kwargs):
                pid = real_fork_exec(*args, **kwargs)
                spawned_pids.append(pid)
                if fault == "sigint-before-pid-registration" and not injected:
                    ready()
                    injected.append(fault)
                    os.kill(os.getpid(), signal.SIGINT)
                return pid

            def select(selector, timeout):
                if not injected and fault in ("sigint-during-cleanup", "sigint-during-output-wait"):
                    ready()
                    if fault == "sigint-during-cleanup":
                        raise KeyboardInterrupt("synthetic execution interruption")
                    injected.append(fault)
                    os.kill(os.getpid(), signal.SIGINT)
                return real_select(selector, timeout)

            def wait(process, *args, **kwargs):
                if fault == "sigint-during-exit-wait" and not injected:
                    ready()
                    injected.append(fault)
                    os.kill(os.getpid(), signal.SIGINT)
                return real_wait(process, *args, **kwargs)

            def killpg(pid, signum):
                if fault == "group-created-during-cleanup" and not group_lookup_missed:
                    group_lookup_missed.append(True)
                    raise ProcessLookupError("synthetic pre-setsid race")
                if fault == "sigint-during-cleanup" and not injected:
                    injected.append(fault)
                    os.kill(os.getpid(), signal.SIGINT)
                return real_killpg(pid, signum)

            def close(fd):
                if fd == lock_fd[0]:
                    process = processes[0] if processes else None
                    peer_stopped = False
                    if connections and getattr(process, "returncode", None) is not None:
                        try:
                            peer_stopped = connections[0].recv(1) == b""
                        except TimeoutError:
                            pass
                    release_observations.append((
                        getattr(process, "returncode", None),
                        all(stream is None or stream.closed for stream in
                            (getattr(process, "stdout", None), getattr(process, "stderr", None))),
                        peer_stopped,
                    ))
                return real_close(fd)

            try:
                with ExitStack() as patches:
                    patches.enter_context(patch.object(subprocess.Popen, "__init__", record_init))
                    patches.enter_context(patch("autoprotect.runner.os.read", handshake_read))
                    patches.enter_context(patch("autoprotect.runner.os.close", close))
                    patches.enter_context(patch("subprocess._fork_exec", fork_exec))
                    patches.enter_context(patch("autoprotect.runner.os.killpg", killpg))
                    patches.enter_context(patch("autoprotect.runner.selectors.DefaultSelector.select", select))
                    patches.enter_context(patch.object(subprocess.Popen, "wait", wait))
                    started = time.monotonic()
                    sys.settrace(trace)
                    try:
                        with self.assertRaises(expected_exception) as caught:
                            with runner.dpkg_frontend_lock():
                                lock_fd[0] = runner._frontend_lock.descriptor
                                runner.run([PYTHON, "-c", script, socket_path], timeout=3)
                    finally:
                        sys.settrace(previous_trace)
                self.assertIs(signal.getsignal(signal.SIGINT), handler)
                self.assertEqual(injected, [fault], "fault did not reach its intended startup boundary")
                self.assertEqual(len(release_observations), 1)
                returncode, streams_closed, peer_stopped = release_observations[0]
                self.assertIsNotNone(returncode, "frontend lock released before child was stopped and reaped")
                self.assertTrue(streams_closed, "frontend lock released before child pipes were closed")
                self.assertTrue(peer_stopped, "frontend lock released with a surviving command or descendant")
                self.assertLess(time.monotonic() - started, 2, "interrupt was delayed until the command deadline")
                self.assertEqual(connections[0].recv(1), b"", "runner left a live synthetic command")
                self.assertNotIn("secret", str(caught.exception))
                self.assertNotIn("\x1b", str(caught.exception))
                with runner.dpkg_frontend_lock():
                    pass
            finally:
                sys.settrace(previous_trace)
                # Explicit fallback keeps failing regression tests from leaking a child.
                for pid in spawned_pids:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for process in processes:
                    if getattr(process, "pid", None):
                        process.wait(timeout=2)
                    for stream in (getattr(process, "stdout", None), getattr(process, "stderr", None)):
                        if stream is not None:
                            stream.close()
                for pid in spawned_pids:
                    try:
                        os.waitpid(pid, 0)
                    except ChildProcessError:
                        pass
                for connection in connections:
                    connection.close()

    def test_interrupt_at_runner_handle_registration_cleans_before_unlock(self):
        self._assert_startup_cleanup("runner-registration", KeyboardInterrupt)

    def test_interrupt_before_popen_returns_cleans_before_unlock(self):
        self._assert_startup_cleanup("popen-return", KeyboardInterrupt)

    def test_interrupt_at_popen_pid_registration_cleans_before_unlock(self):
        self._assert_startup_cleanup("pid-registration", KeyboardInterrupt)

    def test_sigint_before_pid_registration_cleans_before_unlock(self):
        self._assert_startup_cleanup("sigint-before-pid-registration", KeyboardInterrupt)

    def test_handshake_error_is_indeterminate_and_cleans_before_unlock(self):
        self._assert_startup_cleanup("handshake", IndeterminateError)

    def test_second_sigint_during_cleanup_does_not_release_lock_early(self):
        self._assert_startup_cleanup("sigint-during-cleanup", KeyboardInterrupt)

    def test_sigint_during_output_wait_is_prompt_and_cleans_before_unlock(self):
        self._assert_startup_cleanup("sigint-during-output-wait", KeyboardInterrupt)

    def test_sigint_during_exit_wait_is_prompt_and_cleans_before_unlock(self):
        self._assert_startup_cleanup("sigint-during-exit-wait", KeyboardInterrupt)

    def test_startup_cleanup_handles_group_created_after_first_lookup(self):
        self._assert_startup_cleanup("group-created-during-cleanup", KeyboardInterrupt)

    def test_invalid_missing_symlink_and_replaced_lock_files_are_rejected(self):
        self.path.chmod(0o666)
        with self.assertRaises(BackendError):
            with Runner().dpkg_frontend_lock():
                pass
        self.path.unlink()
        with self.assertRaises(BackendError):
            with Runner().dpkg_frontend_lock():
                pass
        self.assertFalse(self.path.exists(), "runner must not create a missing native lock file")
        target = self.path.with_name("target")
        target.touch(mode=0o600)
        self.path.symlink_to(target)
        with self.assertRaises(BackendError):
            with Runner().dpkg_frontend_lock():
                pass
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaises(BackendError):
            with Runner().dpkg_frontend_lock():
                pass
        self.path.rmdir()
        self.path.touch(mode=0o600)
        runner = Runner()
        with runner.dpkg_frontend_lock():
            replacement = self.path.with_name("replacement")
            replacement.touch(mode=0o600)
            replacement.replace(self.path)
            with patch("autoprotect.runner.subprocess.Popen.__init__", autospec=True) as popen:
                with self.assertRaises(BackendError):
                    runner.run([PYTHON, "-c", "pass"])
                popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
