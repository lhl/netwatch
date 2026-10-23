"""Bounded POSIX command execution, without shell or inherited environment.

This runner does not authorize commands. Callers choose fixed executables and
validated arguments. A failed startup handshake does not prove that execution
never began. Startup, timeout or I/O failures are IndeterminateError: callers
must not assume that mutation did not occur.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import math
import os
import selectors
import signal
import stat
import subprocess
import threading
import time

from .core import BackendError, IndeterminateError, ValidationError, integer

_FRONTEND_LOCK_PATH = "/var/lib/dpkg/lock-frontend"
# After the command itself exits, wait at most this long for descendants that
# inherited its output pipes before treating the output as complete.
_PIPE_GRACE = 1.0
# POSIX record locks are process-wide: opening and closing a second descriptor
# for the same inode could drop the first lock. Never enter a second context.
_FRONTEND_GUARD = threading.Lock()


@dataclass(frozen=True)
class _FrontendLock:
    descriptor: int
    device: int
    inode: int
    pid: int
    thread: int


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@contextmanager
def _defer_sigint():
    """Defer a Python SIGINT handler without blocking SIGINT in the child.

    Popen's native spawn returns before Python stores the PID. Raising in that
    interval loses the only process handle. Python dispatches signals only in
    the main thread; other threads do not need this guard. The caller explicitly
    delivers pending interrupts only inside its cleanup-protected body. Keep
    deferral active through cleanup, including the transition into finally.
    Do not change an ignored signal or a terminating default action.
    """
    handler = signal.getsignal(signal.SIGINT)
    if threading.current_thread() is not threading.main_thread() or not callable(handler):
        yield lambda: None
        return
    pending = []

    def defer(signum, frame):
        if not pending:
            pending.append((signum, frame))

    def deliver():
        if pending:
            handler(*pending.pop())

    try:
        signal.signal(signal.SIGINT, defer)
        yield deliver
    finally:
        signal.signal(signal.SIGINT, handler)
        deliver()


class _CommandProcess(subprocess.Popen):
    """Allocate ownership before starting Popen's fallible initialization."""

    def __init__(self):
        self.pid = None
        self.stdout = None
        self.stderr = None
        self.returncode = None

    def start(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def stop(self, *, kill=True):
        try:
            if self.pid is not None and kill:
                try:
                    # Include descendants even when their leader already exited.
                    os.killpg(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    # Interrupted startup may precede setsid() in the child.
                    # Never signal the parent's process group in that case.
                    if self.returncode is None:
                        try:
                            os.kill(self.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        # The child could have called setsid() between the
                        # failed group lookup and the leader-directed kill.
                        try:
                            os.killpg(self.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
        except OSError as exc:
            raise IndeterminateError("command process group could not be stopped; inspect surviving processes") from exc
        finally:
            try:
                for stream in (self.stdout, self.stderr):
                    if stream is not None:
                        stream.close()
            finally:
                if self.pid is not None:
                    try:
                        self.wait(timeout=1)
                    except subprocess.TimeoutExpired as exc:
                        raise IndeterminateError("command cleanup did not finish; inspect surviving processes") from exc


class Runner:
    """Execute argument arrays with a combined stdout/stderr byte limit.

    The default output limit is 16 MiB; constructor-only overrides may set a
    limit from 1 byte through 64 MiB. Execution uses an elapsed deadline of up
    to 3600 seconds and a one-second cleanup wait. Native spawn/exec handshake
    itself cannot be forcibly timed out here. UTF-8 decoding replaces malformed
    bytes. All processes in the command's process group are killed on exit,
    including timeout, output overflow, and caller KeyboardInterrupt. Ownership
    begins before Popen initialization; SIGINT is delivered at protected checks
    at most 0.1 seconds apart during output/exit waits, and deferred through
    spawn and cleanup, without changing the child's signal mask.
    Cleanup requires Python exception unwinding: SIGKILL, interpreter/host
    crashes and terminating signal defaults cannot run it. Other custom signal
    handlers that raise during native spawn are not guarded. Deliberately
    detached descendants are outside process-group containment; this is not a
    sandbox for hostile executables. A durable recovery gate is still required.
    """

    def __init__(self, *, max_output_bytes: int = 16 * 1024 * 1024):
        self.max_output_bytes = integer(max_output_bytes, "max_output_bytes", minimum=1, maximum=64 * 1024 * 1024)
        self._frontend_lock = None

    @contextmanager
    def dpkg_frontend_lock(self):
        """Hold the fixed native frontend lock and enable dpkg lock handoff.

        Enter this context *instead of* separately opening/locking the frontend
        file. The lock is a nonblocking POSIX record lock, not flock(). It spans
        all commands issued by this runner until context exit. Only its owning
        process/thread receives DPKG_FRONTEND_LOCKED=true. The file must already
        exist, be regular, owned by the invoking user, and not group/world
        writable; the live backend must separately require root authorization.

        Do not open/close this inode elsewhere in this process: POSIX record
        locks are released by any close of the same file. The backend must use
        this context for preflight and installation, and keep its separate
        target/recovery gate. Recovery also needs the dpkg database lock; this
        context does not provide it. Tests patch _FRONTEND_LOCK_PATH to a private
        synthetic file. There is no runtime path or environment override.
        """
        if os.name != "posix":
            raise BackendError("dpkg frontend lock requires POSIX record locks")
        import fcntl

        if not _FRONTEND_GUARD.acquire(blocking=False):
            raise BackendError("dpkg frontend lock is already held by this process")
        descriptor = None
        try:
            try:
                descriptor = os.open(_FRONTEND_LOCK_PATH, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o022 or info.st_nlink != 1):
                    raise BackendError("dpkg frontend lock must be a private regular file owned by the invoking user")
                fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._frontend_lock = _FrontendLock(descriptor, info.st_dev, info.st_ino,
                                                    os.getpid(), threading.get_ident())
            except OSError as exc:
                raise BackendError("dpkg frontend lock is unavailable; check permissions and other package operations") from exc
            yield self
        finally:
            self._frontend_lock = None
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                _FRONTEND_GUARD.release()

    def _environment(self) -> dict[str, str]:
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": "/nonexistent",
            "DEBIAN_FRONTEND": "noninteractive",
        }
        lock = self._frontend_lock
        if lock is not None:
            if lock.pid != os.getpid() or lock.thread != threading.get_ident():
                raise BackendError("dpkg frontend lock belongs to another process or thread")
            try:
                descriptor_info = os.fstat(lock.descriptor)
                path_info = os.stat(_FRONTEND_LOCK_PATH, follow_symlinks=False)
            except OSError as exc:
                raise BackendError("dpkg frontend lock descriptor or path changed") from exc
            if any(not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (lock.device, lock.inode)
                   for info in (descriptor_info, path_info)):
                raise BackendError("dpkg frontend lock descriptor or path changed")
            environment["DPKG_FRONTEND_LOCKED"] = "true"
        return environment

    def run(self, argv, *, timeout=60, cwd=None, keep_descendants=False) -> CommandResult:
        """Run an absolute executable; return nonzero exit codes without output in errors.

        By default every process in the command's group is killed when it
        returns. ``keep_descendants=True`` leaves descendants running only after
        the command itself exited normally (for example services started by
        package maintainer scripts); timeouts, output overflow, interrupts and
        errors still kill the whole group. Descendants that keep the command's
        output pipes open lose them after a one-second grace period.

        Validation and environment checks run before spawn. Once startup is
        attempted, an OSError/ValueError or subprocess handshake failure raises
        IndeterminateError, even when it resembles a missing executable: Popen
        does not expose a reliable pre-execution failure flag. KeyboardInterrupt
        propagates after cleanup, not as proof that execution never began.
        Consumers decide whether their operation was read-only or may require
        recovery. The default working directory is ``/``.
        """
        if not isinstance(argv, (list, tuple)) or not 1 <= len(argv) <= 256:
            raise ValidationError("command must be an argument array of 1 to 256 strings")
        command = list(argv)
        if any(not isinstance(arg, str) or "\0" in arg or len(arg) > 32768 for arg in command):
            raise ValidationError("command arguments must be bounded strings without NUL bytes")
        try:
            if sum(len(arg.encode("utf-8")) + 1 for arg in command) > 128 * 1024:
                raise ValidationError("command arguments exceed the byte limit")
        except UnicodeError as exc:
            raise ValidationError("command arguments must be valid UTF-8") from exc
        if not os.path.isabs(command[0]):
            raise ValidationError("command executable must be an absolute path")
        if (type(timeout) not in (int, float) or not 0 < timeout <= 3600
                or not math.isfinite(timeout)):
            raise ValidationError("command timeout must be a finite number from above zero through 3600 seconds")
        directory = "/" if cwd is None else cwd
        if not isinstance(directory, str) or not os.path.isabs(directory) or "\0" in directory or len(directory) > 4096:
            raise ValidationError("command working directory must be a bounded absolute path")
        try:
            directory.encode("utf-8")
        except UnicodeError as exc:
            raise ValidationError("command working directory must be valid UTF-8") from exc
        if type(keep_descendants) is not bool:
            raise ValidationError("keep_descendants must be a boolean")
        if os.name != "posix":
            raise BackendError("command runner requires POSIX process groups")
        environment = self._environment()
        deadline = time.monotonic() + timeout
        output = [bytearray(), bytearray()]
        total = 0
        selector = None
        # No OS process exists yet. The same object remains reachable if
        # Popen.__init__ raises after creating a child but before returning.
        process = _CommandProcess()
        completed = False
        with _defer_sigint() as interrupt:
            try:
                try:
                    process.start(
                        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        cwd=directory, env=environment, shell=False, start_new_session=True,
                        close_fds=True, bufsize=0,
                    )
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    raise IndeterminateError("command startup could not be confirmed; inspect operation state before retrying") from exc
                interrupt()
                selector = selectors.DefaultSelector()
                for stream, index in ((process.stdout, 0), (process.stderr, 1)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                exited_at = None
                while selector.get_map():
                    interrupt()
                    if exited_at is None and process.poll() is not None:
                        exited_at = time.monotonic()
                    remaining = deadline - time.monotonic()
                    # A command that exited within its deadline is complete even
                    # if its pipe grace would extend past that deadline.
                    if exited_at is not None and (remaining <= 0 or time.monotonic() - exited_at >= _PIPE_GRACE):
                        break  # The command exited; a descendant still holds an output pipe.
                    if remaining <= 0:
                        raise IndeterminateError("command exceeded its deadline; inspect operation state before retrying")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        # At most one byte beyond the cap is read to detect overflow.
                        try:
                            chunk = os.read(key.fd, min(65536, self.max_output_bytes - total + 1))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > self.max_output_bytes:
                            raise IndeterminateError("command exceeded its output limit; inspect operation state before retrying")
                        output[key.data].extend(chunk)
                while process.returncode is None:
                    interrupt()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise IndeterminateError("command exceeded its deadline; inspect operation state before retrying")
                    try:
                        process.wait(timeout=min(remaining, 0.1))
                    except subprocess.TimeoutExpired:
                        continue
                returncode = process.returncode
                # Descendants may be kept only after a successful exit.
                completed = returncode == 0
                return CommandResult(returncode, output[0].decode("utf-8", errors="replace"),
                                     output[1].decode("utf-8", errors="replace"))
            except OSError as exc:
                raise IndeterminateError("command output could not be read; inspect operation state before retrying") from exc
            finally:
                try:
                    process.stop(kill=not (keep_descendants and completed))
                finally:
                    if selector is not None:
                        selector.close()
