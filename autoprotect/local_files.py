"""Protected CLI paths; trusted owners can still modify their own local state.

No function changes permissions on an existing object or follows a symlink.
Descriptor-relative opens protect path traversal; the CLI must keep using the
returned private directory for SQLite. These checks are not an authorization
service, a database lock, or protection against the invoking user or root.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat

from .core import ValidationError, integer


_MAX_BYTES = 128 * 1024 * 1024


def _owner(live: bool) -> int:
    if type(live) is not bool:
        raise ValidationError("live mode must be a boolean")
    if os.name != "posix":
        raise ValidationError("protected local paths require POSIX file controls")
    uid = os.geteuid()
    if live and uid != 0:
        raise ValidationError("live operations require effective root ownership")
    return uid


def _path(value) -> Path:
    try:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or "\0" in raw or len(raw.encode("utf-8")) > 4096:
            raise ValueError()
        # Preserve '..' until each preceding component has been opened and
        # checked. abspath() here would erase symlink/missing/unsafe ancestors.
        return Path(os.path.join(os.getcwd(), raw))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValidationError("local path must be nonempty bounded UTF-8 text without NUL bytes") from exc


def _directory_info(info, *, protected: bool, owner: int, leaf: bool = False):
    if not stat.S_ISDIR(info.st_mode):
        raise ValidationError("local path component must be a directory")
    if not protected:
        return
    if leaf:
        if info.st_uid != owner or info.st_mode & 0o077:
            raise ValidationError("state directory must be owned by the invoking user with mode 0700 or stricter")
    else:
        if info.st_uid not in (0, owner):
            raise ValidationError("protected path ancestors must be owned by root or the invoking user")
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if info.st_mode & 0o022 and not sticky_root:
            raise ValidationError("protected path ancestors must not be writable by other users")


@contextmanager
def _directory(path: Path, *, protected: bool, owner: int, create_last: bool = False):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    descriptor = os.open("/", flags)
    try:
        _directory_info(os.fstat(descriptor), protected=protected, owner=owner)
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            try:
                next_fd = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create_last or index != len(parts) - 1:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass  # Validate the winning object's type, ownership and mode.
                next_fd = os.open(part, flags, dir_fd=descriptor)
            old_fd, descriptor = descriptor, next_fd
            os.close(old_fd)
            _directory_info(os.fstat(descriptor), protected=protected, owner=owner)
        yield descriptor
    finally:
        os.close(descriptor)


def _regular(info, *, private: bool, owner: int):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValidationError("local input must be a regular file with exactly one link")
    if private and (info.st_uid != owner or info.st_mode & 0o077):
        raise ValidationError("private file must be owned by the invoking user with mode 0600 or stricter")


def read_bytes(path, *, max_bytes: int, private: bool = False, live: bool = False) -> bytes:
    """Read one bounded, stable regular file; live mode always implies private.

    General imports need not have private ownership: they remain untrusted data.
    Policy callers must set private=True, and reload for every policy request.
    A changed size/time/metadata check rejects observed concurrent writes; this
    is not a snapshot guarantee against a malicious trusted owner.
    """
    owner = _owner(live)
    if type(private) is not bool:
        raise ValidationError("private-file mode must be a boolean")
    private = private or live
    integer(max_bytes, "file byte limit", minimum=1, maximum=_MAX_BYTES)
    target = _path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        with _directory(target.parent, protected=private, owner=owner) as parent:
            descriptor = os.open(target.name, flags, dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                _regular(before, private=private, owner=owner)
                if before.st_size > max_bytes:
                    raise ValidationError("local input exceeds its byte limit")
                data = bytearray()
                while True:
                    chunk = os.read(descriptor, min(65536, max_bytes - len(data) + 1))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > max_bytes:
                        raise ValidationError("local input exceeds its byte limit")
                after = os.fstat(descriptor)
                _regular(after, private=private, owner=owner)
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_uid", "st_mode")
                if any(getattr(before, key) != getattr(after, key) for key in fields):
                    raise ValidationError("local input changed while being read; retry with a stable file")
                return bytes(data)
            finally:
                os.close(descriptor)
    except OSError as exc:
        raise ValidationError("local input cannot be opened safely; check path, type and permissions") from exc


def prepare_database(directory, *, live: bool = False) -> Path:
    """Create/validate a private directory and fixed SQLite path, never truncate.

    Parent directories must exist. Existing database and sidecar objects are
    checked without changing them. The protected directory prevents other users
    from swapping paths after this function returns; its owner remains trusted.
    SQLite must still implement locking, transactions and schema validation.
    """
    owner = _owner(live)
    target = _path(directory)
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        with _directory(target, protected=True, owner=owner, create_last=True) as parent:
            _directory_info(os.fstat(parent), protected=True, owner=owner, leaf=True)
            for suffix in ("-wal", "-shm", "-journal", ""):
                name = "state.sqlite3" + suffix
                created = False
                try:
                    descriptor = os.open(name, flags, dir_fd=parent)
                except FileNotFoundError:
                    if suffix:
                        continue
                    try:
                        descriptor = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
                        created = True
                    except FileExistsError:
                        descriptor = os.open(name, flags, dir_fd=parent)
                try:
                    _regular(os.fstat(descriptor), private=True, owner=owner)
                    if created:
                        os.fsync(descriptor)
                        os.fsync(parent)
                finally:
                    os.close(descriptor)
    except OSError as exc:
        raise ValidationError("state cannot be opened safely; check existing parents, ownership and permissions") from exc
    # Traversal has now established that no component is a symlink and every
    # parent exists. Lexical normalization is safe only after those checks.
    return Path(os.path.abspath(target)) / "state.sqlite3"
