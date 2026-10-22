"""Disposable simulation and a single-package, opt-in Debian backend.

Backends enforce local invariants, not approvals. Engine owns authorization,
claim persistence and independent full-inventory verification. A retained gate
is never a retry lease. No import in this module requires python3-apt.
"""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tempfile
import threading

from .core import (BackendError, IndeterminateError, PolicyError, ValidationError,
                   canonical, identifier, integer, load_json, now, package_name, text, version)
from .debian import compare_versions
from .inventory import collect_local, inventory_fingerprint, normalize_inventory
from .local_files import _directory as _checked_directory, _directory_info, _path
from .runner import Runner

_TARGET_FIELDS = {"name", "architecture", "from_version", "to_version", "source_name",
                  "source_version", "sha256", "size", "origins", "config_digest", "metadata_digest"}
_ORIGIN_FIELDS = {"origin", "label", "archive", "codename", "component", "site"}
_CODENAMES = {"trixie", "trixie-updates", "trixie-security"}
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
_MAX_STATE_BYTES = 64 * 1024 * 1024
_MAX_GATE_BYTES = 4096
_INITIAL_GENERATION = "0" * 64
_COORDINATION_SUFFIXES = (".lock", ".gate", ".generation")
_NATIVE_STATE = Path("/var/lib/autoprotect/targets")
_DATABASE_LOCK = Path("/var/lib/dpkg/lock")
_DATABASE_GUARD = threading.Lock()
_PROBE = str(Path(__file__).with_name("_apt_probe.py").absolute())
_SENSITIVE = {"apt", "apt-utils", "dpkg", "libc6", "libc-bin", "systemd", "systemd-sysv",
              "udev", "init", "init-system-helpers", "sysvinit-core", "sysvinit-utils"}
_SENSITIVE_PREFIXES = ("linux-", "grub-", "shim-", "systemd-", "libapt-pkg", "initramfs-", "dracut")
_SENSITIVE_SOURCES = {"apt", "dpkg", "glibc", "systemd", "linux", "grub2", "shim", "initramfs-tools", "dracut", "sysvinit"}


def _hash(value, field="digest"):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _target(data):
    if not isinstance(data, dict) or set(data) != _TARGET_FIELDS:
        raise ValidationError("repository target fields do not match the exact schema")
    result = copy.deepcopy(data)
    for key in ("name", "source_name"):
        package_name(result[key], key)
    for key in ("from_version", "to_version", "source_version"):
        version(result[key], key)
    if result["architecture"] not in ("amd64", "all"):
        raise BackendError("only amd64 and architecture-independent packages are supported")
    for key in ("sha256", "config_digest", "metadata_digest"):
        _hash(result[key], key)
    integer(result["size"], "artifact size", minimum=1, maximum=MAX_ARTIFACT_BYTES)
    if compare_versions(result["to_version"], result["from_version"]) <= 0:
        raise BackendError("candidate binary version must strictly increase")
    origins = result["origins"]
    if not isinstance(origins, list) or not 1 <= len(origins) <= 32:
        raise ValidationError("target requires between one and 32 repository origins")
    for origin in origins:
        if not isinstance(origin, dict) or set(origin) != _ORIGIN_FIELDS:
            raise ValidationError("repository origin fields do not match the exact schema")
        for value in origin.values():
            text(value, "repository origin", max_length=256)
            if any(not 33 <= ord(c) <= 126 for c in value):
                raise ValidationError("repository origins must be printable ASCII without whitespace")
    if len({canonical(o) for o in origins}) != len(origins):
        raise ValidationError("target contains duplicate repository origins")
    return result


def _ready(inventory, collector):
    if not isinstance(inventory, dict) or inventory.get("collector") != collector:
        raise BackendError("inventory collector does not match the backend")
    normalized = normalize_inventory(inventory, collector=collector)
    if normalized != inventory:
        raise BackendError("backend requires a complete normalized inventory")
    if (inventory["os"], inventory["release"], inventory["architecture"]) != ("debian", "trixie", "amd64"):
        raise BackendError("backend supports only Debian trixie on amd64")
    if not inventory["complete"] or not inventory["packages"]:
        raise BackendError("complete nonempty inventory is required")
    if any(p["ecosystem"] != "deb" or p["status"] != "installed"
           or p["architecture"] not in ("amd64", "all") for p in inventory["packages"]):
        raise BackendError("inventory contains unsupported or non-ready package state")
    return normalized


def _package(inventory, name, architecture):
    matches = [p for p in inventory["packages"] if (p["name"], p["architecture"]) == (name, architecture)]
    if len(matches) != 1 or matches[0]["held"]:
        raise BackendError("target must be uniquely installed and not held")
    return matches[0]


def _policy(policy, inventory, package, backend, *, applying=False):
    if not isinstance(policy, dict) or policy.get("backend") != backend:
        raise PolicyError("policy does not select this backend")
    if applying and policy.get("mode") not in ("manual", "auto"):
        raise PolicyError("observation policy cannot mutate package state")
    if inventory["asset_id"] not in policy.get("allowed_assets", []):
        raise PolicyError("asset is not allowed by policy")
    if package["name"] not in policy.get("allowed_packages", []):
        raise PolicyError("package is not allowed by policy")
    if backend == "debian-apt":
        if any(policy.get(key) is not True for key in
               ("allow_maintainer_scripts", "recovery_confirmed", "trusted_installed_lineage")):
            raise PolicyError("native operations require script, recovery and installed-lineage acknowledgements")
        if (package["name"] in _SENSITIVE or package["name"].startswith(_SENSITIVE_PREFIXES)
                or package["source_name"] in _SENSITIVE_SOURCES):
            raise BackendError("sensitive package requires an external maintenance procedure")


def _finding(inventory, finding):
    if (not isinstance(finding, dict) or finding.get("status") != "affected"
            or finding.get("asset_id") != inventory["asset_id"]
            or not isinstance(finding.get("package"), dict)):
        raise BackendError("resolution requires an affected finding for this asset")
    candidate = finding["package"]
    package = _package(inventory, candidate.get("name"), candidate.get("architecture"))
    if candidate != package:
        raise BackendError("finding package does not match the inventory")
    fixed = version(finding.get("fixed_version"), "fixed source version")
    if fixed == "0" or compare_versions(fixed, package["source_version"]) <= 0:
        raise BackendError("finding does not identify an ordinary newer source fix")
    return package, fixed


def _replacement(inventory, target):
    result = copy.deepcopy(inventory)
    package = _package(result, target["name"], target["architecture"])
    if package["version"] != target["from_version"] or package["source_name"] != target["source_name"]:
        raise BackendError("target no longer matches installed binary and source identity")
    package["version"] = target["to_version"]
    package["source_version"] = target["source_version"]
    result["observed_at"] = now()
    return result


def _check_release_times(constraints, max_age):
    """Check retained, validated bounds only; no I/O or candidate recomputation."""
    timestamp = integer(now(), "current repository-check time")
    for date, expiry in constraints:
        if (date > timestamp or timestamp - date > max_age
                or (expiry is not None and (expiry <= timestamp or expiry <= date))):
            raise BackendError("repository metadata is stale, future-dated or expired")


def _release_constraints(target, releases, policy):
    if not isinstance(releases, list) or not 1 <= len(releases) <= 1024:
        raise BackendError("candidate requires between one and 1024 release evidence records")
    age = integer(policy.get("max_repository_age"), "max_repository_age", minimum=1, maximum=31_536_000)
    covered, constraints = set(), []
    for release in releases:
        if not isinstance(release, dict) or set(release) != {"origin", "codename", "date", "valid_until"}:
            raise BackendError("repository release freshness evidence is malformed")
        origin = release["origin"]
        if not isinstance(origin, dict) or origin not in target["origins"]:
            raise BackendError("release evidence does not belong to an exact target origin")
        if release["codename"] != origin["codename"]:
            raise BackendError("release evidence has the wrong codename")
        date = integer(release["date"], "release date")
        expiry = release["valid_until"]
        if expiry is not None:
            integer(expiry, "release expiry")
        covered.add(canonical(origin))
        constraints.append((date, expiry))
    if covered != {canonical(origin) for origin in target["origins"]}:
        raise BackendError("candidate has incomplete release freshness evidence")
    # Keep every contributing record, including different constraints for the
    # same origin. A later, fresher record cannot hide an older/expired one.
    constraints = tuple(constraints)
    _check_release_times(constraints, age)
    return constraints, age


def _private_directory(path, *, create=False, uid=None):
    # Share the CLI's descriptor-relative traversal so '..' cannot erase an
    # unchecked component, and untrusted ancestors cannot redirect later opens.
    owner = os.geteuid() if uid is None else uid
    path = _path(path)
    try:
        with _checked_directory(path, protected=True, owner=owner, create_last=create) as descriptor:
            _directory_info(os.fstat(descriptor), protected=True, owner=owner, leaf=True)
    except (OSError, ValidationError) as exc:
        raise BackendError("backend state requires a private operator-owned directory and protected nonsymlink ancestors") from exc
    # Normalizing is safe only after every preceding component was checked.
    return Path(os.path.abspath(path))


def _publication_path(path):
    # A fixed reserved alias makes a crash between link() and unlink()
    # identifiable without an unbounded directory scan or an arbitrary link.
    return path.with_name(".publish-" + hashlib.sha256(path.name.encode("utf-8")).hexdigest())


def _publication_alias(path, info):
    if info.st_nlink != 2:
        return False
    try:
        alias = _publication_path(path).lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISREG(alias.st_mode) and (alias.st_dev, alias.st_ino) == (info.st_dev, info.st_ino))


def _open_private(path, flags, *, uid=None, publication=False):
    descriptor = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode)
                or (info.st_nlink != 1 and not (publication and _publication_alias(path, info)))
                or info.st_uid != (os.geteuid() if uid is None else uid) or info.st_mode & 0o077):
            raise BackendError("backend state must be a private regular file without unrecognized links")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_private_bytes(path, limit, *, publication=False):
    descriptor = _open_private(path, os.O_RDONLY, publication=publication)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > limit:
            raise BackendError("backend record exceeds its byte limit")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > limit:
        raise BackendError("backend record exceeds its byte limit")
    fields = ("st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise BackendError("backend record changed while being read")
    return raw


def _read_private(path, limit, *, publication=False):
    return load_json(_read_private_bytes(path, limit, publication=publication), max_bytes=limit, max_nodes=8_000_000)


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _exclusive_json(path, body):
    # Serialize before creating anything. link() publishes complete, flushed
    # bytes atomically and cannot replace an existing gate, even a symlink.
    raw = canonical(body)
    temporary = _publication_path(path)
    descriptor = _open_private(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        # A crash or a second interruption can leave the two-link state. Only
        # this exact alias is accepted on read; recovery removes it before gate
        # removal. An unpublished alias is safe to discard under the target lock.
        temporary.unlink()
    _sync_directory(path.parent)


def _atomic_json(path, body):
    descriptor, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(canonical(body))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class _Gated:
    """One stable flock inode and durable gate, independent of any database."""

    def _setup_gate(self, directory, stem):
        self._directory = directory
        self._lock_path = directory / (stem + ".lock")
        self._gate_path = directory / (stem + ".gate")
        self._generation_path = directory / (stem + ".generation")
        self._owner = None
        self._recovery = False
        self._asset = None
        self._begun_plan = None

    def _require_lock(self, *, recovery=None):
        if self._owner != (os.getpid(), threading.get_ident()):
            raise BackendError("operation requires the backend target lock")
        if recovery is not None and self._recovery != recovery:
            raise BackendError("operation requires the correct execution or recovery lock")

    def generation(self):
        """Read the target-wide recovery token without creating native state."""
        try:
            with _checked_directory(_path(self._directory), protected=True, owner=os.geteuid()) as descriptor:
                _directory_info(os.fstat(descriptor), protected=True, owner=os.geteuid(), leaf=True)
                try:
                    record = _read_private(self._generation_path, 256)
                except FileNotFoundError:
                    return _INITIAL_GENERATION
        except FileNotFoundError:
            return _INITIAL_GENERATION  # The checked traversal found absent state.
        except (OSError, ValidationError) as exc:
            raise BackendError("recovery generation cannot be read safely; inspect protected target state") from exc
        if not isinstance(record, dict) or set(record) != {"generation"}:
            raise BackendError("recovery generation record is malformed; inspect protected target state")
        try:
            return _hash(record["generation"], "recovery generation")
        except ValidationError as exc:
            raise BackendError("recovery generation record is malformed; inspect protected target state") from exc

    def _gate(self):
        try:
            raw = _read_private_bytes(self._gate_path, _MAX_GATE_BYTES, publication=True)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BackendError("execution gate cannot be read safely; inspect its type and permissions") from exc
        try:
            gate = load_json(raw, max_bytes=_MAX_GATE_BYTES)
            if not isinstance(gate, dict) or set(gate) != {"plan_id"}:
                raise ValidationError("invalid gate schema")
            _hash(gate["plan_id"], "gate plan ID")
        except ValidationError:
            return {"malformed": True, "digest": hashlib.sha256(raw).hexdigest()}
        return gate

    def _discard_unpublished_gate(self):
        # Only called with the target lock held and no published gate. A
        # leftover unlinked preparation file cannot have authorized mutation.
        temporary = _publication_path(self._gate_path)
        try:
            _read_private_bytes(temporary, _MAX_GATE_BYTES)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise BackendError("unpublished gate cannot be read safely; inspect protected target state") from exc
        try:
            temporary.unlink()
            _sync_directory(self._directory)
        except OSError as exc:
            raise BackendError("unpublished gate cleanup failed; inspect protected target state") from exc

    @contextmanager
    def _target_lock(self, asset_id, *, recovery=False):
        identifier(asset_id, "asset_id")
        if type(recovery) is not bool or self._owner is not None:
            raise BackendError("target lock is already held or recovery flag is invalid")
        descriptor = None
        try:
            _private_directory(self._directory)
            descriptor = _open_private(self._lock_path, os.O_RDWR | os.O_CREAT)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BackendError("target is locked by another operation") from exc
            self._owner = (os.getpid(), threading.get_ident())
            self._recovery = recovery
            self._asset = asset_id
            self._begun_plan = None
            gate = self._gate()
            if gate is None:
                self._discard_unpublished_gate()
            if gate is not None and not recovery:
                raise BackendError("unresolved execution gate requires explicit recovery")
            yield gate
        finally:
            self._owner = None
            self._recovery = False
            self._asset = None
            self._begun_plan = None
            if descriptor is not None:
                os.close(descriptor)

    def begin(self, plan_id):
        self._require_lock(recovery=False)
        _hash(plan_id, "plan ID")
        if self._gate() is not None:
            raise BackendError("execution gate already exists")
        self._begun_plan = None
        try:
            _exclusive_json(self._gate_path, {"plan_id": plan_id})
        except OSError as exc:
            raise IndeterminateError("execution gate could not be durably recorded; inspect recovery state") from exc
        self._begun_plan = plan_id

    def _remove_gate(self, expected):
        if self._gate() != expected:
            raise BackendError("execution gate changed before removal; inspect recovery state")
        try:
            if _publication_alias(self._gate_path, self._gate_path.lstat()):
                _publication_path(self._gate_path).unlink()
            self._gate_path.unlink()
            _sync_directory(self._directory)
        except OSError as exc:
            raise IndeterminateError("gate removal durability is uncertain; inspect recovery state") from exc

    def _clear(self, plan_id):
        _hash(plan_id, "plan ID")
        if self._gate() != {"plan_id": plan_id}:
            raise BackendError("recovery requires the exact retained gate plan ID")
        self._remove_gate({"plan_id": plan_id})
        self._begun_plan = None

    def finish(self, plan_id, outcome):
        """Engine calls this only AFTER its outcome transaction commits durably."""
        self._require_lock(recovery=False)
        _hash(plan_id, "plan ID")
        if self._gate() != {"plan_id": plan_id}:
            raise BackendError("outcome does not match the retained gate")
        if outcome in ("succeeded", "failed"):
            self._clear(plan_id)
        elif outcome not in ("needs_attention", "executing"):
            raise ValidationError("unsupported execution outcome")

    def clear_gate(self, plan_id, resolution, *, malformed_digest=None):
        self._require_lock(recovery=True)
        _hash(plan_id, "plan ID")
        if not text(resolution, "recovery resolution", max_length=4096).strip():
            raise ValidationError("recovery resolution must explain the operator action")
        gate = self._gate()
        if gate is None:
            raise BackendError("recovery requires a retained execution gate")
        if "plan_id" in gate:
            if gate != {"plan_id": plan_id} or malformed_digest is not None:
                raise BackendError("recovery requires the exact gate plan ID without a malformed override")
        elif malformed_digest is None or _hash(malformed_digest, "malformed gate digest") != gate["digest"]:
            raise BackendError("malformed gate recovery requires its exact raw digest and explicit attestation")
        current = self.generation()
        token = secrets.token_hex(32)
        if token in (current, _INITIAL_GENERATION):
            raise BackendError("recovery generation did not change; retry explicit resolution")
        try:
            # Persist the invalidation before removing the gate. A crash leaves
            # either the old token plus gate, or a new token with or without gate;
            # never a cleared gate with authority from an older generation.
            _atomic_json(self._generation_path, {"generation": token})
        except OSError as exc:
            raise IndeterminateError("recovery generation durability is uncertain; retain the gate and inspect state") from exc
        self._remove_gate(gate)

    def _require_execution(self):
        self._require_lock(recovery=False)
        if self._begun_plan is None or self._gate() != {"plan_id": self._begun_plan}:
            raise BackendError("mutation requires a successfully published durable execution gate")


class Simulator(_Gated):
    """Atomic disposable JSON state; synthetic catalog entries are not downloads."""

    name = "simulator"

    @staticmethod
    def _state_path(path):
        path = _path(path)
        if path.name.startswith(".") or path.name.endswith(_COORDINATION_SUFFIXES):
            raise ValidationError("simulator state names must not use hidden or reserved coordination filenames")
        return _private_directory(path.parent) / path.name

    def __init__(self, path):
        self.path = self._state_path(path)
        self._setup_gate(self.path.parent, self.path.name)
        self._state()

    @classmethod
    def initialize(cls, path, inventory, catalog, *, failure_mode=None):
        path = cls._state_path(path)
        state = cls._validate_state({"inventory": inventory, "catalog": catalog, "failure_mode": failure_mode})
        _exclusive_json(path, state)
        return cls(path)

    @staticmethod
    def _validate_state(state):
        if not isinstance(state, dict) or set(state) != {"inventory", "catalog", "failure_mode"}:
            raise ValidationError("simulator state fields do not match the schema")
        inventory = normalize_inventory(state["inventory"], collector="simulator")
        catalog = state["catalog"]
        if not isinstance(catalog, list) or len(catalog) > 10000:
            raise ValidationError("simulator catalog must contain at most 10000 targets")
        targets = [_target(t) for t in catalog]
        if state["failure_mode"] not in (None, "before_write", "after_write"):
            raise ValidationError("simulator failure mode must be null, before_write or after_write")
        result = {"inventory": inventory, "catalog": targets, "failure_mode": state["failure_mode"]}
        if len(canonical(result)) > _MAX_STATE_BYTES:
            raise ValidationError("simulator state exceeds its byte limit")
        return result

    def _state(self):
        return self._validate_state(_read_private(self.path, _MAX_STATE_BYTES, publication=True))

    def inspect(self):
        inventory = self._state()["inventory"]
        inventory["observed_at"] = now()
        return inventory

    @contextmanager
    def lock(self, asset_id, *, recovery=False):
        with self._target_lock(asset_id, recovery=recovery) as gate:
            if self.inspect()["asset_id"] != asset_id:
                raise BackendError("asset does not identify this simulator state")
            yield gate

    def set_failure(self, mode):
        if mode not in (None, "before_write", "after_write"):
            raise ValidationError("simulator failure mode must be null, before_write or after_write")
        # A failure control is not recovery and cannot clear or bypass a gate.
        with self.lock(self.inspect()["asset_id"]):
            state = self._state()
            state["failure_mode"] = mode
            _atomic_json(self.path, state)

    def resolve(self, inventory, finding, policy):
        _ready(inventory, "simulator")
        package, fixed = _finding(inventory, finding)
        _policy(policy, inventory, package, self.name)
        choices = [t for t in self._state()["catalog"]
                   if (t["name"], t["architecture"], t["from_version"], t["source_name"])
                   == (package["name"], package["architecture"], package["version"], package["source_name"])
                   and compare_versions(t["source_version"], fixed) >= 0]
        if not choices:
            raise BackendError("synthetic catalog has no exact applicable candidate")
        best = choices[0]
        for choice in choices[1:]:
            order = compare_versions(choice["to_version"], best["to_version"])
            if order > 0:
                best = choice
        if any(t != best and compare_versions(t["to_version"], best["to_version"]) == 0 for t in choices):
            raise BackendError("synthetic candidate has ambiguous same-version artifacts")
        return copy.deepcopy(best)

    def apply(self, target, policy, *, before_mutation):
        self._require_execution()
        target = _target(target)
        state = self._state()
        inventory = _ready(state["inventory"], "simulator")
        if inventory["asset_id"] != self._asset:
            raise BackendError("simulator asset changed while locked")
        package = _package(inventory, target["name"], target["architecture"])
        _policy(policy, inventory, package, self.name, applying=True)
        current = self.resolve(inventory, {"status": "affected", "asset_id": self._asset,
                               "package": package, "fixed_version": target["source_version"]}, policy)
        if current != target:
            raise BackendError("synthetic repository target changed; replan")
        state["inventory"] = _replacement(inventory, target)
        if not callable(before_mutation):
            raise ValidationError("before_mutation must be callable")
        if state["failure_mode"] == "before_write":
            raise BackendError("simulated failure before state mutation")
        before_mutation()
        try:
            _atomic_json(self.path, state)
        except Exception as exc:
            raise IndeterminateError("simulator write durability is uncertain; inspect disposable state") from exc
        if state["failure_mode"] == "after_write":
            raise IndeterminateError("simulated failure after state mutation")
        return {"backend": self.name, "installed_version": target["to_version"], "synthetic": True}


class DebianApt(_Gated):
    """Fixed local Debian backend. Constructor injection is for offline tests only.

    System python3-apt, apt-get, apt-helper, gpgv and dpkg are prerequisites.
    Neither the probe nor this module refreshes indexes. Configuration, keys,
    hooks and installed lineage must already be reviewed by the operator.
    Conffiles use dpkg's default answer, preserving a locally changed file when
    no default is available (--force-confdef --force-confold). No rollback runs.
    """

    name = "debian-apt"

    def __init__(self, runner=None, *, live=False):
        if type(live) is not bool:
            raise ValidationError("live must be a boolean")
        self.runner = Runner() if runner is None else runner
        self.live = live
        self._setup_gate(_NATIVE_STATE, "local")

    def inspect(self):
        return collect_local(self.runner)

    def _live(self):
        if not self.live or os.geteuid() != 0:
            raise PolicyError("native mutation requires explicit live opt-in and root")

    @contextmanager
    def lock(self, asset_id, *, recovery=False):
        self._live()
        # Fixed shared path, not selected by asset IDs, plan IDs or SQLite paths.
        _private_directory(self._directory.parent, create=True)
        _private_directory(self._directory, create=True)
        with self._target_lock(asset_id, recovery=recovery) as gate:
            with self.runner.dpkg_frontend_lock():
                with ExitStack() as stack:
                    if recovery:
                        stack.enter_context(self._database_lock())
                    inventory = self.inspect()
                    if not recovery:
                        _ready(inventory, "native")
                    if inventory["asset_id"] != asset_id:
                        raise BackendError("asset does not identify this native host")
                    yield gate

    @contextmanager
    def _database_lock(self):
        # Recovery must exclude a surviving dpkg child, not just its frontend.
        if not _DATABASE_GUARD.acquire(blocking=False):
            raise BackendError("dpkg database lock is held by this process")
        descriptor = None
        try:
            descriptor = os.open(_DATABASE_LOCK, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022 or info.st_nlink != 1):
                raise BackendError("dpkg database lock has unsafe ownership or permissions")
            fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except OSError as exc:
            raise BackendError("dpkg database lock is unavailable; inspect surviving package operations") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            _DATABASE_GUARD.release()

    def _probe(self, action, *args, timeout=120, cwd="/"):
        result = self.runner.run(["/usr/bin/python3", "-I", _PROBE, action, *args], timeout=timeout, cwd=cwd)
        if result.returncode != 0:
            raise BackendError("APT probe failed; check python3-apt, approved sources, keys and current signed indexes")
        try:
            return load_json(result.stdout, max_bytes=4 * 1024 * 1024)
        except ValidationError as exc:
            raise BackendError("APT probe returned invalid bounded metadata") from exc

    def _candidate(self, inventory, package, fixed, policy):
        data = self._probe("resolve", package["name"], package["architecture"])
        if not isinstance(data, dict) or set(data) != {"target", "authenticated", "releases", "relationships", "essential"}:
            raise BackendError("APT probe returned an unsupported response")
        if data["authenticated"] is not True or data["essential"] is not False:
            raise BackendError("candidate must be authenticated and nonessential")
        if data["relationships"] != {"Conflicts": "", "Breaks": "", "Replaces": ""}:
            raise BackendError("candidate relationship fields require external maintenance")
        target = _target(data["target"])
        if (target["name"], target["architecture"], target["from_version"], target["source_name"]) != (
                package["name"], package["architecture"], package["version"], package["source_name"]):
            raise BackendError("APT candidate does not match installed binary and source identity")
        if compare_versions(target["source_version"], fixed) < 0:
            raise BackendError("APT candidate source version does not contain the required fix")
        if target["config_digest"] != _hash(policy.get("approved_config_digest"), "approved configuration digest"):
            raise PolicyError("APT configuration or keyrings differ from the approved digest")
        allowed = policy.get("allowed_origins", [])
        for origin in target["origins"]:
            if origin not in allowed or origin["codename"] not in _CODENAMES:
                raise PolicyError("candidate origin or codename is not approved")
        constraints, age = _release_constraints(target, data["releases"], policy)
        self._simulate(target)
        return target, constraints, age

    def _simulate(self, target):
        selector = target["name"] + ":" + ("amd64" if target["architecture"] == "all" else target["architecture"])
        result = self.runner.run(["/usr/bin/apt-get", "--simulate", "--assume-yes", "--no-remove",
                                  "--only-upgrade", "--no-install-recommends", "install", "--",
                                  selector + "=" + target["to_version"]], timeout=120, cwd="/")
        if result.returncode != 0:
            raise BackendError("exact APT simulation failed; dependency changes require external maintenance")
        # APT's C locale simulation emits Inst/Conf/Remv/Purg records. Ignore
        # headings, but reject any unfamiliar transaction-looking record.
        records = []
        for line in result.stdout.splitlines():
            if re.match(r"^(Inst|Conf|Remv|Purg)\b", line):
                records.append(line)
        if len(records) != 2:
            raise BackendError("APT simulation is not a singleton upgrade")
        name = re.escape(target["name"])
        arch = r"(?::amd64)?"
        old = re.escape(target["from_version"])
        new = re.escape(target["to_version"])
        if (not re.fullmatch(rf"Inst {name}{arch} \[{old}\] \({new} [^\r\n\x00-\x1f]+\)", records[0])
                or not re.fullmatch(rf"Conf {name}{arch} \({new} [^\r\n\x00-\x1f]+\)", records[1])):
            raise BackendError("APT simulation changes packages outside the exact approved upgrade")

    def resolve(self, inventory, finding, policy):
        _ready(inventory, "native")
        package, fixed = _finding(inventory, finding)
        _policy(policy, inventory, package, self.name)
        # An imported object cannot select a remotely named native host.
        if inventory_fingerprint(self.inspect()) != inventory_fingerprint(inventory):
            raise BackendError("native inventory changed; collect and replan")
        return self._candidate(inventory, package, fixed, policy)[0]

    def _artifact(self, staging, target):
        path = staging / "package.deb"
        if set(p.name for p in staging.iterdir()) != {"package.deb"}:
            raise BackendError("APT staging contains unexpected artifacts")
        descriptor = _open_private(path, os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as stream:
            if os.fstat(stream.fileno()).st_size != target["size"]:
                raise BackendError("downloaded artifact size does not match the target")
            checksum = hashlib.sha256()
            size = 0
            while chunk := stream.read(65536):
                size += len(chunk)
                if size > target["size"]:
                    raise BackendError("downloaded artifact exceeds its approved size")
                checksum.update(chunk)
        if size != target["size"] or checksum.hexdigest() != target["sha256"]:
            raise BackendError("downloaded artifact hash does not match the target")
        data = self._probe("artifact", str(path))
        expected = {key: target[key] for key in ("name", "architecture", "source_name", "source_version")}
        expected.update(version=target["to_version"], relationships={"Conflicts": "", "Breaks": "", "Replaces": ""}, essential=False)
        if data != expected:
            raise BackendError("downloaded artifact identity or relationship fields differ from the approved target")
        return path

    def apply(self, target, policy, *, before_mutation):
        self._live()
        self._require_execution()
        target = _target(target)
        inventory = _ready(self.inspect(), "native")
        if inventory["asset_id"] != self._asset:
            raise BackendError("native asset identity changed while locked")
        package = _package(inventory, target["name"], target["architecture"])
        _policy(policy, inventory, package, self.name, applying=True)
        if self._candidate(inventory, package, target["source_version"], policy)[0] != target:
            raise BackendError("APT target changed; collect and replan")
        expected = _replacement(inventory, target)
        if not callable(before_mutation):
            raise ValidationError("before_mutation must be callable")
        staging = Path(tempfile.mkdtemp(prefix="download-", dir=self._directory))
        try:
            self._probe("download", target["name"], target["architecture"], target["to_version"],
                        target["sha256"], str(target["size"]), target["config_digest"], target["metadata_digest"],
                        str(staging), timeout=300, cwd=str(staging))
            artifact = self._artifact(staging, target)
            # Recheck the candidate, freshness, transaction and complete database
            # after network preparation, still under the same frontend lock.
            fresh = _ready(self.inspect(), "native")
            if inventory_fingerprint(fresh) != inventory_fingerprint(inventory):
                raise BackendError("package state changed during download; replan")
            candidate, constraints, max_age = self._candidate(fresh, package, target["source_version"], policy)
            if candidate != target:
                raise BackendError("repository state changed during download; replan")
            before_mutation()
            # The Engine callback can be expensive. Close the final time window
            # using only immutable, bounded release constraints, not more I/O.
            _check_release_times(constraints, max_age)
            try:
                result = self.runner.run(["/usr/bin/dpkg", "--force-confdef", "--force-confold", "--install", str(artifact)],
                                         timeout=900, cwd=str(staging))
                if result.returncode != 0:
                    raise IndeterminateError("dpkg did not complete successfully; inspect package state")
                observed = self.inspect()
                if inventory_fingerprint(observed) != inventory_fingerprint(expected):
                    raise IndeterminateError("installed package state differs from the exact singleton delta")
            except (IndeterminateError, KeyboardInterrupt):
                raise
            except Exception as exc:
                # Even a post-start BackendError cannot prove no package change.
                raise IndeterminateError("installation or verification could not be confirmed") from exc
            return {"backend": self.name, "installed_version": target["to_version"], "verified_singleton": True}
        finally:
            # Cleanup affects only this generated private directory. It must not
            # mask an installation outcome; stale staging is never reused.
            shutil.rmtree(staging, ignore_errors=True)
