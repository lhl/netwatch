"""Inventory data validation and read-only collection; imported labels grant no trust."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from typing import Any

from .core import BackendError, ValidationError, digest, identifier, integer, now, package_name, text, version
from .runner import Runner

MAX_PACKAGES = 100_000
MAX_QUERY_BYTES = 16 * 1024 * 1024
_COLLECTORS = ("imported", "native", "simulator")
_QUERY = [
    "/usr/bin/dpkg-query", "--show",
    r"--showformat=${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Status}\n",
]


def _boolean(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise ValidationError(f"{field} must be a boolean")
    return value


def _opaque_identity(value: Any, field: str) -> str:
    """Preserve unsupported ecosystem syntax without accepting control characters."""
    value = text(value, field, max_length=256)
    if any(not 33 <= ord(char) <= 126 for char in value):
        raise ValidationError(f"{field} must be bounded printable ASCII without whitespace")
    return value


def normalize_inventory(data: Any, collector: str = "imported") -> dict:
    """Return independent, sorted inventory data, never trust the body's collector.

    Only trusted internal callers select ``native`` or ``simulator``. Import
    entrypoints must use the default. ``deb`` uses the shared strict package-name
    and dpkg version validators: malformed versions reject the entire import,
    rather than dropping a package. Other ecosystems retain printable ASCII
    identities and versions for unknown matching, and fall back to binary
    identity for absent source fields. Source fields for ``deb`` must be
    explicit; supply source metadata rather than guessing through a binary-only
    rebuild. Explicit null/empty values are rejected. No lineage is inferred.

    ``complete`` describes collection coverage, not package readiness. Held and
    non-installed states remain visible. Unknown fields are not authority and
    are omitted from the normalized result.
    """
    if not isinstance(data, dict):
        raise ValidationError("inventory must be an object")
    if collector not in _COLLECTORS:
        raise ValidationError("collector must be imported, native, or simulator")
    integer(data.get("schema_version"), "schema_version", minimum=1, maximum=1)
    result = {
        "schema_version": 1,
        "asset_id": identifier(data.get("asset_id"), "asset_id"),
        "observed_at": integer(data.get("observed_at"), "observed_at"),
        "os": identifier(data.get("os"), "os"),
        "release": identifier(data.get("release"), "release"),
        "architecture": identifier(data.get("architecture"), "architecture"),
        "collector": collector,
        "complete": _boolean(data.get("complete"), "complete"),
    }
    packages = data.get("packages")
    if not isinstance(packages, list) or len(packages) > MAX_PACKAGES:
        raise ValidationError(f"packages must be a list of at most {MAX_PACKAGES} records")
    normalized = []
    identities = set()
    for package in packages:
        if not isinstance(package, dict):
            raise ValidationError("each package must be an object")
        ecosystem = identifier(package.get("ecosystem"), "ecosystem")
        if ecosystem == "deb" and ("source_name" not in package or "source_version" not in package):
            raise ValidationError("deb packages require source_name and source_version; supply source metadata")
        name_validator = package_name if ecosystem == "deb" else _opaque_identity
        version_validator = version if ecosystem == "deb" else _opaque_identity
        name = name_validator(package.get("name"), "package name")
        binary_version = version_validator(package.get("version"), "package version")
        record = {
            "ecosystem": ecosystem,
            "name": name,
            "version": binary_version,
            "source_name": name_validator(package.get("source_name", name), "source name"),
            "source_version": version_validator(package.get("source_version", binary_version), "source version"),
            "architecture": identifier(package.get("architecture"), "package architecture"),
            "status": identifier(package.get("status"), "package status"),
            "held": _boolean(package.get("held"), "held"),
        }
        identity = (ecosystem, name, record["architecture"])
        if identity in identities:
            raise ValidationError("inventory contains a duplicate package identity")
        identities.add(identity)
        normalized.append(record)
    result["packages"] = sorted(normalized, key=lambda p: (p["ecosystem"], p["name"], p["architecture"]))
    return result


def inventory_fingerprint(inventory: dict) -> str:
    """Hash normalized inventory, excluding only its observation timestamp.

    Call normalize_inventory first. This function does not relabel provenance,
    reorder records, remove additional fields, or change the caller's object.
    """
    if not isinstance(inventory, dict):
        raise ValidationError("inventory must be an object")
    return digest({key: value for key, value in inventory.items() if key != "observed_at"})


def _read_file(path: str, limit: int) -> bytes:
    """Read at most limit+1 bytes; do not block opening a substituted FIFO.

    Standard os-release symlinks are allowed. The collector supplies only fixed
    paths. Tests may patch this function, but no CLI option supplies a file root.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise BackendError("native identity input must be a regular file")
        if info.st_size > limit:
            raise BackendError("native identity input exceeds its byte limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise BackendError("native identity input exceeds its byte limit")
        return data
    finally:
        os.close(descriptor)


def _read_text(path: str, limit: int) -> str:
    raw = _read_file(path, limit)
    # Recheck even injected readers: a fake must not bypass parser bounds.
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise BackendError("native identity input exceeds its byte limit or is not bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise BackendError("native identity input must be UTF-8") from exc


def _os_release_value(raw: str) -> str:
    """Decode one os-release value, without expansion or quote concatenation."""
    if not raw:
        return ""
    if raw[0] == "'":
        if len(raw) < 2 or raw[-1] != "'" or "'" in raw[1:-1]:
            raise ValidationError("os-release contains invalid quoting")
        return raw[1:-1]
    if raw[0] == '"':
        if len(raw) < 2 or raw[-1] != '"':
            raise ValidationError("os-release contains invalid quoting")
        value = []
        index = 1
        while index < len(raw) - 1:
            char = raw[index]
            if char == '"':
                raise ValidationError("os-release contains concatenated quotes")
            if char == "\\":
                index += 1
                if index >= len(raw) - 1:
                    raise ValidationError("os-release contains an incomplete escape")
                if raw[index] not in '\\"$`':
                    value.append("\\")
                char = raw[index]
            value.append(char)
            index += 1
        return "".join(value)
    if any(char.isspace() or char in "'\"`$\\;|&()< >" for char in raw):
        raise ValidationError("os-release contains an invalid unquoted value")
    return raw


def _parse_os_release(content: str) -> dict[str, str]:
    if any((ord(char) < 32 and char not in "\n\t") or 127 <= ord(char) <= 159 for char in content):
        raise ValidationError("os-release contains control characters")
    result = {}
    for line in content.split("\n"):
        line = line.strip(" \t")
        if not line or line.startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        if (not separator or len(line) > 4096 or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key)
                or key in result or "\t" in raw):
            raise ValidationError("os-release contains a malformed or duplicate assignment")
        result[key] = _os_release_value(raw)
    return result


def _native_architecture(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value):
        raise ValidationError("dpkg architecture must be a bounded lowercase identifier")
    return value


def _native_packages(output: str) -> list[dict]:
    if (not isinstance(output, str) or len(output) > MAX_QUERY_BYTES
            or len(output.encode("utf-8")) > MAX_QUERY_BYTES):
        raise ValidationError("dpkg query output exceeds its byte limit")
    if not output or not output.endswith("\n"):
        raise ValidationError("dpkg query returned empty or incomplete package data")
    if output.count("\n") > MAX_PACKAGES:
        raise ValidationError("dpkg query exceeds the package count limit")
    packages = []
    for row in output[:-1].split("\n"):
        if len(row) > 2048:
            raise ValidationError("dpkg query row exceeds its length limit")
        fields = row.split("\t")
        if len(fields) != 6:
            raise ValidationError("dpkg query returned a malformed package row")
        name, binary_version, architecture, source_name, source_version, raw_status = fields
        status_parts = raw_status.split(" ")
        if len(status_parts) != 3:
            raise ValidationError("dpkg query returned a malformed package status")
        desired, error, state = status_parts
        if (desired not in ("unknown", "install", "hold", "deinstall", "purge")
                or error not in ("ok", "reinstreq")
                or state not in ("not-installed", "config-files", "half-installed", "unpacked",
                                 "half-configured", "triggers-awaited", "triggers-pending", "installed")):
            raise ValidationError("dpkg query returned an unrecognized package status")
        # Keep non-default wanted/error states visibly non-ready. A hold is a
        # separate boolean, so even a healthy held package cannot be upgraded.
        status = "-".join(([desired] if desired not in ("install", "hold") else [])
                          + ([error] if error != "ok" else []) + [state])
        packages.append({
            "ecosystem": "deb", "name": name, "version": binary_version,
            "architecture": _native_architecture(architecture),
            # dpkg virtual fields normally already apply this documented
            # fallback for an omitted Source field. Do not strip '+bN' or guess
            # source names; an explicit source version always takes precedence.
            "source_name": source_name or name, "source_version": source_version or binary_version,
            "status": status, "held": desired == "hold",
        })
    return packages


def collect_local(runner=None) -> dict:
    """Collect local dpkg data with fixed read-only commands and hashed identity.

    Tests inject a runner and patch ``_read_file(path, limit)`` and ``now()``;
    neither facility is exposed through imported content or CLI configuration.
    Two complete package queries must agree after normalization. This detects
    observed drift, not every possible concurrent change; the native executor
    must also hold its package-manager lock across preflight and installation.

    ``ID_LIKE`` never substitutes for OS identity. Unsupported dpkg platforms
    stay visible for unknown matching. Collection failure produces no empty
    successful snapshot. This observes package state, not installed-byte
    lineage, running binaries, application health, or foreign package managers.
    """
    command_runner = Runner() if runner is None else runner
    try:
        try:
            os_release = _read_text("/etc/os-release", 65536)
        except FileNotFoundError:
            os_release = _read_text("/usr/lib/os-release", 65536)
        platform = _parse_os_release(os_release)
        machine = _read_text("/etc/machine-id", 4096)
        if not re.fullmatch(r"[0-9a-f]{32}\n?", machine) or machine.rstrip("\n") == "0" * 32:
            raise ValidationError("machine identity is missing or uninitialized")
        asset_id = "machine-" + hashlib.sha256(machine.rstrip("\n").encode("ascii")).hexdigest()
        architecture_result = command_runner.run(["/usr/bin/dpkg", "--print-architecture"], timeout=60, cwd="/")
        if architecture_result.returncode != 0:
            raise BackendError("native architecture query failed; check dpkg availability")
        raw_architecture = architecture_result.stdout
        if not isinstance(raw_architecture, str):
            raise ValidationError("dpkg architecture output must be text")
        architecture = _native_architecture(raw_architecture.removesuffix("\n"))
        base = {
            "schema_version": 1, "asset_id": asset_id, "observed_at": now(),
            "os": platform.get("ID", "linux"),
            "release": platform.get("VERSION_CODENAME") or platform.get("VERSION_ID") or "unknown",
            "architecture": architecture, "complete": True,
        }
        inventories = []
        for _ in range(2):
            result = command_runner.run(list(_QUERY), timeout=60, cwd="/")
            if result.returncode != 0:
                raise BackendError("native package query failed; check dpkg database access")
            inventories.append(normalize_inventory({**base, "packages": _native_packages(result.stdout)}, collector="native"))
        if inventory_fingerprint(inventories[0]) != inventory_fingerprint(inventories[1]):
            raise BackendError("package state changed during collection; collect again under the package-manager lock")
        inventories[1]["observed_at"] = integer(now(), "observed_at")
        return inventories[1]
    except (OSError, UnicodeError, ValidationError) as exc:
        raise BackendError("native inventory data is missing or invalid; check identity files and dpkg metadata") from exc
