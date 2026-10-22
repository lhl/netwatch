"""Shared validation and content identities. No input in this module grants trust."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from typing import Any


class AutoprotectError(Exception):
    """A bounded, operator-facing failure."""


class ValidationError(AutoprotectError):
    """Input cannot be interpreted under the supported contract."""


class PolicyError(AutoprotectError):
    """Current authorization or preconditions do not permit this action."""


class BackendError(AutoprotectError):
    """Backend failure known to occur before package mutation."""


class IndeterminateError(AutoprotectError):
    """Mutation may have occurred; inspect and recover before replanning."""


def now() -> int:
    return int(time.time())


def integer(
    value: Any,
    field: str = "value",
    *,
    minimum: int = 0,
    maximum: int = 2**63 - 1,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{field} must be an integer from {minimum} to {maximum}")
    return value


def text(
    value: Any,
    field: str = "value",
    *,
    max_length: int = 8192,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or len(value) > max_length:
        raise ValidationError(f"{field} must be text of at most {max_length} characters")
    if not allow_empty and not value:
        raise ValidationError(f"{field} must not be empty")
    # Control characters in prose remain data and are escaped by JSON output.
    # Lone Unicode surrogates cannot be encoded consistently across consumers.
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValidationError(f"{field} must not contain lone Unicode surrogates")
    return value


def identifier(value: Any, field: str = "identifier") -> str:
    value = text(value, field, max_length=128)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", value, flags=re.ASCII):
        raise ValidationError(f"{field} must be a bounded ASCII identifier")
    return value


def package_name(value: Any, field: str = "package name") -> str:
    value = text(value, field, max_length=128)
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", value, flags=re.ASCII):
        raise ValidationError(f"{field} must be a Debian package name without architecture")
    return value


def version(value: Any, field: str = "version") -> str:
    """Validate the supported Debian version syntax; never compare it lexically."""
    value = text(value, field, max_length=256)
    body = value
    if ":" in value:
        epoch, body = value.split(":", 1)
        if not re.fullmatch(r"[0-9]+", epoch, flags=re.ASCII) or int(epoch) > 2**31 - 1:
            raise ValidationError(f"{field} has an invalid or out-of-range Debian epoch")
    upstream, separator, revision = body.rpartition("-")
    if not separator:
        upstream = body
    elif not re.fullmatch(r"[A-Za-z0-9+.~]+", revision, flags=re.ASCII):
        raise ValidationError(f"{field} has an unsupported Debian revision")
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", upstream, flags=re.ASCII):
        raise ValidationError(f"{field} has unsupported Debian version syntax")
    return value


def _check_tree(value: Any, *, max_nodes: int, max_depth: int) -> None:
    # Keep only one iterator per nesting level. Expanding a wide container into
    # (child, depth) tuples can exhaust memory before its node limit is checked.
    def object_children(mapping):
        for key, child in mapping.items():
            if not isinstance(key, str):
                raise ValidationError("JSON object keys must be strings")
            yield key
            yield child

    stack = [iter((value,))]
    visited = 0
    while stack:
        try:
            item = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        visited += 1
        if visited > max_nodes or len(stack) - 1 > max_depth:
            raise ValidationError("JSON exceeds the nesting or node limit")
        if item is None or type(item) in (bool, int):
            continue
        if isinstance(item, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise ValidationError("JSON contains a lone Unicode surrogate")
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValidationError("JSON numbers must be finite")
        elif isinstance(item, dict):
            stack.append(iter(object_children(item)))
        elif isinstance(item, list):
            stack.append(iter(item))
        else:
            raise ValidationError("Value is not a supported JSON type")


def canonical(value: Any) -> str:
    """Stable JSON text, also safe to print without interpreting terminal controls."""
    _check_tree(value, max_nodes=8_000_000, max_depth=32)
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValidationError("Value cannot be encoded as canonical JSON") from exc


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValidationError("JSON numbers must be finite")


def load_json(
    raw: bytes | str,
    *,
    max_bytes: int = 8 * 1024 * 1024,
    max_nodes: int = 1_000_000,
    max_depth: int = 32,
) -> Any:
    """Parse bounded UTF-8 JSON, rejecting ambiguous objects and unsafe numbers."""
    if not isinstance(raw, (bytes, str)):
        raise ValidationError("JSON input must be UTF-8 bytes or text")
    try:
        byte_count = len(raw) if isinstance(raw, bytes) else len(raw.encode("utf-8"))
        if byte_count > max_bytes:
            raise ValidationError("JSON input exceeds the byte limit")
        decoded = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        result = json.loads(decoded, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValidationError("Input is not valid bounded UTF-8 JSON") from exc
    _check_tree(result, max_nodes=max_nodes, max_depth=max_depth)
    return result
