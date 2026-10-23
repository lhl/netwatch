"""Small shared validation and JSON helpers."""
import hashlib
import json
import re


class Error(Exception):
    pass


ValidationError = Error


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def version(value):
    if not isinstance(value, str) or len(value) > 256 or not re.fullmatch(r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+:~\-]*", value):
        raise Error("Unsupported dpkg version syntax")
    epoch, colon, body = value.partition(":")
    if colon and (not epoch.isdigit() or int(epoch) > 2147483647):
        raise Error("Unsupported dpkg epoch")
    if value.endswith("-"):
        raise Error("Empty dpkg revision")
    return value


def text(value, label="value"):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Error(f"Invalid {label}")
    return value


def name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise Error("Name must contain 1–80 letters, digits, dots, underscores or hyphens")
    return value
