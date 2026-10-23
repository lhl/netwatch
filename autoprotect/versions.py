"""dpkg epoch/upstream/revision ordering, independent of the host platform."""

from __future__ import annotations

from .core import version


def _parts(value: str) -> tuple[int, str, str]:
    version(value)
    epoch, colon, body = value.partition(":")
    if not colon:
        epoch, body = "0", value
    upstream, dash, revision = body.rpartition("-")
    if not dash:
        upstream, revision = body, "0"
    return int(epoch), upstream, revision


def _order(char: str) -> int:
    if char == "~":
        return -1
    if not char or "0" <= char <= "9":
        return 0
    if "A" <= char <= "Z" or "a" <= char <= "z":
        return ord(char)
    return ord(char) + 256


def _revision_compare(left: str, right: str) -> int:
    """Compare alternating non-numeric and numeric runs, as dpkg does."""
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (
            j < len(right) and not right[j].isdigit()
        ):
            a = _order(left[i] if i < len(left) else "")
            b = _order(right[j] if j < len(right) else "")
            if a != b:
                return -1 if a < b else 1
            i += i < len(left)
            j += j < len(right)

        # Leading zeroes have no significance. Compare the lengths of numeric
        # runs before their digits, avoiding arbitrary-size integer conversion.
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        i_end, j_end = i, j
        while i_end < len(left) and left[i_end].isdigit():
            i_end += 1
        while j_end < len(right) and right[j_end].isdigit():
            j_end += 1
        if i_end - i != j_end - j:
            return -1 if i_end - i < j_end - j else 1
        a, b = left[i:i_end], right[j:j_end]
        if a != b:
            return -1 if a < b else 1
        i, j = i_end, j_end
    return 0


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 using dpkg semantics, rejecting unsupported syntax."""
    left_epoch, left_upstream, left_revision = _parts(left)
    right_epoch, right_upstream, right_revision = _parts(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    upstream = _revision_compare(left_upstream, right_upstream)
    return upstream or _revision_compare(left_revision, right_revision)
