"""Conservative source-package applicability; incident prose never selects a fix."""

from __future__ import annotations

import re
from typing import Any

from .core import ValidationError, canonical, digest, identifier, integer, package_name, text
from .debian import compare_versions


_URGENCY = {"high": 80, "medium": 50, "low": 20, "unimportant": 10}
_SEVERITY = {"critical": 100, "high": 80, "medium": 50, "low": 20}
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.ASCII)
_DEBIAN_TEMP = re.compile(r"TEMP-[0-9]{7,}-[0-9A-F]{6}", re.ASCII)
_MAX_ASSERTIONS = 500_000
_MAX_ASSOCIATIONS = 300_000
_MAX_RESULT_BYTES = 64 * 1024 * 1024
_MAX_INCIDENTS = 20_000
_MAX_FINDINGS = 300_000


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _assertions(rows: Any) -> dict[tuple[str, str], list[dict]]:
    if not isinstance(rows, list) or len(rows) > _MAX_ASSERTIONS:
        raise ValidationError("advisories must be a bounded list")
    index: dict[tuple[str, str], list[dict]] = {}
    identities = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValidationError("advisory must be an object")
        advisory_id = text(row.get("id"), "advisory ID", max_length=128)
        if not _CVE.fullmatch(advisory_id) and not _DEBIAN_TEMP.fullmatch(advisory_id):
            raise ValidationError("Debian advisory ID must be a CVE or TEMP identifier")
        source = package_name(row.get("source_name"), "advisory source package")
        release = identifier(row.get("release"), "advisory release")
        text(row.get("status"), "advisory status", max_length=128)
        text(row.get("urgency"), "advisory urgency", max_length=128, allow_empty=True)
        fixed = row.get("fixed_version")
        if fixed is not None:
            text(fixed, "advisory fixed version", max_length=256, allow_empty=True)
        identity = (source, release, advisory_id)
        if identity in identities:
            raise ValidationError("duplicate Debian assertion identity")
        identities.add(identity)
        index.setdefault((source, release), []).append(row)
    return index


def _incidents(rows: Any) -> tuple[dict[str, list[dict]], list[dict]]:
    if not isinstance(rows, list) or len(rows) > _MAX_INCIDENTS:
        raise ValidationError("incidents must be a bounded list")
    index: dict[str, list[dict]] = {}
    identities = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValidationError("incident must be an object")
        key = identifier(row.get("id"), "incident ID")
        if key in identities:
            raise ValidationError("duplicate incident identity")
        identities.add(key)
        if type(row.get("is_example")) is not bool:
            raise ValidationError("incident is_example must be a boolean")
        text(row.get("severity"), "incident severity", max_length=128)
        ids = row.get("identifiers")
        if not isinstance(ids, list) or len(ids) > 256:
            raise ValidationError("incident identifiers must be a bounded list")
        seen_advisories = set()
        for advisory in ids:
            text(advisory, "incident identifier", max_length=128)
            if _CVE.fullmatch(advisory) and not row["is_example"] and advisory not in seen_advisories:
                index.setdefault(advisory, []).append(row)
                seen_advisories.add(advisory)
    return index, rows


def _verdict(package: dict, assertion: dict) -> tuple[str, str]:
    if _DEBIAN_TEMP.fullmatch(assertion["id"]):
        return "unknown", "Temporary Debian advisory identifier; investigation required"
    status, fixed = assertion["status"], assertion.get("fixed_version")
    if status == "resolved" and fixed == "0":
        return "not_affected", "Debian explicitly marks this release/source package not affected"
    if status == "open" and not fixed:
        return "affected", "Debian reports this release/source package affected with no fixed version"
    if status != "resolved" or not fixed:
        return "unknown", "Debian status or fixed-version evidence is unresolved or contradictory"
    try:
        comparison = compare_versions(package["source_version"], fixed)
    except ValidationError:
        return "unknown", "Unsupported Debian source/fixed version syntax; no lexical comparison used"
    if comparison < 0:
        return "affected", "Installed Debian source version is below the release-specific fix"
    return "not_affected", "Installed Debian source version meets the release-specific fix"


_ACQUISITIONS = (None, "https", "import")


def _global_reason(inventory: dict, now: int, max_inventory_age: int) -> str | None:
    if inventory["observed_at"] > now:
        return "Inventory observation is in the future"
    if now - inventory["observed_at"] > max_inventory_age:
        return "Inventory is stale; collect a fresh inventory"
    if not inventory["complete"]:
        return "Inventory is incomplete; missing packages cannot be declared safe"
    if (inventory["os"], inventory["release"], inventory["architecture"]) != ("debian", "trixie", "amd64"):
        return "Unsupported platform; only Debian trixie amd64 applicability is implemented"
    return None


def _package_reason(package: dict) -> str | None:
    if package["ecosystem"] != "deb" or package["architecture"] not in ("amd64", "all"):
        return "Unsupported package ecosystem or architecture"
    if package["status"] != "installed":
        return "Package is not in a fully installed state; investigate package state"
    return None


def _urgency(assertion: dict) -> int:
    return _URGENCY.get(assertion["urgency"].removesuffix("**"), 30)


_NOT_AFFECTED = ("Installed Debian source version meets the release-specific fix, "
                 "or Debian marks it not affected, for every listed advisory")


def _groups(package: dict, applicable: list[dict]) -> list[dict]:
    """Group one assessable package's verdicts by remediation identity.

    Assertions that share a status, fixed version and explanation need the same
    action (or investigation), so one finding lists all of their advisories.
    An affected group with a fixed version is exactly one candidate upgrade.
    """
    groups: dict[tuple, dict] = {}
    for assertion in applicable:
        status, detail = _verdict(package, assertion)
        if status == "not_affected":
            key, fixed, detail = (status, None, _NOT_AFFECTED), None, _NOT_AFFECTED
        else:
            fixed = assertion.get("fixed_version") if status == "affected" else None
            key = (status, fixed, detail)
        group = groups.setdefault(key, {"status": status, "fixed_version": fixed, "reason": detail, "assertions": []})
        group["assertions"].append(assertion)
    return [groups[key] for key in sorted(groups, key=lambda item: (item[0], item[1] or "", item[2]))]


def verify_affected(
    inventory: dict,
    assertions: list[dict],
    *,
    package: dict,
    advisory_ids: list[str],
    fixed_version: str,
    max_inventory_age: int,
) -> bool:
    """Recompute one affected finding exactly as match() would, without fan-out.

    The inventory is evaluated at its own observation time; callers check
    current freshness separately. Only assertions for the package's own source
    are validated and consulted. The advisory group must match exactly.
    """
    from .inventory import normalize_inventory

    if not isinstance(inventory, dict):
        raise ValidationError("inventory must be an object")
    inventory = normalize_inventory(inventory, collector=inventory.get("collector", "imported"))
    integer(max_inventory_age, "inventory maximum age", minimum=1, maximum=31_536_000)
    if not isinstance(assertions, list) or len(assertions) > _MAX_ASSERTIONS:
        raise ValidationError("advisories must be a bounded list")
    if not isinstance(advisory_ids, list) or not advisory_ids:
        return False
    if package not in inventory["packages"] or package["ecosystem"] != "deb":
        return False
    if (_global_reason(inventory, inventory["observed_at"], max_inventory_age)
            or _package_reason(package)):
        return False
    relevant = [row for row in assertions if isinstance(row, dict) and row.get("source_name") == package["source_name"]]
    applicable = _assertions(relevant).get((package["source_name"], inventory["release"]), [])
    return any(group["status"] == "affected" and group["fixed_version"] == fixed_version
               and sorted(row["id"] for row in group["assertions"]) == advisory_ids
               for group in _groups(package, applicable))


def match(
    inventory: dict,
    assertions: list[dict],
    incidents: list[dict],
    *,
    inventory_id: str,
    source_digest: str,
    now: int,
    max_inventory_age: int,
    evidence_acquisition: str | None = None,
) -> list[dict]:
    """Return deterministic findings for normalized data, with explicit unknowns.

    Provenance and source health are Engine responsibilities. Each package row
    covers the advisories listed in ``advisory_ids``; a not_affected row is
    scoped to those assertions, not universal host safety. Rows group one
    package's assertions by status, fixed version and explanation, so output
    grows with distinct remediation decisions rather than with each binary's
    full advisory history. An unassessable package has a single unknown row.
    """
    from .inventory import normalize_inventory

    if not isinstance(inventory, dict):
        raise ValidationError("inventory must be an object")
    inventory = normalize_inventory(inventory, collector=inventory.get("collector", "imported"))
    _hash(inventory_id, "inventory ID")
    _hash(source_digest, "source digest")
    integer(now, "current time")
    integer(max_inventory_age, "inventory maximum age", minimum=1, maximum=31_536_000)
    if evidence_acquisition not in _ACQUISITIONS:
        raise ValidationError("evidence acquisition must be https, import, or null")
    assertion_index = _assertions(assertions)
    incident_index, incident_rows = _incidents(incidents)
    findings: list[dict] = []
    correlated = set()
    association_count = result_bytes = 0
    imported = "; Debian evidence was imported, not acquired by a fixed-endpoint HTTPS poll"

    global_reason = _global_reason(inventory, now, max_inventory_age)

    def append(package: dict | None, covered: list[dict], status: str, reason: str,
               related: list[dict], priority: int, fixed_version: str | None = None) -> None:
        nonlocal association_count, result_bytes
        if len(findings) >= _MAX_FINDINGS:
            raise ValidationError("Applicability result exceeds the finding limit; narrow inventory scope")
        association_count += len(related)
        if association_count > _MAX_ASSOCIATIONS:
            raise ValidationError("Applicability result exceeds the correlation limit; narrow inventory scope")
        if status == "not_affected":
            priority_reasons = ["Not affected by these assertions: priority 0"]
        elif related and all(item["is_example"] for item in related):
            priority_reasons = ["Example incident is not actionable: priority 0"]
        else:
            priority_reasons = []
            if covered:
                highest = max(covered, key=lambda row: (_urgency(row), row["urgency"]))
                priority_reasons.append("Highest Debian urgency: " + highest["urgency"])
            priority_reasons.extend(
                "Incident " + item["id"] + " severity: " + item["severity"]
                for item in sorted(related, key=lambda row: row["id"])
            )
            if not priority_reasons:
                priority_reasons = ["Unknown coverage baseline: priority 30"]
            priority_reasons.append("Ordering only; neither probability nor execution authorization")
        if covered and evidence_acquisition == "import":
            reason += imported
        body = {
            "asset_id": inventory["asset_id"],
            "inventory_id": inventory_id,
            "package": package,
            "advisory_ids": sorted(row["id"] for row in covered),
            "source_name": package["source_name"] if package else None,
            "source_digest": source_digest,
            "evidence_acquisition": evidence_acquisition,
            "status": status,
            "reason": reason,
            "fixed_version": fixed_version,
            "priority": priority,
            "priority_reasons": priority_reasons,
            "incident_ids": sorted({item["id"] for item in related}),
        }
        finding = {"id": digest(body), **body}
        result_bytes += len(canonical(finding)) + 1
        if result_bytes > _MAX_RESULT_BYTES:
            raise ValidationError("Applicability result exceeds the output byte limit; narrow inventory scope")
        findings.append(finding)

    def related_to(covered: list[dict]) -> list[dict]:
        related = {item["id"]: item for assertion in covered for item in incident_index.get(assertion["id"], [])}
        correlated.update(related)
        return [related[key] for key in sorted(related)]

    # Verdicts depend on source identity/version, not on the binary. Compute
    # them once per source so multi-binary sources do not repeat the work.
    grouped: dict[tuple, list[dict]] = {}
    for package in inventory["packages"]:
        reason = global_reason or _package_reason(package)
        applicable = (
            assertion_index.get((package["source_name"], inventory["release"]), [])
            if package["ecosystem"] == "deb" else []
        )
        if not applicable:
            append(package, [], "unknown", reason or "No assertion for this source package/release in this dataset", [], 30)
            continue
        # The held flag affects remediation permission, not whether code is
        # vulnerable. It is retained in the package and explained here.
        held = "; package is held, so native remediation is blocked" if package["held"] else ""
        if reason:
            related = related_to(applicable)
            priority = max([_urgency(row) for row in applicable] + [_SEVERITY.get(item["severity"], 30) for item in related])
            append(package, applicable, "unknown", reason + held, related, priority)
            continue
        key = (package["source_name"], package["source_version"])
        if key not in grouped:
            grouped[key] = _groups(package, applicable)
        for group in grouped[key]:
            covered = group["assertions"]
            related = related_to(covered)
            priority = 0 if group["status"] == "not_affected" else max(
                [_urgency(row) for row in covered] + [_SEVERITY.get(item["severity"], 30) for item in related])
            append(package, covered, group["status"], group["reason"] + held, related, priority, group["fixed_version"])

    for incident in incident_rows:
        if incident["id"] not in correlated:
            example = incident["is_example"]
            append(None, [], "unknown",
                   "Example incident; excluded from applicability evidence" if example else
                   "Incident has no supported package assertion in this inventory; investigate separately",
                   [incident], 0 if example else _SEVERITY.get(incident["severity"], 30))
    if not inventory["packages"]:
        append(None, [], "unknown", global_reason or
               "No packages were observed; this does not establish host safety", [], 30)
    return sorted(findings, key=lambda row: (-row["priority"], row["id"]))
