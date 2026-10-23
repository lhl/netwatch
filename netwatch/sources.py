"""Advisory evidence, never installation commands. Explicit coverage limits."""
import json
import time
import urllib.request
import urllib.error

from .core import Error, digest
from .versions import compare_versions

USN = "https://usn.ubuntu.com/usn-db/database.json"
ARCH = "https://security.archlinux.org/issues/all.json"
OSV = "https://api.osv.dev/v1/query"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise Error("Advisory endpoint redirected; check source configuration in code")


def fetch(url, body=None):
    if url not in (USN, ARCH, OSV):
        raise Error("Unknown advisory endpoint")
    request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"User-Agent": "netwatch/0.2", "Content-Type": "application/json",
                                              "Accept-Encoding": "identity"})
    limit = 512 * 1024 * 1024 if url == USN else 20 * 1024 * 1024
    start, chunks, size = time.monotonic(), [], 0
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise Error("Unsupported compressed advisory response")
            while chunk := response.read(64 * 1024):
                size += len(chunk)
                if size > limit or time.monotonic() - start > 120:
                    raise Error("Advisory response exceeds byte/time limit")
                chunks.append(chunk)
        return json.loads(b"".join(chunks))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise Error("Advisory request failed; previous findings retained") from exc


def finding(p, advisory, state, fixes, reason, link):
    return {"key": digest([p["ecosystem"], p["name"], p.get("architecture"), advisory]),
            "package": p["name"], "installed": p["version"], "advisory": advisory,
            "state": state, "fix_versions": sorted(set(fixes)), "reason": reason, "url": link}


def compact_usn(data):
    """Cache only Noble matching evidence, not the large historical artifact corpus."""
    result = {}
    for key, notice in data.items():
        entry = notice.get("releases", {}).get("noble")
        if entry is not None:
            result[key] = {"id": notice["id"], "is_hidden": notice.get("is_hidden", False),
                           "cves": notice.get("cves", []), "releases": {"noble": {
                               "sources": {n: {"version": r.get("version")} for n, r in entry.get("sources", {}).items()},
                               "allbinaries": {n: {k: r.get(k) for k in ("source", "version", "pocket")}
                                               for n, r in entry.get("allbinaries", {}).items()}}}}
    if not result:
        raise Error("No Noble evidence in Ubuntu feed")
    return result


def ubuntu(packages, data):
    if not isinstance(data, dict) or not data:
        raise Error("Ubuntu feed is empty or malformed")
    result = []
    by_source = {}
    for p in packages:
        by_source.setdefault(p["source"], []).append(p)
    for key, notice in data.items():
        if notice.get("id") not in (key, "USN-" + key):
            raise Error("Malformed USN identity")
        entry = notice.get("releases", {}).get("noble", {})
        for source, info in entry.get("sources", {}).items():
            for p in by_source.get(source, []):
                binary = entry.get("allbinaries", {}).get(p["name"], {})
                fixed = info.get("version")
                supported = (notice.get("is_hidden", False) in (False, "false") and
                             binary.get("source") == source and binary.get("pocket") == "security" and
                             p.get("architecture") in ("amd64", "all") and fixed and fixed != "0" and
                             binary.get("version") and binary["version"] != "0" and
                             "esm" not in (fixed + binary["version"] + p["version"] + p["source_version"]).lower())
                state, fixes = "unknown", []
                reason = "Notice lacks supported standard-security binary/source evidence"
                if supported:
                    try:
                        if compare_versions(p["source_version"], fixed) >= 0:
                            continue
                        state, fixes = "affected", [fixed]
                        reason = "Installed source version is below this Noble notice fix"
                    except Error:
                        reason = "Unsupported version comparison"
                row = finding(p, "USN-" + key, state, fixes, reason,
                              "https://ubuntu.com/security/notices/USN-" + key)
                row["references"] = notice.get("cves", [])  # Notice-level links, not per-package CVE claims.
                result.append(row)
    return result


def arch(packages, data, kind):
    if not isinstance(data, list) or not data:
        raise Error("Arch feed is empty or malformed")
    result = []
    installed = {p["name"]: p for p in packages}
    for row in data:
        for n in row["packages"]:
            if n not in installed:
                continue
            p = installed[n]
            if kind == "arch" and not p.get("foreign") and row.get("fixed") == p["version"]:
                continue
            exact = (kind == "arch" and not p.get("foreign") and p["version"] == row.get("affected")
                     and row.get("status") in ("Vulnerable", "Fixed"))
            item = finding(p, row["name"], "affected" if exact else "unknown",
                           [row["fixed"]] if row.get("fixed") else [],
                           "Exact published affected version" if exact else
                           "Name match only; rebuild/version applicability requires investigation",
                           "https://security.archlinux.org/" + row["name"])
            item.update(references=row.get("issues", []), severity=row.get("severity", "Unknown"))
            result.append(item)
    return result


def osv(p, data):
    if not isinstance(data, dict) or "error" in data or not isinstance(data.get("vulns", []), list):
        raise Error("OSV response is malformed")
    result = []
    for row in data.get("vulns", []):
        if row.get("withdrawn"):
            continue
        fixes = []
        for affected in row.get("affected", []):
            ap = affected.get("package", {})
            normalize = lambda n: n.lower().replace("_", "-").replace(".", "-") if p["ecosystem"] == "PyPI" else n
            if ap.get("ecosystem") != p["ecosystem"] or normalize(ap.get("name", "")) != normalize(p["name"]):
                continue
            for r in affected.get("ranges", []):
                fixes.extend(e["fixed"] for e in r.get("events", []) if "fixed" in e)
        item = finding(p, row["id"], "affected", fixes,
                       "OSV exact installed-version query; fixes are evidence, not installation targets",
                       "https://osv.dev/vulnerability/" + row["id"])
        item.update(references=row.get("aliases", []), severity=row.get("severity", []))
        result.append(item)
    return result


def assess(t, packages, store, *, offline=False, refresh=False, refreshed=None, request=fetch):
    findings, warnings, evidence, complete = [], [], [], True
    refreshed = set() if refreshed is None else refreshed
    kind = t["kind"]
    def cached(key, url, body=None):
        def load():
            data = request(url, body)
            return compact_usn(data) if url == USN else data
        value = store.cached(key, load, offline=offline, max_age=0 if refresh and key not in refreshed else 3600)
        refreshed.add(key)
        at = store.db.execute("SELECT at FROM cache WHERE key=?", (key,)).fetchone()[0]
        evidence.append({"source": url, "cache_key": key, "fetched_at": at})
        return value
    try:
        if kind == "ubuntu":
            findings = ubuntu(packages, cached("ubuntu-usn", USN))
            warnings.append("Coverage: Noble published security notices only, not all CVEs or pre-patch vulnerabilities; Pro/ESM excluded")
        elif kind in ("arch", "cachyos"):
            findings = arch(packages, cached("arch-tracker", ARCH), kind)
            warnings.append("Coverage: Arch tracker is incomplete and may lag current releases; name-only and CachyOS matches require investigation")
        else:
            unknown = sum(p["ecosystem"] == "Conda" for p in packages)
            if unknown:
                warnings.append(f"Coverage unknown for {unknown} conda-native packages; not mapped to PyPI")
            for p in packages:
                if p["ecosystem"] in ("PyPI", "npm"):
                    body = {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
                    findings.extend(osv(p, cached("osv:" + digest(body), OSV, body)))
            warnings.append("Coverage: OSV exact-version matches for collected PyPI/npm packages only; source forks and uncollected environments are not assessed")
    except (Error, KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        complete = False
        warnings.append("Advisory check failed: " + (str(exc) if isinstance(exc, Error) else "unexpected source format"))
    # Multiple installed versions can share an advisory: retain every affected version.
    merged = {}
    for row in findings:
        if row["key"] in merged:
            old = merged[row["key"]]
            row["installed"] = ", ".join(sorted(set(old["installed"].split(", ") + [row["installed"]])))
        merged[row["key"]] = row
    return list(merged.values()), warnings, complete, evidence
