"""Advisory evidence, never installation commands. Explicit coverage limits."""
import json
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone

from . import adapters
from .core import Error, digest, text
from .versions import compare_versions

USN = "https://usn.ubuntu.com/usn-db/database.json"
ARCH = "https://security.archlinux.org/issues/all.json"
OSV = "https://api.osv.dev/v1/query"
PWN = "https://pwn.watch/incidents.json"
CVE_NOW = "https://cve.now/api/v1/entries/"
CVE_ID = r"CVE-[0-9]{4}-[0-9]{4,19}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Only the documented cve.now entry-to-storage hop; never follow feed links.
        cve = req.full_url.removeprefix(CVE_NOW)
        dest = urllib.parse.urlsplit(newurl)
        if (req.full_url == CVE_NOW + cve and re.fullmatch(CVE_ID, cve) and
                dest.scheme == "https" and dest.hostname and
                dest.hostname.endswith(".public.blob.vercel-storage.com") and
                dest.netloc == dest.hostname and not dest.query and not dest.fragment and
                dest.path == f"/public/entries/{cve}.json"):
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        raise Error("Advisory endpoint redirected; check source configuration in code")


def fetch(url, body=None):
    cve_lookup = url.startswith(CVE_NOW) and re.fullmatch(CVE_ID, url[len(CVE_NOW):])
    if url not in (USN, ARCH, OSV, PWN) and not cve_lookup:
        raise Error("Unknown advisory endpoint")
    if (cve_lookup or url == PWN) and body is not None:
        raise Error("Context sources accept only public GET requests")
    request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"User-Agent": "netwatch/0.2", "Content-Type": "application/json",
                                              "Accept-Encoding": "identity"})
    limit = 512 * 1024 * 1024 if url == USN else (2 if cve_lookup else 20) * 1024 * 1024
    timeout = 10 if cve_lookup or url == PWN else 30
    start, chunks, size = time.monotonic(), [], 0
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise Error("Unsupported compressed advisory response")
            while chunk := response.read(64 * 1024):
                size += len(chunk)
                if size > limit or time.monotonic() - start > (20 if cve_lookup or url == PWN else 120):
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


def arch(packages, data, kind, *, compare=None, stats=None):
    if not isinstance(data, list) or not data:
        raise Error("Arch feed is empty or malformed")
    installed = {p["name"]: p for p in packages}
    matches = [(installed[n], row) for row in data for n in row["packages"] if n in installed]
    def comparable(p, row):
        return (not p.get("foreign") and row.get("fixed") != "0" and
                adapters.valid_arch_version(p["version"]) and adapters.valid_arch_version(row.get("fixed")))
    pairs = sorted({(p["version"], row["fixed"]) for p, row in matches if comparable(p, row)})
    if pairs and compare is None:
        raise Error("Arch matching requires vercmp on the target")
    orders = compare(pairs) if pairs else {}
    result, omitted = [], 0
    for p, row in matches:
        if comparable(p, row) and orders[(p["version"], row["fixed"])] >= 0:
            omitted += 1
            continue
        exact = (kind == "arch" and not p.get("foreign") and p["version"] == row.get("affected")
                 and row.get("status") in ("Vulnerable", "Fixed"))
        item = finding(p, row["name"], "affected" if exact else "unknown",
                       [row["fixed"]] if row.get("fixed") else [],
                       "Exact published affected version" if exact else
                       "Installed version needs review against this notice; package lineage or fix evidence is uncertain",
                       "https://security.archlinux.org/" + row["name"])
        item.update(references=row.get("issues", []), severity=row.get("severity", "Unknown"))
        result.append(item)
    if stats is not None:
        stats["fixed_notices_omitted"] = omitted
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


def advisory_references(findings, *, cves_only=False):
    """Notice-level links are context, not per-package applicability claims."""
    values = set()
    for row in findings:
        refs = row.get("references", [])
        refs = refs if isinstance(refs, list) else [refs]
        for value in [row["advisory"], *refs]:
            if isinstance(value, str) and re.fullmatch(CVE_ID if cves_only else r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", value):
                values.add(value)
    return sorted(values)


def cve_context(cve, data):
    if not isinstance(data, dict) or data.get("id") != cve or data.get("status") not in ("published", "rejected", "superseded"):
        raise Error("Invalid cve.now entry identity or status")
    summary = data.get("summary")
    if summary is not None:
        summary = {"text": text(summary["text"], "summary"), "model": text(summary["model"], "summary model"),
                   "license": "CC-BY-4.0"}
    severity = data.get("severity")
    if severity is not None:
        score = severity["cvss"]
        if type(score) not in (int, float) or not 0 <= score <= 10:
            raise Error("Invalid cve.now severity")
        severity = {"cvss": score, "source": text(severity["source"], "severity source")}
    exploitation = data.get("exploitation", {})
    signals = {}
    for key, fields in (("kev", ("dateAdded", "dueDate")), ("epssReached", ("date",))):
        value = exploitation.get(key)
        if value is not None and not isinstance(value, dict):
            raise Error("Invalid cve.now exploitation signal")
        signals[key] = {field: text(value[field], field) for field in fields if field in value} if value is not None else None
        if value is not None and not signals[key]:
            raise Error("Invalid cve.now exploitation signal")
    signals["public_exploit_sources"] = [key for key in ("exploitDb", "metasploit", "nuclei", "githubPoc") if exploitation.get(key)]
    upstream = []
    if not isinstance(data.get("sources", []), list) or len(data.get("sources", [])) > 100:
        raise Error("Invalid cve.now sources")
    for source in data.get("sources", []):
        link = text(source["url"], "source URL")
        if urllib.parse.urlsplit(link).scheme not in ("http", "https"):
            raise Error("Invalid cve.now source URL")
        upstream.append({"name": text(source["name"], "source name"), "url": link,
                         "license": text(source.get("license", "Not specified"), "source license")})
    return {"id": cve, "url": "https://cve.now/" + cve, "status": data["status"],
            "modified_at": text(data["modifiedAt"], "entry timestamp"), "summary": summary,
            "severity": severity, "signals": signals, "sources": upstream}


def pwn_context(packages, findings, data):
    if not isinstance(data, dict) or not isinstance(data.get("incidents"), list) or not data["incidents"] or len(data["incidents"]) > 20000:
        raise Error("Invalid or empty pwn.watch incident catalog")
    text(data["generatedAt"], "catalog timestamp")
    # Fixed aliases only. Tags and exact names identify review leads, never affected versions.
    aliases = {"linux-lts": "linux", "linux-zen": "linux", "linux-hardened": "linux",
               "nodejs": "node", "bind9": "bind"}
    names = {}
    for p in packages:
        normalize = lambda n: re.sub(r"[-_.]+", "-", n.lower()) if p["ecosystem"] == "PyPI" else n.lower()
        for name in {p["name"], p.get("source", p["name"])}:
            tag = normalize(name)
            for value in {tag, aliases.get(tag, tag)}:
                names.setdefault(value, set()).add(p["name"])
    references = set(advisory_references(findings))
    result, seen = [], set()
    for row in data["incidents"]:
        slug = row["slug"]
        if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,199}", slug) or slug in seen:
            raise Error("Invalid or duplicate pwn.watch incident identity")
        seen.add(slug)
        for field in ("title", "product", "severity", "patchStatus", "updatedAt"):
            text(row[field], "incident " + field)
        if len(row["updatedAt"]) != 10 and datetime.fromisoformat(row["updatedAt"]).tzinfo is None:
            raise Error("Incident timestamp lacks a time zone")
        datetime.fromisoformat(row["updatedAt"])  # Older catalog entries may contain only a date.
        if (type(row.get("isExample")) is not bool or row["category"] not in ("patch", "supply-chain", "breach") or
                row["status"] not in ("live", "closed")):
            raise Error("Invalid pwn.watch category or status")
        tags, ids = row["tags"], row["cveIds"]
        if (not isinstance(tags, list) or len(tags) > 100 or any(not isinstance(t, str) for t in tags) or
                not isinstance(ids, list) or len(ids) > 1000 or any(not isinstance(c, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", c) for c in ids)):
            raise Error("Invalid pwn.watch tags or advisory references")
        if row["isExample"] or row["category"] == "breach" or row["status"] != "live":
            continue
        matched_tags = sorted(names.keys() & set(tags))
        # A generic Linux platform tag must not associate every Linux application with the kernel.
        if "linux" in matched_tags and not row["product"].lower().startswith("linux kernel"):
            matched_tags.remove("linux")
        matched_refs = sorted(references & set(ids))
        if not matched_tags and not matched_refs:
            continue
        result.append({"id": slug, "url": "https://pwn.watch/i/" + slug,
                       "title": row["title"], "product": row["product"], "category": row["category"],
                       "severity": text(row["severity"], "incident severity"),
                       "patch_status": text(row["patchStatus"], "incident patch status"),
                       "updated_at": text(row["updatedAt"], "incident timestamp"),
                       "references": sorted(set(ids)), "matched_references": matched_refs, "matched_tags": matched_tags,
                       "packages": sorted({n for tag in matched_tags for n in names[tag]}),
                       "state": "review", "reason": "Advisory reference or package/source tag overlap only; applicability is not established"})
    return sorted(result, key=lambda r: (datetime.fromisoformat(r["updated_at"]).replace(tzinfo=timezone.utc)
                                         if len(r["updated_at"]) == 10 else datetime.fromisoformat(r["updated_at"]), r["id"]), reverse=True)


def context(packages, findings, store, *, offline=False, refresh=False, refreshed=None, request=fetch):
    """Optional context is stored separately; it cannot change findings or commands."""
    refreshed = set() if refreshed is None else refreshed
    result = {}
    def cached(key, url, parse, evidence):
        value = store.cached(key, lambda: parse(request(url)), offline=offline,
                             max_age=0 if refresh and key not in refreshed else 3600)
        refreshed.add(key)
        evidence.append({"source": url, "fetched_at": store.db.execute("SELECT at FROM cache WHERE key=?", (key,)).fetchone()[0]})
        return value
    failures = (Error, KeyError, TypeError, ValueError, AttributeError, RecursionError)
    cves = advisory_references(findings, cves_only=True)
    items, errors, evidence = [], [], []
    start = time.monotonic()
    for cve in cves[:20]:
        if time.monotonic() - start > 60:
            errors.append(cve + ": lookup time budget exhausted; prior context retained if present")
            continue
        try:
            item = cached("cve-now:" + cve, CVE_NOW + cve, lambda data: cve_context(cve, data), evidence)
            items.append({**item, "fetched_at": evidence[-1]["fetched_at"]})
        except failures:
            errors.append(cve + ": context unavailable or invalid; prior context retained if present")
    if len(cves) > 20:
        errors.append(f"CVE context limited to 20 of {len(cves)} referenced IDs")
    result["cve_now"] = {"status": "incomplete" if errors else "ok", "items": items, "errors": errors, "evidence": evidence}
    try:
        # Cache the public catalog once for all targets; relevance is evaluated locally each time.
        def compact(data):
            pwn_context([], [], data)  # Validate before replacing the last usable cache.
            fields = ("slug", "title", "product", "category", "status", "severity", "patchStatus", "tags", "cveIds", "updatedAt", "isExample")
            return {"generatedAt": data["generatedAt"],
                    "incidents": [{key: row[key] for key in fields} for row in data["incidents"]]}
        catalog = cached("pwn-watch", PWN, compact, evidence := [])
        incidents = [{**row, "fetched_at": evidence[-1]["fetched_at"]} for row in pwn_context(packages, findings, catalog)]
        result["pwn_watch"] = {"status": "ok", "items": incidents, "errors": [], "evidence": evidence,
                               "generated_at": catalog["generatedAt"]}
    except failures:
        result["pwn_watch"] = {"status": "incomplete", "items": [], "evidence": [],
                               "errors": ["Incident context unavailable or invalid; prior context retained if present"]}
    return result


def assess(t, packages, store, *, offline=False, refresh=False, refreshed=None, request=fetch, runner=adapters.run):
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
            data = cached("arch-tracker", ARCH)
            stats = {}
            findings = arch(packages, data, kind, compare=lambda pairs: adapters.arch_compare(t, pairs, runner), stats=stats)
            evidence[-1]["matching"] = stats
            warnings.append("Coverage: Arch tracker may lag releases; remaining CachyOS and foreign-package matches require investigation")
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
