"""Bounded advisory inputs. Feed content is evidence, never execution authority.

The public parsers accept decoded JSON objects; parse_source accepts UTF-8 bytes
or text. Fetching uses only the two endpoints below. A 304 has raw=None; the
caller must verify that it has a prior successful snapshot for that endpoint.

Tests can replace _CONNECTION_FACTORY with a picklable HTTPSConnection-compatible
factory. _fetch_http also accepts a factory, monotonic clock and binary sink for
deterministic socket/read tests. Neither interface is exposed as a CLI option.
"""

from __future__ import annotations

import http.client
import math
import multiprocessing
from pathlib import Path
import re
import ssl
import tempfile
import time

from .core import AutoprotectError, ValidationError, identifier, load_json, package_name, text, version


_ENDPOINTS = {
    "pwn": ("pwn.watch", "/incidents.json"),
    "ubuntu": ("usn.ubuntu.com", "/usn-db/database.json"),
}
_BYTE_LIMITS = {"pwn": 8 * 1024 * 1024, "ubuntu": 512 * 1024 * 1024}
_MAX_NODES = 8_000_000
_MAX_UBUNTU_NODES = 32_000_000
_MAX_DEPTH = 32
_MAX_TEXT = 65536
_MAX_PWN_RECORDS = 10_000
_MAX_UBUNTU_RECORDS = 500_000
_MAX_NOTICES = 50_000
_MAX_BINARIES = 10_000
_MAX_USN_REFERENCES = 4096
_MAX_LIST = 256
_SOCKET_TIMEOUT = 10
_TOTAL_TIMEOUT = 60
_READ_SIZE = 64 * 1024
_MAX_HEADER_FIELDS = 100
_MAX_HEADER_BYTES = 32768
_FIELD_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
# Trailers cannot change framing, representation, routing, authentication,
# caching or validators. Other bounded fields are discarded, not trusted.
_FORBIDDEN_TRAILERS = frozenset({
    "transfer-encoding", "content-length", "host", "connection", "keep-alive",
    "proxy-connection", "upgrade", "trailer", "te", "max-forwards",
    "content-encoding", "content-type", "content-range", "content-location",
    "content-language", "content-disposition", "authorization", "proxy-authorization",
    "www-authenticate", "proxy-authenticate", "authentication-info",
    "proxy-authentication-info", "cookie", "set-cookie", "cache-control", "age",
    "date", "expires", "location", "retry-after", "vary", "warning", "etag", "last-modified",
})
_CONNECTION_FACTORY = http.client.HTTPSConnection
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.ASCII)
_USN = re.compile(r"[0-9]+-[0-9]+", re.ASCII)
_GHSA = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", re.ASCII)
_MAL = re.compile(r"MAL-[0-9]{4}-[0-9]+", re.ASCII)
_ETAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e]*"', re.ASCII)


def _source(source):
    if not isinstance(source, str) or source not in _ENDPOINTS:
        raise ValidationError("Source must be pwn or ubuntu; custom endpoints are not supported")
    return source


def _object(value, field):
    if not isinstance(value, dict):
        raise ValidationError(f"{field} must be a JSON object")
    return value


def _check_structure(data, source):
    """Bound decoded inputs too, including ignored fields and cyclic objects.

    Iterator frames keep traversal memory proportional to depth, not tree width.
    The decoded byte budget counts UTF-8 text and structural overhead. Raw input
    has a separate exact byte limit in parse_source.
    """
    stack = [iter((data,))]
    nodes = size = 0
    while stack:
        try:
            item = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        nodes += 1
        size += 2
        node_limit = _MAX_UBUNTU_NODES if source == "ubuntu" else _MAX_NODES
        if nodes > node_limit or len(stack) - 1 > _MAX_DEPTH:
            raise ValidationError("Feed exceeds the nesting or node limit")
        if isinstance(item, str):
            size += len(text(item, "feed text", max_length=_MAX_TEXT, allow_empty=True).encode("utf-8"))
        elif type(item) is dict:
            # Keys are visited as values, with a separate string-key check.
            def children(mapping):
                for key, child in mapping.items():
                    if not isinstance(key, str):
                        raise ValidationError("Feed object keys must be strings")
                    yield key
                    yield child
            stack.append(iter(children(item)))
        elif type(item) is list:
            stack.append(iter(item))
        elif item is None or type(item) is bool:
            size += 5
        elif type(item) is int:
            if item.bit_length() > 256:
                raise ValidationError("Feed integer exceeds the supported size")
            size += 80
        elif type(item) is float and math.isfinite(item):
            size += 32
        else:
            raise ValidationError("Feed contains an unsupported JSON value")
        if size > _BYTE_LIMITS[source]:
            raise ValidationError("Decoded feed exceeds the byte budget")


def _strings(value, field, *, max_length=8192, max_items=_MAX_LIST):
    if not isinstance(value, list) or len(value) > max_items:
        raise ValidationError(f"{field} must be a list of at most {max_items} strings")
    return [text(item, field, max_length=max_length) for item in value]


def _advisory_id(value):
    value = identifier(value, "advisory ID")
    pattern = _CVE if value.startswith("CVE-") else (
        _GHSA if value.startswith("GHSA-") else _MAL if value.startswith("MAL-") else None
    )
    if pattern is not None and not pattern.fullmatch(value):
        raise ValidationError("Advisory ID has an invalid namespace-specific format")
    return value


def parse_pwn(data):
    """Normalize the incidents.json envelope without interpreting its prose.

    Duplicate slugs reject the complete snapshot; repeated advisory IDs within
    one incident are deduplicated. Unknown state strings and examples remain
    visible. URLs, source claims and executable-looking fields confer no trust.
    """
    _check_structure(data, "pwn")
    root = _object(data, "pwn feed")
    records = root.get("incidents")
    if not isinstance(records, list) or len(records) > _MAX_PWN_RECORDS:
        raise ValidationError("pwn incidents must be a bounded list")
    result = []
    seen = set()
    for record in records:
        record = _object(record, "pwn incident")
        slug = identifier(record.get("slug"), "incident slug")
        if slug in seen:
            raise ValidationError("pwn feed contains a duplicate incident slug")
        seen.add(slug)
        example = record.get("isExample", False)
        if type(example) is not bool:
            raise ValidationError("isExample must be a boolean")
        result.append({
            "id": slug,
            "title": text(record.get("title"), "incident title", max_length=2048),
            "summary": text(record.get("summary", ""), "incident summary", max_length=32768, allow_empty=True),
            "identifiers": sorted({_advisory_id(item) for item in _strings(record.get("cveIds", []), "cveIds", max_length=128)}),
            "severity": text(record.get("severity", "unknown"), "incident severity", max_length=128),
            "patch_status": text(record.get("patchStatus", "unknown"), "patch status", max_length=128),
            "product": text(record.get("product", ""), "incident product", max_length=2048, allow_empty=True),
            "updated_at": text(record.get("updatedAt", ""), "publisher update time", max_length=128, allow_empty=True),
            "is_example": example,
            "affected_versions": _strings(record.get("affectedVersions", []), "affectedVersions"),
            "fixed_versions": _strings(record.get("fixedVersions", []), "fixedVersions"),
        })
    return sorted(result, key=lambda row: row["id"])


def parse_ubuntu(data, release="noble"):
    """Normalize Canonical's USN database, not a generic vulnerability tracker.

    The raw shape is notice ID -> releases -> sources/allbinaries. A USN lists
    CVEs at notice level; do not invent a source-package/CVE cross product.
    Missing release/source/pocket/fix evidence stays unknown. Only standard
    security-pocket fixes are assessable; Pro/ESM and special pockets are not.
    Feed artifact URLs and action prose are never installation instructions.
    """
    if release != "noble":
        raise ValidationError("Only Ubuntu 24.04 LTS noble is supported")
    _check_structure(data, "ubuntu")
    notices = _object(data, "Ubuntu USN database")
    if len(notices) > _MAX_NOTICES:
        raise ValidationError("Ubuntu feed exceeds the notice limit")
    result = []
    for notice_id, notice in notices.items():
        notice_id = identifier(notice_id, "Ubuntu notice ID")
        if not _USN.fullmatch(notice_id):
            raise ValidationError("Ubuntu database keys must be numeric USN identities")
        notice = _object(notice, "Ubuntu notice")
        if notice.get("id") not in (notice_id, "USN-" + notice_id):
            raise ValidationError("Ubuntu notice ID does not match its database key")
        hidden = notice.get("is_hidden", False)
        if type(hidden) is not bool:
            if hidden not in ("true", "false"):
                raise ValidationError("Ubuntu notice is_hidden must be a boolean or literal true/false string")
            hidden = hidden == "true"
        references = _strings(notice.get("cves", []), "Ubuntu notice references", max_length=2048,
                              max_items=_MAX_USN_REFERENCES)
        # The publisher's cves list also contains bug/notice URLs. They are not
        # CVE identities, and neither their content nor their location is trusted.
        cves = []
        for reference in references:
            if _CVE.fullmatch(reference):
                cves.append(identifier(reference, "Ubuntu CVE"))
            elif not re.fullmatch(r"https?://[^\s\x00-\x20\x7f]+", reference, re.ASCII):
                raise ValidationError("Ubuntu notice reference must be a CVE or an HTTP(S) URL")
        cves = sorted(set(cves))
        description = text(notice.get("description", ""), "Ubuntu description", max_length=_MAX_TEXT, allow_empty=True)
        releases = _object(notice.get("releases", {}), "Ubuntu releases")
        # Preserve source-level unknown coverage for notices lacking Noble data.
        # A source mentioned only for another release never inherits that fix.
        source_names = set()
        for release_entry in releases.values():
            release_entry = _object(release_entry, "Ubuntu release")
            for name, entry in _object(release_entry.get("sources", {}), "Ubuntu source packages").items():
                source_names.add(package_name(name, "Ubuntu source package"))
                _object(entry, "Ubuntu source entry")
        entry = _object(releases.get(release, {}), "Ubuntu Noble release")
        sources = _object(entry.get("sources", {}), "Ubuntu Noble sources")
        binaries = _object(entry.get("allbinaries", {}), "Ubuntu binary packages")
        if len(binaries) > _MAX_BINARIES:
            raise ValidationError("Ubuntu notice exceeds the binary-package limit")
        binary_index = {}
        for name, binary in binaries.items():
            name = package_name(name, "Ubuntu binary package")
            binary = _object(binary, "Ubuntu binary entry")
            source = binary.get("source")
            if source is None:
                continue  # Missing lineage cannot establish a source/binary link.
            source = package_name(source, "Ubuntu binary source")
            source_names.add(source)
            pocket = binary.get("pocket")
            if pocket is not None:
                pocket = text(pocket, "Ubuntu pocket", max_length=128, allow_empty=True)
            binary_version = binary.get("version")
            valid_version = False
            if binary_version is not None:
                binary_version = text(binary_version, "Ubuntu binary fixed version", max_length=256, allow_empty=True)
                try:
                    version(binary_version)
                    valid_version = binary_version != "0" and "esm" not in binary_version.lower()
                except ValidationError:
                    pass
            binary_index.setdefault(source, []).append((name, pocket, valid_version))
        for source in sorted(source_names):
            if len(result) >= _MAX_UBUNTU_RECORDS:
                raise ValidationError("Ubuntu feed exceeds the assertion limit")
            source_entry = _object(sources.get(source, {}), "Ubuntu source assertion")
            fixed = source_entry.get("version")
            if fixed is not None:
                fixed = text(fixed, "Ubuntu source fixed version", max_length=256, allow_empty=True) or None
            linked = binary_index.get(source, [])
            pockets = {pocket for _, pocket, _ in linked}
            pocket = next(iter(pockets)) if len(pockets) == 1 else None
            status = "unknown"
            if (not hidden and fixed and fixed != "0" and "esm" not in fixed.lower() and pocket == "security"
                    and all(valid for _, _, valid in linked)):
                try:
                    version(fixed)
                    status = "resolved"
                except ValidationError:
                    pass
            result.append({
                "id": "USN-" + notice_id,
                "source_name": source,
                "release": release,
                "status": status,
                "fixed_version": fixed,
                "urgency": "unknown",  # This database does not supply severity.
                "description": description,
                "cve_ids": cves,
                "pocket": pocket,
                "binary_packages": sorted(name for name, _, _ in linked),
            })
    return sorted(result, key=lambda row: (row["source_name"], row["id"]))


def decode_source(source, raw):
    """Decode a complete source using its shared byte, node and depth limits."""
    source = _source(source)
    return load_json(raw, max_bytes=_BYTE_LIMITS[source],
                     max_nodes=_MAX_UBUNTU_NODES if source == "ubuntu" else _MAX_NODES,
                     max_depth=_MAX_DEPTH)


def parse_source(source, raw):
    """Load an entire bounded snapshot; reject it rather than return partial data."""
    data = decode_source(source, raw)
    return parse_pwn(data) if source == "pwn" else parse_ubuntu(data)


def _validate_etag(etag):
    if etag is None:
        return None
    if not isinstance(etag, str) or len(etag) > 512 or not _ETAG.fullmatch(etag):
        raise ValidationError("ETag must be a quoted bounded ASCII validator without controls")
    return etag


def _headers(response):
    headers = {}
    total = 0
    pairs = response.getheaders()
    if len(pairs) > _MAX_HEADER_FIELDS:
        raise AutoprotectError("Source response has too many headers")
    significant = {"etag", "content-encoding", "transfer-encoding", "content-length", "content-type", "trailer", "connection"}
    for name, value in pairs:
        total += len(name) + len(value)
        if total > _MAX_HEADER_BYTES or not _FIELD_NAME.fullmatch(name):
            raise AutoprotectError("Source response headers exceed the supported format or size")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise AutoprotectError("Source response headers contain control characters")
        name = name.lower()
        if name in significant and name in headers:
            raise AutoprotectError("Source response contains an ambiguous repeated header")
        headers[name] = value
    if headers.get("content-encoding", "identity").lower() != "identity":
        raise AutoprotectError("Source response compression is not supported")
    transfer = headers.get("transfer-encoding")
    if transfer is not None and transfer.lower() != "chunked":
        raise AutoprotectError("Source transfer encoding is not supported")
    if transfer is not None and "content-length" in headers:
        raise AutoprotectError("Source response has conflicting length headers")
    content_type = headers.get("content-type")
    if content_type is not None and not re.fullmatch(
        r'application/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?', content_type, re.IGNORECASE | re.ASCII
    ):
        raise AutoprotectError("Source response must be UTF-8 JSON")
    return headers


def _guard_trailers(response, headers, sock, remaining):
    """Replace only HTTPResponse's permissive trailer-discard hook.

    CPython calls this hook after the zero-size chunk and before closing fp.
    Retain its chunk/body decoder, but require a complete, bounded trailer
    section. Real HTTPResponse fixtures exercise this private stdlib dependency.
    Accepted fields never enter response headers or the public fetch result.
    """
    def field_names(value):
        names = [item.strip().lower() for item in value.split(",")]
        if (len(names) > _MAX_HEADER_FIELDS or len(set(names)) != len(names)
                or any(not _FIELD_NAME.fullmatch(name) for name in names)):
            raise AutoprotectError("Source response has an invalid trailer field declaration")
        return set(names)

    forbidden = _FORBIDDEN_TRAILERS | headers.keys()
    if "connection" in headers:
        forbidden |= field_names(headers["connection"])
    declared = None
    if "trailer" in headers:
        declared = field_names(headers["trailer"])
        if headers.get("transfer-encoding", "").lower() != "chunked" or declared & forbidden:
            raise AutoprotectError("Source response has a forbidden trailer declaration")
    if not isinstance(response, http.client.HTTPResponse) or not response.chunked:
        return  # Constructor-only test doubles may already provide decoded bodies.
    stream = response.fp

    def discard():
        total = 0
        seen = set()
        while True:
            sock.settimeout(remaining())
            # Cap each read by the remaining section budget, plus one byte to
            # detect overflow. A huge or unterminated line is never read in full.
            line = stream.readline(_MAX_HEADER_BYTES - total + 1)
            remaining()
            total += len(line)
            if total > _MAX_HEADER_BYTES:
                raise AutoprotectError("Source response trailers exceed the byte limit")
            if not line.endswith(b"\r\n"):
                raise AutoprotectError("Source response has incomplete or invalid trailer framing")
            if line == b"\r\n":
                return
            if len(seen) >= _MAX_HEADER_FIELDS:
                raise AutoprotectError("Source response has too many trailer fields")
            name, colon, value = line[:-2].partition(b":")
            name = name.decode("iso-8859-1")
            if not colon or not _FIELD_NAME.fullmatch(name):
                raise AutoprotectError("Source response has an invalid trailer field")
            if any(byte < 32 or byte == 127 for byte in value):
                raise AutoprotectError("Source response trailers contain control characters")
            name = name.lower()
            if name in forbidden or name in seen or (declared is not None and name not in declared):
                raise AutoprotectError("Source response has forbidden or ambiguous trailer metadata")
            seen.add(name)

    response._read_and_discard_trailer = discard


def _fetch_http(source, etag, output, *, connection_factory, clock, max_bytes, timeout):
    """One direct HTTPS request, streaming to a bounded binary sink.

    Socket deadlines bound individual operations. fetch_source supplies a worker
    deadline as well: socket timeouts alone cannot bound DNS or slow headers.
    """
    host, path = _ENDPOINTS[_source(source)]
    etag = _validate_etag(etag)
    deadline = clock() + timeout

    def remaining():
        seconds = deadline - clock()
        if seconds <= 0:
            raise AutoprotectError("Source fetch exceeded its deadline")
        return min(_SOCKET_TIMEOUT, seconds)

    connection = response = None
    try:
        connection = connection_factory(host, port=443, timeout=remaining(), context=ssl.create_default_context())
        connection.connect()
        # Hold the socket reference even if HTTPConnection detaches it for a
        # Connection: close response; HTTPResponse still holds its file object.
        sock = connection.sock
        sock.settimeout(remaining())
        headers = {"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "autoprotect/0.1", "Connection": "close"}
        if etag is not None:
            headers["If-None-Match"] = etag
        connection.request("GET", path, headers=headers)
        sock.settimeout(remaining())
        response = connection.getresponse()
        remaining()
        if response.status not in (200, 304):
            raise AutoprotectError("Source returned an unsuccessful HTTP status; redirects are not followed")
        received = _headers(response)
        response_etag = _validate_etag(received.get("etag"))
        if response.status == 304:
            if etag is None:
                raise AutoprotectError("Source returned 304 without a request validator")
            return {"not_modified": True, "etag": response_etag or etag}
        _guard_trailers(response, received, sock, remaining)
        declared = received.get("content-length")
        if declared is not None:
            if not re.fullmatch(r"[0-9]{1,12}", declared, re.ASCII) or int(declared) > max_bytes:
                raise AutoprotectError("Source content length is invalid or exceeds the byte limit")
            declared = int(declared)
        count = 0
        # HTTPResponse can close its socket as soon as the declared body is
        # consumed. Do not set another timeout or read from that closed socket.
        while declared is None or count < declared:
            sock.settimeout(remaining())
            chunk = response.read1(min(_READ_SIZE, max_bytes - count + 1))
            remaining()
            if not chunk:
                break
            count += len(chunk)
            if count > max_bytes:
                raise AutoprotectError("Source response exceeds the byte limit")
            output.write(chunk)
        if declared is not None and count != declared:
            raise AutoprotectError("Source response length does not match Content-Length")
        return {"not_modified": False, "etag": response_etag}
    except (OSError, http.client.HTTPException) as exc:
        raise AutoprotectError("Source HTTPS transport failed") from exc
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def _fetch_worker(source, etag, directory, connection_factory, max_bytes, timeout):
    """Child writes only to its parent's private scratch directory."""
    import json

    try:
        with (Path(directory) / "body").open("wb") as output:
            result = _fetch_http(source, etag, output, connection_factory=connection_factory,
                                 clock=time.monotonic, max_bytes=max_bytes, timeout=timeout)
    except AutoprotectError as exc:
        result = {"error": str(exc)}  # Only locally constructed bounded diagnostics.
    except Exception:
        result = {"error": "Source fetch worker failed"}
    (Path(directory) / "result").write_text(json.dumps(result, ensure_ascii=True), encoding="ascii")


def fetch_source(source, etag=None):
    """Fetch a fixed HTTPS endpoint with a 60-second worker deadline.

    No environment proxies, redirects, compression, feed links or arbitrary URLs
    are used. TLS uses the standard verified context. Cleanup allows at most two
    0.25-second process joins after timeout. Failure never returns partial bytes.
    This function does not assert freshness or attach acquisition provenance.
    """
    source = _source(source)
    etag = _validate_etag(etag)
    limit = _BYTE_LIMITS[source]
    # Process isolation gives DNS resolution and every response phase a hard
    # parent-side bound, without leaking a blocked resolver thread per attempt.
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="autoprotect-feed-") as directory:
        worker = context.Process(target=_fetch_worker, args=(source, etag, directory, _CONNECTION_FACTORY, limit, _TOTAL_TIMEOUT))
        try:
            worker.start()
            worker.join(_TOTAL_TIMEOUT)
            if worker.is_alive():
                raise AutoprotectError("Source fetch exceeded its deadline")
            if worker.exitcode != 0:
                raise AutoprotectError("Source fetch worker exited unsuccessfully")
            with (Path(directory) / "result").open("rb") as metadata:
                result = load_json(metadata.read(4097), max_bytes=4096)
            if "error" in result:
                raise AutoprotectError(result["error"])
            raw = None
            if not result["not_modified"]:
                with (Path(directory) / "body").open("rb") as body:
                    raw = body.read(limit + 1)
                if len(raw) > limit:
                    raise AutoprotectError("Source response exceeds the byte limit")
            return {"not_modified": result["not_modified"], "raw": raw, "etag": result["etag"]}
        except (OSError, RuntimeError) as exc:
            raise AutoprotectError("Source fetch worker could not complete") from exc
        finally:
            # Inspect the Process itself: start() may succeed and then be
            # interrupted before a caller-maintained flag can be assigned.
            # is_alive() is also safe for a Process that has not started.
            if worker.is_alive():
                worker.terminate()
                worker.join(0.25)
                if worker.is_alive():
                    worker.kill()
                    worker.join(0.25)
            if not worker.is_alive():
                worker.close()
