import copy
import http.client
import io
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time
import unittest
from unittest.mock import Mock, patch

from autoprotect import feeds
from autoprotect.core import AutoprotectError, ValidationError, canonical


FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


def fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_bytes())


class ParseTests(unittest.TestCase):
    def test_pwn_observed_shape_and_exact_output_contract(self):
        data = fixture("pwn")
        original = copy.deepcopy(data)
        records = feeds.parse_pwn(data)
        row = next(row for row in records if row["id"] == "example-open-incident")
        self.assertEqual(set(row), {
            "id", "title", "summary", "identifiers", "severity", "patch_status",
            "product", "updated_at", "is_example", "affected_versions", "fixed_versions",
        })
        self.assertEqual(row["identifiers"], ["CVE-2026-10001", "GHSA-2345-6789-cfgh", "MAL-2026-123"])
        self.assertEqual(row["fixed_versions"], data["incidents"][0]["fixedVersions"])
        self.assertEqual(row["updated_at"], "2026-01-02T01:00:00+01:00")
        self.assertEqual(data, original)
        self.assertEqual(len(records), 2)  # The live list is not the whole feed.

    def test_hostile_text_is_preserved_but_not_authority(self):
        row = feeds.parse_pwn(fixture("pwn"))[1]
        self.assertIn("\x1b", row["summary"])
        self.assertIn("\x00", row["summary"])
        self.assertIn("$(never-execute)", row["fixed_versions"][0])
        for field in ("url", "json", "trusted", "acquisition", "agentBrief"):
            self.assertNotIn(field, row)
        self.assertNotIn("\x1b", canonical(row))
        self.assertNotIn("\n", canonical(row))

    def test_pwn_unknowns_examples_and_defaults_remain_visible(self):
        row = feeds.parse_pwn(fixture("pwn"))[0]
        self.assertEqual(row["severity"], "future-severity")
        self.assertEqual(row["patch_status"], "future-patch-state")
        self.assertTrue(row["is_example"])
        self.assertEqual(row["summary"], "")
        minimal = feeds.parse_pwn({"incidents": [{"slug": "minimal", "title": "Title"}]})[0]
        self.assertEqual(minimal["severity"], "unknown")
        self.assertEqual(minimal["patch_status"], "unknown")
        self.assertEqual(minimal["identifiers"], [])

    def test_duplicates_are_rejected_or_deduplicated_without_overwriting(self):
        data = fixture("pwn")
        data["incidents"].append(copy.deepcopy(data["incidents"][0]))
        with self.assertRaises(ValidationError):
            feeds.parse_pwn(data)
        data = fixture("pwn")
        data["incidents"][0]["cveIds"] *= 2
        self.assertEqual(len(feeds.parse_pwn(data)[1]["identifiers"]), 3)
        for source, raw in (
            ("pwn", '{"incidents":[],"incidents":[]}'),
            ("debian", '{"example-source":{"CVE-2026-10001":{},"CVE-2026-10001":{}}}'),
        ):
            with self.subTest(source=source), self.assertRaises(ValidationError):
                feeds.parse_source(source, raw)

    def test_identifiers_require_safe_ascii_but_preserve_namespaces(self):
        data = fixture("pwn")
        data["incidents"][0]["cveIds"] = ["OTHER-2026-123", "MAL-2026-1"]
        self.assertEqual(feeds.parse_pwn(data)[1]["identifiers"], ["MAL-2026-1", "OTHER-2026-123"])
        for value in ("CVE-2026-1", "CVE-2026-1234;id", "CVE-2026-1234\n", "GHSA-bbbb-bbbb-bbbb", "MAL-2026-nope", "../../x", "日本語"):
            data["incidents"][0]["cveIds"] = [value]
            with self.subTest(value=value), self.assertRaises(ValidationError):
                feeds.parse_pwn(data)
        for slug in ("../x", "https://evil.invalid", "x\n", "x" * 129):
            data["incidents"][0]["slug"] = slug
            with self.subTest(slug=slug), self.assertRaises(ValidationError):
                feeds.parse_pwn(data)

    def test_pwn_malformed_types_fail_the_whole_snapshot(self):
        for data in (None, [], {}, {"incidents": {}}, {"incidents": [None]}):
            with self.subTest(data=data), self.assertRaises(ValidationError):
                feeds.parse_pwn(data)
        for field, value in (("title", None), ("slug", None), ("severity", 10),
                             ("isExample", "false"), ("isExample", 0),
                             ("cveIds", "CVE-2026-1234"), ("fixedVersions", [1]),
                             ("summary", "\ud800")):
            data = fixture("pwn")
            data["incidents"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                feeds.parse_pwn(data)

    def test_debian_observed_nested_shape_and_release_scope(self):
        data = fixture("debian")
        records = feeds.parse_debian(data)
        self.assertEqual(len(records), 7)
        self.assertEqual({row["release"] for row in records}, {"trixie"})
        row = next(row for row in records if row["source_name"] == "example-source" and row["id"] == "CVE-2026-10001")
        self.assertEqual(row, {
            "id": "CVE-2026-10001", "source_name": "example-source", "release": "trixie",
            "status": "resolved", "fixed_version": "1:1.0-1+deb13u2", "urgency": "high",
            "description": data["example-source"]["CVE-2026-10001"]["description"],
        })
        self.assertIn("\x1b", row["description"])
        self.assertNotIn("repositories", row)
        self.assertEqual(feeds.parse_debian(dict(reversed(list(data.items())))), records)
        with self.assertRaises(ValidationError):
            feeds.parse_debian(data, release="stable")

    def test_debian_zero_open_unknown_and_missing_release(self):
        rows = {row["id"]: row for row in feeds.parse_debian(fixture("debian")) if row["source_name"] == "example-source"}
        self.assertEqual((rows["CVE-2026-10002"]["status"], rows["CVE-2026-10002"]["fixed_version"]), ("resolved", "0"))
        self.assertEqual((rows["CVE-2026-10003"]["status"], rows["CVE-2026-10003"]["fixed_version"]), ("open", None))
        self.assertEqual(rows["CVE-2026-10004"]["status"], "future-state")
        self.assertEqual(rows["CVE-2026-10005"]["status"], "unknown")
        self.assertIsNone(rows["CVE-2026-10005"]["fixed_version"])

    def test_debian_temporary_ids_are_retained_only_as_unknown(self):
        row = next(row for row in feeds.parse_debian(fixture("debian")) if row["id"].startswith("TEMP-"))
        self.assertEqual(row["id"], "TEMP-0000000-ABCDEF")
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["fixed_version"], "0")
        for advisory_id in ("TEMP-0-ABCDEF", "TEMP-0000000-GHIJKL", "TEMP-0000000-ABCDEF\n"):
            with self.subTest(advisory_id=advisory_id), self.assertRaises(ValidationError):
                feeds.parse_debian({"example-source": {advisory_id: {}}})

    def test_debian_incomplete_conflicting_and_unsupported_assertions_are_unknown(self):
        for release in ({}, {"status": "resolved"}, {"status": "resolved", "fixed_version": ""},
                        {"status": "open", "fixed_version": "0"},
                        {"status": "open", "fixed_version": "1.0-1"},
                        {"status": "resolved", "fixed_version": "<end-of-life>"},
                        {"status": "resolved", "fixed_version": "1;run"}):
            data = {"example-source": {"CVE-2026-10001": {"releases": {"trixie": release}}}}
            row = feeds.parse_debian(data)[0]
            with self.subTest(release=release):
                self.assertEqual(row["status"], "unknown")
                self.assertEqual(row["fixed_version"], release.get("fixed_version") or None)

    def test_debian_malformed_identity_or_structure_rejects_all(self):
        for data in ([], {"../pkg": {}}, {"example-source": []},
                     {"example-source": {"GHSA-2345-6789-cfgh": {}}},
                     {"example-source": {"CVE-2026-10001": []}},
                     {"example-source": {"CVE-2026-10001": {"releases": []}}},
                     {"example-source": {"CVE-2026-10001": {"releases": {"trixie": None}}}}):
            with self.subTest(data=data), self.assertRaises(ValidationError):
                feeds.parse_debian(data)
        for key, value in (("status", False), ("fixed_version", 0), ("urgency", [])):
            data = {"example-source": {"CVE-2026-10001": {"releases": {"trixie": {key: value}}}}}
            with self.subTest(key=key), self.assertRaises(ValidationError):
                feeds.parse_debian(data)

    def test_parse_source_dispatch_and_bounded_raw_input(self):
        for source in ("pwn", "debian"):
            raw = (FIXTURES / f"{source}.json").read_bytes()
            expected = getattr(feeds, f"parse_{source}")(json.loads(raw))
            self.assertEqual(feeds.parse_source(source, raw), expected)
            self.assertEqual(feeds.parse_source(source, raw.decode()), expected)
        for source in ("https://pwn.watch/incidents.json", "other", [], None):
            with self.subTest(source=source), self.assertRaises(ValidationError):
                feeds.parse_source(source, b"{}")
        for raw in (b'"\xff"', b'NaN', b'Infinity', b'1e999', b'{', b'"\\ud800"', {}):
            with self.subTest(raw=raw), self.assertRaises(ValidationError):
                feeds.parse_source("pwn", raw)
        with patch.dict(feeds._BYTE_LIMITS, pwn=16), self.assertRaises(ValidationError):
            feeds.parse_source("pwn", b'{"incidents": []} ')

    def test_depth_nodes_records_lists_and_all_strings_are_bounded(self):
        deep = 0
        for _ in range(40):
            deep = [deep]
        cycle = []
        cycle.append(cycle)
        for extra in (deep, cycle, {1: "bad-key"}, float("nan"), "x" * 65537, "\udfff"):
            data = {"incidents": [], "ignored": extra}
            with self.subTest(kind=type(extra)), self.assertRaises(ValidationError):
                feeds.parse_pwn(data)
        with patch.object(feeds, "_MAX_NODES", 4), self.assertRaises(ValidationError):
            feeds.parse_pwn(fixture("pwn"))
        with patch.object(feeds, "_MAX_PWN_RECORDS", 1), self.assertRaises(ValidationError):
            feeds.parse_pwn(fixture("pwn"))
        with patch.object(feeds, "_MAX_DEBIAN_RECORDS", 1), self.assertRaises(ValidationError):
            feeds.parse_debian(fixture("debian"))
        data = fixture("pwn")
        data["incidents"][0]["fixedVersions"] = ["x"] * 257
        with self.assertRaises(ValidationError):
            feeds.parse_pwn(data)
        data = {"incidents": [], "ignored": "x" * 100}
        with patch.dict(feeds._BYTE_LIMITS, pwn=64), self.assertRaises(ValidationError):
            feeds.parse_pwn(data)


class FakeClock:
    def __init__(self):
        self.value = 0

    def __call__(self):
        return self.value


class FakeSocket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, seconds):
        self.timeouts.append(seconds)


class FakeResponse:
    def __init__(self, factory):
        self.factory = factory
        self.status = factory.status
        self.body = io.BytesIO(factory.body)
        self.read_sizes = []
        self.closed = False

    def getheaders(self):
        return self.factory.headers

    def read1(self, size):
        self.read_sizes.append(size)
        if self.factory.delay_at == "read":
            threading.Event().wait(30)
        if self.factory.clock is not None:
            self.factory.clock.value += self.factory.read_elapsed
        if self.factory.fail_at == "read":
            raise OSError("untrusted network diagnostic\x1b")
        return self.body.read(min(size, self.factory.chunk_size))

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, factory, host, **kwargs):
        self.factory = factory
        self.host = host
        self.kwargs = kwargs
        self.sock = FakeSocket()
        self.response = FakeResponse(factory)
        self.closed = False
        self.requests = []

    def connect(self):
        if self.factory.delay_at == "connect":
            threading.Event().wait(30)
        if self.factory.fail_at == "connect":
            raise OSError("untrusted DNS diagnostic\x1b")
        if self.factory.clock is not None:
            self.factory.clock.value += self.factory.connect_elapsed

    def request(self, method, path, *, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        if self.factory.delay_at == "headers":
            threading.Event().wait(30)
        if self.factory.fail_at == "headers":
            raise OSError("untrusted header diagnostic\x1b")
        return self.response

    def close(self):
        self.closed = True


class FakeConnectionFactory:
    """Picklable transport injection, also usable inside the isolated fetch worker."""
    def __init__(self, *, status=200, headers=None, body=b'{"incidents":[]}',
                 chunk_size=3, clock=None, read_elapsed=0, connect_elapsed=0,
                 fail_at=None, delay_at=None):
        self.status = status
        self.headers = headers if headers is not None else [("Content-Type", "application/json"), ("ETag", '"synthetic"')]
        self.body = body
        self.chunk_size = chunk_size
        self.clock = clock
        self.read_elapsed = read_elapsed
        self.connect_elapsed = connect_elapsed
        self.fail_at = fail_at
        self.delay_at = delay_at
        self.connections = []

    def __call__(self, host, **kwargs):
        connection = FakeConnection(self, host, **kwargs)
        self.connections.append(connection)
        return connection


class WireStream(io.BytesIO):
    """Synthetic wire bytes with observable, optionally slow trailer reads."""
    def __init__(self, wire, factory):
        super().__init__(wire)
        self.factory = factory
        self.line_reads = []
        self.consumed = 0

    def readline(self, size=-1):
        offset = self.tell()
        if offset >= self.factory.trailer_offset:
            if self.factory.delay_at == "trailers":
                threading.Event().wait(30)
            if self.factory.clock is not None:
                self.factory.clock.value += self.factory.read_elapsed
        line = super().readline(size)
        self.consumed = self.tell()
        self.line_reads.append((offset, size, len(line)))
        return line


class WireConnectionFactory(FakeConnectionFactory):
    """Real HTTPResponse decoding over synthetic bytes, including in workers."""
    def __init__(self, trailers=b"\r\n", *, extra_headers=b"", body=b'{"incidents":[]}', **kwargs):
        super().__init__(**kwargs)
        prefix = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                  b"Content-Type: application/json\r\nETag: \"initial\"\r\n" + extra_headers + b"\r\n")
        chunks = (f"{len(body):x}\r\n".encode() + body + b"\r\n") if body else b""
        prefix += chunks + b"0\r\n"
        self.trailer_offset = len(prefix)
        self.wire = prefix + trailers
        self.body = body

    def __call__(self, host, **kwargs):
        connection = super().__call__(host, **kwargs)
        connection.stream = WireStream(self.wire, self)
        connection.sock.makefile = lambda mode: connection.stream
        connection.response = http.client.HTTPResponse(connection.sock)
        connection.response.begin()
        return connection


class TransportTests(unittest.TestCase):
    def direct(self, factory=None, *, source="pwn", etag=None, cap=1024, timeout=60):
        factory = factory or FakeConnectionFactory()
        output = io.BytesIO()
        result = feeds._fetch_http(source, etag, output, connection_factory=factory,
                                   clock=factory.clock or time.monotonic,
                                   max_bytes=cap, timeout=timeout)
        return result, output.getvalue(), factory.connections[0]

    def test_200_fixed_request_verified_tls_no_proxy_or_body_authority(self):
        factory = FakeConnectionFactory(body=b'{"url":"http://evil.invalid","trusted":true}')
        with patch.dict(os.environ, {"https_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://evil.invalid"}):
            result, raw, connection = self.direct(factory, etag='W/"prior"')
        self.assertEqual(raw, factory.body)
        self.assertFalse(result["not_modified"])
        self.assertEqual(result["etag"], '"synthetic"')
        self.assertEqual(connection.host, "pwn.watch")
        self.assertEqual(connection.kwargs["port"], 443)
        self.assertLessEqual(connection.kwargs["timeout"], 10)
        context = connection.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        method, path, headers = connection.requests[0]
        self.assertEqual((method, path), ("GET", "/incidents.json"))
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["If-None-Match"], 'W/"prior"')
        self.assertNotIn("Proxy-Authorization", headers)
        self.assertTrue(connection.closed)
        self.assertTrue(connection.response.closed)
        self.assertEqual(len(factory.connections), 1)

    def test_debian_endpoint_is_fixed(self):
        _, _, connection = self.direct(source="debian")
        self.assertEqual(connection.host, "security-tracker.debian.org")
        self.assertEqual(connection.requests[0][1], "/tracker/data/json")

    def test_304_requires_validator_and_never_reads_body(self):
        factory = FakeConnectionFactory(status=304, headers=[], body=b"must not read")
        result, raw, connection = self.direct(factory, etag='"prior"')
        self.assertEqual(result, {"not_modified": True, "etag": '"prior"'})
        self.assertEqual(raw, b"")
        self.assertEqual(connection.response.read_sizes, [])
        with self.assertRaises(AutoprotectError):
            self.direct(FakeConnectionFactory(status=304))
        result, _, _ = self.direct(FakeConnectionFactory(status=304), etag='"prior"')
        self.assertEqual(result["etag"], '"synthetic"')

    def test_200_without_etag_does_not_reuse_an_old_validator(self):
        result, _, _ = self.direct(FakeConnectionFactory(headers=[]), etag='"prior"')
        self.assertIsNone(result["etag"])

    def test_redirects_and_http_errors_are_not_followed(self):
        for status in (201, 204, 206, 301, 302, 303, 305, 307, 308, 400, 403, 404, 429, 500):
            factory = FakeConnectionFactory(status=status, headers=[("Location", "http://127.0.0.1/secret")])
            with self.subTest(status=status), self.assertRaises(AutoprotectError):
                self.direct(factory)
            self.assertEqual(len(factory.connections), 1)
            self.assertTrue(factory.connections[0].closed)
            self.assertEqual(factory.connections[0].response.read_sizes, [])

    def test_valid_etags_and_invalid_request_validators_before_network(self):
        for etag in ('""', '"abc-123"', 'W/"abc"'):
            self.assertEqual(feeds._validate_etag(etag), etag)
        for etag in ("bare", '"x"\r\nInjected: y', '"a b"', '"a\x7f"', '"日本語"', 'w/"x"', '"a","b"', '"' + 'x' * 512 + '"', 1, True):
            with self.subTest(etag=etag), patch.object(feeds, "_CONNECTION_FACTORY") as factory:
                with self.assertRaises(ValidationError):
                    feeds.fetch_source("pwn", etag)
                factory.assert_not_called()
        for source in ("https://pwn.watch/incidents.json", "pwn/../x", {}, None):
            with self.subTest(source=source), self.assertRaises(ValidationError):
                feeds.fetch_source(source)

    def test_untrusted_headers_encodings_and_ambiguous_lengths_are_rejected(self):
        cases = [
            [("ETag", "bare")], [("ETag", '"one"'), ("etag", '"two"')],
            [("Content-Encoding", "gzip")], [("Content-Encoding", "br")],
            [("Content-Encoding", "identity, gzip")], [("Transfer-Encoding", "gzip, chunked")],
            [("Content-Type", "application/json; charset=iso-8859-1")],
            [("Content-Type", "text/html")], [("Content-Length", "-1")],
            [("Content-Length", "1, 1")], [("Content-Length", "100"), ("content-length", "100")],
            [("Content-Length", "100"), ("Transfer-Encoding", "chunked")],
            [("X-Other", "\x1b")], [("X-Other", "x" * 65537)],
        ]
        for headers in cases:
            with self.subTest(headers=str(headers)[:100]), self.assertRaises(AutoprotectError):
                self.direct(FakeConnectionFactory(headers=headers))
        for headers in ([('Content-Encoding', 'identity')], [('Transfer-Encoding', 'chunked')],
                        [('Content-Type', 'application/json; charset=UTF-8')]):
            self.direct(FakeConnectionFactory(headers=headers))

    def test_body_limit_declared_size_and_truncation(self):
        factory = FakeConnectionFactory(body=b"0123456789", headers=[("Content-Length", "10")])
        self.assertEqual(self.direct(factory, cap=10)[1], b"0123456789")
        for headers, body, cap in (([], b"01234567890", 10),
                                  ([("Content-Length", "11")], b"", 10),
                                  ([("Content-Length", "10")], b"short", 10),
                                  ([("Content-Length", "2")], b"long", 10)):
            factory = FakeConnectionFactory(headers=headers, body=body)
            with self.subTest(headers=headers, cap=cap), self.assertRaises(AutoprotectError):
                self.direct(factory, cap=cap)
            self.assertTrue(factory.connections[0].closed)
            self.assertTrue(all(size <= cap + 1 for size in factory.connections[0].response.read_sizes))

    def test_httpresponse_closes_completed_body_without_an_extra_socket_operation(self):
        # Use the real standard-library response reader over a local socket pair
        # to catch socket lifetime behavior that a BytesIO-only fake cannot model.
        for framing, payload in ((b"Content-Length: 3\r\n", b"abc"),
                                 (b"Content-Length: 0\r\n", b""),
                                 (b"Transfer-Encoding: chunked\r\n", b"3\r\nabc\r\n0\r\n\r\n"),
                                 (b"", b"abc")):
            with self.subTest(framing=framing):
                client, server = socket.socketpair()
                self.addCleanup(client.close)
                self.addCleanup(server.close)
                server.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n" + framing + b"\r\n" + payload)
                server.shutdown(socket.SHUT_WR)
                response = http.client.HTTPResponse(client)
                response.begin()
                client.close()  # HTTPConnection detaches Connection: close sockets.
                factory = FakeConnectionFactory()
                connection = FakeConnection(factory, "ignored")
                connection.sock = client
                connection.response = response
                output = io.BytesIO()
                feeds._fetch_http("pwn", None, output,
                                  connection_factory=lambda *args, **kwargs: connection,
                                  clock=time.monotonic, max_bytes=1024, timeout=5)
                self.assertEqual(output.getvalue(), b"" if b"Length: 0" in framing else b"abc")

    def test_real_chunked_response_accepts_bounded_trailers_without_promoting_metadata(self):
        for trailers, headers in (
            (b"\r\n", b""),
            (b"X-Report: checked\r\nDigest: sha-256=synthetic\r\n\r\n", b""),
            (b"X-Report: checked\r\n\r\n", b"Trailer: X-Report\r\n"),
        ):
            with self.subTest(trailers=trailers):
                factory = WireConnectionFactory(trailers, extra_headers=headers)
                result, raw, connection = self.direct(factory, cap=len(factory.body))
                self.assertIs(type(connection.response), http.client.HTTPResponse)
                self.assertEqual(raw, factory.body)
                self.assertEqual(feeds.parse_source("pwn", raw), [])
                self.assertEqual(result, {"not_modified": False, "etag": '"initial"'})
                self.assertIsNone(connection.response.getheader("X-Report"))
                self.assertTrue(connection.response.isclosed())
                self.assertTrue(connection.closed)
        with self.assertRaisesRegex(AutoprotectError, "byte limit"):
            self.direct(WireConnectionFactory(), cap=4)

    def test_real_chunked_trailer_field_count_is_bounded(self):
        fields = b"".join(f"X-Note-{index}: value\r\n".encode() for index in range(100))
        self.direct(WireConnectionFactory(fields + b"\r\n"))
        factory = WireConnectionFactory(fields + b"X-Extra: value\r\n\r\n")
        with self.assertRaisesRegex(AutoprotectError, "trailer"):
            self.direct(factory)
        self.assertTrue(factory.connections[0].closed)
        self.assertTrue(factory.connections[0].response.isclosed())

    def test_real_chunked_trailer_bytes_are_bounded_before_consuming_the_section(self):
        # The 32 KiB trailer budget includes field delimiters and the final CRLF.
        boundary = b"X-Note: " + b"x" * (32768 - len(b"X-Note: \r\n\r\n")) + b"\r\n\r\n"
        self.direct(WireConnectionFactory(boundary))
        for trailers in (
            boundary[:-4] + b"x\r\n\r\n",
            b"X-One: " + b"a" * 32000 + b"\r\nX-Two: " + b"b" * 32000 + b"\r\n\r\n",
            b"X-Long: " + b"x" * 262144,  # No newline: do not read the whole field.
        ):
            factory = WireConnectionFactory(trailers)
            with self.subTest(size=len(trailers)):
                with self.assertRaisesRegex(AutoprotectError, "trailer"):
                    self.direct(factory)
                stream = factory.connections[0].stream
                self.assertLessEqual(stream.consumed - factory.trailer_offset, 32769)
                self.assertTrue(all(0 < size <= 32769 for offset, size, _ in stream.line_reads
                                    if offset >= factory.trailer_offset))

    def test_real_chunked_trailers_reject_control_characters(self):
        for control in (*range(32), 127):
            factory = WireConnectionFactory(b"X-Note: before" + bytes([control]) + b"after\r\n\r\n")
            with self.subTest(control=control):
                with self.assertRaises(AutoprotectError) as caught:
                    self.direct(factory)
                self.assertNotIn("before", str(caught.exception))
                self.assertNotIn(chr(control), str(caught.exception))

    def test_real_chunked_trailers_require_complete_crlf_framing_and_field_syntax(self):
        for trailers in (
            b"", b"\r", b"\n", b"X-Note: value", b"X-Note: value\r\n",
            b"X-Note: value\n\r\n", b"X-Note: value\r\n\n",
            b"X-Note value\r\n\r\n", b"Bad Name: value\r\n\r\n", b"Bad : value\r\n\r\n",
            b": value\r\n\r\n", b" X-Note: value\r\n\r\n",
            b"X-Note: value\r\n continuation\r\n\r\n",
        ):
            with self.subTest(trailers=trailers), self.assertRaisesRegex(AutoprotectError, "trailer"):
                self.direct(WireConnectionFactory(trailers))

    def test_real_chunked_trailers_reject_forbidden_and_ambiguous_metadata(self):
        for name in (
            b"ETag", b"Content-Length", b"Transfer-Encoding", b"Content-Type", b"Content-Encoding",
            b"Content-Range", b"Host", b"Authorization", b"Proxy-Authorization", b"WWW-Authenticate",
            b"Proxy-Authenticate", b"Authentication-Info", b"Cookie", b"Set-Cookie", b"Cache-Control",
            b"Age", b"Date", b"Expires", b"Location", b"Retry-After", b"Vary", b"Last-Modified",
            b"Connection", b"Keep-Alive", b"Upgrade", b"Trailer", b"TE",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(AutoprotectError, "trailer"):
                self.direct(WireConnectionFactory(name + b": hostile\r\n\r\n"))
        for trailers, headers in (
            (b"X-Note: one\r\nx-note: two\r\n\r\n", b""),
            (b"x-note: changed\r\n\r\n", b"X-Note: initial\r\n"),
            (b"X-Hop: value\r\n\r\n", b"Connection: close, X-Hop\r\n"),
            (b"X-Other: value\r\n\r\n", b"Trailer: X-Note\r\n"),
            (b"\r\n", b"Trailer: ETag\r\n"),
            (b"\r\n", b"Trailer: X-Note, x-note\r\n"),
            (b"\r\n", b"Trailer: X-Note,\r\n"),
            (b"\r\n", b"Trailer: Bad Name\r\n"),
            (b"\r\n", b"Trailer: X-One\r\nTrailer: X-Two\r\n"),
        ):
            with self.subTest(trailers=trailers, headers=headers), self.assertRaises(AutoprotectError):
                self.direct(WireConnectionFactory(trailers, extra_headers=headers))

    def test_real_chunked_trailer_reads_recheck_cumulative_deadline(self):
        factory = WireConnectionFactory(b"X-One: a\r\nX-Two: b\r\nX-Three: c\r\n\r\n",
                                        clock=FakeClock(), read_elapsed=2)
        with self.assertRaisesRegex(AutoprotectError, "deadline"):
            self.direct(factory, timeout=5)
        stream = factory.connections[0].stream
        trailer_reads = [row for row in stream.line_reads if row[0] >= factory.trailer_offset]
        self.assertEqual(len(trailer_reads), 3)
        self.assertLessEqual(factory.connections[0].sock.timeouts[-1], 1)

    def test_public_fetch_validates_real_chunked_trailers_and_keeps_worker_deadline(self):
        with patch.object(feeds, "_CONNECTION_FACTORY", WireConnectionFactory(b"X-Note: value\r\n\r\n")):
            result = feeds.fetch_source("pwn")
        self.assertEqual(result, {"not_modified": False, "raw": b'{"incidents":[]}', "etag": '"initial"'})
        with patch.object(feeds, "_CONNECTION_FACTORY", WireConnectionFactory(b"X-Note: \x1b\r\n\r\n")):
            with self.assertRaisesRegex(AutoprotectError, "trailer"):
                feeds.fetch_source("pwn")
        start = time.monotonic()
        with patch.object(feeds, "_CONNECTION_FACTORY", WireConnectionFactory(delay_at="trailers")), \
                patch.object(feeds, "_TOTAL_TIMEOUT", 0.5):
            with self.assertRaisesRegex(AutoprotectError, "deadline"):
                feeds.fetch_source("pwn")
        self.assertLess(time.monotonic() - start, 3)

    def test_socket_and_cumulative_deadlines(self):
        clock = FakeClock()
        factory = FakeConnectionFactory(clock=clock, read_elapsed=2, body=b"123456789012345")
        with self.assertRaisesRegex(AutoprotectError, "deadline"):
            self.direct(factory, timeout=5)
        self.assertEqual(len(factory.connections[0].response.read_sizes), 3)
        self.assertLessEqual(factory.connections[0].sock.timeouts[-1], 1)
        clock = FakeClock()
        with self.assertRaisesRegex(AutoprotectError, "deadline"):
            self.direct(FakeConnectionFactory(clock=clock, connect_elapsed=6), timeout=5)

    def test_transport_errors_do_not_echo_untrusted_details_and_close(self):
        for stage in ("connect", "headers", "read"):
            factory = FakeConnectionFactory(fail_at=stage)
            with self.subTest(stage=stage), self.assertRaises(AutoprotectError) as caught:
                self.direct(factory)
            self.assertNotIn("untrusted", str(caught.exception))
            self.assertNotIn("\x1b", str(caught.exception))
            self.assertTrue(factory.connections[0].closed)

    def test_public_fetch_200_304_and_failure_in_isolated_worker(self):
        for factory, etag in ((FakeConnectionFactory(), None),
                              (FakeConnectionFactory(status=304), '"prior"')):
            with patch.object(feeds, "_CONNECTION_FACTORY", factory):
                result = feeds.fetch_source("pwn", etag)
            self.assertEqual(result["not_modified"], factory.status == 304)
            self.assertEqual(result["raw"], None if factory.status == 304 else factory.body)
            self.assertEqual(result["etag"], '"synthetic"')
        with patch.object(feeds, "_CONNECTION_FACTORY", FakeConnectionFactory(status=403)):
            with self.assertRaises(AutoprotectError):
                feeds.fetch_source("pwn")

    def test_worker_start_interruption_cleanup_uses_actual_process_state(self):
        context = feeds.multiprocessing.get_context("spawn")
        process_type = context.Process
        for launch in (False, True):
            processes = []
            workers = []

            def create_worker(*args, **kwargs):
                process = process_type(*args, **kwargs)
                processes.append(process)
                worker = Mock(wraps=process)
                workers.append(worker)

                def interrupted_start():
                    if launch:
                        process.start()  # Real successful spawn, before the caller's flag assignment.
                    raise KeyboardInterrupt("synthetic start interruption")

                worker.start.side_effect = interrupted_start
                return worker

            started_at = time.monotonic()
            try:
                with self.subTest(launch=launch), patch.object(context, "Process", side_effect=create_worker), \
                        patch.object(feeds, "_CONNECTION_FACTORY", FakeConnectionFactory(delay_at="connect")):
                    with self.assertRaises(KeyboardInterrupt):
                        feeds.fetch_source("pwn")
                    worker = workers[0]
                    if launch:
                        worker.terminate.assert_called_once_with()
                        self.assertGreaterEqual(worker.join.call_count, 1)
                        self.assertLessEqual(worker.join.call_count, 2)
                        self.assertTrue(all(call.args == (0.25,) for call in worker.join.call_args_list))
                    else:
                        worker.terminate.assert_not_called()
                        worker.join.assert_not_called()
                    worker.close.assert_called_once_with()
                    self.assertTrue(processes[0]._closed)
                    self.assertLess(time.monotonic() - started_at, 3)
            finally:
                # The red-first run must not leak the child that the bug leaves running.
                for process in processes:
                    if not process._closed:
                        if process.is_alive():
                            process.kill()
                            process.join(1)
                        process.close()

    def test_interrupted_worker_cleanup_is_bounded_and_never_closes_a_live_worker(self):
        worker = Mock()
        worker.start.side_effect = KeyboardInterrupt("synthetic start interruption")
        worker.is_alive.return_value = True  # Model termination not yet observed after either join.
        context = Mock()
        context.Process.return_value = worker
        with patch.object(feeds.multiprocessing, "get_context", return_value=context):
            with self.assertRaises(KeyboardInterrupt):
                feeds.fetch_source("pwn")
        worker.terminate.assert_called_once_with()
        worker.kill.assert_called_once_with()
        self.assertEqual([call.args for call in worker.join.call_args_list], [(0.25,), (0.25,)])
        worker.close.assert_not_called()

    def test_hard_deadline_including_stalled_dns_headers_and_body(self):
        for stage in ("connect", "headers", "read"):
            start = time.monotonic()
            with self.subTest(stage=stage), patch.object(feeds, "_TOTAL_TIMEOUT", 0.5), \
                    patch.object(feeds, "_CONNECTION_FACTORY", FakeConnectionFactory(delay_at=stage)):
                with self.assertRaisesRegex(AutoprotectError, "deadline"):
                    feeds.fetch_source("pwn")
            self.assertLess(time.monotonic() - start, 3)


if __name__ == "__main__":
    unittest.main()
