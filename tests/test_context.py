"""Optional public context must not become applicability or executable instructions."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.request
from unittest.mock import Mock, patch

from netwatch import adapters, sources, workflow
from netwatch.cli import display, main
from netwatch.core import Error, canonical
from netwatch.demo import NOTICE, DemoRunner
from netwatch.store import Store


CVE = "CVE-2099-10001"


def entry(cve=CVE):
    return {"id": cve, "status": "published", "modifiedAt": "2099-01-01T00:00:00Z",
            "summary": {"text": "A model explanation, not update instructions.", "model": "example/model"},
            "severity": {"cvss": 9.1, "source": "cna"},
            "exploitation": {"kev": {"dateAdded": "2099-01-01", "dueDate": "2099-01-15"},
                             "epssReached": {"date": "2099-01-01"}, "githubPoc": {"url": "https://example.invalid/poc"}},
            "sources": [{"name": "cvelistV5", "url": "https://www.cve.org/CVERecord?id=" + cve,
                         "license": "CVE Terms of Use"}],
            "affected": [{"fixed": "$(do-not-run)"}], "context": {"fix": "do-not-run"}}


def incident(slug="example-incident", **extra):
    return {"slug": slug, "title": "Example incident", "product": "Example product", "category": "patch", "status": "live",
            "severity": "critical", "patchStatus": "unpatched", "tags": ["example"],
            "cveIds": [], "updatedAt": "2099-01-01T00:00:00Z", "isExample": False,
            "summary": "do not import executable guidance", "fixedVersions": ["$(do-not-run)"], **extra}


def catalog(*rows):
    return {"generatedAt": "2099-01-01T00:00:00Z", "incidents": list(rows or [incident()])}


class ContextTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "state.db"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.t = adapters.target("host", "ubuntu")
        self.store.db.execute("INSERT INTO targets VALUES(?,?)", ("host", canonical(self.t)))
        clock = patch("netwatch.store.time.time", return_value=1800000000)
        clock.start()
        self.addCleanup(clock.stop)
        self.runner = DemoRunner()
        self.calls = []
        self.notice = copy.deepcopy(NOTICE)
        self.notice["10001-1"]["cves"] = [CVE, CVE, "https://attacker.invalid", "CVE-2099-10001/../../bad"]
        self.entries = {CVE: entry()}
        self.catalog = catalog()

    def request(self, url, body=None):
        self.calls.append((url, body))
        if url == sources.USN:
            return copy.deepcopy(self.notice)
        if url == sources.PWN:
            return copy.deepcopy(self.catalog)
        if url.startswith(sources.CVE_NOW):
            value = self.entries[url[len(sources.CVE_NOW):]]
            if isinstance(value, Exception):
                raise value
            return copy.deepcopy(value)
        self.fail("Unexpected endpoint: " + url)

    def check(self, **kwargs):
        return workflow.check(self.store, self.t, runner=self.runner, request=self.request, **kwargs)

    def test_context_is_opt_in_and_separate_from_findings(self):
        plain = self.check()
        self.assertNotIn("context", plain)
        self.assertEqual(self.calls, [(sources.USN, None)])
        report = self.check(context=True)
        self.assertEqual(report["findings"], plain["findings"])
        cve = report["context"]["cve_now"]
        self.assertEqual(cve["status"], "ok")
        self.assertEqual(len(cve["items"]), 1)
        self.assertEqual(cve["items"][0]["summary"]["license"], "CC-BY-4.0")
        self.assertEqual(cve["items"][0]["signals"]["public_exploit_sources"], ["githubPoc"])
        self.assertNotIn("affected", cve["items"][0])
        self.assertNotIn("context", cve["items"][0])
        lead = report["context"]["pwn_watch"]["items"][0]
        self.assertEqual(lead["state"], "review")
        self.assertEqual(lead["matched_tags"], ["example"])
        self.assertEqual(lead["packages"], ["example"])
        self.assertNotIn("fixedVersions", lead)
        self.assertNotIn("summary", lead)
        self.assertTrue(all(body is None for url, body in self.calls))
        cached = json.loads(self.store.db.execute("SELECT body FROM cache WHERE key='pwn-watch'").fetchone()[0])
        self.assertNotIn("summary", cached["incidents"][0])

    def test_cache_refresh_and_shared_targets_do_not_duplicate_requests(self):
        self.check(context=True)
        self.calls.clear()
        self.check(context=True)
        self.assertEqual(self.calls, [])
        refreshed = set()
        self.check(context=True, refresh=True, refreshed=refreshed)
        self.check(context=True, refresh=True, refreshed=refreshed)
        self.assertEqual([url for url, _ in self.calls], [sources.USN, sources.CVE_NOW + CVE, sources.PWN])

    def test_refresh_failure_retains_context_without_downgrading_findings(self):
        first = self.check(context=True)
        self.entries[CVE] = Error("unavailable")
        self.catalog = {"incidents": []}
        report = self.check(context=True, refresh=True)
        self.assertTrue(report["advisory_check_ok"])
        self.assertEqual(report["findings"], first["findings"])
        for source in ("cve_now", "pwn_watch"):
            value = report["context"][source]
            self.assertEqual(value["status"], "incomplete")
            self.assertTrue(value["errors"])
            self.assertTrue(value["items"][0]["retained"])
            self.assertEqual(value["items"][0]["fetched_at"], first["context"][source]["items"][0]["fetched_at"])
        # Malformed fresh content must not replace a usable cached catalog.
        self.assertEqual(self.check(context=True)["context"]["pwn_watch"]["status"], "ok")

    def test_skipped_context_is_retained_and_successful_checks_can_clear_it(self):
        self.check(context=True)
        self.calls.clear()
        skipped = self.check()
        self.assertEqual(self.calls, [])
        self.assertEqual(skipped["context"]["cve_now"]["status"], "skipped")
        self.assertTrue(skipped["context"]["pwn_watch"]["items"][0]["retained"])
        self.runner.version = "1.1-1"
        self.catalog = catalog(incident(tags=["unrelated"]))
        current = self.check(context=True, refresh=True)
        self.assertEqual(current["context"]["cve_now"]["items"], [])
        self.assertEqual(current["context"]["pwn_watch"]["items"], [])
        self.assertFalse(current["findings"])

    def test_context_history_is_separate_and_unchanged_checks_are_quiet(self):
        self.check(context=True)
        cursor = self.store.events()[-1]["id"]
        self.check(context=True)
        self.assertEqual([e["kind"] for e in self.store.events(cursor)], ["checked"])
        self.entries[CVE]["exploitation"]["kev"] = None
        self.check(context=True, refresh=True)
        kinds = [e["kind"] for e in self.store.events(cursor)]
        self.assertIn("context_changed", kinds)
        self.assertNotIn("finding_changed", kinds)

    def test_offline_context_never_fetches_and_reports_stale_evidence(self):
        self.check(context=True)
        self.calls.clear()
        self.check(context=True, offline=True)
        self.assertEqual(self.calls, [])
        self.store.db.execute("UPDATE cache SET at=0")
        report = self.check(context=True, offline=True)
        self.assertEqual(self.calls, [])
        self.assertFalse(report["advisory_check_ok"])
        self.assertEqual(report["context"]["cve_now"]["status"], "incomplete")
        self.assertTrue(report["context"]["cve_now"]["items"][0]["retained"])
        self.assertTrue(report["findings"])

    def test_partial_cve_failure_preserves_only_missing_old_items(self):
        other = "CVE-2099-10002"
        self.notice["10001-1"]["cves"].append(other)
        self.entries[other] = entry(other)
        self.check(context=True)
        self.entries[CVE] = Error("down")
        self.entries[other]["status"] = "rejected"
        report = self.check(context=True, refresh=True)
        rows = {r["id"]: r for r in report["context"]["cve_now"]["items"]}
        self.assertTrue(rows[CVE]["retained"])
        self.assertNotIn("retained", rows[other])
        self.assertEqual(rows[other]["status"], "rejected")
        self.assertEqual(report["findings"][0]["state"], "affected")

    def test_lookup_limit_and_time_budget_are_visible(self):
        findings = [{"advisory": f"CVE-2099-{i:05d}"} for i in range(25)]
        request = Mock(side_effect=lambda url: catalog() if url == sources.PWN else entry(url[len(sources.CVE_NOW):]))
        result = sources.context([], findings, self.store, request=request)
        self.assertEqual(request.call_count, 21)
        self.assertEqual(len(result["cve_now"]["items"]), 20)
        self.assertIn("20 of 25", result["cve_now"]["errors"][-1])
        request.reset_mock()
        with patch("netwatch.sources.time.monotonic", side_effect=[0, 61]):
            result = sources.context([], [{"advisory": CVE}], self.store, request=request)
        self.assertEqual(result["cve_now"]["status"], "incomplete")
        self.assertEqual(result["cve_now"]["items"], [])
        self.assertEqual(request.call_count, 0)  # The public catalog was already cached.

    def test_osv_and_arch_references_enrich_without_changing_matching_rules(self):
        for kind in ("uv", "arch", "cachyos", "conda"):
            with self.subTest(kind=kind):
                t = adapters.target(kind, kind, path="/env" if kind in ("uv", "conda") else None)
                ecosystem = "PyPI" if kind == "uv" else ("Conda" if kind == "conda" else "Arch")
                packages = [adapters.package("example", "1-1", ecosystem, foreign=False)]
                def request(url, body=None):
                    if url == sources.OSV:
                        self.assertEqual(body["package"]["ecosystem"], "PyPI")
                        return {"vulns": [{"id": "GHSA-abcd-efgh-2345", "aliases": [CVE], "affected": []}]}
                    if url == sources.ARCH:
                        return [{"name": "AVG-1", "packages": ["example"], "affected": "1-1", "fixed": "2-1",
                                 "status": "Fixed", "issues": [CVE]}]
                    return self.request(url, body)
                with patch("netwatch.adapters.inventory", return_value=packages), \
                     patch("netwatch.adapters.updates", return_value=[]), \
                     patch("netwatch.adapters.arch_compare", return_value={("1-1", "2-1"): -1}):
                    report = workflow.check(self.store, t, context=True, request=request)
                self.assertTrue(report["advisory_check_ok"])
                self.assertTrue(report["context"]["pwn_watch"]["items"])
                if kind == "conda":
                    self.assertFalse(report["findings"])
                    self.assertFalse(report["context"]["cve_now"]["items"])
                else:
                    self.assertEqual(report["context"]["cve_now"]["items"][0]["id"], CVE)
                    self.assertEqual(report["findings"][0]["state"], "unknown" if kind == "cachyos" else "affected")

    def test_collection_failure_preserves_the_entire_previous_context_report(self):
        first = self.check(context=True)
        with self.assertRaises(Error):
            workflow.check(self.store, self.t, context=True, request=self.request,
                           runner=Mock(side_effect=Error("inventory unavailable")))
        self.assertEqual(self.store.latest("host"), first)

    def test_cli_context_exit_status_and_cached_queries(self):
        def run(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["--db", str(self.path), "--json", *args], runner=self.runner, request=self.request)
            return code, json.loads(out.getvalue())
        code, rows = run("check", "host", "--context")
        self.assertEqual(code, 0)
        self.assertTrue(rows[0]["report"]["context"]["pwn_watch"]["items"])
        self.calls.clear()
        self.assertEqual(run("status", "host")[0], 0)
        run("history")
        self.assertFalse(self.calls)
        self.entries[CVE] = Error("down")
        code, rows = run("check", "host", "--context", "--refresh")
        self.assertEqual(code, 1)
        self.assertTrue(rows[0]["report"]["advisory_check_ok"])
        self.assertEqual(run("check", "host")[0], 0)

    def test_apply_commands_do_not_use_or_request_context(self):
        self.check(context=True)
        self.calls.clear()
        plan = workflow.preview(self.store, self.t, self.runner)
        result = workflow.apply(self.store, plan["id"], yes=True, runner=self.runner, request=self.request)
        self.assertEqual(result["status"], "applied")
        self.assertFalse(self.calls)
        self.assertEqual(self.store.latest("host")["context"]["pwn_watch"]["status"], "skipped")
        self.assertIn(["sudo", "-n", "apt-get", "upgrade", "-y"], self.runner.commands)
        self.assertNotIn("do-not-run", canonical(self.runner.commands))

    def test_plain_and_json_reports_show_context_and_escape_untrusted_strings(self):
        self.catalog = catalog(*(incident(slug=f"incident-{i}") for i in range(7)))
        report = self.check(context=True)
        report["context"]["pwn_watch"]["items"][0]["title"] = "[bold]bad\x1b[31m\nnext"
        result = [{"target": self.t, "report": report, "pending_updates": [], "last_attempt": {"kind": "checked"}}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            display(result)
        rendered = out.getvalue()
        self.assertIn("not applicability evidence", rendered)
        self.assertIn("CISA KEV listed", rendered)
        self.assertIn("not a current score", rendered)
        self.assertIn("Model summary (example/model; CC-BY-4.0)", rendered)
        self.assertIn("Showing 5 of 7 context records", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertIn(r"\u001b[31m\nnext", rendered)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            display(result, json_output=True)
        self.assertEqual(json.loads(out.getvalue()), result)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            display(result, show_all=True)
        self.assertNotIn("Showing 5", out.getvalue())
        # Rich must also render feed text literally on narrow and wide terminals.
        for width in (40, 120):
            terminal = io.StringIO()
            terminal.isatty = lambda: True
            with patch.dict("os.environ", {"TERM": "xterm", "COLUMNS": str(width)}, clear=True), contextlib.redirect_stdout(terminal):
                display(result)
            self.assertIn("[bold]bad", terminal.getvalue())
            self.assertNotIn("\x1b[31m\\nnext", terminal.getvalue())


class ParsingTests(unittest.TestCase):
    def test_incident_relevance_is_exact_and_excludes_breaches_closed_and_examples(self):
        packages = [adapters.package("example", "9", "PyPI")]
        data = catalog(incident(), incident("prefix", tags=["example-extra"]), incident("closed", status="closed"),
                       incident("breach", category="breach"), incident("demo", isExample=True),
                       incident("cve-only", tags=[], cveIds=[CVE]), incident("supply", category="supply-chain"))
        rows = sources.pwn_context(packages, [{"advisory": CVE}], data)
        self.assertEqual({r["id"] for r in rows}, {"example-incident", "cve-only", "supply"})
        self.assertEqual(next(r for r in rows if r["id"] == "cve-only")["packages"], [])
        self.assertEqual(next(r for r in rows if r["id"] == "cve-only")["matched_references"], [CVE])
        self.assertTrue(all(r["state"] == "review" for r in rows))

    def test_non_cve_advisory_ids_are_retained_and_matched_without_guessing_cves(self):
        ghsa, mal = "GHSA-abcd-efgh-2345", "MAL-2099-1234"
        rows = sources.pwn_context([], [{"advisory": ghsa}, {"advisory": "OSV-1", "references": [mal]}],
                                   catalog(incident(tags=[], cveIds=[ghsa, mal])))
        self.assertEqual(rows[0]["matched_references"], [ghsa, mal])
        self.assertEqual(rows[0]["references"], [ghsa, mal])
        self.assertEqual(sources.advisory_references([{"advisory": ghsa, "references": [mal]}], cves_only=True), [])
        self.assertEqual(sources.advisory_references([{"advisory": CVE, "references": 123}], cves_only=True), [CVE])

    def test_fixed_aliases_source_names_and_pypi_normalization(self):
        packages = [adapters.package("linux-lts", "9", "Arch"), adapters.package("some-binary", "9", "Ubuntu", source="example"),
                    adapters.package("Example_Package", "9", "PyPI"), adapters.package("openssl", "3", "Conda")]
        rows = sources.pwn_context(packages, [], catalog(incident(tags=["linux", "example", "example-package", "openssl"], product="Linux kernel")))
        self.assertEqual(rows[0]["packages"], ["Example_Package", "linux-lts", "openssl", "some-binary"])
        self.assertEqual(rows[0]["state"], "review")  # No conda or rebuild vulnerability semantics.

    def test_linux_kernel_packages_do_not_match_generic_linux_application_tags(self):
        rows = sources.pwn_context([adapters.package("linux-lts", "9", "Arch")], [],
                                   catalog(incident("kernel", tags=["linux"], product="Linux kernel (networking)"),
                                           incident("application", tags=["linux"], product="An unrelated Linux application")))
        self.assertEqual([r["id"] for r in rows], ["kernel"])

    def test_bad_catalogs_and_duplicate_identities_fail_visibly(self):
        for data in ({}, catalog() | {"incidents": []}, catalog(incident(slug="../bad")),
                     catalog(incident(), incident()), catalog(incident(tags="example")),
                     catalog(incident(cveIds=["https://attacker.invalid"])), catalog(incident(title="bad\x1b"))):
            with self.subTest(data=data), self.assertRaises((Error, KeyError)):
                sources.pwn_context([], [], data)

    def test_incident_order_respects_time_zone_offsets(self):
        rows = sources.pwn_context([adapters.package("example", "1", "PyPI")], [],
                                   catalog(incident("later", updatedAt="2099-01-01T10:00:00Z"),
                                           incident("earlier", updatedAt="2099-01-01T11:00:00+02:00"),
                                           incident("date-only", updatedAt="2099-01-01")))
        self.assertEqual([r["id"] for r in rows], ["later", "earlier", "date-only"])
        self.assertEqual(rows[-1]["updated_at"], "2099-01-01")
        with self.assertRaises(Error):
            sources.pwn_context([], [], catalog(incident(updatedAt="2099-01-01T10:00:00")))

    def test_cve_identity_scores_signals_and_generated_provenance_are_validated(self):
        for data in (entry("CVE-2099-99999"), entry() | {"severity": {"cvss": float("nan"), "source": "cna"}},
                     entry() | {"exploitation": {"kev": True}}, entry() | {"summary": {"text": "unlabeled"}},
                     entry() | {"status": "reserved"}, entry() | {"sources": [{"name": "bad", "url": "file:///etc/passwd"}]}):
            with self.subTest(data=data), self.assertRaises((Error, KeyError, TypeError)):
                sources.cve_context(CVE, data)
        empty = sources.cve_context(CVE, entry() | {"summary": None, "severity": None, "exploitation": {}})
        self.assertIsNone(empty["signals"]["kev"])
        self.assertIsNone(empty["signals"]["epssReached"])


class TransportTests(unittest.TestCase):
    def test_only_fixed_get_endpoints_and_valid_cve_ids_are_accepted(self):
        for url in ("https://attacker.invalid/", sources.CVE_NOW + "../bad", sources.CVE_NOW + CVE + "?x=1",
                    "https://user@cve.now/api/v1/entries/" + CVE):
            with self.subTest(url=url), self.assertRaises(Error):
                sources.fetch(url)
        for url in (sources.PWN, sources.CVE_NOW + CVE):
            with self.assertRaises(Error):
                sources.fetch(url, {"packages": ["private"]})
        response = io.BytesIO(b'{}')
        response.headers = {}
        with patch("netwatch.sources.urllib.request.build_opener") as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(sources.fetch(sources.CVE_NOW + CVE), {})
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(req.get_method(), "GET")
            self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 10)

    def test_redirects_allow_one_exact_https_entry_storage_hop_only(self):
        handler = sources.NoRedirect()
        req = urllib.request.Request(sources.CVE_NOW + CVE)
        allowed = "https://example.public.blob.vercel-storage.com/public/entries/" + CVE + ".json"
        redirected = handler.redirect_request(req, None, 302, "Found", {}, allowed)
        self.assertEqual(redirected.full_url, allowed)
        for url in ("http:" + allowed[6:], allowed + "?x=1", allowed + "#fragment", allowed.replace(CVE, "CVE-2099-99999"),
                    allowed.replace("example.public", "user@example.public"), allowed.replace(".com/", ".com.evil/"),
                    "https://127.0.0.1/public/entries/" + CVE + ".json"):
            with self.subTest(url=url), self.assertRaises(Error):
                handler.redirect_request(req, None, 302, "Found", {}, url)
        for source in (sources.PWN, sources.USN, sources.OSV, allowed):
            with self.assertRaises(Error):
                handler.redirect_request(urllib.request.Request(source), None, 302, "Found", {}, allowed)

    def test_context_response_byte_and_encoding_limits(self):
        for raw, headers in ((b' ' * (2 * 1024 * 1024 + 1), {}), (b'{}', {"Content-Encoding": "gzip"})):
            response = io.BytesIO(raw)
            response.headers = headers
            with patch("netwatch.sources.urllib.request.build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(Error):
                    sources.fetch(sources.CVE_NOW + CVE)


if __name__ == "__main__":
    unittest.main()
