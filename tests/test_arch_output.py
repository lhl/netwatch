"""Synthetic regression cases for historical-notice noise and concise reports."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from netwatch import adapters, sources, workflow
from netwatch.cli import display
from netwatch.core import Error, canonical
from netwatch.store import Store


def package(version="9.0-1", foreign=False):
    return adapters.package("example", version, "Arch", foreign=foreign)


def notice(fixed="2.0-1", affected="1.0-1", status="Fixed", name="AVG-1"):
    return {"name": name, "packages": ["example"], "affected": affected, "fixed": fixed,
            "status": status, "severity": "High", "issues": ["CVE-2099-10001"]}


class ArchRelevanceTests(unittest.TestCase):
    def test_equal_or_newer_installed_versions_omit_old_notices(self):
        for kind in ("arch", "cachyos"):
            for version, order in (("2.0-1", 0), ("9.0-1.1", 1), ("1:1.0-1", 1)):
                with self.subTest(kind=kind, version=version):
                    compare = Mock(return_value={(version, "2.0-1"): order})
                    stats = {}
                    rows = sources.arch([package(version)], [notice()], kind, compare=compare, stats=stats)
                    self.assertEqual(rows, [])
                    self.assertEqual(stats["fixed_notices_omitted"], 1)
                    compare.assert_called_once_with([(version, "2.0-1")])

    def test_older_fix_and_missing_fix_remain_visible(self):
        for kind in ("arch", "cachyos"):
            rows = sources.arch([package("1.0-1")], [notice()], kind,
                                compare=lambda pairs: {p: -1 for p in pairs})
            self.assertEqual(rows[0]["state"], "affected" if kind == "arch" else "unknown")
            missing = sources.arch([package()], [notice(fixed=None)], kind,
                                   compare=Mock(side_effect=AssertionError("no comparison needed")))
            self.assertEqual(missing[0]["state"], "unknown")

    def test_foreign_packages_and_malformed_fix_are_not_filtered(self):
        for p, fixed in ((package(foreign=True), "2.0-1"), (package(), "$(touch bad)"), (package(), "0")):
            rows = sources.arch([p], [notice(fixed=fixed)], "cachyos",
                                compare=Mock(side_effect=AssertionError("unsafe or inapplicable comparison")))
            self.assertEqual(rows[0]["state"], "unknown")

    def test_rule_change_is_logged_as_reassessment_not_update(self):
        with tempfile.TemporaryDirectory() as root:
            store = Store(Path(root) / "db")
            try:
                first = OutputTests().result()[0]["report"]
                first.pop("at")
                prior = store.save_scan("local", first)
                failed = store.save_scan("local", {**first, "findings": [], "matcher_revision": 2, "advisory_check_ok": False})
                self.assertEqual(failed["matcher_revision"], 1)
                self.assertEqual(len(failed["findings"]), 200)
                cursor = store.events()[-1]["id"]
                current = {**first, "findings": [], "matcher_revision": 2}
                store.save_scan("local", current)
                events = store.events(cursor)
                reassessed = next(e for e in events if e["kind"] == "findings_reassessed")
                self.assertEqual(reassessed["body"]["removed"], 200)
                self.assertEqual(reassessed["body"]["previous_scan"], failed["id"])
                self.assertNotIn("finding_no_longer_detected", [e["kind"] for e in events])
                cursor = events[-1]["id"]
                store.save_scan("local", {**current, "findings": []})
                self.assertEqual([e["kind"] for e in store.events(cursor)], ["checked"])
            finally:
                store.close()

    def test_comparisons_are_deduplicated(self):
        compare = Mock(return_value={("9.0-1", "2.0-1"): 1})
        rows = sources.arch([package()], [notice(), notice(name="AVG-2")], "cachyos", compare=compare)
        self.assertEqual(rows, [])
        compare.assert_called_once_with([("9.0-1", "2.0-1")])

    def test_batch_runner_passes_versions_as_arguments_and_validates_results(self):
        t = adapters.target("remote", "cachyos", "example.invalid")
        pairs = [(f"{i}.0-1", "2.0-1") for i in range(130)]
        calls = []
        def runner(target, argv, **kwargs):
            calls.append(argv)
            self.assertEqual(target, t)
            self.assertEqual(argv[:2], ["sh", "-c"])
            self.assertIn('vercmp "$1" "$2"', argv[2])
            self.assertNotIn("2.0-1", argv[2])
            return "1\n" * ((len(argv) - 4) // 2)
        self.assertEqual(len(adapters.arch_compare(t, pairs, runner)), 130)
        self.assertEqual(len(calls), 3)
        for bad in ("garbage\n", "", "1\n0\n"):
            with self.subTest(bad=bad), self.assertRaises(Error):
                adapters.arch_compare(t, [("1-1", "2-1")], lambda *a: bad)
        with self.assertRaises(Error):
            adapters.arch_compare(t, [("1-1", "$(id)")], Mock())

    def test_missing_comparator_retains_findings_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as root:
            store = Store(Path(root) / "db")
            self.addCleanup(store.close)
            t = adapters.target("local", "cachyos")
            store.db.execute("INSERT INTO targets VALUES(?,?)", ("local", canonical(t)))
            def runner(t, argv, **kwargs):
                if argv[0] == "cat": return "ID=cachyos\n"
                if argv == ["pacman", "-Qm"]: return ""
                if argv == ["pacman", "-Q"]: return "example 1.0-1\n"
                if argv == ["checkupdates"]: return "example 1.0-1 -> 2.0-1\n"
                if argv[:2] == ["sh", "-c"]: return "-1\n"
                raise AssertionError(argv)
            request = lambda *a: [notice()]
            first = workflow.check(store, t, runner=runner, request=request)
            self.assertTrue(first["findings"])
            def failed(t, argv, **kwargs):
                if argv[:2] == ["sh", "-c"]: raise Error("vercmp missing")
                return runner(t, argv, **kwargs)
            report = workflow.check(store, t, runner=failed, request=request)
            self.assertFalse(report["advisory_check_ok"])
            self.assertEqual(len(report["findings"]), 1)
            self.assertTrue(any("vercmp" in w for w in report["warnings"]))


class OutputTests(unittest.TestCase):
    def result(self):
        findings = [sources.finding(package(), f"AVG-{i}", "unknown", [], "needs investigation", "https://example.invalid") for i in range(200)]
        return [{"target": adapters.target("local", "cachyos"), "last_attempt": {"kind": "checked", "at": 1000},
                 "pending_updates": [], "report": {"at": 1000, "packages": [package()], "findings": findings,
                     "updates": [{"package": f"pkg-{i}", "candidate": "2-1"} for i in range(50)],
                     "update_error": None, "updates_observed_at": 1000, "advisory_check_ok": True,
                     "warnings": ["CachyOS matching is incomplete"], "evidence": []}}]

    def render(self, result, **kwargs):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): display(result, **kwargs)
        return out.getvalue()

    def test_default_groups_and_limits_rows_but_json_keeps_everything(self):
        result = self.result()
        text = self.render(result)
        self.assertLess(len(text.splitlines()), 35)
        self.assertIn("200 notices", text)
        self.assertIn("50 available updates", text)
        self.assertIn("--all", text)
        self.assertNotIn('"key":', text)
        self.assertEqual(len(json.loads(self.render(result, json_output=True))[0]["report"]["findings"]), 200)
        self.assertIn("pkg-49", self.render(result, show_all=True))

    def test_output_has_versions_health_and_escaped_remote_text(self):
        result = self.result()
        r = result[0]["report"]
        r["updates"] = [{"package": "example", "candidate": "10.0-1"}]
        r["update_error"] = "repository unavailable"
        r["advisory_check_ok"] = False
        result[0]["last_attempt"]["kind"] = "collection_failed"
        r["warnings"].append("bad\x1b[31m\ntext")
        text = self.render(result)
        self.assertIn("9.0-1 -> 10.0-1", text)
        self.assertIn("Collection failed", text)
        self.assertIn("Advisory check incomplete", text)
        self.assertIn("repository unavailable", text)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\n", text)


if __name__ == "__main__":
    unittest.main()
