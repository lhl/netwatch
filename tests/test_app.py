import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netwatch import adapters, sources, workflow
from netwatch.cli import main
from netwatch.core import Error, canonical
from netwatch.demo import DemoRunner, NOTICE, demo
from netwatch.store import Store


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.db"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.t = adapters.target("host", "ubuntu")
        self.store.db.execute("INSERT INTO targets VALUES(?,?)", ("host", canonical(self.t)))
        self.runner = DemoRunner()
        self.request = lambda url, body=None: copy.deepcopy(NOTICE)

    def check(self, **kwargs):
        return workflow.check(self.store, self.t, runner=self.runner, request=self.request, **kwargs)

    def test_demo(self):
        self.assertEqual(demo()["result"]["status"], "applied")

    def test_success_approval_replay_and_history(self):
        self.check()
        p = workflow.preview(self.store, self.t, self.runner)
        with self.assertRaises(Error):
            workflow.apply(self.store, p["id"], runner=self.runner)
        result = workflow.apply(self.store, p["id"], yes=True, runner=self.runner, request=self.request)
        self.assertTrue(result["package_state_changed"])
        self.assertFalse(result["remaining_findings"])
        self.assertIn("Not verified", result["runtime"])
        with self.assertRaises(Error):
            workflow.apply(self.store, p["id"], yes=True, runner=self.runner)
        kinds = [e["kind"] for e in self.store.events()]
        self.assertIn("approved_and_started", kinds)
        self.assertIn("finding_no_longer_detected", kinds)
        self.assertEqual(kinds[-1], "applied")

    def test_no_duplicate_changes_on_unchanged_scan(self):
        self.check()
        cursor = self.store.events()[-1]["id"]
        self.check()
        self.assertEqual([e["kind"] for e in self.store.events(cursor)], ["checked"])

    def test_refresh_records_evidence_and_failed_refresh_retains_it(self):
        first = self.check()
        self.assertTrue(first["evidence"][0]["fetched_at"])
        self.assertTrue(first["findings"][0]["first_seen"])
        calls = []
        request = lambda *a: calls.append(a) or copy.deepcopy(NOTICE)
        workflow.check(self.store, self.t, runner=self.runner, request=request)
        self.assertFalse(calls)
        workflow.check(self.store, self.t, runner=self.runner, request=request, refresh=True)
        self.assertEqual(len(calls), 1)
        self.request = lambda *a: (_ for _ in ()).throw(Error("source unavailable"))
        report = self.check(refresh=True)
        self.assertEqual(report["findings"][0]["state"], "unknown")
        self.assertFalse(report["advisory_check_ok"])

    def test_every_adapter_uses_only_approved_commands_and_rechecks(self):
        for kind in adapters.KINDS:
            with self.subTest(kind=kind):
                t = adapters.target(kind, kind, path="/env" if kind in ("uv", "npm", "conda", "mamba") else None)
                self.store.db.execute("INSERT INTO targets VALUES(?,?)", (kind, canonical(t)))
                calls = []
                runner = lambda t, argv, **kw: calls.append(argv) or "no\n"
                packages = [adapters.package("test", "1", "Conda")]
                with patch("netwatch.adapters.inventory", return_value=packages), \
                     patch("netwatch.adapters.updates", return_value=[]), \
                     patch("netwatch.sources.assess", return_value=([], [], True, [])):
                    p = workflow.preview(self.store, t, runner)
                    result = workflow.apply(self.store, p["id"], yes=True, runner=runner)
                self.assertEqual(calls[:len(adapters.commands(t))], adapters.commands(t))
                self.assertEqual(result["status"], "applied")
                self.assertFalse(result["package_state_changed"])

    def test_bad_target_does_not_prevent_other_checks(self):
        bad = adapters.target("offline", "ubuntu")
        self.store.db.execute("INSERT INTO targets VALUES(?,?)", ("offline", canonical(bad)))
        def runner(t, *args, **kwargs):
            if t["name"] == "offline":
                raise Error("unavailable")
            return self.runner(t, *args, **kwargs)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--db", str(self.path), "--json", "check"], runner=runner, request=self.request)
        rows = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0]["report"])
        self.assertIn("error", rows[1])
        self.assertEqual(rows[1]["last_attempt"]["kind"], "collection_failed")

    def test_stale_cache_failure_preserves_finding(self):
        self.check()
        self.store.db.execute("UPDATE cache SET at=0")
        report = self.check(offline=True)
        self.assertFalse(report["advisory_check_ok"])
        self.assertEqual(report["findings"][0]["state"], "unknown")
        self.assertFalse(any(e["kind"] == "finding_no_longer_detected" for e in self.store.events()))

    def test_inventory_failure_retains_previous_scan(self):
        previous = self.check()
        with self.assertRaises(Error):
            workflow.check(self.store, self.t, runner=lambda *a, **k: (_ for _ in ()).throw(Error("offline")))
        self.assertEqual(self.store.latest("host")["id"], previous["id"])
        self.assertEqual(self.store.events()[-1]["kind"], "collection_failed")

    def test_changes_and_expiry_deny_apply(self):
        p = workflow.preview(self.store, self.t, self.runner)
        self.runner.version = "1.1-1"
        with self.assertRaisesRegex(Error, "changed"):
            workflow.apply(self.store, p["id"], yes=True, runner=self.runner)
        self.runner.version = "1.0-1"
        with patch("netwatch.workflow.time.time", return_value=p["expires_at"]):
            with self.assertRaisesRegex(Error, "expired"):
                workflow.apply(self.store, p["id"], yes=True, runner=self.runner)

    def test_failure_blocks_new_attempt_until_operator_resolution(self):
        p = workflow.preview(self.store, self.t, self.runner)
        self.runner.fail = True
        with self.assertRaises(Error):
            workflow.apply(self.store, p["id"], yes=True, runner=self.runner)
        q = workflow.preview(self.store, self.t, self.runner)
        with self.assertRaisesRegex(Error, "attention"):
            workflow.apply(self.store, q["id"], yes=True, runner=self.runner)
        self.assertEqual(workflow.resolve(self.store, p["id"], "Inspected stopped process and repaired environment")["status"], "resolved")
        self.runner.fail = False
        with self.assertRaises(Error):
            workflow.apply(self.store, q["id"], yes=True, runner=self.runner)
        fresh = workflow.preview(self.store, self.t, self.runner)
        self.assertEqual(workflow.apply(self.store, fresh["id"], yes=True, runner=self.runner, request=self.request)["status"], "applied")

    def test_cli_queries_and_failure_exit(self):
        def cli(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["--db", str(self.path), "--json", *args], runner=self.runner, request=self.request)
            return code, json.loads(out.getvalue())
        self.assertEqual(cli("check", "host")[0], 0)
        self.assertEqual(cli("status", "host")[1][0]["report"]["findings"][0]["state"], "affected")
        self.assertGreater(cli("history")[1]["next_cursor"], 0)
        plan = cli("preview", "host")[1]
        self.assertEqual(cli("status", "host")[1][0]["pending_updates"][0]["id"], plan["id"])
        self.assertEqual(cli("add", "host", "ubuntu")[0], 1)
        self.assertEqual(cli("add", "app", "uv", "--path", "/srv/app")[0], 0)
        self.assertEqual(len(cli("list")[1]), 2)

    def test_store_old_schema_private_permissions_and_cache(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        count = []
        loader = lambda: count.append(1) or {"ok": True}
        self.assertEqual(self.store.cached("test", loader), {"ok": True})
        self.store.cached("test", loader)
        self.assertEqual(len(count), 1)
        self.store.db.execute("PRAGMA user_version=4")
        with self.assertRaisesRegex(Error, "Incompatible"):
            Store(self.path)


class AdapterTests(unittest.TestCase):
    def runner(self, outputs):
        def run(t, argv, **kwargs):
            self.calls.append((argv, kwargs))
            if not outputs:
                raise AssertionError(argv)
            return outputs.pop(0)
        self.calls = []
        return run

    def test_registry_and_paths(self):
        for kind in adapters.KINDS:
            t = adapters.target("test", kind, path="/srv/env" if kind in ("conda", "mamba", "uv", "npm") else None)
            self.assertTrue(adapters.commands(t))
        for host in ("-oProxyCommand=evil", "a;id", "a\nb"):
            with self.assertRaises(Error):
                adapters.target("x", "ubuntu", host)
        with self.assertRaises(Error):
            adapters.target("x", "uv", path="relative")

    def test_conda_and_mamba_do_not_guess_pypi(self):
        for kind in ("conda", "mamba"):
            t = adapters.target("env", kind, path="/env")
            run = self.runner([json.dumps([{"name": "openssl", "version": "3", "channel": "conda-forge"},
                                          {"name": "requests", "version": "2", "channel": "pypi"}]),
                               '{"success":true,"actions":{"LINK":[{"name":"openssl","version":"4"}]}}'])
            rows = adapters.inventory(t, run)
            self.assertEqual([p["ecosystem"] for p in rows], ["Conda", "PyPI"])
            self.assertEqual(adapters.updates(t, run)[0]["candidate"], "4")
            self.assertEqual(adapters.commands(t)[0], [kind, "update", "--all", "--yes", "--prefix", "/env"])

    def test_uv(self):
        t = adapters.target("uv", "uv", path="/project")
        run = self.runner(['[{"name":"jinja2","version":"2.11.2"}]',
                           '[{"name":"jinja2","version":"2.11.2","latest_version":"3.1.6"}]'])
        self.assertEqual(adapters.inventory(t, run)[0]["ecosystem"], "PyPI")
        self.assertEqual(adapters.updates(t, run)[0]["candidate"], "3.1.6")
        self.assertIn("/project/.venv/bin/python", self.calls[0][0])
        self.assertEqual(adapters.commands(t), [["uv", "lock", "--upgrade"], ["uv", "sync", "--locked"]])

    def test_npm_transitive_multiple_versions(self):
        t = adapters.target("npm", "npm", path="/app")
        run = self.runner(['{"dependencies":{"a":{"version":"1","dependencies":{"a":{"version":"2"}}}}}',
                           '{"a":{"wanted":"3","latest":"4"}}'])
        self.assertEqual(len(adapters.inventory(t, run)), 2)
        self.assertEqual(adapters.updates(t, run)[0]["candidate"], "3")
        self.assertEqual(adapters.commands(t), [["npm", "update", "--ignore-scripts"]])
        with self.assertRaises(Error):
            adapters.inventory(t, self.runner(['{"dependencies":{"a":{"missing":true}}}']))

    def test_arch_cachyos_full_upgrade(self):
        for kind in ("arch", "cachyos"):
            t = adapters.target("os", kind)
            run = self.runner([f'ID={kind}\n', 'custom 1-1\n', 'linux 1-1\ncustom 1-1\n', 'linux 1-1 -> 2-1\n'])
            rows = adapters.inventory(t, run)
            self.assertTrue(next(p for p in rows if p["name"] == "custom")["foreign"])
            self.assertEqual(adapters.updates(t, run)[0]["candidate"], "2-1")
            self.assertEqual(adapters.commands(t), [["sudo", "-n", "pacman", "-Syu", "--noconfirm"]])
            self.assertEqual(self.calls[-1][0], ["checkupdates"])

    def test_ssh_quoting_and_fixed_host(self):
        t = adapters.target("app", "npm", "user@host", "/srv/a';touch bad;'")
        with patch("netwatch.adapters.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b'{}', b'')
            popen.return_value.returncode = 0
            adapters.run(t, ["npm", "ls", "--all", "--json"])
            argv = popen.call_args.args[0]
            import shlex
            self.assertIn(shlex.quote(t["path"]), argv[-1])
            self.assertEqual(argv[-2], "user@host")
            self.assertNotIn("shell", popen.call_args.kwargs)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.p = {"name": "example", "version": "1.0-1", "ecosystem": "Ubuntu", "source": "example",
                  "source_version": "1.0-1", "architecture": "amd64"}

    def test_ubuntu_wrong_release_pocket_hidden_and_backport(self):
        self.assertEqual(sources.ubuntu([self.p], NOTICE)[0]["state"], "affected")
        p = {**self.p, "source_version": "1.1-1"}
        self.assertEqual(sources.ubuntu([p], NOTICE), [])
        for field, value in (("pocket", "esm-apps"), ("source", "other")):
            data = copy.deepcopy(NOTICE)
            data["10001-1"]["releases"]["noble"]["allbinaries"]["example"][field] = value
            self.assertEqual(sources.ubuntu([self.p], data)[0]["state"], "unknown")
        data = copy.deepcopy(NOTICE)
        data["10001-1"]["is_hidden"] = True
        self.assertEqual(sources.ubuntu([self.p], data)[0]["state"], "unknown")
        data["10001-1"]["releases"]["jammy"] = data["10001-1"]["releases"].pop("noble")
        self.assertEqual(sources.ubuntu([self.p], data), [])

    def test_arch_and_rebuild_uncertainty(self):
        rows = [{"name":"AVG-1", "packages":["test"], "affected":"1-1", "fixed":"2-1", "status":"Fixed"}]
        p = adapters.package("test", "1-1", "Arch", foreign=False)
        compare = lambda pairs: {pair: 0 if pair[0] == pair[1] else -1 for pair in pairs}
        self.assertEqual(sources.arch([p], rows, "arch", compare=compare)[0]["state"], "affected")
        self.assertEqual(sources.arch([p], rows, "cachyos", compare=compare)[0]["state"], "unknown")
        self.assertEqual(sources.arch([{**p,"version":"2-1"}], rows, "arch", compare=compare), [])
        rows[0]["status"] = "Unknown"
        self.assertEqual(sources.arch([p], rows, "arch", compare=compare)[0]["state"], "unknown")

    def test_osv_fixes_only_for_correct_package(self):
        p = adapters.package("jinja2", "2.11.2", "PyPI")
        data = {"vulns":[{"id":"TEST-1", "affected":[
            {"package":{"name":"other","ecosystem":"PyPI"},"ranges":[{"events":[{"fixed":"9"}]}]},
            {"package":{"name":"jinja2","ecosystem":"PyPI"},"ranges":[{"events":[{"fixed":"2.11.3"}]}]}]}]}
        row = sources.osv(p, data)[0]
        self.assertEqual(row["fix_versions"], ["2.11.3"])
        self.assertEqual(row["state"], "affected")
        data["vulns"][0]["withdrawn"] = "2020"
        self.assertEqual(sources.osv(p, data), [])

    def test_bad_sources_do_not_turn_into_clean_reports(self):
        for parse, data in ((sources.ubuntu, {}), (sources.arch, [])):
            with self.assertRaises(Error):
                parse([], data, "arch") if parse == sources.arch else parse([], data)
        with self.assertRaises(Error):
            sources.osv(adapters.package("p", "1", "PyPI"), {"error": "bad request"})
        compact = sources.compact_usn({**NOTICE, "999-1": {"id": "999-1", "releases": {}}})
        self.assertEqual(set(compact), {"10001-1"})

    def test_conda_coverage_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            db = Store(Path(root)/"db")
            try:
                t = adapters.target("env", "conda", path="/env")
                rows, warnings, ok, evidence = sources.assess(t, [adapters.package("openssl", "3", "Conda")], db,
                                                  request=lambda *a: self.fail("must not guess PyPI"))
                self.assertTrue(ok)
                self.assertFalse(rows)
                self.assertTrue(any("unknown" in w for w in warnings))
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
