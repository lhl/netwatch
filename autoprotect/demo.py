"""Disposable demonstration using the real workflow and an injected command runner."""
import tempfile
from pathlib import Path

from . import adapters, workflow
from .core import Error, canonical
from .store import Store


NOTICE = {"10001-1": {"id": "10001-1", "releases": {"noble": {
    "sources": {"example": {"version": "1.1-1"}},
    "allbinaries": {"example": {"source": "example", "version": "1.1-1", "pocket": "security"}}}}}}


class DemoRunner:
    def __init__(self):
        self.version = "1.0-1"
        self.fail = False
        self.commands = []

    def __call__(self, t, argv, **kwargs):
        self.commands.append(argv)
        if argv == ["cat", "/etc/os-release"]:
            return 'ID=ubuntu\nVERSION_CODENAME=noble\n'
        if argv == ["dpkg", "--print-architecture"]:
            return "amd64\n"
        if argv[0] == "dpkg-query":
            return f"example\t{self.version}\texample\t{self.version}\tamd64\tinstalled\n"
        if argv[:3] == ["apt", "list", "--upgradable"]:
            return "example/noble-security 1.1-1 amd64 [upgradable from: 1.0-1]\n" if self.version == "1.0-1" else ""
        if argv == ["sudo", "-n", "apt-get", "update"]:
            return ""
        if argv == ["sudo", "-n", "apt-get", "upgrade", "-y"]:
            if self.fail:
                raise Error("Simulated package-manager failure")
            self.version = "1.1-1"
            return ""
        if argv[:2] == ["sh", "-c"]:
            return "no\n"
        raise AssertionError("Unexpected demo command: " + canonical(argv))


def demo():
    with tempfile.TemporaryDirectory(prefix="autoprotect-demo-") as root:
        store = Store(Path(root) / "state.db")
        try:
            t, runner = adapters.target("demo", "ubuntu"), DemoRunner()
            store.db.execute("INSERT INTO targets VALUES(?,?)", (t["name"], canonical(t)))
            request = lambda url, body=None: NOTICE
            first = workflow.check(store, t, runner=runner, request=request)
            assert first["findings"][0]["state"] == "affected"
            plan = workflow.preview(store, t, runner)
            try:
                workflow.apply(store, plan["id"], runner=runner)
            except Error:
                pass
            else:
                raise AssertionError("Missing approval was accepted")
            result = workflow.apply(store, plan["id"], yes=True, runner=runner, request=request)
            assert result["package_state_changed"] and not result["remaining_findings"]
            return {"synthetic": True, "network": False, "native_updates": False,
                    "initial_findings": len(first["findings"]), "result": result,
                    "events": len(store.events()), "temporary_state_removed_on_return": True}
        finally:
            store.close()
