"""Disposable command-level simulation; no user policy, network or native tools.

The only direct backend operation is setting a failure control on state created
by this invocation. All lifecycle operations run through separate ordinary CLI
processes. Runner supplies output/deadline bounds and process-group cleanup;
its documented spawn and forced-termination limitations still apply.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import sys
import tempfile
import time

from . import core
from .backends import Simulator
from .inventory import inventory_fingerprint
from .runner import Runner

_ASSET = "synthetic-demo"
_PACKAGES = ("demo-alpha", "demo-beta")
_OLD = "1.0-1"
_NEW = "1.0-2"
_ACTOR = "synthetic-demo-operator"
_MAX_OUTPUT = 256 * 1024
_MAX_SUMMARY = 8192
_COMMAND_TIMEOUT = 15
_DEMO_TIMEOUT = 120
_MAX_COMMANDS = 128
_COMMANDS = frozenset({
    "init-simulator", "import-feed", "inventory", "triage", "plan", "approve",
    "execute", "queue", "audit", "export", "recovery-status", "resolve-recovery",
})
_ERROR = "Disposable demo failed a bounded command or state check; no demo success is claimed."
# Exact public CLI categories and reviewed Engine/backend reasons. A generic
# failure, even with exit 1, does not demonstrate an authorization boundary.
_DENIALS = {
    "unapproved": ("policy_error", "Manual execution requires explicit approval of this immutable plan"),
    "repeat": ("policy_error", "Plan is final or already claimed; collect and create a new plan"),
    "gate": ("backend_error", "unresolved execution gate requires explicit recovery"),
    "collection": ("policy_error", "Collection context or recovery generation changed; collect fresh backend inventory before planning"),
    "generation": ("policy_error", "Plan recovery generation changed; collect, create a new plan, and renew authorization"),
}


def _require(condition):
    if not condition:
        raise core.AutoprotectError(_ERROR)


def _is_id(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _fixture_data():
    """Return fresh, public synthetic inputs, never records from the host."""
    inventory = {
        "schema_version": 1, "asset_id": _ASSET, "observed_at": core.now(),
        "os": "debian", "release": "trixie", "architecture": "amd64",
        "collector": "imported", "complete": True,
        "packages": [
            {"ecosystem": "deb", "name": name, "version": _OLD,
             "source_name": name, "source_version": _OLD,
             "architecture": "amd64", "status": "installed", "held": False}
            for name in _PACKAGES
        ],
    }
    origin = {"origin": "Synthetic", "label": "Synthetic", "archive": "synthetic",
              "codename": "trixie", "component": "main", "site": "synthetic.invalid"}
    catalog = [
        {"name": name, "architecture": "amd64", "from_version": _OLD,
         "to_version": _NEW, "source_name": name, "source_version": _NEW,
         "sha256": core.digest(["synthetic-artifact", name]), "size": 1,
         "origins": [copy.deepcopy(origin)],
         "config_digest": core.digest("synthetic-config"),
         "metadata_digest": core.digest("synthetic-metadata")}
        for name in _PACKAGES
    ]
    # These invented advisory identities do not assert a real vulnerability.
    debian = {
        name: {f"CVE-2099-{10001 + index}": {
            "description": "Invented advisory for disposable simulation only.",
            "releases": {"trixie": {"status": "resolved", "fixed_version": _NEW,
                                      "urgency": "high"}},
        }} for index, name in enumerate(_PACKAGES)
    }
    pwn = {"incidents": [{
        "slug": "synthetic-demo-incident", "title": "Invented demo incident",
        "summary": "Synthetic evidence only; never an instruction or real incident claim.",
        "cveIds": ["CVE-2099-10001"], "severity": "high", "patchStatus": "patched",
        "product": "demo-alpha", "isExample": True,
    }]}
    policy = {
        "schema_version": 1, "mode": "manual", "backend": "simulator",
        "allowed_assets": [_ASSET], "allowed_packages": list(_PACKAGES),
        "allowed_origins": [], "approved_config_digest": None,
        "max_inventory_age": 3600, "max_feed_age": 3600, "max_repository_age": 3600,
        "plan_ttl": 3600, "approval_ttl": 3600,
        "allow_maintainer_scripts": False, "recovery_confirmed": False,
        "trusted_installed_lineage": False,
    }
    automatic = copy.deepcopy(policy)
    automatic["mode"] = "auto"
    return {"inventory": inventory, "catalog": catalog, "debian": debian, "pwn": pwn,
            "manual": policy, "auto": automatic}


def _write_fixtures(root):
    paths = {}
    for name, data in _fixture_data().items():
        path = root / (name + ".json")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(core.canonical(data))
        paths[name] = path
    return paths


class _Commands:
    """One bounded session, with no inherited shell/Python environment."""

    def __init__(self):
        self.runner = Runner(max_output_bytes=_MAX_OUTPUT)
        self.deadline = time.monotonic() + _DEMO_TIMEOUT
        self.count = 0
        # Works from a source checkout or site-packages, without caller cwd or
        # PYTHONPATH. The installed module never imports repository test data.
        self.cwd = str(Path(__file__).absolute().parent.parent)

    def call(self, state, policy, *arguments, expect="ok", denial=None):
        _require(arguments and arguments[0] in _COMMANDS and "--live" not in arguments)
        _require(expect in ("ok", "outcome", "denied"))
        _require(denial in _DENIALS if expect == "denied" else denial is None)
        remaining = self.deadline - time.monotonic()
        _require(remaining > 0 and self.count < _MAX_COMMANDS)
        self.count += 1
        # Runner intentionally does not inherit PYTHONDONTWRITEBYTECODE. Keep
        # interpreter cache writes out of the caller's installed/source package.
        argv = [sys.executable, "-B", "-m", "autoprotect", "--state-dir", str(state),
                "--policy", str(policy), *arguments]
        try:
            result = self.runner.run(argv, timeout=min(_COMMAND_TIMEOUT, remaining), cwd=self.cwd)
            _require(type(result.returncode) is int and result.returncode == (0 if expect == "ok" else 1))
            _require(isinstance(result.stdout, str) and isinstance(result.stderr, str))
            _require(len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")) <= _MAX_OUTPUT)
            # Failed execution outcomes are structured stdout, while rejected
            # actions are structured stderr. Do not accept arbitrary exit 1.
            raw, other = ((result.stderr, result.stdout) if expect == "denied"
                          else (result.stdout, result.stderr))
            _require(not other.strip())
            value = core.load_json(raw, max_bytes=_MAX_OUTPUT, max_nodes=20000)
            _require(type(value) in (dict, list))
            if expect == "denied":
                code, message = _DENIALS[denial]
                _require(value == {"error": {"code": code, "message": message}})
            return value
        except Exception:
            # Even OS/decoder/test-double errors must not leak child logs or
            # paths. KeyboardInterrupt propagates after Runner's cleanup.
            raise core.AutoprotectError(_ERROR) from None


class _Scenario:
    def __init__(self, root, name, mode, fixtures, commands):
        self.state = root / name
        self.state.mkdir(mode=0o700)
        self.policy = fixtures[mode]
        self.commands = commands
        self.call("init-simulator", "--inventory", str(fixtures["inventory"]),
                  "--catalog", str(fixtures["catalog"]))
        self.duplicate_imports = {}
        for source in ("debian", "pwn"):
            first = self.call("import-feed", source, str(fixtures[source]))
            second = self.call("import-feed", source, str(fixtures[source]))
            for health in (first, second):
                _require(health["source"] == source and health["acquisition"] == "import"
                         and health["error"] is None and _is_id(health["snapshot_id"]))
            _require(first["snapshot_id"] == second["snapshot_id"])
            self.duplicate_imports[source] = True
        self.initial = self.inventory()
        expected = _fixture_data()["inventory"]
        expected["collector"] = "simulator"
        _require(inventory_fingerprint(self.initial) == inventory_fingerprint(expected))

    def call(self, *arguments, expect="ok"):
        return self.commands.call(self.state, self.policy, *arguments, expect=expect)

    def denied(self, *arguments, reason):
        code, message = _DENIALS[reason]
        # The target gate rejects before Engine._run and emits no audit event.
        # Its exact backend error is corroborated by queue/gate observations.
        audited = code == "policy_error"
        before = self.call("audit") if audited else None
        self.commands.call(self.state, self.policy, *arguments, expect="denied", denial=reason)
        if audited:
            after = self.call("audit")
            _require(type(before) is list and type(after) is list
                     and after[:len(before)] == before and len(after) == len(before) + 1)
            event = after[-1]
            _require(event["event"] == "action-denied" and event["details"] == {
                "action": arguments[0],
                "plan_id": arguments[1] if arguments[0] == "execute" else None,
                "reason": message,
            })
            _require(type(event["id"]) is int and event["id"] > 0
                     and all(type(row["id"]) is int and row["id"] < event["id"] for row in before))

    def inventory(self):
        observed = self.call("inventory")
        _require(_is_id(observed["id"]) and core.digest(observed["body"]) == observed["id"])
        body = observed["body"]
        _require(body["asset_id"] == _ASSET and body["collector"] == "simulator")
        return body

    def findings(self):
        result = self.call("triage", _ASSET)
        _require(type(result) is list)
        return result

    def finding(self, name):
        rows = [row for row in self.findings()
                if row["package"] is not None and row["package"]["name"] == name
                and row["status"] == "affected" and row["fixed_version"] == _NEW]
        _require(len(rows) == 1 and _is_id(rows[0]["id"]))
        return rows[0]

    def plan(self, finding):
        plan = self.call("plan", finding["id"])
        _require(plan["status"] == "pending" and _is_id(plan["id"])
                 and core.digest(plan["body"]) == plan["id"])
        body = plan["body"]
        _require(body["backend"] == "simulator" and body["asset_id"] == _ASSET
                 and body["finding_id"] == finding["id"] and _is_id(body["target_generation"])
                 and body["target"]["name"] == finding["package"]["name"]
                 and body["target"]["from_version"] == _OLD and body["target"]["to_version"] == _NEW)
        return plan

    def approve(self, plan):
        approved = self.call("approve", plan["id"], "--actor", _ACTOR)
        _require(approved == {**plan, "status": "approved"})
        self.queue_status(plan, "approved")

    def execute(self, plan, status):
        result = self.call("execute", plan["id"], expect="ok" if status == "succeeded" else "outcome")
        _require(result["plan_id"] == plan["id"] and result["status"] == status
                 and result["result"]["verified"] is (status == "succeeded")
                 and _is_id(result["inventory_id"]))
        self.queue_status(plan, status)
        return result

    def queue_status(self, plan, status):
        rows = [row for row in self.call("queue") if row["id"] == plan["id"]]
        _require(len(rows) == 1 and rows[0] == {**plan, "status": status})

    def state_matches(self, before, changed=()):
        expected = copy.deepcopy(before)
        for package in expected["packages"]:
            if package["name"] in changed:
                package["version"] = _NEW
                package["source_version"] = _NEW
        observed = self.inventory()
        _require(inventory_fingerprint(observed) == inventory_fingerprint(expected))
        return observed

    def recovery_status(self, plan, status, retained):
        result = self.call("recovery-status", plan["id"])
        _require(result["plan_id"] == plan["id"] and result["asset_id"] == _ASSET
                 and result["status"] == status and _is_id(result["generation"])
                 and result["gate"] == ({"plan_id": plan["id"]} if retained else None)
                 and result["prior_plan_identity_verified"] is retained)
        return result

    def audit(self, plan, approved, status):
        events = self.call("audit")
        _require(type(events) is list)
        relevant = [row for row in events if row["details"].get("plan_id") == plan["id"]]
        approvals = [row for row in relevant if row["event"] == "plan-approved"]
        _require(len(approvals) == (1 if approved else 0))
        _require(sum(row["event"] == "execution-start" for row in relevant) == 1)
        outcomes = [row["details"]["status"] for row in relevant if row["event"] == "execution-outcome"]
        _require(outcomes == [status])
        return events


def _success(root, fixtures, commands, mode):
    scenario = _Scenario(root, mode, mode, fixtures, commands)
    plan = scenario.plan(scenario.finding(_PACKAGES[0]))
    if mode == "manual":
        scenario.denied("execute", plan["id"], reason="unapproved")
        scenario.queue_status(plan, "pending")
        scenario.state_matches(scenario.initial)
        scenario.approve(plan)
    scenario.execute(plan, "succeeded")
    scenario.state_matches(scenario.initial, (_PACKAGES[0],))
    scenario.denied("execute", plan["id"], reason="repeat")
    scenario.queue_status(plan, "succeeded")
    scenario.recovery_status(plan, "succeeded", False)
    scenario.audit(plan, mode == "manual", "succeeded")
    exported = scenario.call("export", _ASSET)
    _require(exported["kind"] == "untrusted-advisory-data" and exported["trusted"] is False
             and isinstance(exported["warning"], str) and bool(exported["warning"]))
    findings = exported["findings"]
    _require(any(row["package"] is not None and row["package"]["name"] == _PACKAGES[0]
                 and row["status"] == "not_affected" for row in findings))
    return {"status": "succeeded", "verified_package_state": True,
            "manual_approval": mode == "manual", "repeat_execution": "denied",
            "duplicate_imports": scenario.duplicate_imports, "export_trusted": False}


def _before_write(root, fixtures, commands):
    scenario = _Scenario(root, "before-write", "manual", fixtures, commands)
    plan = scenario.plan(scenario.finding(_PACKAGES[0]))
    scenario.approve(plan)
    Simulator(scenario.state / "simulator.json").set_failure("before_write")
    scenario.execute(plan, "failed")
    scenario.state_matches(scenario.initial)
    scenario.recovery_status(plan, "failed", False)
    scenario.audit(plan, True, "failed")
    return {"status": "failed", "verified": False, "package_state_unchanged": True,
            "gate_retained": False, "failure": "synthetic-before-write"}


def _after_write(root, fixtures, commands):
    scenario = _Scenario(root, "after-write", "manual", fixtures, commands)
    plan = scenario.plan(scenario.finding(_PACKAGES[0]))
    scenario.approve(plan)
    Simulator(scenario.state / "simulator.json").set_failure("after_write")
    scenario.execute(plan, "needs_attention")
    changed = scenario.state_matches(scenario.initial, (_PACKAGES[0],))
    retained = scenario.recovery_status(plan, "needs_attention", True)
    _require(retained["generation"] == plan["body"]["target_generation"])
    scenario.audit(plan, True, "needs_attention")

    # Bind another approved plan to the already changed inventory. A later
    # denial cannot be explained by the first package's update or a final plan.
    finding = scenario.finding(_PACKAGES[1])
    old = scenario.plan(finding)
    scenario.approve(old)
    scenario.denied("execute", old["id"], reason="gate")
    scenario.queue_status(old, "approved")
    scenario.recovery_status(plan, "needs_attention", True)
    resolution = scenario.call("resolve-recovery", plan["id"], "--actor", _ACTOR,
                               "--reason", "Inspected disposable synthetic state; no real recovery is asserted.")
    _require(resolution["plan_id"] == plan["id"] and resolution["status"] == "needs_attention"
             and resolution["gate_cleared"] is True and resolution["verified"] is False
             and resolution["prior_plan_identity_verified"] is True
             and resolution["gate"] == {"plan_id": plan["id"]}
             and _is_id(resolution["target_generation"])
             and resolution["target_generation"] != old["body"]["target_generation"])
    cleared = scenario.recovery_status(plan, "needs_attention", False)
    _require(cleared["generation"] == resolution["target_generation"])
    # Old collection context cannot authorize a new plan. Fresh collection
    # restores planning, but must not revive a previously approved generation.
    scenario.denied("plan", finding["id"], reason="collection")
    scenario.state_matches(changed)
    scenario.denied("execute", old["id"], reason="generation")
    scenario.queue_status(old, "stale")
    events = scenario.call("audit")
    _require(any(row["event"] == "action-denied" and row["details"].get("plan_id") == old["id"]
                 and row["details"].get("action") == "execute"
                 and "generation" in row["details"].get("reason", "") for row in events))
    _require(any(row["event"] == "recovery-gate-cleared" and row["details"].get("plan_id") == plan["id"]
                 and row["details"].get("target_generation") == cleared["generation"] for row in events))
    Simulator(scenario.state / "simulator.json").set_failure(None)
    renewed = scenario.plan(scenario.finding(_PACKAGES[1]))
    _require(renewed["id"] != old["id"]
             and renewed["body"]["target_generation"] == cleared["generation"])
    scenario.approve(renewed)
    scenario.execute(renewed, "succeeded")
    scenario.state_matches(changed, (_PACKAGES[1],))
    scenario.queue_status(plan, "needs_attention")
    scenario.recovery_status(renewed, "succeeded", False)
    scenario.audit(renewed, True, "succeeded")
    return {"status": "needs_attention", "verified": False,
            "package_state_changed": True, "gate_retained_before_resolution": True,
            "gate_blocked_other_plan": True, "failure": "synthetic-after-write",
            "recovery": {"gate_cleared": True, "verified": False, "generation_changed": True,
                         "fresh_collection_required": True, "old_approved_plan": "stale",
                         "new_approved_plan": "succeeded", "original_status": "needs_attention"}}


def run_demo() -> dict:
    """Run the self-contained simulator matrix and remove generated state.

    There are no caller-supplied paths or operational options. A result is
    returned only after successful cleanup; failures expose no raw child logs.
    Graceful interruption unwinds child and temporary-directory cleanup. Forced
    process/host death cannot guarantee cleanup and is not simulated recovery.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="autoprotect-demo-") as temporary:
            root = Path(temporary)
            fixtures = _write_fixtures(root)
            commands = _Commands()
            scenarios = {"manual": _success(root, fixtures, commands, "manual"),
                         "automatic": _success(root, fixtures, commands, "auto"),
                         "before_write": _before_write(root, fixtures, commands),
                         "after_write": _after_write(root, fixtures, commands)}
        _require(not root.exists())
        result = {
            "schema_version": 1, "kind": "disposable-command-demo", "synthetic": True,
            "backend": "simulator", "scenarios": scenarios, "commands_run": commands.count,
            "cleanup": {"temporary_state_removed": True, "caller_state_used": False},
            "limits": ["Invented public fixtures only; no network, host inventory or native package tools.",
                       "Verified synthetic package state is not runtime health or removal of compromise.",
                       "Recovery is an operator attestation, not rollback or proof of reversed side effects.",
                       "Actor labels are not authenticated identities.",
                       "Cleanup requires normal unwinding; forced process or host death may leave temporary state."],
        }
        _require(len(core.canonical(result)) <= _MAX_SUMMARY)
        return result
    except Exception:
        raise core.AutoprotectError(_ERROR) from None
