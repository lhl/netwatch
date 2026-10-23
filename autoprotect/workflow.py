"""Check, report and apply. Human approval covers an environment-wide update."""
import json
import os
import time

from . import adapters, sources
from .core import Error, canonical, digest


def check(store, t, *, offline=False, refresh=False, refreshed=None, runner=adapters.run, request=sources.fetch):
    try:
        packages = adapters.inventory(t, runner)
    except (Error, ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError) as exc:
        store.event(t["name"], "collection_failed", {"error": str(exc) if isinstance(exc, Error) else "Invalid inventory output"})
        raise Error("Inventory collection failed; previous report retained (see history)") from exc
    findings, warnings, complete, evidence = sources.assess(t, packages, store, offline=offline, refresh=refresh, refreshed=refreshed, request=request)
    available, update_error = [], None
    if offline:
        update_error = "Update availability not refreshed in offline mode"
    else:
        try:
            available = adapters.updates(t, runner)
        except (Error, ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError) as exc:
            update_error = str(exc) if isinstance(exc, Error) else "Invalid package-manager update output"
    if update_error:
        warnings.append(update_error)
    if t["kind"] == "ubuntu":
        warnings.append("APT candidates use current local indexes; apply refreshes them, so its transaction can change")
    if t["kind"] == "uv":
        warnings.append("Outdated versions may be excluded by project constraints; apply updates the lock and syncs the project default environment")
    if t["kind"] in ("conda", "mamba"):
        warnings.append("Environment updates do not update separately pip-installed packages")
    return store.save_scan(t["name"], {"target": t, "packages": packages, "findings": findings,
                                      "updates": available, "warnings": warnings,
                                      "advisory_check_ok": complete, "evidence": evidence, "update_error": update_error})


def preview(store, t, runner=adapters.run):
    packages = adapters.inventory(t, runner)
    available = adapters.updates(t, runner)
    body = {"target": t, "inventory_digest": digest(packages), "commands": adapters.commands(t),
            "observed_updates": available,
            "scope": "Update the ENTIRE selected environment using configured repositories and project constraints. "
                     "This is not an exact-version transaction: repository changes can change what is installed. "
                     "Dependencies, scripts and services may be affected. Back up first.",
            "expires_at": int(time.time()) + 3600}
    with store.transaction():
        row = store.db.execute("INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
                               (t["name"], int(time.time()), "proposed", canonical(body)))
        id_ = row.lastrowid
        store.event(t["name"], "proposed", {"plan": id_, **body})
    return {"id": id_, "status": "proposed", **body}


def apply(store, id_, *, yes=False, runner=adapters.run, request=sources.fetch):
    if not yes:
        raise Error("Read preview first; apply requires --yes to approve the whole environment update")
    row = store.db.execute("SELECT * FROM plans WHERE id=?", (id_,)).fetchone()
    if not row or row["status"] != "proposed":
        raise Error("Plan missing or already attempted; never replay an interrupted update")
    body = json.loads(row["body"])
    t = store.target(row["target"])
    if body["target"] != t or body["commands"] != adapters.commands(t):
        raise Error("Target or adapter changed; create a new preview")
    before = adapters.inventory(t, runner)
    if body["inventory_digest"] != digest(before) or int(time.time()) >= body["expires_at"]:
        raise Error("Inventory changed or preview expired; create a new preview")
    with store.transaction():
        busy = store.db.execute("SELECT id FROM plans WHERE target=? AND status IN ('running','needs_attention')", (t["name"],)).fetchone()
        if busy:
            raise Error("Previous update is running or needs attention; inspect history and resolve it first")
        updated = store.db.execute("UPDATE plans SET status='running' WHERE id=? AND status='proposed'", (id_,))
        if updated.rowcount != 1:
            raise Error("Plan was already claimed")
        store.event(t["name"], "approved_and_started", {"plan": id_, "operator_uid": os.getuid(), "commands": body["commands"]})
    try:
        for argv in body["commands"]:
            runner(t, argv, timeout=1800)
            store.event(t["name"], "command_completed", {"plan": id_, "argv": argv})
        report = check(store, t, runner=runner, request=request)
        changed = digest(before) != digest(report["packages"])
        result = {"plan": id_, "status": "applied", "package_state_changed": changed,
                  "remaining_findings": report["findings"], "advisory_check_ok": report["advisory_check_ok"],
                  "runtime": "Not verified. Check running services and restart/reboot requirements before declaring remediation complete."}
        if t["kind"] == "ubuntu":
            try:
                result["reboot_required"] = runner(t, ["sh", "-c", "if test -f /var/run/reboot-required; then echo yes; else echo no; fi"]).strip() == "yes"
            except Error:
                result["reboot_required"] = "unknown"
        with store.transaction():
            store.db.execute("UPDATE plans SET status='applied',result=? WHERE id=?", (canonical(result), id_))
            store.event(t["name"], "applied", result)
        return result
    except BaseException as exc:
        with store.transaction():
            store.db.execute("UPDATE plans SET status='needs_attention',result=? WHERE id=?",
                             (canonical({"error": "Update interrupted/failed or verification unavailable; inspect the system before retrying"}), id_))
            store.event(t["name"], "needs_attention", {"plan": id_, "error": type(exc).__name__})
        raise


def resolve(store, id_, note):
    with store.transaction():
        row = store.db.execute("SELECT * FROM plans WHERE id=?", (id_,)).fetchone()
        if not row or row["status"] not in ("running", "needs_attention"):
            raise Error("Only interrupted or uncertain updates can be resolved")
        store.db.execute("UPDATE plans SET status='resolved' WHERE id=?", (id_,))
        store.db.execute("UPDATE plans SET status='stale' WHERE target=? AND status='proposed'", (row["target"],))
        store.event(row["target"], "operator_resolved", {"plan": id_, "note": note,
                    "warning": "Operator attests no process still runs and recovery is complete; not a verified remediation"})
    return {"plan": id_, "status": "resolved"}
