"""Small CLI. Reports are data, not instructions to a privileged agent."""
import argparse
import json
import os
from datetime import datetime, timezone
from collections import defaultdict
import sqlite3

from . import adapters, sources, workflow
from .core import Error, canonical, text
from .store import Store


def parser():
    p = argparse.ArgumentParser(prog="netwatch", description="Track environments, security advisories and human-approved updates.")
    p.add_argument("--db", default=os.path.expanduser("~/.local/state/netwatch/state.db"))
    p.add_argument("--json", action="store_true", help="machine-readable JSON (all strings escaped)")
    p.add_argument("--version", action="version", version="netwatch 0.2.0")
    commands = p.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add", help="register one OS, environment or project; does not connect")
    add.add_argument("name")
    add.add_argument("kind", choices=adapters.KINDS)
    add.add_argument("--host", default="local", help="local or a configured SSH alias/user@host")
    add.add_argument("--path", help="absolute conda prefix or uv/npm project directory")
    commands.add_parser("list", help="list explicitly registered environments")
    check = commands.add_parser("check", help="collect inventory, query/cache advisories and discover updates")
    check.add_argument("name", nargs="?", help="omit to check all registered environments")
    check.add_argument("--all", action="store_true", help="show all finding and update rows")
    mode = check.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true", help="use fresh advisory cache; still collects inventory over SSH")
    mode.add_argument("--refresh", action="store_true", help="fetch fresh advisories instead of using the one-hour cache")
    status = commands.add_parser("status", help="query cached reports without connecting")
    status.add_argument("name", nargs="?")
    status.add_argument("--all", action="store_true", help="show all finding and update rows")
    history = commands.add_parser("history", help="query events, including changes, failures and update attempts")
    history.add_argument("--name")
    history.add_argument("--since", type=int, default=0, help="event cursor; at most 1000 events per page")
    preview = commands.add_parser("preview", help="show/save environment-wide update commands and observed candidates")
    preview.add_argument("name")
    apply = commands.add_parser("apply", help="approve and run a saved environment-wide update")
    apply.add_argument("plan", type=int)
    apply.add_argument("--yes", action="store_true", help="explicitly approve the scope and commands shown by preview")
    resolve = commands.add_parser("resolve", help="record manual recovery after inspecting an uncertain update")
    resolve.add_argument("plan", type=int)
    resolve.add_argument("--note", required=True)
    commands.add_parser("demo", help="run a temporary simulated workflow; no network or package operations")
    return p


def status(store, t):
    last = store.db.execute("SELECT kind,at FROM events WHERE target=? AND kind IN ('checked','collection_failed') ORDER BY id DESC LIMIT 1",
                            (t["name"],)).fetchone()
    report = store.latest(t["name"])
    pending = [dict(r) for r in store.db.execute("SELECT id,status,at FROM plans WHERE target=? AND status IN ('proposed','running','needs_attention') ORDER BY id", (t["name"],))]
    return {"target": t, "last_attempt": dict(last) if last else None, "report": report, "pending_updates": pending}


def dispatch(args, store, runner, request):
    if args.command == "add":
        t = adapters.target(args.name, args.kind, args.host, args.path)
        with store.transaction():
            if store.db.execute("SELECT 1 FROM targets WHERE name=?", (args.name,)).fetchone():
                raise Error("Environment already exists; use a new name rather than rewriting its history")
            store.db.execute("INSERT INTO targets VALUES(?,?)", (args.name, canonical(t)))
            store.event(args.name, "registered", t)
        return t
    if args.command == "list":
        return store.targets()
    if args.command in ("check", "status"):
        targets = [store.target(args.name)] if args.name else store.targets()
        results, refreshed = [], set()
        for t in targets:
            if args.command == "check":
                try:
                    workflow.check(store, t, offline=args.offline, refresh=args.refresh, refreshed=refreshed, runner=runner, request=request)
                except Error as exc:
                    results.append({**status(store, t), "error": str(exc)})
                    continue
            results.append(status(store, t))
        return results
    if args.command == "history":
        if args.since < 0:
            raise Error("Cursor must be nonnegative")
        rows = store.events(args.since, args.name)
        return {"events": rows, "next_cursor": rows[-1]["id"] if rows else args.since}
    if args.command == "preview":
        return workflow.preview(store, store.target(args.name), runner)
    if args.command == "apply":
        return workflow.apply(store, args.plan, yes=args.yes, runner=runner, request=request)
    if args.command == "resolve":
        return workflow.resolve(store, args.plan, text(args.note, "recovery note"))
    raise Error("Unknown command")


def display(result, json_output=False, show_all=False):
    if json_output or not (isinstance(result, list) and result and "report" in result[0]):
        print(json.dumps(result, ensure_ascii=True, indent=None if json_output else 2))
        return
    safe = lambda value: json.dumps(str(value), ensure_ascii=True)[1:-1]
    date = lambda at: datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if at is not None else "unknown"
    for item in result:
        t, report = item["target"], item["report"]
        print(f"{safe(t['name'])} ({safe(t['kind'])} on {safe(t['host'])})")
        if item.get("error"):
            print("  Error: " + safe(item["error"]))
        if (item.get("last_attempt") or {}).get("kind") == "collection_failed":
            print("  Collection failed; showing the previous report.")
        if not report:
            print("  No inventory collected. Run netwatch check " + safe(t["name"]))
            continue
        print(f"  Checked {date(report['at'])} | {len(report['packages'])} installed packages | {len(report['updates'])} available updates")
        if not report["advisory_check_ok"]:
            print("  Advisory check incomplete; retained results need review.")
        if report["update_error"]:
            print(f"  Update check: {safe(report['update_error'])}; last observed {date(report.get('updates_observed_at'))}")
        for plan in item["pending_updates"]:
            print(f"  Update plan {plan['id']}: {safe(plan['status'])}")
        updates = {u["package"]: u for u in report["updates"]}
        shortened = False
        for state, label in (("affected", "Affected"), ("unknown", "Needs review")):
            groups = defaultdict(list)
            for row in report["findings"]:
                if row["state"] == state:
                    groups[(row["package"], row["installed"])].append(row)
            print(f"\n{label}: {len(groups)} packages ({sum(map(len, groups.values()))} notices)")
            if groups and all(not r["fix_versions"] for rows in groups.values() for r in rows):
                print("  These notices have no published fix version; check applicability before taking action.")
            ordered = sorted(groups, key=lambda key: (key[0] not in updates, key))
            for key in ordered if show_all else ordered[:5]:
                rows = groups[key]
                ids = sorted({r["advisory"] for r in rows})
                fixes = sorted({v for r in rows for v in r["fix_versions"]})
                count = len(rows)
                print(f"  {safe(key[0])} {safe(key[1])}: {count} {'notice' if count == 1 else 'notices'}")
                print("    " + safe(", ".join(ids if show_all else ids[:3])) + (" ..." if not show_all and len(ids) > 3 else ""))
                print("    Reported fixes: " + safe(", ".join(fixes if show_all else fixes[:3]) or "none listed"))
                shortened |= not show_all and (len(ids) > 3 or len(fixes) > 3)
            shortened |= not show_all and len(ordered) > 5
        omitted = sum(e.get("matching", {}).get("fixed_notices_omitted", 0) for e in report.get("evidence", []))
        if omitted:
            print(f"\n{omitted} historical notices omitted: installed versions meet the tracker fixes.")
        if updates:
            print("\nAvailable updates:")
            versions = defaultdict(set)
            for p in report["packages"]:
                versions[p["name"]].add(p["version"])
            affected = {r["package"] for r in report["findings"] if r["state"] == "affected"}
            ordered = sorted(updates, key=lambda n: (n not in affected, n))
            for n in ordered if show_all else ordered[:10]:
                print(f"  {safe(n)}: {safe(', '.join(sorted(versions[n])) or '?')} -> {safe(updates[n].get('candidate') or 'unknown')}")
            shortened |= not show_all and len(ordered) > 10
        for warning in report["warnings"]:
            print("\n" + safe(warning))
        if shortened:
            print(f"\nAll rows: netwatch status {safe(t['name'])} --all")
        print(f"Full records: netwatch --json status {safe(t['name'])}\n")


def main(argv=None, *, runner=adapters.run, request=sources.fetch):
    args = parser().parse_args(argv)
    store = None
    try:
        if args.command == "demo":
            from .demo import demo
            result = demo()
        else:
            store = Store(args.db)
            result = dispatch(args, store, runner, request)
        display(result, args.json, show_all=getattr(args, "all", False))
        if args.command == "check" and any(r.get("error") or not r["report"]["advisory_check_ok"] or r["report"]["update_error"] for r in result):
            return 1
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError, sqlite3.Error) as exc:
        error = {"error": str(exc) if isinstance(exc, Error) else "Operation failed; check configuration and history"}
        if store:
            try:
                store.event(getattr(args, "name", None), "command_failed", {"command": args.command, "error_type": type(exc).__name__})
            except sqlite3.Error:
                error["logging_error"] = "Could not record failure; inspect storage and any running update"
        display(error, True)
        return 1
    except KeyboardInterrupt:
        display({"error": "Interrupted; inspect history before retrying an update"}, True)
        return 130
    finally:
        if store:
            store.close()
