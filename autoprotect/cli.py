"""Small CLI. Reports are data, not instructions to a privileged agent."""
import argparse
import json
import os
from pathlib import Path
import sqlite3

from . import adapters, sources, workflow
from .core import Error, canonical, text
from .store import Store


def parser():
    p = argparse.ArgumentParser(description="Track environments, security advisories and human-approved updates.")
    p.add_argument("--db", default=os.path.expanduser("~/.local/state/autoprotect/state.db"))
    p.add_argument("--json", action="store_true", help="machine-readable JSON (all strings escaped)")
    p.add_argument("--version", action="version", version="autoprotect 0.2.0")
    commands = p.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add", help="register one OS, environment or project; does not connect")
    add.add_argument("name")
    add.add_argument("kind", choices=adapters.KINDS)
    add.add_argument("--host", default="local", help="local or a configured SSH alias/user@host")
    add.add_argument("--path", help="absolute conda prefix or uv/npm project directory")
    commands.add_parser("list", help="list explicitly registered environments")
    check = commands.add_parser("check", help="collect inventory, query/cache advisories and discover updates")
    check.add_argument("name", nargs="?", help="omit to check all registered environments")
    mode = check.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true", help="use fresh advisory cache; still collects inventory over SSH")
    mode.add_argument("--refresh", action="store_true", help="fetch fresh advisories instead of using the one-hour cache")
    status = commands.add_parser("status", help="query cached reports without connecting")
    status.add_argument("name", nargs="?")
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


def display(result, json_output=False):
    # Escaping prevents control sequences in remote package names or source text.
    if not json_output and isinstance(result, list) and result and "report" in result[0]:
        for item in result:
            report = item["report"]
            print(canonical({"environment": item["target"]["name"], "last_attempt": item["last_attempt"],
                             "error": item.get("error"), "pending_updates": item["pending_updates"],
                             "checked_at": report["at"] if report else None}))
            if report:
                print(f"  {len(report['packages'])} packages; {len(report['findings'])} findings; {len(report['updates'])} available updates")
                for field in ("findings", "updates", "warnings"):
                    for row in report[field]:
                        print("  " + field + ": " + canonical(row))
    else:
        print(json.dumps(result, ensure_ascii=True, indent=None if json_output else 2))


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
        display(result, args.json)
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
