"""Local recordkeeping. The database owner is trusted; this is not an auth service."""
import json
import os
from pathlib import Path
import sqlite3
import time
from contextlib import contextmanager

from .core import Error, canonical


class Store:
    def __init__(self, path):
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise Error("Database must not be a symlink")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
            raise Error("Database must be owned by this user with mode 600")
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        schema = self.db.execute("PRAGMA user_version").fetchone()[0]
        tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        if schema != 10 and (schema or tables):
            self.db.close()
            raise Error("Incompatible old database; keep it for history and use a new --db path")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS targets(name TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, body TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, kind TEXT, body TEXT);
            CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, at INTEGER, body TEXT);
            CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, status TEXT, body TEXT, result TEXT);
            PRAGMA user_version=10;
        """)

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.rollback()
            raise
        else:
            self.db.commit()

    def event(self, target, kind, body):
        self.db.execute("INSERT INTO events(target,at,kind,body) VALUES(?,?,?,?)",
                        (target, int(time.time()), kind, canonical(body)))

    def targets(self):
        return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM targets ORDER BY name")]

    def target(self, name):
        row = self.db.execute("SELECT body FROM targets WHERE name=?", (name,)).fetchone()
        if row is None:
            raise Error("Unknown environment; use add first")
        return json.loads(row[0])

    def latest(self, name):
        row = self.db.execute("SELECT id,at,body FROM scans WHERE target=? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
        return {"id": row["id"], "at": row["at"], **json.loads(row["body"])} if row else None

    def save_scan(self, name, report):
        with self.transaction():
            previous = self.latest(name)
            if previous and not report["advisory_check_ok"]:
                report["matcher_revision"] = previous.get("matcher_revision", 1)
            old = {r["key"]: r for r in previous["findings"]} if previous else {}
            new = {r["key"]: r for r in report["findings"]}
            for key, row in new.items():
                row["first_seen"] = old.get(key, {}).get("first_seen", int(time.time()))
                row["last_seen"] = int(time.time())
                semantic = lambda r: {k: v for k, v in r.items() if k not in ("first_seen", "last_seen")}
                if semantic(old.get(key, {})) != semantic(row):
                    self.event(name, "finding_changed" if key in old else "finding_new", row)
            # Only successful evidence collection can clear previous findings.
            if report["advisory_check_ok"]:
                removed = old.keys() - new.keys()
                if removed and previous.get("matcher_revision", 1) != report.get("matcher_revision", 1):
                    self.event(name, "findings_reassessed", {"previous_scan": previous["id"], "removed": len(removed),
                               "reason": "Matching rules changed; fewer findings do not imply packages were updated"})
                else:
                    for key in removed:
                        self.event(name, "finding_no_longer_detected", old[key])
            else:
                for key in old.keys() - new.keys():
                    new[key] = {**old[key], "state": "unknown", "reason": "Evidence incomplete; previous finding retained"}
                    if new[key] != old[key]:
                        self.event(name, "finding_changed", new[key])
            report["findings"] = sorted(new.values(), key=lambda r: r["key"])
            report["updates_observed_at"] = int(time.time())
            if report["update_error"]:
                report["updates"] = previous["updates"] if previous else []
                report["updates_observed_at"] = previous.get("updates_observed_at") if previous else None
            for field in ("updates", "warnings"):
                if not previous or previous.get(field) != report[field]:
                    self.event(name, field + "_changed", {field: report[field]})
            self.db.execute("INSERT INTO scans(target,at,body) VALUES(?,?,?)", (name, int(time.time()), canonical(report)))
            self.event(name, "checked", {"packages": len(report["packages"]), "advisory_check_ok": report["advisory_check_ok"]})
        return self.latest(name)

    def events(self, since=0, target=None):
        rows = self.db.execute("SELECT * FROM events WHERE id>? AND (? IS NULL OR target=?) ORDER BY id LIMIT 1000",
                               (since, target, target)).fetchall()
        return [{**dict(r), "body": json.loads(r["body"])} for r in rows]

    def cached(self, key, loader, *, offline=False, max_age=86400):
        row = self.db.execute("SELECT at,body FROM cache WHERE key=?", (key,)).fetchone()
        age = int(time.time()) - row["at"] if row else None
        if row and max_age > 0 and 0 <= age <= max_age:
            return json.loads(row["body"])
        if offline:
            raise Error("Missing or stale cached advisory evidence; run check without --offline")
        body = loader()
        self.db.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?)", (key, int(time.time()), canonical(body)))
        return body
