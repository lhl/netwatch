"""SQLite persistence for content identities and the serialized local lifecycle.

Callers must use transaction() for writes and read() for consistent read-only
views. Hashes detect corruption, not a writer who controls this database.
Approval actor labels are not authentication. Plans, approvals, outcomes and
audit events are never deleted. Source snapshots, findings sets and inventories
are retained while a head, plan, outcome or current findings set references
them; prune() removes the rest so repeated polling and triage stay bounded.
"""

from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
import json
import re
import sqlite3

from .core import AutoprotectError, PolicyError, ValidationError, canonical, digest, identifier, integer, load_json


SCHEMA_VERSION = 3
_PRUNABLE = ("source", "findings", "inventory")
_EXPECTED_TABLES = {"objects", "source_health", "inventory_heads", "finding_index", "finding_sets", "plan_status",
                    "approval_heads", "outcomes", "audit"}
# Verified canonical text for large immutable objects. Byte-identical rows are
# re-parsed without repeating validation/hashing; any difference re-verifies.
_VERIFIED_CACHE = 2
_VERIFIED_MIN_BYTES = 64 * 1024
_KINDS = {"source", "inventory", "findings", "plan", "approval"}
FINAL_STATUSES = frozenset({"succeeded", "failed", "needs_attention", "stale"})
_STATUSES = FINAL_STATUSES | {"pending", "approved", "executing"}


def content_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValidationError("Content ID must be a lowercase SHA-256 digest")
    return value


class Store:
    def __init__(self, path):
        self.connection = sqlite3.connect(str(path), timeout=5, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self._verified = OrderedDict()
        try:
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA busy_timeout = 5000")
            self.connection.execute("PRAGMA synchronous = FULL")
            with self.transaction():
                version = self.connection.execute("PRAGMA user_version").fetchone()[0]
                tables = self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
                names = {row[0] for row in tables}
                if version == 2 and names == _EXPECTED_TABLES - {"finding_sets"}:
                    self._migrate_from_2()
                elif version != SCHEMA_VERSION:
                    if version != 0 or tables:
                        raise ValidationError("Unsupported store schema version; use a compatible application")
                    self._initialize()
                elif names != _EXPECTED_TABLES:
                    raise ValidationError("Store schema is incomplete or unsupported")
        except BaseException:
            self.close()
            raise

    def _initialize(self):
        statements = [
            """CREATE TABLE objects (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('source','inventory','findings','plan','approval')),
                body TEXT NOT NULL)""",
            """CREATE TABLE source_health (
                source TEXT PRIMARY KEY CHECK(source IN ('pwn','debian')),
                snapshot_id TEXT REFERENCES objects(id), acquisition TEXT, endpoint TEXT, etag TEXT,
                last_attempt INTEGER NOT NULL, last_success INTEGER, error TEXT, revision INTEGER NOT NULL)""",
            """CREATE TABLE inventory_heads (
                asset_id TEXT PRIMARY KEY, inventory_id TEXT NOT NULL REFERENCES objects(id),
                backend TEXT CHECK(backend IN ('simulator','debian-apt')), target_generation TEXT,
                CHECK((backend IS NULL AND target_generation IS NULL) OR
                      (backend IS NOT NULL AND target_generation IS NOT NULL)))""",
            """CREATE TABLE finding_index (
                finding_id TEXT PRIMARY KEY, set_id TEXT NOT NULL REFERENCES objects(id))""",
            self._FINDING_SETS,
            """CREATE TABLE plan_status (
                plan_id TEXT PRIMARY KEY REFERENCES objects(id),
                status TEXT NOT NULL CHECK(status IN ('pending','approved','executing','succeeded','failed','needs_attention','stale')))""",
            """CREATE TABLE approval_heads (
                plan_id TEXT PRIMARY KEY REFERENCES plan_status(plan_id),
                approval_id TEXT NOT NULL REFERENCES objects(id))""",
            """CREATE TABLE outcomes (
                plan_id TEXT PRIMARY KEY REFERENCES plan_status(plan_id),
                body TEXT NOT NULL, digest TEXT NOT NULL, inventory_id TEXT REFERENCES objects(id))""",
            """CREATE TABLE audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL)""",
        ]
        for statement in statements:
            self.connection.execute(statement)
        for table in ("objects", "outcomes", "audit"):
            for operation in ("UPDATE", "DELETE"):
                if (table, operation) == ("objects", "DELETE"):
                    self.connection.execute(self._OBJECT_DELETE)
                    continue
                self.connection.execute(
                    f"CREATE TRIGGER immutable_{table}_{operation.lower()} BEFORE {operation} ON {table} "
                    "BEGIN SELECT RAISE(ABORT, 'immutable record'); END"
                )
        self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    _FINDING_SETS = """CREATE TABLE finding_sets (
        set_id TEXT PRIMARY KEY REFERENCES objects(id), inventory_id TEXT, source_digest TEXT)"""
    # Plans and approvals are permanent. Evidence objects may be removed only
    # through prune(), which first proves that nothing retained references them.
    _OBJECT_DELETE = ("CREATE TRIGGER immutable_objects_delete BEFORE DELETE ON objects "
                      "WHEN OLD.kind NOT IN ('source','findings','inventory') "
                      "BEGIN SELECT RAISE(ABORT, 'immutable record'); END")

    def _migrate_from_2(self):
        """Add findings-set metadata and evidence retention; keep every record."""
        self.connection.execute(self._FINDING_SETS)
        for (key,) in self.connection.execute("SELECT id FROM objects WHERE kind='findings'").fetchall():
            body = self.get("findings", key)
            self.connection.execute("INSERT INTO finding_sets VALUES (?,?,?)",
                                    (key, body.get("inventory_id"), body.get("source_digest")))
        self.connection.execute("DROP TRIGGER immutable_objects_delete")
        self.connection.execute(self._OBJECT_DELETE)
        self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @contextmanager
    def transaction(self):
        if self.connection.in_transaction:
            raise AutoprotectError("Nested store transactions are not supported")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    @contextmanager
    def read(self):
        """A consistent deferred read view that does not block a running writer."""
        if self.connection.in_transaction:
            raise AutoprotectError("Nested store transactions are not supported")
        self.connection.execute("BEGIN DEFERRED")
        try:
            yield self
        finally:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")

    def _writing(self):
        if not self.connection.in_transaction:
            raise AutoprotectError("Store writes require an explicit transaction")

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def put(self, kind, body):
        self._writing()
        if kind not in _KINDS:
            raise ValidationError("Unsupported immutable object kind")
        key = digest(body)
        existing = self.connection.execute("SELECT kind FROM objects WHERE id=?", (key,)).fetchone()
        if existing:
            if existing["kind"] != kind or self.get(kind, key) != body:
                raise ValidationError("Immutable content identity conflict")
        else:
            self.connection.execute("INSERT INTO objects VALUES (?, ?, ?)", (key, kind, canonical(body)))
        return key

    def get(self, kind, key):
        content_id(key)
        row = self.connection.execute("SELECT kind,body FROM objects WHERE id=?", (key,)).fetchone()
        if row is None or row["kind"] != kind:
            raise ValidationError("Requested immutable object does not exist with the expected kind")
        raw = row["body"]
        if self._verified.get(key) == raw:
            self._verified.move_to_end(key)
            return json.loads(raw)  # Exactly the canonical text verified below.
        body = load_json(raw, max_bytes=256 * 1024 * 1024, max_nodes=8_000_000)
        if digest(body) != key:
            raise ValidationError("Immutable object failed its content hash check")
        if len(raw) >= _VERIFIED_MIN_BYTES and canonical(body) == raw:
            self._verified[key] = raw
            while len(self._verified) > _VERIFIED_CACHE:
                self._verified.popitem(last=False)
        return body

    def source_health(self, source):
        row = self.connection.execute("SELECT * FROM source_health WHERE source=?", (source,)).fetchone()
        return dict(row) if row else None

    def record_source(self, source, at, *, body=None, etag=None, error=None):
        self._writing()
        if source not in ("pwn", "debian"):
            raise ValidationError("Source must be pwn or debian")
        integer(at, "source attempt time")
        previous = self.source_health(source)
        if error is not None:
            # Failures retain every last-good field, including validators and success time.
            values = dict(previous) if previous else {
                "snapshot_id": None, "acquisition": None, "endpoint": None, "etag": None, "last_success": None,
            }
        else:
            if body is None:
                if not previous or previous["snapshot_id"] is None:
                    raise ValidationError("Source refresh requires a previous snapshot")
                body = self.get("source", previous["snapshot_id"])
            if body["source"] != source:
                raise ValidationError("Source snapshot identity does not match its head")
            key = self.put("source", body)
            values = {"snapshot_id": key, "acquisition": body["acquisition"], "endpoint": body["endpoint"],
                      "etag": etag, "last_success": at}
        self.connection.execute(
            """INSERT INTO source_health VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(source) DO UPDATE SET snapshot_id=excluded.snapshot_id,
               acquisition=excluded.acquisition, endpoint=excluded.endpoint, etag=excluded.etag,
               last_attempt=excluded.last_attempt, last_success=excluded.last_success,
               error=excluded.error, revision=excluded.revision""",
            (source, values["snapshot_id"], values["acquisition"], values["endpoint"], values["etag"], at,
             values["last_success"], error, previous["revision"] + 1 if previous else 1),
        )
        return self.source_health(source)

    def save_inventory(self, body, *, backend=None, target_generation=None):
        """Record collection context separately; imported body labels cannot set it.

        An identical same-second observation may retain its content ID while a
        new collection replaces its head's recovery generation.
        """
        self._writing()
        if backend is not None or target_generation is not None:
            if backend not in ("simulator", "debian-apt") or target_generation is None:
                raise ValidationError("Collection context requires a supported backend and its generation")
            content_id(target_generation)
        key = self.put("inventory", body)
        self.connection.execute(
            """INSERT INTO inventory_heads VALUES (?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET
               inventory_id=excluded.inventory_id, backend=excluded.backend, target_generation=excluded.target_generation""",
            (body["asset_id"], key, backend, target_generation),
        )
        return {"id": key, "body": body}

    def inventory_context(self, asset_id):
        row = self.connection.execute(
            "SELECT inventory_id,backend,target_generation FROM inventory_heads WHERE asset_id=?", (asset_id,)
        ).fetchone()
        return dict(row) if row else None

    def inventory_head(self, asset_id):
        row = self.connection.execute("SELECT inventory_id FROM inventory_heads WHERE asset_id=?", (asset_id,)).fetchone()
        if row is None:
            raise PolicyError("No inventory is available; collect or import this asset first")
        return {"id": row[0], "body": self.get("inventory", row[0])}

    def save_findings(self, body):
        key = self.put("findings", body)
        self.connection.execute("INSERT OR IGNORE INTO finding_sets VALUES (?,?,?)",
                                (key, body.get("inventory_id"), body.get("source_digest")))
        for finding in body["findings"]:
            if digest({k: v for k, v in finding.items() if k != "id"}) != finding["id"]:
                raise ValidationError("Finding failed its content hash check")
            self.connection.execute("INSERT OR IGNORE INTO finding_index VALUES (?,?)", (finding["id"], key))
        return key

    def finding(self, key):
        content_id(key)
        row = self.connection.execute("SELECT set_id FROM finding_index WHERE finding_id=?", (key,)).fetchone()
        if row is None:
            raise ValidationError("Finding does not exist or is not plannable; run triage first")
        body = self.get("findings", row[0])
        for finding in body["findings"]:
            if finding["id"] == key:
                if digest({k: v for k, v in finding.items() if k != "id"}) != key:
                    raise ValidationError("Finding failed its content hash check")
                return finding
        raise ValidationError("Finding index does not match its immutable set")

    def save_plan(self, body):
        key = self.put("plan", body)
        self.connection.execute("INSERT OR IGNORE INTO plan_status VALUES (?, 'pending')", (key,))
        return self.plan(key)

    def plan(self, key):
        body = self.get("plan", key)
        row = self.connection.execute("SELECT status FROM plan_status WHERE plan_id=?", (key,)).fetchone()
        if row is None:
            raise ValidationError("Plan status is missing")
        return {"id": key, "body": body, "status": row[0]}

    def plans(self):
        return [self.plan(row[0]) for row in self.connection.execute("SELECT plan_id FROM plan_status ORDER BY rowid")]

    def set_status(self, key, status, *, expected):
        self._writing()
        if status not in _STATUSES or not expected or any(item not in _STATUSES for item in expected):
            raise ValidationError("Unsupported plan status transition")
        placeholders = ",".join("?" for _ in expected)
        changed = self.connection.execute(
            f"UPDATE plan_status SET status=? WHERE plan_id=? AND status IN ({placeholders})", (status, key, *expected)
        ).rowcount
        if changed != 1:
            raise PolicyError("Plan status changed or is final; inspect the queue and create a new plan")

    def approve(self, body):
        self._writing()
        key = self.put("approval", body)
        self.connection.execute(
            "INSERT INTO approval_heads VALUES (?,?) ON CONFLICT(plan_id) DO UPDATE SET approval_id=excluded.approval_id",
            (body["plan_id"], key),
        )
        self.set_status(body["plan_id"], "approved", expected=("pending", "approved"))
        return key

    def approval(self, plan_id):
        row = self.connection.execute("SELECT approval_id FROM approval_heads WHERE plan_id=?", (plan_id,)).fetchone()
        return self.get("approval", row[0]) if row else None

    def claim(self, plan_id, at, *, expected):
        self._writing()
        self.set_status(plan_id, "executing", expected=expected)
        self.event(at, "execution-start", {"plan_id": plan_id})

    def save_outcome(self, plan_id, status, result, inventory_id, at, *, expected=("executing",)):
        self._writing()
        self.set_status(plan_id, status, expected=expected)
        body = {"plan_id": plan_id, "status": status, "result": result, "inventory_id": inventory_id}
        self.connection.execute("INSERT INTO outcomes VALUES (?,?,?,?)", (plan_id, canonical(body), digest(body), inventory_id))
        self.event(at, "execution-outcome", {"plan_id": plan_id, "status": status, "reason": result["reason"]})
        return body

    def outcome(self, plan_id):
        row = self.connection.execute("SELECT body,digest FROM outcomes WHERE plan_id=?", (plan_id,)).fetchone()
        if row is None:
            return None
        body = load_json(row["body"])
        if digest(body) != row["digest"]:
            raise ValidationError("Execution outcome failed its content hash check")
        return body

    def prune(self):
        """Delete unreferenced evidence objects inside the caller's transaction.

        Retained: source heads and every plan's source snapshot; findings sets
        referenced by a plan, or built from a current inventory head and the
        current Debian head; inventory heads and every inventory named by a
        plan, outcome or retained findings set. Returns deleted counts by kind.
        """
        self._writing()
        plans = [self.get("plan", row[0]) for row in self.connection.execute("SELECT plan_id FROM plan_status")]
        keep_sources = {row[0] for row in self.connection.execute(
            "SELECT snapshot_id FROM source_health WHERE snapshot_id IS NOT NULL")}
        keep_sources |= {plan["source_digest"] for plan in plans if "source_digest" in plan}
        heads = {row[0] for row in self.connection.execute("SELECT inventory_id FROM inventory_heads")}
        debian = self.connection.execute("SELECT snapshot_id FROM source_health WHERE source='debian'").fetchone()
        current_source = debian[0] if debian else None
        keep_sets = set()
        for plan in plans:
            if "finding_id" in plan:
                row = self.connection.execute("SELECT set_id FROM finding_index WHERE finding_id=?",
                                              (plan["finding_id"],)).fetchone()
                if row:
                    keep_sets.add(row[0])
        for set_id, inventory_id, source_digest in self.connection.execute(
                "SELECT set_id, inventory_id, source_digest FROM finding_sets"):
            if current_source is not None and source_digest == current_source and inventory_id in heads:
                keep_sets.add(set_id)
        keep_inventories = set(heads)
        keep_inventories |= {plan["inventory_id"] for plan in plans if "inventory_id" in plan}
        keep_inventories |= {row[0] for row in self.connection.execute(
            "SELECT inventory_id FROM outcomes WHERE inventory_id IS NOT NULL")}
        for set_id, inventory_id in self.connection.execute("SELECT set_id, inventory_id FROM finding_sets"):
            if set_id in keep_sets and inventory_id is not None:
                keep_inventories.add(inventory_id)
        deleted = {}
        candidates = {kind: [row[0] for row in self.connection.execute("SELECT id FROM objects WHERE kind=?", (kind,))]
                      for kind in _PRUNABLE}
        keep = {"source": keep_sources, "findings": keep_sets, "inventory": keep_inventories}
        for kind in ("findings", "source", "inventory"):
            doomed = [key for key in candidates[kind] if key not in keep[kind]]
            for key in doomed:
                if kind == "findings":
                    self.connection.execute("DELETE FROM finding_index WHERE set_id=?", (key,))
                    self.connection.execute("DELETE FROM finding_sets WHERE set_id=?", (key,))
                self.connection.execute("DELETE FROM objects WHERE id=? AND kind=?", (key, kind))
                self._verified.pop(key, None)
            deleted[kind] = len(doomed)
        return deleted

    def event(self, at, event, details):
        self._writing()
        integer(at, "audit time")
        identifier(event, "audit event")
        encoded = canonical(details)
        if len(encoded) > 16384:
            raise ValidationError("Audit details exceed the supported size")
        self.connection.execute("INSERT INTO audit(at,event,details) VALUES (?,?,?)", (at, event, encoded))

    def audit(self):
        return [{"id": row["id"], "at": row["at"], "event": row["event"], "details": load_json(row["details"])}
                for row in self.connection.execute("SELECT * FROM audit ORDER BY id")]
