"""Policy-bound local remediation with immutable plans and durable recovery gates."""

from __future__ import annotations

import copy
import re
import sqlite3

from . import core, feeds
from .core import BackendError, IndeterminateError, PolicyError, ValidationError
from .debian import compare_versions
from .inventory import inventory_fingerprint, normalize_inventory
from .matching import match, verify_affected
from .store import FINAL_STATUSES, content_id


_MAX_DURATION = 31_536_000
_ORIGIN_FIELDS = {"origin", "label", "archive", "codename", "component", "site"}
_POLICY_FIELDS = {
    "schema_version", "mode", "backend", "allowed_assets", "allowed_packages", "allowed_origins",
    "approved_config_digest", "max_inventory_age", "max_feed_age", "max_repository_age", "plan_ttl", "approval_ttl",
    "allow_maintainer_scripts", "recovery_confirmed", "trusted_installed_lineage",
}
_TARGET_FIELDS = {"name", "architecture", "from_version", "to_version", "source_name", "source_version",
                  "sha256", "size", "origins", "config_digest", "metadata_digest"}
_ENDPOINTS = {"pwn": "https://pwn.watch/incidents.json",
              "debian": "https://security-tracker.debian.org/tracker/data/json"}


class _Stale(PolicyError):
    pass


class _AuthorizationStopped(BackendError):
    """Raised only by our callback before the backend may start installation."""


def _exact(data, fields, label):
    if type(data) is not dict or set(data) != fields:
        raise ValidationError(f"{label} must contain exactly the documented fields")


def _label(value, field, limit=256):
    value = core.text(value, field, max_length=limit)
    if value.strip() != value or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValidationError(f"{field} must be bounded printable ASCII without surrounding whitespace")
    return value


def _origins(value):
    if type(value) is not list or len(value) > 256:
        raise ValidationError("Origins must be a list of at most 256 exact origin tuples")
    result = []
    for origin in value:
        _exact(origin, _ORIGIN_FIELDS, "Origin")
        item = {key: _label(origin[key], "origin " + key) for key in sorted(_ORIGIN_FIELDS)}
        if item["codename"] not in ("trixie", "trixie-updates", "trixie-security"):
            raise ValidationError("Repository codename must be trixie, trixie-updates, or trixie-security")
        result.append(item)
    encoded = [core.canonical(item) for item in result]
    if len(set(encoded)) != len(encoded):
        raise ValidationError("Origins must not contain duplicates")
    return sorted(result, key=core.canonical)


def validate_policy(data):
    """Validate every field; return a detached, canonicalized policy.

    Durations are 1..31,536,000 seconds, matching the supported matching window.
    Actor labels and the three live assertions are not identity/backup proofs.
    """
    _exact(data, _POLICY_FIELDS, "Policy")
    core.integer(data["schema_version"], "schema_version", minimum=1, maximum=1)
    if data["mode"] not in ("observe", "manual", "auto"):
        raise ValidationError("Policy mode must be observe, manual, or auto")
    if data["backend"] not in ("simulator", "debian-apt"):
        raise ValidationError("Policy backend must be simulator or debian-apt")
    result = copy.deepcopy(data)
    for field, validator in (("allowed_assets", core.identifier), ("allowed_packages", core.package_name)):
        values = data[field]
        if type(values) is not list or not 1 <= len(values) <= 10000:
            raise ValidationError(f"{field} must be a nonempty list of at most 10000 exact identities")
        checked = [validator(item, field) for item in values]
        if len(set(checked)) != len(checked):
            raise ValidationError(f"{field} must not contain duplicates")
        result[field] = sorted(checked)
    result["allowed_origins"] = _origins(data["allowed_origins"])
    if data["approved_config_digest"] is not None:
        content_id(data["approved_config_digest"])
    if data["backend"] == "debian-apt" and (not result["allowed_origins"] or data["approved_config_digest"] is None):
        raise ValidationError("Native policy requires exact approved origins and a configuration digest")
    for field in ("max_inventory_age", "max_feed_age", "max_repository_age", "plan_ttl", "approval_ttl"):
        core.integer(data[field], field, minimum=1, maximum=_MAX_DURATION)
    for field in ("allow_maintainer_scripts", "recovery_confirmed", "trusted_installed_lineage"):
        if type(data[field]) is not bool:
            raise ValidationError(f"{field} must be a boolean")
    return result


class Engine:
    def __init__(self, store, policy_provider, backend, *, clock=core.now, fetcher=None):
        if not callable(policy_provider):
            raise ValidationError("Policy provider must be callable and reload policy at each boundary")
        if not callable(clock) or (fetcher is not None and not callable(fetcher)):
            raise ValidationError("Clock and fetcher must be callable constructor dependencies")
        self.store = store
        self.policy_provider = policy_provider
        self.backend = backend
        self.clock = clock
        self._fetcher = feeds.fetch_source if fetcher is None else fetcher
        # Snapshot IDs whose records digest was checked. The Store re-verifies
        # the immutable bytes on every load; this property follows from them.
        self._content_checked = set()

    def _now(self):
        return core.integer(self.clock(), "current time")

    def _policy(self):
        return validate_policy(self.policy_provider())

    def _run(self, action, operation, plan_id=None):
        """Commit denials/staleness, but never a partly completed operation."""
        failure = None
        with self.store.transaction():
            # A savepoint rolls back partial work while retaining the denial event.
            self.store.connection.execute("SAVEPOINT decision")
            try:
                value = operation()
            except (PolicyError, ValidationError) as exc:
                self.store.connection.execute("ROLLBACK TO decision")
                if isinstance(exc, _Stale) and plan_id is not None:
                    current = self.store.plan(plan_id)
                    if current["status"] in ("pending", "approved"):
                        self.store.set_status(plan_id, "stale", expected=("pending", "approved"))
                self.store.event(self._now(), "action-denied", {"action": action, "plan_id": plan_id,
                                                               "reason": str(exc)})
                failure = exc
            finally:
                self.store.connection.execute("RELEASE decision")
        if failure is not None:
            raise failure
        return value

    @staticmethod
    def _source(source):
        if not isinstance(source, str) or source not in _ENDPOINTS:
            raise ValidationError("Source must be pwn or debian; custom endpoints are not supported")
        return source

    @staticmethod
    def _etag(value):
        if value is not None and (not isinstance(value, str) or len(value) > 512 or
                                  not re.fullmatch(r'(?:W/)?"[\x21\x23-\x7e]*"', value)):
            raise ValidationError("ETag must be a bounded quoted ASCII validator")
        return value

    def _source_body(self, source, raw, acquisition):
        # Parse once at the entry point so explicit provenance envelopes cannot
        # be mistaken for source documents. Unknown ordinary feed fields remain data.
        data = core.load_json(raw, max_bytes=(128 if source == "debian" else 8) * 1024 * 1024,
                              max_nodes=8_000_000)
        if isinstance(data, dict) and ("acquisition" in data or "provenance" in data):
            raise ValidationError("Feed bodies cannot supply acquisition provenance")
        records = feeds.parse_pwn(data) if source == "pwn" else feeds.parse_debian(data)
        return {"schema_version": 1, "source": source, "parser_version": 1, "acquisition": acquisition,
                "endpoint": _ENDPOINTS[source] if acquisition == "https" else None,
                "content_digest": core.digest(records), "records": records}

    def ingest(self, source, raw, acquisition="import", etag=None):
        source = self._source(source)
        if acquisition != "import" or etag is not None:
            raise ValidationError("Ingest accepts imports only, without HTTPS provenance or validators; use poll")
        try:
            body = self._source_body(source, raw, "import")
        except ValidationError:
            with self.store.transaction():
                self.store.record_source(source, self._now(), error="Import validation failed; previous good data retained")
                self.store.event(self._now(), "source-error", {"source": source, "operation": "import"})
            raise
        with self.store.transaction():
            result = self.store.record_source(source, self._now(), body=body)
            self.store.event(self._now(), "source-import", {"source": source, "snapshot_id": result["snapshot_id"]})
            self._prune()
            return result

    def _prune(self):
        deleted = self.store.prune()
        if any(deleted.values()):
            self.store.event(self._now(), "evidence-pruned", deleted)

    def poll(self, source):
        source = self._source(source)
        # Fetch and parse without holding the write lock. The response is
        # installed only if the source head is still the one it was requested
        # against, so a concurrent import/poll is never overwritten.
        with self.store.read():
            previous = self.store.source_health(source)
            validator = prior_body = None
            if previous and previous["snapshot_id"] and previous["acquisition"] == "https":
                prior_body = self.store.get("source", previous["snapshot_id"])
                if prior_body["endpoint"] == _ENDPOINTS[source] and prior_body["source"] == source:
                    validator = self._etag(previous["etag"])
        revision = previous["revision"] if previous else None
        failure = body = etag = response = None
        try:
            response = self._fetcher(source, etag=validator)
            _exact(response, {"not_modified", "raw", "etag"}, "Fetch result")
            if type(response["not_modified"]) is not bool:
                raise ValidationError("Fetch result not_modified must be boolean")
            etag = self._etag(response["etag"])
            if response["not_modified"]:
                if validator is None or response["raw"] is not None:
                    raise ValidationError("304 requires a prior same-source HTTPS snapshot and request validator")
                body = prior_body
                etag = etag or validator
            else:
                body = self._source_body(source, response["raw"], "https")
        except (Exception, KeyboardInterrupt) as exc:
            failure = exc
        with self.store.transaction():
            current = self.store.source_health(source)
            if (current["revision"] if current else None) != revision:
                self.store.event(self._now(), "source-error", {"source": source, "operation": "poll",
                                                               "reason": "source head changed concurrently"})
                changed = True
            else:
                changed = False
                if failure is None:
                    # A savepoint rolls back a partly recorded success while
                    # retaining the failed-acquisition record below.
                    self.store.connection.execute("SAVEPOINT poll_result")
                    try:
                        result = self.store.record_source(source, self._now(), body=body, etag=etag)
                        self.store.event(self._now(), "source-poll", {"source": source, "snapshot_id": result["snapshot_id"],
                                                                     "not_modified": response["not_modified"]})
                        self._prune()
                    except (Exception, KeyboardInterrupt) as exc:
                        self.store.connection.execute("ROLLBACK TO poll_result")
                        failure = exc
                    finally:
                        self.store.connection.execute("RELEASE poll_result")
                if failure is not None:
                    result = self.store.record_source(source, self._now(), error="HTTPS refresh failed; previous good data retained")
                    self.store.event(self._now(), "source-error", {"source": source, "operation": "poll"})
        if isinstance(failure, KeyboardInterrupt):
            raise failure
        if changed:
            raise core.AutoprotectError("Source head changed during this poll; the response was discarded, poll again")
        # Health summaries expose failed acquisition without leaking remote text.
        return result

    def _inspect(self):
        if self.backend.name not in ("simulator", "debian-apt"):
            raise PolicyError("Unsupported backend")
        expected = "simulator" if self.backend.name == "simulator" else "native"
        data = self.backend.inspect()
        if not isinstance(data, dict) or data.get("collector") != expected:
            raise BackendError("Backend inventory has the wrong collector provenance")
        return normalize_inventory(data, collector=expected)

    def _generation(self):
        if self.backend.name not in ("simulator", "debian-apt"):
            raise PolicyError("Unsupported backend")
        return content_id(self.backend.generation())

    def _collection_generation(self, asset_id):
        context = self.store.inventory_context(asset_id)
        generation = self._generation()
        if (context is None or context["backend"] != self.backend.name or
                context["target_generation"] != generation):
            raise _Stale("Collection context or recovery generation changed; collect fresh backend inventory before planning")
        return generation

    def inventory(self, data=None):
        with self.store.transaction():
            generation = self._generation() if data is None else None
            body = normalize_inventory(data) if data is not None else self._inspect()
            if data is None and generation != self._generation():
                raise _Stale("Recovery generation changed during observation; collect again")
            result = self.store.save_inventory(body, backend=self.backend.name if data is None else None,
                                               target_generation=generation)
            self.store.event(self._now(), "inventory-observed", {"asset_id": body["asset_id"], "inventory_id": result["id"],
                "collector": body["collector"], "backend": self.backend.name if data is None else None,
                "target_generation": generation})
            return result

    def _source_snapshot(self, source):
        health = self.store.source_health(source)
        if not health or not health["snapshot_id"]:
            return health, None
        body = self.store.get("source", health["snapshot_id"])
        if (body["source"] != source or body["acquisition"] != health["acquisition"] or
                body["endpoint"] != health["endpoint"]):
            raise ValidationError("Source head does not match its immutable acquisition metadata")
        if health["snapshot_id"] not in self._content_checked:
            if core.digest(body["records"]) != body["content_digest"]:
                raise ValidationError("Source head does not match its immutable acquisition metadata")
            self._content_checked.add(health["snapshot_id"])
        return health, body

    def _triage(self, asset_id, policy):
        inventory = self.store.inventory_head(asset_id)
        health, debian = self._source_snapshot("debian")
        _, pwn = self._source_snapshot("pwn")
        usable = health and health["last_success"] is not None and not health["error"] and (
            0 <= self._now() - health["last_success"] <= policy["max_feed_age"])
        findings = match(inventory["body"], debian["records"] if debian and usable else [], pwn["records"] if pwn else [],
                         inventory_id=inventory["id"], source_digest=health["snapshot_id"] if debian else core.digest([]),
                         now=self._now(), max_inventory_age=policy["max_inventory_age"],
                         evidence_acquisition=debian["acquisition"] if debian and usable else None)
        if not usable:
            for row in findings:
                row["reason"] += "; Debian source is missing, stale, or has a current error; refresh it before remediation"
                row["id"] = core.digest({k: v for k, v in row.items() if k != "id"})
        # Only affected findings can become plans. Persist those, not the
        # complete (possibly large) investigation result returned to the caller.
        self.store.save_findings({"inventory_id": inventory["id"], "source_digest": health["snapshot_id"] if debian else None,
                                  "findings": [row for row in findings if row["status"] == "affected"]})
        self._prune()
        return findings

    def triage(self, asset_id):
        asset_id = core.identifier(asset_id, "asset ID")
        with self.store.transaction():
            findings = self._triage(asset_id, self._policy())
            self.store.event(self._now(), "triage", {"asset_id": asset_id, "count": len(findings)})
            return findings

    def _evidence(self, policy, inventory, source_digest):
        at = self._now()
        if not 0 <= at - inventory["observed_at"] <= policy["max_inventory_age"]:
            raise _Stale("Inventory is stale or in the future; collect again and replan")
        health, body = self._source_snapshot("debian")
        if body is None or health["snapshot_id"] != source_digest:
            raise _Stale("Debian source head changed or is missing; refresh triage and replan")
        if health["error"] or health["last_success"] is None or not 0 <= at - health["last_success"] <= policy["max_feed_age"]:
            raise _Stale("Debian source is stale or has a current error; refresh it and replan")
        if policy["backend"] == "debian-apt" and (body["acquisition"] != "https" or body["endpoint"] != _ENDPOINTS["debian"]):
            raise PolicyError("Native execution requires Debian evidence acquired by a successful fixed-endpoint poll")
        return body

    def _permission(self, policy, inventory, package):
        if self.backend.name != policy["backend"]:
            raise PolicyError("Configured backend does not match policy")
        if inventory["asset_id"] not in policy["allowed_assets"] or package["name"] not in policy["allowed_packages"]:
            raise PolicyError("Asset or package is outside the exact policy allowlists")
        if not inventory["complete"] or (inventory["os"], inventory["release"], inventory["architecture"]) != ("debian", "trixie", "amd64"):
            raise PolicyError("Remediation requires complete Debian trixie amd64 inventory")
        if package["ecosystem"] != "deb" or package["architecture"] not in ("amd64", "all") or package["held"] or package["status"] != "installed":
            raise PolicyError("Target package must be a supported, fully installed, unheld Debian package")
        if policy["backend"] == "debian-apt":
            if inventory["collector"] != "native":
                raise PolicyError("Native remediation requires fresh native inventory, not an imported collector label")
            if not all(policy[field] for field in ("allow_maintainer_scripts", "recovery_confirmed", "trusted_installed_lineage")):
                raise PolicyError("Native remediation requires explicit script, recovery, and installed-lineage assertions")

    def _target(self, target, package, fixed, policy):
        _exact(target, _TARGET_FIELDS, "Repository target")
        for field in ("name", "source_name"):
            core.package_name(target[field], field)
        core.identifier(target["architecture"], "target architecture")
        for field in ("from_version", "to_version", "source_version"):
            core.version(target[field], field)
        for field in ("sha256", "config_digest", "metadata_digest"):
            content_id(target[field])
        core.integer(target["size"], "artifact size", minimum=1)
        origins = _origins(target["origins"])
        if (target["name"], target["architecture"], target["from_version"], target["source_name"]) != (
            package["name"], package["architecture"], package["version"], package["source_name"]
        ):
            raise PolicyError("Repository target does not match the bound installed package")
        if compare_versions(target["to_version"], package["version"]) <= 0 or compare_versions(target["source_version"], fixed) < 0:
            raise PolicyError("Repository candidate must increase the binary version and meet the Debian source fix")
        if policy["backend"] == "debian-apt":
            if target["config_digest"] != policy["approved_config_digest"] or not origins or any(
                origin not in policy["allowed_origins"] for origin in origins
            ):
                raise PolicyError("Repository configuration or exact artifact origins are not approved")
        # Bind the complete backend object, including its original list ordering.
        return copy.deepcopy(target)

    def _finding_context(self, finding, policy):
        if "advisory_ids" not in finding:
            raise _Stale("Finding predates grouped advisory findings; triage again and replan")
        if finding["status"] != "affected" or finding["package"] is None or finding["fixed_version"] in (None, "0"):
            raise PolicyError("Only an affected Debian finding with a supported fix can produce a plan")
        core.version(finding["fixed_version"], "fixed version")
        original = self.store.get("inventory", finding["inventory_id"])
        current = self.store.inventory_head(finding["asset_id"])
        if inventory_fingerprint(original) != inventory_fingerprint(current["body"]):
            raise _Stale("Finding inventory changed; collect, triage, and replan")
        source = self._evidence(policy, current["body"], finding["source_digest"])
        self._permission(policy, current["body"], finding["package"])
        self._collection_generation(finding["asset_id"])
        # Recompute rather than letting a stored affected label grant authority.
        if not verify_affected(
                original, source["records"], package=finding["package"], advisory_ids=finding["advisory_ids"],
                fixed_version=finding["fixed_version"], max_inventory_age=policy["max_inventory_age"]):
            raise PolicyError("Finding is not supported by its immutable Debian evidence")
        return current["body"]

    def plan(self, finding_id):
        content_id(finding_id)
        def create():
            policy = self._policy()
            finding = self.store.finding(finding_id)
            inventory = self._finding_context(finding, policy)
            target = self._target(self.backend.resolve(copy.deepcopy(inventory), copy.deepcopy(finding), copy.deepcopy(policy)),
                                  finding["package"], finding["fixed_version"], policy)
            # Resolving may be lengthy; reload policy/freshness before binding it.
            if core.digest(self._policy()) != core.digest(policy):
                raise _Stale("Policy changed during planning; retry with current policy")
            self._finding_context(finding, policy)
            at = self._now()
            body = {"schema_version": 1, "asset_id": finding["asset_id"], "backend": self.backend.name,
                    "target_generation": self._collection_generation(finding["asset_id"]),
                    "inventory_id": finding["inventory_id"], "inventory_fingerprint": inventory_fingerprint(inventory),
                    "source_digest": finding["source_digest"], "finding_id": finding_id, "advisory_ids": finding["advisory_ids"],
                    "fixed_version": finding["fixed_version"], "policy_digest": core.digest(policy), "target": target,
                    "created_at": at, "expires_at": at + policy["plan_ttl"]}
            self._final_authorization(body, inventory_at=inventory["observed_at"], allow_observe=True)
            result = self.store.save_plan(body)
            self.store.event(at, "plan-created", {"plan_id": result["id"], "finding_id": finding_id})
            return result
        return self._run("plan", create)

    def _final_authorization(self, body, *, inventory_at, approved=None, fresh_at=None, allow_observe=False):
        """Bounded final check, after all inventory/source hashing and matching.

        The write transaction fixes source, inventory and approval rows. Only
        small head/context reads, the bounded policy document and generation
        token are reloaded here. Read the clock last, then compare scalar time
        bounds; never call inventory matching or immutable source loading here.
        """
        if self._collection_generation(body["asset_id"]) != content_id(body["target_generation"]):
            raise _Stale("Plan recovery generation changed; collect, create a new plan, and renew authorization")
        health = self.store.source_health("debian")
        if (health is None or health["snapshot_id"] != body["source_digest"] or health["error"] or
                health["last_success"] is None):
            raise _Stale("Debian source head changed or has a current error; refresh it and replan")
        policy = self._policy()
        if not allow_observe and policy["mode"] == "observe":
            raise PolicyError("Observe policy permits neither approval nor execution")
        if core.digest(policy) != body["policy_digest"]:
            raise _Stale("Policy changed during authorization; create a plan bound to current policy")
        at = self._now()
        if not body["created_at"] <= at < body["expires_at"]:
            raise _Stale("Plan expired or has a future creation time; replan")
        for observed_at in (inventory_at, fresh_at):
            if observed_at is not None and not 0 <= at - observed_at <= policy["max_inventory_age"]:
                raise _Stale("Inventory is stale or in the future; collect again and replan")
        if not 0 <= at - health["last_success"] <= policy["max_feed_age"]:
            raise _Stale("Debian source is stale or in the future; refresh it and replan")
        if approved is not None and not approved["created_at"] <= at < approved["expires_at"]:
            raise _Stale("Approval expired or has a future creation time; renew authorization")

    def _validate_plan(self, plan_id, *, executing=False, approval=True, fresh_observed_at=None):
        envelope = self.store.plan(plan_id)
        if envelope["status"] not in (("executing",) if executing else ("pending", "approved")):
            raise PolicyError("Plan is final or already claimed; collect and create a new plan")
        body = envelope["body"]
        if "advisory_ids" not in body:
            raise _Stale("Plan predates grouped advisory findings; triage again and create a new plan")
        policy = self._policy()
        if policy["mode"] == "observe":
            raise PolicyError("Observe policy permits neither approval nor execution")
        if core.digest(policy) != body["policy_digest"]:
            raise _Stale("Policy changed; create a plan bound to current policy")
        at = self._now()
        if not body["created_at"] <= at < body["expires_at"]:
            raise _Stale("Plan expired or has a future creation time; replan")
        if body["backend"] != self.backend.name:
            raise PolicyError("Plan backend does not match this executor")
        original = self.store.get("inventory", body["inventory_id"])
        current = self.store.inventory_head(body["asset_id"])["body"]
        if (inventory_fingerprint(original) != body["inventory_fingerprint"] or
                inventory_fingerprint(current) != body["inventory_fingerprint"]):
            raise _Stale("Inventory head no longer matches the plan; collect and replan")
        finding = self.store.finding(body["finding_id"])
        if any(body[field] != finding[field] for field in ("asset_id", "inventory_id", "source_digest", "advisory_ids", "fixed_version")):
            raise ValidationError("Plan does not match its bound finding")
        self._finding_context(finding, policy)
        self._target(body["target"], finding["package"], body["fixed_version"], policy)
        approved = None
        if approval and policy["mode"] == "manual":
            approved = self.store.approval(plan_id)
            if approved is None:
                raise PolicyError("Manual execution requires explicit approval of this immutable plan")
            if (approved["plan_id"] != plan_id or approved["policy_digest"] != body["policy_digest"] or
                    approved["expires_at"] > body["expires_at"] or not approved["created_at"] <= at < approved["expires_at"]):
                raise _Stale("Approval expired or does not match the plan; create and approve a fresh plan")
            if envelope["status"] != ("executing" if executing else "approved"):
                raise PolicyError("Manual plan does not have approved queue status")
        self._final_authorization(body, inventory_at=current["observed_at"], approved=approved, fresh_at=fresh_observed_at)
        return body, policy, finding

    def approve(self, plan_id, actor):
        content_id(plan_id)
        actor = _label(actor, "actor audit label", 128)
        def approve():
            body, policy, _ = self._validate_plan(plan_id, approval=False)
            at = self._now()
            self.store.approve({"plan_id": plan_id, "policy_digest": body["policy_digest"], "actor": actor,
                                "created_at": at, "expires_at": min(body["expires_at"], at + policy["approval_ttl"])})
            self.store.event(at, "plan-approved", {"plan_id": plan_id, "actor": actor, "actor_is_authenticated": False})
            return self.store.plan(plan_id)
        return self._run("approve", approve, plan_id)

    def _preflight(self, plan_id, *, executing=False):
        body, policy, finding = self._validate_plan(plan_id, executing=executing)
        fresh = self._inspect()
        if inventory_fingerprint(fresh) != body["inventory_fingerprint"]:
            raise _Stale("Backend package state changed; collect and replan")
        self._evidence(policy, fresh, body["source_digest"])
        target = self._target(self.backend.resolve(copy.deepcopy(fresh), copy.deepcopy(finding), copy.deepcopy(policy)),
                              finding["package"], body["fixed_version"], policy)
        if target != body["target"]:
            raise _Stale("Repository artifact or transaction changed; replan and obtain renewed authorization")
        # The last validation ends with bounded policy/generation reads and a
        # clock check of every deadline, after its final costly matching pass.
        self._validate_plan(plan_id, executing=executing, fresh_observed_at=fresh["observed_at"])
        return body, policy, fresh

    def execute(self, plan_id):
        content_id(plan_id)
        envelope = self.store.plan(plan_id)
        with self.backend.lock(envelope["body"]["asset_id"]):
            def claim():
                body, policy, _ = self._preflight(plan_id)
                # begin must be durable before committing executing. Any error,
                # including an interrupt or uncertain commit, leaves this gate.
                self.backend.begin(plan_id)
                self.store.claim(plan_id, self._now(), expected=("approved",) if policy["mode"] == "manual" else ("pending", "approved"))
                return body
            try:
                self._run("execute", claim, plan_id)
            except sqlite3.Error as exc:
                raise IndeterminateError("Execution claim persistence is uncertain; inspect the queue and resolve the target gate") from exc
            return self._execute_claimed(plan_id)

    def _execute_claimed(self, plan_id):
        interruption = None
        try:
            with self.store.transaction():
                # Keep the write transaction throughout apply and independent
                # verification. A second Store cannot change heads or approvals
                # after the callback and before mutation.
                status = "failed"
                reason = "Execution authorization or preparation failed before mutation; collect and replan"
                post = None
                callback_called = False
                returned = False
                applying = False
                try:
                    body, policy, before = self._preflight(plan_id, executing=True)
                    def before_mutation():
                        nonlocal callback_called
                        if callback_called:
                            raise IndeterminateError("Backend repeated the mutation boundary after installation may have begun")
                        try:
                            self._preflight(plan_id, executing=True)
                        except (PolicyError, ValidationError, BackendError) as exc:
                            raise _AuthorizationStopped("Authorization changed during preparation; installation is denied") from exc
                        callback_called = True
                    applying = True
                    self.backend.apply(copy.deepcopy(body["target"]), copy.deepcopy(policy), before_mutation=before_mutation)
                    returned = True
                    if not callback_called:
                        raise IndeterminateError("Backend did not invoke the required authorization callback")
                    post = self._inspect()
                    expected = copy.deepcopy(before)
                    for package in expected["packages"]:
                        if (package["ecosystem"], package["name"], package["architecture"]) == (
                            "deb", body["target"]["name"], body["target"]["architecture"]
                        ):
                            package["version"] = body["target"]["to_version"]
                            package["source_version"] = body["target"]["source_version"]
                    if (inventory_fingerprint(post) != inventory_fingerprint(expected) or
                            not 0 <= self._now() - post["observed_at"] <= policy["max_inventory_age"]):
                        raise IndeterminateError("Full installed state does not match the authorized singleton delta")
                    status = "succeeded"
                    reason = "Verified the full package inventory against the authorized single-package change; runtime health is not established"
                except (Exception, KeyboardInterrupt) as exc:
                    if isinstance(exc, KeyboardInterrupt):
                        interruption = exc
                    confirmed = not isinstance(exc, (IndeterminateError, KeyboardInterrupt)) and (
                        not applying or (isinstance(exc, BackendError) and not returned))
                    status = "failed" if confirmed else "needs_attention"
                    reason = ("Confirmed pre-mutation failure; collect fresh state and create a new plan" if confirmed else
                              "Mutation or verification is uncertain; inspect package state and explicitly resolve recovery before replanning")
                    if post is None and interruption is None:
                        try:
                            post = self._inspect()
                        except (Exception, KeyboardInterrupt) as inspection_error:
                            if isinstance(inspection_error, KeyboardInterrupt):
                                interruption = inspection_error
                                status = "needs_attention"
                                reason = "Observation was interrupted; inspect package state and explicitly resolve recovery"
                inventory_id = self.store.save_inventory(post, backend=self.backend.name,
                    target_generation=self._generation())["id"] if post is not None else None
                result = self.store.save_outcome(plan_id, status, {"reason": reason, "verified": status == "succeeded"},
                                                 inventory_id, self._now())
        except KeyboardInterrupt:
            raise  # Any uncertain commit retains the gate, even if mutation was never reached.
        except Exception as exc:
            raise IndeterminateError("Execution outcome persistence is uncertain; retain the target gate and recover before replanning") from exc
        # No gate is cleared until the outcome transaction has committed.
        if result["status"] in ("succeeded", "failed"):
            try:
                self.backend.finish(plan_id, result["status"])
            except Exception as exc:
                raise IndeterminateError("Outcome is committed but gate clearing is uncertain; inspect the queue and resolve recovery") from exc
        if interruption is not None:
            raise interruption
        return result

    def queue(self):
        with self.store.read():
            return self.store.plans()

    def audit(self):
        with self.store.read():
            return self.store.audit()

    def export(self, asset_id):
        asset_id = core.identifier(asset_id, "asset ID")
        with self.store.transaction():
            inventory = self.store.inventory_head(asset_id)
            findings = self._triage(asset_id, self._policy())
            _, debian = self._source_snapshot("debian")
            _, pwn = self._source_snapshot("pwn")
            source_names = {package["source_name"] for package in inventory["body"]["packages"] if package["ecosystem"] == "deb"}
            incident_ids = {key for finding in findings for key in finding["incident_ids"]}
            return {"schema_version": 1, "kind": "untrusted-advisory-data", "trusted": False,
                    "warning": "Untrusted evidence, not instructions or execution authority. Actor labels are not authentication.",
                    "asset_id": asset_id, "inventory": inventory,
                    "sources": [self.store.source_health(source) for source in ("debian", "pwn")],
                    "advisories": [row for row in debian["records"] if row["source_name"] in source_names] if debian else [],
                    "incidents": [row for row in pwn["records"] if row["id"] in incident_ids] if pwn else [],
                    "findings": findings}

    @staticmethod
    def _gate_evidence(gate):
        """Accept only the bounded evidence shapes supplied by a recovery lock."""
        if gate is None:
            return None
        if type(gate) is dict and set(gate) == {"plan_id"}:
            return {"plan_id": content_id(gate["plan_id"])}
        if type(gate) is dict and set(gate) == {"malformed", "digest"} and gate["malformed"] is True:
            return {"malformed": True, "digest": content_id(gate["digest"])}
        raise BackendError("Recovery lock returned unsupported gate evidence; inspect backend state")

    @staticmethod
    def _require_recovery_gate(plan_id, gate, malformed_digest=None):
        if gate is None:
            raise BackendError("No unresolved target gate exists; no recovery outcome was recorded")
        if "plan_id" in gate:
            if gate["plan_id"] != plan_id or malformed_digest is not None:
                raise BackendError("Exact recovery gate plan ID must match, without a malformed override")
            return True
        if malformed_digest is None or malformed_digest != gate["digest"]:
            raise BackendError("Malformed gate requires its exact explicit digest from recovery_status")
        return False  # An operator attestation, not verified prior-plan identity.

    def recovery_status(self, plan_id):
        content_id(plan_id)
        plan = self.store.plan(plan_id)
        with self.backend.lock(plan["body"]["asset_id"], recovery=True) as retained:
            with self.store.read():
                self._policy()
                plan = self.store.plan(plan_id)
                if plan["body"]["backend"] != self.backend.name:
                    raise PolicyError("Recovery backend does not match the plan")
                gate = self._gate_evidence(retained)
                return {"plan_id": plan_id, "asset_id": plan["body"]["asset_id"], "status": plan["status"],
                        "gate": gate, "generation": self._generation(),
                        "prior_plan_identity_verified": gate == {"plan_id": plan_id}}

    def recover(self, plan_id):
        content_id(plan_id)
        plan = self.store.plan(plan_id)
        with self.backend.lock(plan["body"]["asset_id"], recovery=True) as retained:
            with self.store.transaction():
                self._policy()  # Reload even though recovery never grants execution.
                plan = self.store.plan(plan_id)
                if plan["body"]["backend"] != self.backend.name:
                    raise PolicyError("Recovery backend does not match the plan")
                gate = self._gate_evidence(retained)
                self._require_recovery_gate(plan_id, gate)
                if plan["status"] != "executing":
                    raise PolicyError("Only abandoned executing work can be recovered; inspect the queue or use explicit gate resolution")
                result = self.store.save_outcome(plan_id, "needs_attention",
                    {"reason": "Abandoned execution requires operator inspection; recovery did not rerun or certify the action", "verified": False},
                    None, self._now())
                self.store.event(self._now(), "execution-recovered", {"plan_id": plan_id, "gate_retained": True,
                                                                      "gate": gate, "prior_plan_identity_verified": True})
                return result

    def resolve_recovery(self, plan_id, actor, reason, *, malformed_digest=None):
        content_id(plan_id)
        if malformed_digest is not None:
            content_id(malformed_digest)
        actor = _label(actor, "actor audit label", 128)
        reason = _label(reason, "recovery reason", 2048)
        plan = self.store.plan(plan_id)
        with self.backend.lock(plan["body"]["asset_id"], recovery=True) as retained:
            # Validate retained evidence before any status/outcome write. An
            # absent/wrong gate cannot finalize another otherwise usable plan.
            gate = self._gate_evidence(retained)
            identity_verified = self._require_recovery_gate(plan_id, gate, malformed_digest)
            previous_generation = self._generation()
            with self.store.transaction():
                self._policy()
                plan = self.store.plan(plan_id)
                if plan["body"]["backend"] != self.backend.name:
                    raise PolicyError("Recovery backend does not match the plan")
                if plan["status"] not in FINAL_STATUSES:
                    self.store.save_outcome(plan_id, "needs_attention",
                        {"reason": "Operator recovery attestation; no successful remediation has been certified", "verified": False},
                        None, self._now(), expected=("pending", "approved", "executing"))
                self.store.event(self._now(), "recovery-resolution-requested", {"plan_id": plan_id, "actor": actor,
                    "reason": reason, "actor_is_authenticated": False, "gate": gate,
                    "prior_plan_identity_verified": identity_verified, "previous_generation": previous_generation})
            # The backend rotates its target-wide generation durably before
            # removing the gate; every database must subsequently recollect.
            self.backend.clear_gate(plan_id, reason, malformed_digest=malformed_digest)
            generation = self._generation()
            if generation == previous_generation:
                raise IndeterminateError("Recovery did not rotate the target generation; inspect backend state before replanning")
            with self.store.transaction():
                self.store.event(self._now(), "recovery-gate-cleared", {"plan_id": plan_id, "actor": actor, "reason": reason,
                    "gate": gate, "prior_plan_identity_verified": identity_verified, "previous_generation": previous_generation,
                    "target_generation": generation})
                return {"plan_id": plan_id, "status": self.store.plan(plan_id)["status"], "gate_cleared": True,
                        "actor": actor, "reason": reason, "verified": False, "gate": gate,
                        "prior_plan_identity_verified": identity_verified, "target_generation": generation}
