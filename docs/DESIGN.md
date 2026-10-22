# Autoprotect system design

## Status and scope

This is the implementation contract for the proof of concept. The status table records delivered behavior; a contract below is not itself evidence of implementation. Source research and its limits are in [SOURCES.md](SOURCES.md). The complete acceptance checklist is [DELIVERY.md](DELIVERY.md).

| Capability | Status at design baseline |
| --- | --- |
| Feed and inventory research; immutable development worklog | Implemented and checked |
| Python CLI, SQLite state, pwn.watch and Debian adapters | Contract defined; implementation pending |
| Inventory, Debian applicability and ranking | Contract defined; implementation pending |
| Manual approval, policy-authorized automation and simulation | Contract defined; implementation pending |
| Single-package Debian APT/dpkg backend | Contract defined; fake-runner verification pending; live execution not authorized |
| OSV, GitHub, KEV, EPSS, other distributions and fleet agents | Proposed production work, not implemented |
| Authenticated multi-user approval and external immutable audit | Proposed production work, not implemented |

The first supported applicability ecosystem is Debian 13 (`trixie`) on `amd64`, with binary packages mapped to their Debian source packages and source versions. Other imported platforms or ecosystems remain visible as `unknown`. The simulator uses the same matching rules with synthetic data. A real target must be this local Debian host, freshly collected by the native collector, not an imported or remotely named asset.

The product answers: what was reported; what is installed; which supported package/advisory pairs are affected; which exact repository artifacts can remediate them; whether current policy permits execution; and what happened. It does not prove absence of compromise or cover every installed component. Credential theft, malicious releases, tenant breaches and persistence require incident response, not an automatically inferred package command.

## Threat model and authority

Untrusted inputs include every feed field, imported inventory, model response, package description, URL and terminal-bound string. Attackers may insert commands, control characters, malformed JSON, duplicate keys, incorrect source labels, old observations, misleading version strings or huge payloads. External data cannot choose executables, repositories, arbitrary downloads, policy, approval identity or shell syntax.

Trusted local components are the installed application, the invoking Unix administrator, the policy file, protected state storage, clock, package-manager configuration and explicitly approved Debian archive trust roots. The proof of concept is a single-operator local program, not a multi-tenant service. A writer to its database or policy can control it: content hashes detect accidental changes and bind actions, but are not signatures or protection against that writer. A typed `--actor` label is an audit label, not authenticated identity.

The real executor requires explicit live opt-in, root-owned policy/state with restrictive permissions, native inventory, current HTTPS-acquired Debian evidence, an allowlisted asset/package, approved authenticated repository metadata, and an exact revalidated artifact. Imported feed data can support investigation and simulation but cannot authorize this backend. A feed JSON field claiming `trusted`, `collector` or `origin` is never acquisition provenance.

Repository sources, signing keys and package-manager hooks must be provisioned outside the application. No advisory can add them. Trusted Debian packages can run maintainer scripts as root; explicit policy acknowledgement and a recovery procedure are prerequisites. The tool cannot make those scripts transactional or promise that they do not affect services.

## Processing pipeline

```text
fixed HTTPS endpoints / explicit offline imports
                 -> validated source snapshots + acquisition status
explicit inventory import / read-only native collection
                 -> immutable inventory snapshots
source-package/release matching -> findings + unresolved incident context
repository resolution -> immutable plan -> manual approval or auto policy
execution-time revalidation -> atomic claim + target lock
                 -> bounded backend -> independent installed-state check
                 -> durable outcome + audit + new inventory
```

All user-facing output is JSON with escaped non-ASCII/control characters unless a command explicitly documents another format. Advisory export is a data envelope with an untrusted-content warning; it is never a shell script or system prompt. CLI errors use stable application exceptions and do not dump arbitrary subprocess output or tracebacks by default.

### Acquisition and source health

The first live source IDs and URLs are fixed in code:

- `pwn`: `https://pwn.watch/incidents.json`, incident discovery only.
- `debian`: `https://security-tracker.debian.org/tracker/data/json`, release-specific source-package assertions.

Do not follow links from either feed. Disable redirects, environment proxy discovery and content encodings; use normal TLS certificate verification. Bound request/socket duration, cumulative read time, response size, record count, nesting and text fields. pwn.watch has an 8 MiB input cap; the larger Debian export has a 128 MiB cap. Reject an oversize document in full. Network smoke checks are separate from offline tests.

Conditional requests may use a validated stored ETag. A 304 requires a prior successful snapshot for that same endpoint and acquisition mode. It refreshes contact time, not the advisory publication time. A failed fetch or parse records an attempt/error without replacing the last good snapshot or advancing its success time. The executor rejects stale evidence and a current source error until a successful refresh. Imported data uses `acquisition=import`, never `https`, even if its content includes a source URL.

Normalize a complete input before persisting its new head. Record content digests, parser version, acquisition mode, endpoint ID, attempt/success times and errors. Identical content is deduplicated; a changed digest creates a new immutable snapshot. Offline import does not validate publisher authorship. Polling is an idempotent `poll` invocation suitable for an external timer; no resident scheduler or retry daemon is required for this proof of concept. Operators can schedule it every 15 minutes, with service-manager retry/backoff and alerting. Failed polling must never clear findings.

### Normalized data contracts

Runtime modules use JSON-compatible dictionaries and lists, integer UTC epoch seconds, and lowercase SHA-256 IDs. Identity-bearing fields use strict ASCII validation. Raw free text has a length cap but remains untrusted. Unknown extra feed fields are ignored rather than treated as commands. Duplicate JSON object keys and non-finite numbers are rejected.

The shared functions in `autoprotect/core.py` provide application exceptions, canonical JSON, content digests, strict JSON loading, bounded plain text, integer timestamps and identifier/package/version validators. Concrete interfaces below are the handoff contract; implementation changes require coordinated updates, not parallel edits to another owner's files.

**Inventory:** `schema_version=1`, `asset_id`, `observed_at`, `os`, `release`, `architecture`, `collector` (`imported`, `native`, `simulator`), `complete` (boolean), `packages` (list). Each package has `ecosystem`, `name`, `version`, `source_name`, `source_version`, `architecture`, `status` (`installed` or a visible non-ready state), and `held` (boolean). Package identity is `(ecosystem, name, architecture)`; duplicates are rejected. Native observation derives asset identity from a hashed machine ID and reads the real `/etc/os-release` and dpkg database. It never sources a shell file or executes an installed application. Observation time is supplied by the collector, never feed data. Imported `collector` is forcibly `imported`. A fingerprint excludes only `observed_at`; other package and platform changes invalidate a plan.

**Debian assertion:** `id` (CVE), `source_name`, `release`, `status`, `fixed_version` (string or null), `urgency`, `description`. Parser output is limited to the supported release. `fixed_version="0"` means not affected, not version zero to install. Unrecognized, ambiguous, unsupported or incomplete assertions remain unknown. A resolved archive entry with an ordinary fix still requires comparing the installed source version against that fix. An unfixed/open entry can establish an affected finding but cannot produce an executable plan.

**Incident:** `id` (pwn slug), `title`, `summary`, `identifiers`, `severity`, `patch_status`, `product`, `updated_at` (publisher text), `is_example`, and informational version strings. No incident field is a package candidate or command. Non-CVE identifiers are retained; example incidents are segregated from actionable discovery.

**Finding:** `id`, `asset_id`, `inventory_id`, `package` (the normalized package or null for an incident-only item), `advisory_id`, `source_name`, `source_digest`, `status` (`affected`, `not_affected`, `unknown`), `reason`, `fixed_version`, `priority`, and `incident_ids`. `priority` is an explainable integer ordering, not a calibrated probability. Debian urgency and correlated incident severity can raise ordering but cannot grant execution. Packages without matching evidence produce explicit unknown coverage; unmatched incidents remain investigation context. Never infer universal safety from an empty result.

**Repository target:** `name`, `architecture`, `from_version`, `to_version`, `source_name`, `source_version`, `sha256`, `size`, `origins` (list of exact `{origin, label, archive, codename, component, site}` tuples), `config_digest` and `metadata_digest`. Only the backend creates this object. Plan content binds the complete target, including its artifact hash, repository identities, approved configuration/keyring fingerprint and authenticated index fingerprint. Codenames must be `trixie`, `trixie-updates` or `trixie-security`; moving suite names alone cannot authorize a target. Metadata must be authenticated through the approved APT configuration, have a valid release date and any supplied expiry, and be no older than `max_repository_age` even without `Valid-Until`. The binary version must increase, and the candidate source version must meet the advisory fix using Debian comparison. Version strings are data, never command fragments. The approved transaction is canonically derived: replace only the target package's binary/source versions in the entire pre-execution inventory; every other package field must remain identical. Full post-execution comparison enforces that delta.

### Version semantics and inventory limits

Use Debian epoch/upstream/revision ordering, including tilde ordering, numeric runs and missing revision behavior. Preserve source versions separately from binary versions, including binary rebuild suffixes. Test known native-comparison cases and, when a disposable Debian runtime is available, cross-check with `dpkg --compare-versions`. Unsupported syntax is unknown or an explicit validation failure, never lexical comparison.

Native collection is read-only and reports held, half-configured and error states. Matching can explain these records; remediation refuses incomplete inventories and any target not fully installed. Imported inventory cannot establish origin or runtime activation. Live policy must set `trusted_installed_lineage=true`: an explicit administrator assertion that this is an unmodified Debian-managed installation, not a locally rebuilt or compromised package tree. This is an operational trust assumption, not collector authentication of installed bytes. A matching repository name/version does not prove origin, and older installed versions need not remain in current indexes. A missing assertion, modified/unknown lineage or wrong source identity blocks the native path; the clearing action is independent lineage verification or rebuilding from trusted artifacts, not changing a feed field.

A package database does not prove which binary is running. Success means the expected package database state was observed, not that an application is healthy, a kernel is active, or compromise was removed. Kernel, boot, package-manager and core service-manager changes are outside the initial real-backend allowlist. Application/service restart and health verification are separate production work.

## Policy, plans and approval

Policy is a strict local JSON document, not feed content. Its contract is:

- `schema_version: 1`.
- `mode`: `observe`, `manual`, or `auto`; no implicit live permission.
- `backend`: `simulator` or `debian-apt`.
- `allowed_assets`, `allowed_packages`: exact nonempty identity lists for execution.
- `allowed_origins`: exact origin tuples including codename/component for the native backend; empty is acceptable only for simulation.
- `approved_config_digest`: SHA-256 of the operator-reviewed package-manager source/configuration/keyring state; null only for simulation. Do not learn or approve it automatically during execution.
- `max_inventory_age`, `max_feed_age`, `max_repository_age`, `plan_ttl`, `approval_ttl`: positive bounded integer seconds.
- `allow_maintainer_scripts`, `recovery_confirmed`, `trusted_installed_lineage`: booleans; all must be true for live execution. These are operator assertions, not verified backup existence or installed-byte authentication.

Missing fields, extra fields, bad types, unsafe identities and excessive durations fail validation. Observation and triage remain usable with an observe policy. Manual plans need an explicit approval; auto plans need current auto policy and the same substantive safety checks. Automatic mode does not override allowlists, source trust, staleness, backend limitations or verification.

A plan contains `schema_version`, `asset_id`, `backend`, `inventory_id`, `inventory_fingerprint`, `source_digest`, `finding_id`, `advisory_id`, `fixed_version`, `policy_digest`, `target`, `created_at`, `expires_at`. The ID is the canonical content hash, stored separately. The immutable plan has no mutable status field inside its hashed body. Queue status is separate. Approval binds the plan ID, policy digest, actor label, creation time and expiry no later than plan expiry. Changing an inventory, source assertion, target artifact, policy or plan invalidates approval; renewing it requires a new applicable plan or explicit reapproval as appropriate.

The initial backend plans one finding and one binary package at a time. The approval UI/export shows the bound target, source fix, policy and inventory digests, and expiry. A source correction, even one that still names the same fix, requires replanning if its normalized source snapshot changed. This conservative rule avoids reusing an approval over revised evidence.

## Persistence, serialization and execution lifecycle

SQLite is the local durable store. Use foreign keys, a busy timeout and explicit transactions. Store immutable content-addressed source, inventory, finding-set and plan bodies, mutable current heads/source health, separate approvals, execution status/results and append-only audit rows. Hash-check immutable bodies when reading them. Database initialization must be idempotent; schema version mismatches fail clearly. Do not create a schema migration that silently discards data.

`pending -> approved -> executing -> succeeded | failed | needs_attention` is the manual path. Auto policy permits `pending -> executing`; an `observe` policy permits neither approval nor execution. Expired/changed inputs become `stale`; policy rejection is a denied action with a reason, not successful remediation. Final plans cannot be executed again. A failed plan is not automatically retried: observe the target and create a new plan. `failed` is reserved for confirmed pre-mutation failure; timeout, interruption after mutation may begin, partial package state and failed verification use `needs_attention`.

Claim execution with an atomic conditional SQLite update inside `BEGIN IMMEDIATE`, coupled to an audit record. A second process cannot claim the same plan. Hold a target lock across revalidation, claim, mutation and verification. Native locks and a durable unresolved-execution gate use a common root-owned local location independent of the selected SQLite file; simulation locks and gates protect their particular disposable state. Write and flush the gate while holding the target lock, before committing the transition to `executing` and before invoking mutation; it binds the plan ID and survives process exit. A crash after gate creation retains the gate for recovery even if the database claim was not committed. Any unresolved gate blocks all subsequent plans for that target, across databases. Clear it only after a confirmed pre-mutation failure or successful full verification has been committed durably. `needs_attention`, uncertain persistence and crashes retain the gate. No timeout lease allows another worker to blindly take over an active target.

The native executor also holds the package manager's frontend lock across final inventory/transaction validation and installation. Use the native frontend-lock protocol, with `DPKG_FRONTEND_LOCKED=true` passed only by the trusted runner when that lock is actually held; `dpkg` retains its own database lock. Do not release the frontend lock between final checking and installation. Recovery must also acquire native frontend and database locks to rule out a surviving package-manager child. Exact lock acquisition/handoff behavior is an explicit fake-runner acceptance case and a required future disposable-Debian integration check.

Before claiming, reload and validate policy, plan integrity, source health/provenance/freshness, latest inventory identity, plan/approval expiry and package allowlists. Engine accepts a callable policy provider and reloads it for every sensitive operation; the CLI supplies a protected-file loader rather than a construction-time snapshot. Collect fresh backend inventory and compare its full fingerprint; resolve the target again and require exact artifact/transaction equality. A fresh scan can have a different observation time but not a different package state. Recheck expiry and policy after lengthy preparation, immediately before mutation. Serialize source-head, inventory, approval and execution-claim changes within the same store transaction; no stale authorization decision may cross the claim. Approval is necessary but never sufficient.

Record an execution-start event before mutating. Afterward collect again and require exact installed binary/source versions and ready package status; update inventory, result and audit together. A zero process exit code without matching state is not success. Re-run triage against the new inventory when requested. Audit records contain bounded structured identities and reasons, never unrestricted environment variables, repository credentials or raw command output.

If a process disappears after claiming, its plan remains `executing` and its target gate remains closed. `recover` can acquire the target/native locks and mark it `needs_attention`; it cannot re-run the action or assert success. Operators inspect and recover package state outside the automatic loop. A separate explicit `resolve-recovery` action records the operator label, prior gate plan ID and recovery reason, checks that native locks are available, then clears the target gate without changing any failed plan into success. The next action requires collection and a new plan. The resolution is an operator attestation, not automatic proof that script side effects were undone. SQLite and a local audit trail are not tamper-proof or a distributed consensus service.

## Backends

All backends implement:

```python
name: str
inspect() -> dict
resolve(inventory: dict, finding: dict, policy: dict) -> dict
lock(asset_id: str, *, recovery: bool = False) -> context manager
begin(plan_id: str) -> None
finish(plan_id: str, outcome: str) -> None
clear_gate(plan_id: str, resolution: str) -> None
apply(target: dict, policy: dict, *, before_mutation: callable) -> dict
```

`inspect` returns a new normalized inventory. `resolve` has no host mutation. `lock` rejects a retained gate unless entered for recovery. `begin` durably creates the gate while locked; `finish` clears it only for committed `succeeded` or confirmed `failed`, retaining it otherwise. `clear_gate` requires an exact prior plan ID, explicit resolution and recovery lock. `apply` is invoked only by the authorized lifecycle; it repeats backend-specific target checks and invokes `before_mutation()` after download/preparation immediately before installation, so the engine can reject expired or changed authorization. Exceptions distinguish a pre-mutation failure from an indeterminate/partially applied outcome. Backend results are explanatory evidence, not a substitute for independent `inspect` verification. Constructor-only test injection can supply a fake runner or filesystem; no CLI switch turns those into native provenance.

### Simulator

Use explicitly initialized, private disposable JSON state containing an inventory and synthetic repository catalog. Never derive its path from a feed field or plan ID. Writes are atomic under its lock. Candidate entries carry the same target fields as the native backend; a synthetic artifact hash is not a real download claim. Provide deterministic failure-before-write and failure-after-write injection for tests/demo. A successful apply updates the binary/source version and observation time. Demo must show an authorized manual path, authorized automatic path, repeat-execution rejection, and failed/indeterminate update handling. It must not invoke native package tools.

### Debian APT/dpkg

The supported live host is Debian 13/trixie amd64 with `/usr/bin/dpkg-query`, `/usr/bin/dpkg`, `/usr/bin/apt-get`, and the native APT metadata interface selected by implementation. A `python3-apt` helper is permissible as an OS prerequisite, not a Python package dependency. Missing tools block this backend, not simulation or investigation. The development host lacks these executables; no live update is part of development verification.

1. Read inventory and reject the wrong platform/identity, holds, broken state, sensitive packages, unsupported architecture or incomplete metadata.
2. Resolve the candidate from local APT policy, including authenticated origin and artifact metadata. Reject untrusted repositories, mismatched source identity, missing SHA-256, old/expired repository metadata, ambiguous same-version artifacts, lower source fix or non-increasing binary version. Source/index refresh is a separately authorized operational prerequisite; never hide `apt-get update` inside a read-only command. Root-owned configuration and reviewed hooks are explicit assumptions; disallow known insecure overrides.
3. Simulate the exact pinned request and reject removals, downgrades, newly installed packages, unrelated upgrades and any change set other than the sole planned binary. Reject candidate `Conflicts`, `Breaks` and `Replaces` relationship fields conservatively, including possible package disappearance/file takeover, rather than trying to authorize these side effects. Bind the full accepted result via the singleton package-state delta. Approval cannot authorize an unspecified dependency transaction.
4. At execution, repeat candidate/transaction validation. Download the pinned package through APT's authenticated path into a fresh private staging directory with bounded disk usage. Verify actual SHA-256, byte count, binary name/version/architecture and source identity. No downloaded file path or URL comes from advisory prose.
5. Under the native frontend lock, install only that local artifact using a fixed `dpkg --install` argument vector, with a documented noninteractive conffile policy. Reject removal/replacement relationship fields both in candidate metadata and the actual artifact. Unlike a second APT resolver invocation, `dpkg` cannot automatically fetch and upgrade new dependencies, but a singleton argument alone does not guarantee a singleton state change. Package scripts/triggers can still have effects beyond version fields and are explicitly acknowledged in policy.
6. Read the complete package database again and compare it with the expected singleton delta: the target reaches the exact planned version/source state, all unrelated packages retain their identities, versions, holds and ready states, and none disappear or appear. Any deviation is `needs_attention` with the target gate retained. This does not certify runtime health. Never run generic feed-supplied health commands or automatically downgrade after failure.

The fixed command runner uses `shell=False`, absolute executables, a minimal environment (no inherited `APT_CONFIG`, Python injection, shell startup or loader variables), a controlled working directory, bounded output and deadline, and process-group termination on timeout. Never include arbitrary remote text in error output. Separate pre-mutation download errors from interrupted installation. Temporary artifact cleanup must not remove operator files or mask the recorded outcome.

This one-package boundary is intentionally narrower than general package management. Updates needing dependency upgrades go to manual operations with an explanatory blocker; they are not reported fixed. There is no universal rollback. Backups, replacement deployment or an application-specific recovery procedure must account for maintainer scripts, conffile changes and migrations.

## Module ownership and integration contracts

| Module | Responsibility and primary interface |
| --- | --- |
| `core.py` | `AutoprotectError`, `ValidationError`, `PolicyError`, `BackendError`, `IndeterminateError`; `canonical`, `digest`, `load_json`, `now`, `text`, `identifier`, `package_name`, `version`, `integer` |
| `feeds.py` | `parse_pwn(data)`, `parse_debian(data, release="trixie")`, `parse_source(source, raw)`; `fetch_source(source, etag=None)` returning `{not_modified, raw, etag}`. Parser returns normalized lists, not a trust decision. |
| `inventory.py` | `normalize_inventory(data, collector="imported")`, `inventory_fingerprint(inventory)`, `collect_local(runner=None)` |
| `debian.py` | `compare_versions(left, right)` returning -1, 0, 1; unsupported syntax raises `ValidationError` |
| `matching.py` | `match(inventory, assertions, incidents, *, inventory_id, source_digest, now, max_inventory_age)` returning findings |
| `runner.py` | `CommandResult(returncode, stdout, stderr)` and `Runner.run(argv, *, timeout=60, cwd=None)`; bounded bytes decoded safely |
| `backends.py`, optional `_apt_probe.py` | `Simulator(path)` and `DebianApt(runner=None, *, live=False)` implementing the backend protocol; simulator initialization/failure controls remain explicit local APIs |
| `store.py` | `Store(path)` plus transactional persistence methods chosen with lifecycle implementation; CLI uses Engine, not direct SQL |
| `engine.py` | `validate_policy(data)` and `Engine(store, policy_provider, backend, *, clock=core.now)`; methods `ingest(source, raw, acquisition="import", etag=None)`, `poll(source)`, `inventory(data=None)`, `triage(asset_id)`, `plan(finding_id)`, `approve(plan_id, actor)`, `execute(plan_id)`, `queue()`, `audit()`, `export(asset_id)`, `recover(plan_id)`, `resolve_recovery(plan_id, actor, reason)` |
| `cli.py`, `__main__.py` | Argument parsing, protected live policy/state checks, JSON output, commands and demo orchestration; no authorization shortcuts |

`Engine.ingest` is for imports; an external caller must not be able to grant HTTPS provenance merely by passing the string `https`. Only `poll`, after the fixed network adapter returns successfully, records that provenance. The API may retain the acquisition parameter for explicit validation, rejecting values other than `import`; tests can use injected fetchers rather than spoofing stored trust.

## Deployment and proposed production evolution

The PoC runs as a local command with a private state directory. Observation is unprivileged where package-database permissions permit. Privileged execution is a separately invoked action, not a network listener. Production deployment should separate collectors, planner and minimal executor; authenticate asset enrollment and approvals; provision least-privilege service accounts; centralize protected audit and source freshness alerts; and use signed, time-bound action envelopes.

Future fleet work must handle cloned machine IDs, authenticated collector transport, replay, distributed locks, maintenance windows, canaries, blast-radius limits, fleet rollout verification, per-service health, secret handling, credential rotation and incident containment. Application and container remediation should rebuild approved artifacts and roll out immutable digests through existing deployment controllers. Those capabilities are not simulated into existence by this proof of concept.

Polling failures and source age must be operator-visible. A production timer should avoid overlapping runs, implement capped backoff/jitter, and page on sustained stale data or `needs_attention`. Metrics should distinguish ingest success, source lag, coverage unknowns, plans waiting for approval, policy denials, execution duration and verification failures. Do not log private inventory to public services. The default integration is local; public feeds are downloaded without uploading inventories.

Jouzu can consume the advisory export to investigate, propose code changes and explain findings. It receives data with explicit untrusted provenance, not administrator instructions. Optional TextGuard scanning can add inspection findings to that export. Neither a clean scan nor a model proposal can modify policy, fabricate native provenance, approve an action or select an executable. This design does not install or invoke Jouzu/TextGuard as runtime dependencies.

## Acceptance evidence

Each implementation unit needs offline tests for valid use and its relevant failure boundaries. Final acceptance includes the packaged CLI from a clean environment, the disposable end-to-end demo, duplicate ingestion, hostile/control-bearing inputs, source spoofing, Debian epochs/backports/source versions, stale inventory/evidence/approval, altered policy/plan/target, denied and successful manual/automatic execution, concurrent claims, bounded commands, downloads, interruption, failed verification and recovery limits.

Independent review must inspect the integrated acquisition-to-execution path, not only helpers. Record exact checks and unresolved limits in `docs/REVIEW.md` and the immutable worklog. Native fake-runner tests establish command construction and lifecycle behavior; they do not establish that a real repository download or privileged package update was performed. `README.md` and `docs/OPERATIONS.md` will document only verified commands and distinguish these limits.
