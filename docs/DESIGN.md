# Autoprotect system design

## Status and scope

The active target is **Ubuntu 24.04 LTS (`noble`), `amd64`**. The native backend contract is `UbuntuApt`, selected by policy as `ubuntu-apt`; the applicability source ID is `ubuntu`. Ubuntu Pro and Expanded Security Maintenance (ESM) are excluded from remediation. Other releases, architectures and ecosystems remain visible as unsupported or unknown rather than implicitly safe.

The `ubuntu` source is Canonical's Ubuntu Security Notice (USN) JSON database at `https://usn.ubuntu.com/usn-db/database.json`. The verified [source contract](research/UBUNTU.md) defines notice-based missing-update evidence, not complete CVE vulnerability coverage. The synthetic test fixture at `tests/fixtures/feeds/ubuntu.json` uses that JSON shape; the simulator walkthrough uses the matching example inputs in `examples/ubuntu-synthetic.json`. The recorded Ubuntu suite, demos, packaging and example workflows passed; verification of the latest native regression additions and independent-review approval remain open.

The application has a local CLI, protected state handling, SQLite lifecycle storage, manual/automatic policy, simulator, bounded runner and native APT framework. Parent integration verified the Ubuntu command workflows and 507 offline tests, including native freshness and shared feed-budget regressions. [REVIEW.md](REVIEW.md) separates that evidence from remaining acceptance gates and historical work in the [worklog](../worklog/README.md); [DELIVERY.md](DELIVERY.md) owns acceptance. **No privileged Ubuntu qualification has been performed.** A passing simulation or comparator check does not close the native deployment gates.

| Capability | Scope |
| --- | --- |
| Incident discovery | Fixed pwn.watch JSON source; prose is investigation context, not patch authority |
| Ubuntu applicability | USN missing-update checks using Noble source versions and explicit standard-security binary membership; no complete CVE coverage |
| Inventory | Imported data or read-only local collection; only fresh native collection can authorize a local native target |
| Planning and execution | Immutable one-package plans; manual approval or explicit automatic policy; execution-time revalidation |
| Simulation | Disposable package state and synthetic repositories; no native package commands |
| Native remediation | Approved standard Ubuntu archives only; real APT/download/lock/install/recovery qualification remains open |
| OSV, GitHub, KEV, EPSS, other platforms and fleet agents | Research or proposed production work, not implemented adapters |
| Authenticated multi-user approval and external immutable audit | Proposed production work, not implemented |

The product answers what was reported, what is installed, which supported package/advisory pairs are affected, which approved artifacts can remediate them, whether policy permits execution, and what happened. It does not prove absence of compromise or complete vulnerability coverage. Credential theft, malicious releases and persistence require incident response, not an inferred package command.

## Threat model and authority

Every feed field, imported inventory, model response, package description, URL and terminal-bound string is untrusted. Attackers may supply commands, control characters, malformed JSON, duplicate keys, spoofed source labels, stale observations, misleading versions or oversized payloads. External data cannot select executables, repositories, downloads, policy, operator identity or shell syntax.

Trusted local components are the installed application, invoking Unix administrator, protected policy/state, clock, package-manager configuration and explicitly approved Ubuntu archive trust roots. This is a single-operator local program. A writer to its database or policy can control it: content hashes bind actions and detect accidental changes, but do not protect against that writer. A typed `--actor` is an audit label, not authenticated identity.

Native mutation requires explicit live opt-in, effective root, protected root-owned policy/state, fresh native inventory, current fixed-source HTTPS-acquired Ubuntu evidence, exact asset/package/origin allowlists and a revalidated artifact. An import can support investigation or simulation but cannot authorize native execution, even if its fields claim trusted acquisition or native collection.

Provision sources, signing keys and hooks outside the application. No advisory can add them. Approved packages can execute maintainer scripts as root; policy must explicitly acknowledge their effects and a prepared recovery procedure. Neither package signatures nor those assertions make scripts transactional. Pro/ESM entitlement must not silently expand the supported archive or advisory scope.

## Processing pipeline

```text
fixed HTTPS sources / explicit offline imports
                 -> validated snapshots + acquisition status
inventory import / read-only native collection
                 -> immutable inventory snapshots
release/source-package matching -> findings + incident context
repository resolution -> immutable plan -> approval or automatic policy
execution-time revalidation -> atomic claim + target lock
                 -> bounded backend -> independent installed-state check
                 -> durable outcome + audit + new inventory
```

Operational output is JSON with escaped control/non-ASCII characters; help and version are plain text. Advisory export is an untrusted data envelope, never a shell script or system prompt. Errors are bounded application diagnostics rather than arbitrary subprocess output or tracebacks.

### Acquisition and source health

`pwn` uses `https://pwn.watch/incidents.json`; `ubuntu` uses `https://usn.ubuntu.com/usn-db/database.json`. Both consume UTF-8 JSON from fixed HTTPS endpoints. Feed links, artifact URLs, checksums and action prose cannot select installation targets. The Ubuntu adapter reads published notices, not OVAL or the paginated CVE API.

The shared acquisition framework disables redirects, environment proxy discovery and content encodings, uses normal TLS verification, and bounds socket operations, elapsed handling time and response bytes. A 10-second socket-operation cap and a spawned worker with a 60-second deadline cover DNS and response handling after successful startup, followed by up to 0.5 seconds of cleanup joins. Process creation itself is not forcibly time-bounded. Interrupted startup before the process handle is published, further interruption during cleanup, forced parent death and delayed OS termination still require supervision.

The pwn input cap is 8 MiB. Ubuntu raw and decoded feed budgets are **512 MiB**, with 32,000,000 JSON nodes, depth 32, 50,000 raw notices, 500,000 normalized assertions, 10,000 binary entries per Noble notice and 4,096 CVE or URL references per notice. Strings, including ignored fields, are capped at 65,536 characters; identity/version fields have smaller limits. Unsupported HTTP content encodings are rejected rather than decompressed.

JSON parsing retains a whole snapshot and intermediate object pairs before structural validation. Iterator-based traversal bounds its validation stack by depth, not width, but the byte/node limits are neither a whole-process memory quota nor a parser wall-clock deadline. The source research retrieved 354,359,354 bytes on 2026-10-23; decoding needs substantial additional memory. Reject oversized input in full and budget temporary disk separately. Application entry points use a multiprocessing-safe main guard.

Chunked HTTP trailers have a separate 100-field/32 KiB wire-byte cap and require a complete CRLF terminator. Duplicate, forbidden and metadata-changing trailers are rejected; accepted informational trailers are discarded rather than merged into headers. This uses CPython's private `HTTPResponse._read_and_discard_trailer` hook and needs real-decoder regressions on supported runtimes. Other chunk grammar remains the standard library's responsibility; chunk overhead has no aggregate wire-byte cap.

A conditional request may use a validated stored ETag. A 304 requires a prior successful snapshot for the same endpoint and acquisition mode; it refreshes contact time, not publication time. Failure records an attempt/error without replacing last-good data or advancing success time. Current source errors and stale evidence block execution. Imports always use `acquisition=import`, regardless of embedded URLs or claims.

Normalize a complete input before replacing its head. Store content digest, parser version, acquisition mode, endpoint identity, attempt/success times and errors. Identical content deduplicates; changed content creates an immutable snapshot. Polling is an explicit invocation, not a resident scheduler. An external timer may start with a 15-minute cadence, bounded retry/backoff and alerts, but failed polling must never clear findings or automatically trigger execution. Network smoke checks are separate from offline fixtures.

### Normalized data contracts

Runtime records use JSON-compatible dictionaries/lists, integer UTC epoch seconds and lowercase SHA-256 IDs. Identity-bearing fields use strict ASCII validation. Free text is bounded but remains untrusted. Unknown fields do not become instructions; duplicate object keys and non-finite numbers are rejected.

`autoprotect/core.py` supplies application exceptions, canonical JSON, hashing, strict loading and timestamp/identifier/package/version validators.

**Inventory:** `schema_version=1`, `asset_id`, `observed_at`, `os`, `release`, `architecture`, `collector` (`imported`, `native`, `simulator`), `complete` and `packages`. Package fields are `ecosystem`, `name`, `version`, `source_name`, `source_version`, `architecture`, `status` and `held`. Ubuntu packages retain the ecosystem identifier `deb`; supported platform identity is `os=ubuntu`, `release=noble`, `architecture=amd64`. Remediation targets may be `amd64` or architecture-independent `all` packages.

Imports must explicitly supply source identity/version for these packages. A binary rebuild version cannot safely substitute for its source version. Native collection uses dpkg's source-package/version virtual fields and real OS/package metadata; it does not source a shell file or run installed applications. Asset identity derives from a hashed local machine ID. Imported collector labels are forced to `imported`. Package identity is `(ecosystem, name, architecture)`; duplicates fail. The inventory fingerprint excludes only `observed_at`, so other package/platform drift invalidates plans. Unsupported ecosystems retain bounded identities/versions for visible unknown coverage.

**Ubuntu assertion:** `id` (`USN-<number>-<number>`), `source_name`, `release` (`noble`), `status` (`resolved` or `unknown`), `fixed_version`, `urgency` (`unknown`), bounded `description`, sorted/deduplicated `cve_ids`, `pocket`, and sorted `binary_packages`. Identity is `(source_name, release, id)`. The raw numeric database key must agree with the notice's inner `id`. Source fixes come only from `releases.noble.sources[NAME].version`; `releases.noble.allbinaries` supplies explicit binary-to-source and pocket evidence. The `binaries` map alone is not a fallback.

A source assertion is assessable only when its source fix is valid, nonzero and non-ESM, and all linked binary entries have valid nonzero non-ESM versions and the explicit `security` pocket. Otherwise it is `unknown`; `fixed_version="0"` has no special safe meaning. Missing/mixed pockets, Pro/ESM, realtime and FIPS data cannot authorize remediation. A notice without a Noble entry retains source names from other releases as Noble unknowns, without inheriting their fixes or binary evidence. Sources that cannot be named are not invented.

One notice covering several sources creates one assertion per source, not a source/CVE cross product. `cve_ids` are notice-level references for incident correlation, not proof that each CVE affects every source or release. Findings and plans bind USN IDs. The matcher repeats pocket, source-fix and exact binary-membership checks; an unlisted binary or ESM-labelled installed version remains unknown. Holds do not hide applicability but block remediation.

For supported evidence, compare the installed **source version** with the notice's fix: below is `affected` in this missing-update model; at or above is `not_affected` by that notice's update requirement. `resolved` describes usable published-fix evidence, not the host. The model does not prove that every older package contains every referenced CVE. Packages without notices and vulnerabilities without published fixes are not declared safe.

**Incident:** pwn slug `id`, title, summary, identifiers, severity, patch status, product, publisher update text, example flag and informational version strings. No incident field is an installation candidate or command. Preserve non-CVE identifiers and segregate example incidents from actionable discovery.

**Finding:** `id`, `asset_id`, `inventory_id`, normalized `package` or null, sorted USN `advisory_ids`, `source_name`, `source_digest`, `evidence_acquisition`, `status` (`affected`, `not_affected`, `unknown`), `reason`, `fixed_version`, `priority`, `priority_reasons` and `incident_ids`. Acquisition is `https`, `import` or null when no usable evidence applies. One finding can cover the USNs sharing a fixed boundary for one package. Group affected rows by supported fixed version, not-affected rows together, and unknowns by explanation. Missing fixes produce unknowns, not unfixed affected rows. A wholly unassessable package produces an unknown row with the applicable USN IDs.

The finding count, incident associations and serialized result are bounded to 300,000, 300,000 and 64 MiB respectively; violations fail rather than silently truncate. Incident correlation accepts the USN identity or its CVE references and deduplicates incidents. The USN database supplies no authoritative severity, so normalized `urgency` is `unknown` with priority 30. Correlated incident severity can raise priority: critical 100, high 80, medium 50, low 20, unknown 30. Not-affected rows and example incidents have priority zero. These scores order investigation; they are neither calibrated probabilities nor applicability or execution authority. Unmatched packages and incidents remain visible as coverage gaps or investigation context.

**Repository target:** `name`, `architecture`, `from_version`, `to_version`, `source_name`, `source_version`, `sha256`, `size`, exact `origins` tuples `{origin, label, archive, codename, component, site}`, `config_digest` and `metadata_digest`. Only the backend creates this object. Bind the artifact hash, approved source/key configuration and authenticated index evidence to the plan. Verify Ubuntu's signed release identity and its archive pocket separately: native origins require `origin=Ubuntu`, `label=Ubuntu`, `codename=noble`, with `archive` exactly `noble`, `noble-updates` or `noble-security`. A security/updates pocket is not the codename. Backports, moving aliases, Pro/ESM and unrelated repositories cannot authorize targets. Simulator origins remain explicitly synthetic.

Every contributing Release needs an authenticated signature, valid date, any supplied expiry and compliance with `max_repository_age`, even without `Valid-Until`. The binary version must increase and the candidate source version must meet the supported advisory boundary. The complete approved transaction is the old inventory with only the target's binary/source versions replaced; all other fields remain identical. Full post-execution comparison enforces that delta.

### Version semantics and inventory limits

`autoprotect/versions.py` implements the dpkg package-version comparator used by Ubuntu: epoch, upstream part and packaging revision, including tilde, alternating numeric/non-numeric runs and missing revision behavior. Preserve complete versions and source/binary separation; never use lexical or generic semantic-version ordering. Unsupported syntax, including epochs above `2147483647`, fails validation or produces unknown advisory comparison rather than a guessed result. Unsupported ecosystems retain their own version text.

Offline ordering tests and `scripts/check_package_versions.py` provide separate checks. Parent integration passed 1,028 deterministic comparisons with native `dpkg` in a disposable Ubuntu 24.04 image, without network access or host mounts during comparison. [REVIEW.md](REVIEW.md#ubuntu-verification-results) records its image digest and limits. This validates those ordering cases, not host inventory or native installation.

Native collection reports holds, partial states and errors rather than discarding them. Remediation needs a complete settled package database and a fully installed unheld target. `trusted_installed_lineage=true` is an administrator assertion that the host is an unmodified Ubuntu-managed installation, not authentication of installed bytes. A matching repository name/version does not prove installed origin; old versions may no longer appear in indexes. Unknown or modified lineage requires independent verification or rebuilding, not changing a feed field.

A package database does not prove which binary is running. Success certifies the expected package database state, not application health, active kernel state or removal of compromise. Kernel, boot, package-manager and core service-manager updates are outside the initial real-backend allowlist. Restart/reboot and service-health handling remain separate work.

## Policy, plans and approval

Policy is strict local JSON with these required fields:

- `schema_version: 1`.
- `mode`: `observe`, `manual` or `auto`.
- `backend`: `simulator` or `ubuntu-apt`.
- `allowed_assets`, `allowed_packages`: exact nonempty identity lists.
- `allowed_origins`: exact native origin tuples; empty only for simulation.
- `approved_config_digest`: reviewed package-manager source/configuration/keyring SHA-256; null only for simulation.
- `max_inventory_age`, `max_feed_age`, `max_repository_age`, `plan_ttl`, `approval_ttl`: positive bounded integer seconds.
- `allow_maintainer_scripts`, `recovery_confirmed`, `trusted_installed_lineage`: booleans, all true for native execution. They are operator assertions, not verified backups or installed-byte integrity.

Missing/extra fields, incorrect types and unsafe identities fail. Durations are limited to 1–31,536,000 seconds, asset/package allowlists to 1–10,000 entries and origin lists to 256 tuples. Lists are sorted before hashing. Observation and triage remain usable under `observe`; that mode cannot approve or execute. Manual mode requires explicit approval; auto mode retains every other substantive check and does not schedule itself. No policy can override unsupported archive channels or backend transaction limits.

A plan binds `schema_version`, `asset_id`, `backend`, `target_generation`, `inventory_id`, `inventory_fingerprint`, `source_digest`, `finding_id`, `advisory_ids`, `fixed_version`, `policy_digest`, `target`, `created_at` and `expires_at`. Its ID is the canonical content hash; mutable queue status is separate. Approval binds that ID, policy digest, actor label, creation time and expiry no later than the plan's expiry.

Changing inventory, source evidence, target artifact, policy, generation or deadlines requires replanning or renewed authorization as appropriate. Planning and execution re-derive the exact affected advisory group for the bound package; a stored `affected` label grants nothing. Even a source correction naming the same fix invalidates the old binding if its normalized snapshot changes. One plan covers one finding and one binary package, never an unspecified dependency closure.

## Persistence, serialization and execution lifecycle

SQLite stores immutable content-addressed evidence and plans, mutable current heads/source health, separate approvals, execution outcomes and audit rows. Reads hash-check immutable bodies. A process may cache validation only for byte-identical previously checked text; the verified-text cache is bounded. Database version mismatches fail rather than discarding state.

Schema 4 uses foreign keys, `synchronous=FULL`, explicit transactions and a five-second busy timeout. Previous schemas are rejected with a fresh-state requirement; there is no migration or reinterpretation of earlier evidence, inventories or approvals. Preserve prior state for investigation and provision a new private database. Public inventory envelopes stay `{id, body}` while native collection context is stored separately in the head. A same-second recollection can therefore retain its content ID while changing generation context.

Only affected findings are persisted for planning; `triage` and `export` return the full result. Replacing source heads or recording triage prunes unreferenced evidence transactionally. Retain current heads, evidence referenced by plans/outcomes, and findings associated with current inventory/source heads. Plans, approvals, outcomes and audit rows are never deleted. `evidence-pruned` records summarize deletions, so an audit row may name an evidence object no longer stored. SQLite reuses freed pages; shrinking the file requires a separately chosen `VACUUM`.

The manual path is `pending -> approved -> executing -> succeeded | failed | needs_attention`; auto permits `pending -> executing`. Expired/changed bindings become stale, while policy rejection is a denied action, never successful remediation. Final plans cannot execute again. A confirmed pre-mutation failure is `failed`; timeout, interruption after mutation may begin, partial state and failed verification are `needs_attention`.

Claim a plan atomically with a conditional update in `BEGIN IMMEDIATE` and an audit event. Hold the target lock across revalidation, claim, mutation and verification. Native target coordination is local and shared across all SQLite databases; simulator coordination belongs to its disposable state. Under the target lock, publish and flush a durable gate before committing `executing` and before mutation. Any retained gate blocks every subsequent plan on that target; no timeout lease permits blind takeover.

Publish a complete gate through a private preparation file, exclusive hard link and directory flush. Readers accept a two-link crash state only when the second link is the reserved same-inode publication alias. Unknown links remain rejected. Recovery removes the recognized alias before the gate; an unpublished preparation file can be discarded only under the target lock when no gate exists. Abrupt-process tests do not prove physical power-loss durability.

Reload policy, plan integrity, source health/provenance/freshness, inventory identity, generation, approval/plan expiry and allowlists before claiming. Collect fresh backend inventory and require the full fingerprint and resolved artifact/transaction to match. Recheck policy and time after preparation immediately before mutation. Engine receives a policy callable; the CLI supplies a protected-file loader, not a construction-time snapshot.

Execution holds a write transaction from post-claim validation through preparation, installation, verification and outcome commit. Concurrent head/approval writers can receive a busy-timeout error. `queue`, `audit` and `recovery-status` use deferred reads and remain available. Poll fetch/parse occurs outside the transaction, then installs only if the source revision is unchanged; a race discards the response, records an error and requires another poll. This is not a high-throughput fleet store.

Record start before mutation. Afterward recollect and require the exact full package-state delta, then commit inventory, result and audit together. Exit zero without matching state is not success. Clear the gate only after durably committing verified success or confirmed pre-mutation failure. Uncertainty, failed persistence and crashes retain it. Audit records contain bounded identities/reasons, not credentials, unrestricted environments or raw command output.

### Recovery and generation

If recording the execution claim raises before commit, withdraw the newly published gate with `cancel`; mutation could not have run. Interrupted gate publication or uncertain commit retains it. A retained matching gate with a pending/approved plan establishes that the claim never committed; `recover` records `failed`, commits, rotates generation and clears the gate. For abandoned `executing` work, recovery records `needs_attention` and retains the gate; it neither replays nor declares success.

`resolve-recovery` requires explicit actor/reason attestation after external investigation. It checks the gate and locks, rotates a durable target-wide generation before gate removal, and never turns an old failure into success. Actual backend collection records that generation separately from immutable inventory. Imports cannot supply collection authority. Planning and execution require current collection/plan generations, forcing fresh collection and a new plan across all databases, even in the same second.

`generation()` is a lowercase SHA-256-shaped token, initially 64 zeroes if absent. Unsafe or malformed generation files require external inspection. A normal gate is exactly `{"plan_id": ID}`. A valid gate for a different plan cannot be overridden. A bounded malformed regular gate may return `{"malformed": true, "digest": RAW_SHA256}`; clearing it requires the exact current `malformed_digest` plus attestation. Because it cannot identify a prior plan, this override finalizes only a named `executing` plan, leaving pending/approved rows unchanged but stale by generation. Missing/wrong gates cannot finalize valid plans. Recovery results retain `verified=false` and distinguish verified prior-plan identity from malformed-evidence attestation.

Native recovery also acquires the package-manager locks to exclude a surviving child. Package downgrades are not universal rollback. Scripts, data migrations, configuration changes, service effects and unavailable old artifacts require asset-specific recovery or replacement.

## Backends

The backend protocol is:

```python
name: str
inspect() -> dict
generation() -> str
resolve(inventory: dict, finding: dict, policy: dict) -> dict
lock(asset_id: str, *, recovery: bool = False) -> context manager
begin(plan_id: str) -> None
cancel(plan_id: str) -> None
finish(plan_id: str, outcome: str) -> None
clear_gate(plan_id: str, resolution: str, *, malformed_digest=None) -> None
apply(target: dict, policy: dict, *, before_mutation: callable) -> dict
```

`resolve` does not mutate the host. `lock` refuses retained gates except for recovery. `apply` repeats backend checks and invokes `before_mutation()` after preparation, immediately before installation. Returned backend evidence does not replace independent `inspect` verification. Constructor-only fake runner/filesystem injection exists for tests, not CLI provenance overrides.

### Simulator

Initialize private disposable JSON containing an inventory and synthetic repository catalog. Hidden names and `.lock`, `.gate`, `.generation` suffixes are reserved. Descriptor-relative traversal checks original parent components before normalization so `..` cannot erase an unsafe ancestor. Never derive a state path from a feed field or plan ID. Writes are atomic under the target lock.

Catalog targets have the same fields as native targets, but synthetic hashes are not download claims. Explicit `before_write` and `after_write` failure modes demonstrate confirmed failure versus uncertain mutation. Successful apply changes the target binary/source version and observation time. The demo must cover manual and automatic success, unapproved/repeated execution denial, failure, retained gates and generation-bound recovery without invoking native tools.

### Ubuntu APT/dpkg

The target is local Ubuntu 24.04 LTS noble amd64. Missing tools or unsupported configuration block native work, not simulation or investigation. No update of the development host is part of verification.

1. Read inventory and reject wrong identity/platform, incomplete metadata, unsettled package state, held/sensitive targets and unsupported target architecture.
2. Resolve from local APT policy and authenticated repository evidence. Require approved standard Ubuntu sources, exact source identity, SHA-256/size, fresh signed indexes and an increasing binary version meeting the source fix. Refuse Pro/ESM targets even if locally entitled. Index refresh is separately authorized; never hide `apt-get update` in read-only collection or planning.
3. Simulate the exact pinned request and allow only the sole planned binary change. Reject removals, downgrades, new packages, dependencies and unrelated upgrades. Conservatively reject nonempty `Conflicts`, `Breaks` and `Replaces`; a singleton request can otherwise remove packages or take over files.
4. Revalidate at execution and download through APT's authenticated path into a new private staging directory. Check actual hash, size, binary identity/version/architecture and source identity. No download URL or local artifact path comes from advisory prose.
5. Hold the native frontend lock through final checks and installation. Install only that artifact using fixed `dpkg --force-confdef --force-confold --install` arguments. Reject unsafe relationship fields again on the artifact. Scripts/triggers can still affect services and data; policy acknowledges rather than eliminates those effects.
6. Recollect the entire package database and compare the singleton delta. Any missing/extra package, unrelated drift or non-ready state is `needs_attention`, not success. Do not automatically downgrade or execute feed-supplied health commands.

The runner's frontend-lock context must not independently open/close the same lock inode: POSIX record locks are released when any descriptor for that inode closes. Set `DPKG_FRONTEND_LOCKED=true` only when the trusted runner actually holds the frontend lock. Native recovery additionally takes `/var/lib/dpkg/lock`. Actual acquisition/handoff remains an Ubuntu qualification gate.

### Native prerequisites and implemented limits

The application requires Python 3.12 or newer. The isolated helper uses `/usr/bin/python3 -I` with system `python3-apt` (`apt`, `apt_pkg`, `apt_inst`); these bindings are not application-interpreter dependencies. Native tools include `/usr/bin/dpkg-query`, `/usr/bin/dpkg`, `/usr/bin/apt-get`, `/usr/bin/gpgv` and `/usr/lib/apt/apt-helper`. Armored `.asc` Signed-By files also need `/usr/bin/gpg`; binary `.gpg`/`.pgp` files do not. Noble runtime compatibility must be tested rather than inferred from their presence.

Signature work uses a private temporary home under `/tmp`. Armored keys are copied from protected files and converted with fixed `gpg --dearmor` arguments disabling user configuration, agent startup and remote retrieval. Input/output are capped at 4 MiB, and conversion/verification each have a 30-second timeout. File-size limits apply only to the conversion child of the isolated helper. Normal unwinding removes scratch state; forced death can leave it.

APT source handling supports explicit HTTP/HTTPS binary sources, `.list` and deb822 `.sources`, with approved Signed-By files under `/usr/share/keyrings` or `/etc/apt/keyrings`. Skip `deb-src` and disabled stanzas; they cannot supply binary candidates. Ubuntu standard components are `main`, `restricted`, `universe` and `multiverse`, but being in a recognized component does not establish advisory coverage or authorization. Exact origins, standard pockets and the configuration digest still need independent review. Pro/ESM, third-party sources and unsupported pockets cannot be used to bypass a missing standard-archive fix.

HTTP transport is not the integrity authority: source-specific signatures, Packages hashes, artifact hashes and freshness checks are required. HTTP reveals package fetches and permits withholding/replay within the accepted freshness window. Prefer HTTPS where those risks matter. Reject non-default ports, credentials, query strings, fragments and percent escapes. Every contributing Release must satisfy its own date/expiry; deduplication must not discard earlier constraints. Keep at most 1,024 release records and recheck retained time bounds after the final authorization callback.

The configuration digest covers `/etc/apt`, `/etc/dpkg` and `/usr/share/keyrings`. Root-owned symbolic links may resolve only within checked roots; key aliases must stay in approved keyring directories. Link text and resolved file bytes are fingerprinted. Escaping/dangling/unowned links fail. The metadata digest covers `/var/lib/apt/lists`, excluding lock, partial and auxiliary-cache entries. Reject configuration redirection, insecure trust/date overrides and external includes. Supported dpkg configuration is limited to comments, `no-debsig`, `log /var/log/dpkg.log` and path filters confined to documentation-like `/usr/share` trees (`doc`, `man`, `info`, `locale`, `lintian`, `linda`, `groff`, `help`) with no `..`. Filters affecting executable payload could leave vulnerable files despite a changed package version and are rejected.

`autoprotect native-config` runs the read-only helper configuration report. It prints the digest, parsed source/key-file digests and signed origin tuples, with missing local InRelease records identified and `approved: false`. It writes no policy/state and grants no approval. Operators independently review the configuration and key lineage before provisioning policy. The native metadata investigation observed a base noble Release `Date` of 2024-04-25 and no `Valid-Until` in the inspected noble, noble-updates and noble-security metadata. These are dated observations, not a guarantee about future metadata. Repository age does not block native inventory or `native-config`. Only metadata contributing the exact candidate version is checked during planning/execution: an older base package does not block a newer security candidate, but a stale base record for that same candidate version does. This design recommends no universal `max_repository_age` value. Refreshing local indexes does not change a publisher's Release date, and widening the accepted age also widens replay acceptance when no earlier expiry applies.

Every native inventory record must have a settled dpkg state: installed (including held/marked-for-removal) or removed with retained configuration (`deinstall-config-files`, `purge-config-files`, `unknown-config-files`). Foreign-architecture packages may be present; the unique target must be fully installed, unheld and `amd64` or `all`. Unpacked, half-installed/configured, trigger-pending and reinstall-required states block mutation.

Every effective-root CLI invocation, including demo and configuration observation, checks the code it will run before reading policy/state or invoking the helper. The complete `autoprotect` package, helper and bytecode caches, existing module search paths/importable files and ancestors must be root-owned, not group/world writable and symlink-free; root-owned sticky ancestors are excepted. Missing paths require a trusted nearest existing ancestor. User-owned checkouts, virtual environments and current-directory imports fail. Third-party module contents, `.pth` files and access-control lists inside trusted directories remain provisioning assumptions. Do not claim stock Ubuntu directory compatibility before checking it on an authorized disposable image.

Native coordination paths are `/var/lib/autoprotect/targets/local.lock`, `local.gate` and `local.generation`, independent of SQLite selection. Gate records are capped at 4,096 bytes, generation records at 256 bytes. Download staging is a new private child and is never reused. Artifacts are capped at 256 MiB, uncompressed package indexes at 512 MiB, configuration hashing at 32 MiB and aggregate metadata hashing at 2 GiB. Probe/transaction commands have 120-second execution deadlines, download preparation 300 seconds and installation 900 seconds. These are per-operation bounds, not a total plan deadline.

The runner uses absolute executables, argument arrays, `shell=False`, a minimal environment, controlled working directory and bounded output (16 MiB by default). It terminates process groups on timeout/error. After leader exit it waits at most one second for inherited pipes; a timely exit takes precedence over the execution deadline during that grace. Remaining descendants are killed except when `keep_descendants=True` and exit status is zero; only successful native installation uses this to preserve maintainer-script services.

Validation precedes spawn. Startup/handshake exceptions are conservatively indeterminate once startup is attempted, even for a missing executable or working directory. The runner owns the process object before initialization and defers callable SIGINT handlers across spawn/cleanup. Pending interrupts are checked during output waits, but native startup cannot be forcibly time-bounded here. Cleanup does not contain SIGKILL, host/interpreter death, arbitrary raising signal handlers or detached descendants. Supervision and durable gates remain necessary. Temporary cleanup must not erase operator files or hide an uncertain outcome.

## Module ownership and integration contracts

| Module | Responsibility |
| --- | --- |
| `core.py` | Validation, canonical JSON/digests and application exception classes |
| `feeds.py` | `parse_pwn`, `parse_ubuntu(data, release="noble")`, `parse_source(source, raw)` and bounded fixed-source fetch; normalize USN source assertions without granting authority |
| `inventory.py` | `normalize_inventory`, `inventory_fingerprint`, `collect_local` |
| `versions.py` | `compare_versions(left, right)` returning -1, 0 or 1; unsupported syntax raises `ValidationError` |
| `matching.py` | Grouped `match` results and targeted `verify_affected`; uncertainty never becomes authority |
| `runner.py` | Bounded `Runner.run` and native frontend-lock context |
| `backends.py`, `_apt_probe.py` | `Simulator`, `UbuntuApt` and isolated APT inspection/artifact operations |
| `store.py` | Transactional local persistence and immutable evidence integrity |
| `engine.py` | Strict policy and lifecycle authorization; CLI uses Engine rather than direct SQL |
| `cli.py`, `__main__.py`, `demo.py` | Protected command boundary, multiprocessing-safe entry point and disposable demo |

`Engine.ingest` is import-only. Callers cannot grant HTTPS provenance by supplying an acquisition string, validator or envelope. Only a successful `poll` through the fixed adapter records HTTPS authority. Clock/fetcher/runner injection is constructor-only for tests, not a CLI override.

CLI-facing returns are: source-health summaries for ingest/poll; `{id, body}` inventory; a finding list for triage; `{id, body, status}` plans/approvals/queue rows; `{plan_id, status, result, inventory_id}` execution; structured audit/export and recovery records. Recovery status includes `plan_id`, `asset_id`, `status`, `gate`, `generation`, `prior_plan_identity_verified`; resolution remains `verified=false`.

## CLI implementation contract

`python3 -m autoprotect` and the installed `autoprotect` entry point expose the same interface. Operational commands require explicit global `--state-dir DIR --policy FILE` before the subcommand. Policy alone selects the backend. `--live` is required for native execution/recovery-lock commands and rejected for simulation. It does not grant permission to other commands. Help, version and the self-contained demo do not require policy/state or open native state.

| Command | Arguments and behavior |
| --- | --- |
| `init-simulator` | `--inventory FILE --catalog FILE`; exclusive disposable initialization |
| `import-feed` | `SOURCE FILE`, with `pwn` or `ubuntu`; import provenance only |
| `poll` | `SOURCE`; bounded fixed-source acquisition; nonzero on source-health error |
| `inventory` | Optional `--import FILE`; otherwise selected-backend collection with generation context |
| `triage`, `export` | `ASSET_ID`; findings or untrusted advisory envelope |
| `plan` | `FINDING_ID`; immutable plan |
| `approve` | `PLAN_ID --actor LABEL`; manual approval, not authenticated identity |
| `execute` | `PLAN_ID`; current manual/automatic authorization; nonzero for failed/uncertain outcomes |
| `queue`, `audit` | Persisted structured records |
| `recovery-status`, `recover` | `PLAN_ID`; native recovery locks require `--live` |
| `resolve-recovery` | `PLAN_ID --actor LABEL --reason TEXT [--malformed-digest SHA256]` |
| `native-config` | Read-only configuration observation, no global options or implicit approval |
| `demo` | Isolated synthetic state; no global options, network or native commands |

Errors are bounded JSON on stderr; argument errors use exit 2, application/source/execution errors exit 1 and interruption exit 130. Exit 0 from recovery means that operation completed, not successful remediation. Explicit flush/closure avoids retrying a failed interpreter-owned stream during shutdown; caller-owned capture streams remain open. Output failure can follow a committed operation: inspect persisted state before retrying.

Policy reload uses protected file reads. A backend change cannot switch an already constructed backend. Inventory/catalog inputs are capped at 64 MiB and policy at 1 MiB. Feed fetch/import/parser limits are 8 MiB for pwn and 512 MiB for Ubuntu. No raw SQL, custom endpoint, shell command or test injection is exposed. Backend construction is deferred until needed, so feed/queue/audit/triage/export do not silently collect a native inventory. Imported JSON null is rejected, not converted into a collection request.

Inputs cannot occupy fixed database/simulator/coordination paths or publication aliases. Collision checks equate Linux `/` and `//` spellings while preserving each original path component for protected traversal. `init-simulator` must precede other commands in a new state directory; failed setup can leave private state and is not permission to delete files of uncertain ownership.

The demo invokes ordinary CLI processes across four disposable scenarios and checks queue, audit, inventory, exact denial reasons and recovery generation, not just exit codes. Engine-audited denials require newly appended matching events; retained-gate denial uses gate/queue evidence. Child interpreters use `-B`; the invoking interpreter needs `-B` or `PYTHONDONTWRITEBYTECODE=1` for the same cache guarantee. Each command is bounded to 15 seconds and 256 KiB output, with a 120-second session budget, 128-command ceiling and 8 KiB result. The Ubuntu module and installed-console demos each passed 101 commands; this count comes from the Ubuntu candidate, not an inherited result. Normal unwinding removes temporary state; forced death can leave it. Cleanup failure cannot yield a success summary.

## Deployment and proposed production evolution

Private policy/database files use mode `0600` and state directories `0700`, owned by the invoking user; live mode additionally requires root. Ancestors must be owned by root or that user and not writable by others, except root-owned sticky temporary directories. Descriptor-relative no-follow traversal rejects symlinks, hardlinked/non-regular inputs and oversized reads. Only the final requested directory and fixed SQLite file are created; sidecars are checked too. These rules protect against other users, not the trusted owner or root racing its own files.

Direct observation is unprivileged where package metadata permissions permit; protected native generation state may require root for Engine collection. Privileged execution is a separately invoked command, not a listener. Before any deployment, qualify the Ubuntu bindings, signatures/indexes, downloads, locks, installation, interruption and recovery on a separately authorized disposable target. Package verification alone does not close runtime-health or production gates.

Proposed production work separates collector/planner/minimal-executor roles, authenticates enrollment/approvals, provisions least-privilege accounts, centralizes protected audit and uses signed time-bound action envelopes. Fleet work also needs cloned-identity/replay handling, distributed coordination, maintenance windows, canaries, blast-radius limits, backups, secret rotation and per-service activation/health checks. Application/container remediation should rebuild approved artifacts and roll out immutable digests through existing deployment controllers.

External polling must avoid overlap, bound retries and alert on stale sources, unknown coverage, waiting approvals and `needs_attention`. Public feeds are downloaded without uploading inventories. Jouzu may consume untrusted exports to investigate and propose changes; optional TextGuard inspection does not make cleaned text authoritative. Neither is a runtime dependency or a mechanism to change policy, fabricate provenance or approve itself.

## Acceptance evidence

Verify the integrated package and user-facing paths, not only helpers. Required cases include source spoofing, malformed/hostile data, Ubuntu release/source mapping, epochs/backports, Pro/ESM exclusion, missing/unsupported evidence, stale inventory/approval, changed policy/target, manual and automatic success/denial, concurrency, download failure, interruption, failed verification and recovery limits.

Independent review must inspect the complete acquisition-to-execution boundary. Record exact candidate identity, checks and unresolved limits in [REVIEW.md](REVIEW.md) and the immutable worklog. Fake-native tests establish behavior under their substitutions, not an actual Ubuntu repository download or privileged update.
