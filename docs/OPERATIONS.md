# Operator runbook

## Scope and evidence

Autoprotect is a single-operator, local proof of concept. Use the [disposable simulator procedures](../examples/README.md) to exercise its workflow. **Production-readiness gates remain unmet. The native procedures in this runbook are conditional command contracts, not tested deployment instructions or authorization to change a host.**

Offline evidence includes 452 passing tests, reviewed runtime APIs, synthetic native-command tests, manual and automatic simulator workflows, 101-command module/installed-console demos, and offline wheel/source builds. Independent implementation reviews and repair re-reviews are complete. See [REVIEW.md](REVIEW.md) for exact checks and limits and [DELIVERY.md](DELIVERY.md) for final documentation/acceptance status.

No real APT resolution/download, native lock handoff, privileged installation, private host inventory, application-health check or production rollout was verified by those offline workflows. Source research belongs in [SOURCES.md](SOURCES.md). Detailed schemas, security assumptions and resource limits are in [DESIGN.md](DESIGN.md).

## State, policy and operator authority

Every operational command requires `--state-dir DIR --policy FILE` **before** the subcommand. The policy selects `simulator` or `debian-apt`; there is no command-line backend override. `python3 -m autoprotect` and the installed `autoprotect` command expose the same interface. The application requires Python 3.12 and POSIX file controls.

The examples below use shell variables that the operator must set to reviewed local paths and returned identifiers:

- `state_dir`: private directory for this database; parents must already exist.
- `policy_file`: private policy JSON, separate from writable application state.
- `asset_id`: exact `body.asset_id` returned by collection, not a guessed hostname.
- `finding_id`: an actionable finding's `id` from `triage`.
- `plan_id`: the immutable `id` returned by `plan` or shown by `queue`.
- `actor_label`: a printable ASCII audit label, at most 128 characters. It is **not authenticated identity**.

For non-live commands, this shell function only abbreviates the supported interface; it grants no permission:

```bash
ap() {
  python3 -m autoprotect --state-dir "$state_dir" \
    --policy "$policy_file" "$@"
}
```

### Private files

Use an invoking-user-owned state directory with mode `0700` and policy/database files with mode `0600` (or stricter permissions that still permit the operation). With `--live`, effective root and root-owned private state/policy are required. Ancestors must belong to root or the invoking user and not be writable by others, except root-owned sticky temporary directories. The CLI rejects symlinks in path components, hardlinked/non-regular input files and oversized reads. It does not repair ownership or permissions for you.

The CLI creates only the requested final state directory and its fixed `state.sqlite3`; SQLite sidecars are checked too. Simulator state is `DIR/simulator.json`, with adjacent `.lock`, `.gate` and `.generation` files. Fixed state names and reserved publication files must not contain policy or imported data. Do not move inputs into those names to work around a path rejection. `init-simulator` must be the first operation in a new simulator directory; it refuses existing fixed state. After failed setup, inspect retained files and choose a fresh disposable directory rather than deleting files of uncertain ownership or purpose.

Policy, database, coordination state, inventories and exports are administrator-controlled private material. A writer to policy or SQLite can control this local program; hashes bind content but do not authenticate that writer. File checks protect against other local users, not root or a malicious trusted owner. There is no credential store, multi-user approval service or remote enrollment mechanism. Do not put credentials in policy, actor labels, recovery reasons, worklogs or shared exports.

### Modes and approval

Use the exact [policy schema](DESIGN.md#policy-plans-and-approval). All fields are required; missing/extra fields fail validation. Even an observation policy needs nonempty `allowed_assets` and `allowed_packages`. Native policies also require exact `allowed_origins` and `approved_config_digest`; no automatically trusted native policy is supplied.

| Policy `mode` | Boundary |
| --- | --- |
| `observe` | Acquisition, import, collection, triage and investigation remain available. Planning may succeed if its other prerequisites hold; approval and execution are denied. Observation is not a dry-run permission to mutate. |
| `manual` | A plan needs explicit `approve` before `execute`, plus all execution-time checks. |
| `auto` | `execute` may claim a pending plan without manual approval. It still requires exact allowlists, fresh evidence, approved repositories, matching inventory and target, and verification. It does not schedule or invoke itself. |

The CLI reloads the protected policy at sensitive boundaries. A policy change, including a mode change, invalidates a plan bound to the old digest. Do not switch a manual plan to auto to bypass approval; create a new plan under the intended policy. Changes to inventory, advisory evidence, repository target, recovery generation or expiry likewise require fresh authorization as applicable. See the [plan lifecycle](DESIGN.md#persistence-serialization-and-execution-lifecycle).

Approval binds an immutable plan, not a package name or an open-ended maintenance session. Inspect its complete `body`, including `asset_id`, `inventory_id`, `inventory_fingerprint`, `source_digest`, `policy_digest`, `target_generation`, `target` and `expires_at`. The target includes binary/source versions, artifact SHA-256 and size, exact origins, and configuration/metadata digests. Approvals expire no later than the plan. Typed `--actor` labels record an assertion by whoever can invoke the program with access to its files.

## Native scope and prerequisites

These requirements describe the implemented `debian-apt` boundary, **not a completed deployment qualification**:

- Local Debian 13 (`trixie`) on `amd64`, with a complete, nonempty native inventory. Every package record must be a ready installed Debian package of architecture `amd64` or `all`; the target must be uniquely installed and unheld. Imported/remote asset labels cannot select a native host. Native identity derives from the local machine ID; cloned identities require separate operational handling.
- One affected binary package with an ordinary Debian source-version fix per plan. The candidate must increase its binary version, preserve source identity and meet the source fix using Debian version ordering. Distribution backports and binary rebuilds are not compared as upstream version strings.
- No newly installed packages, dependency upgrades, removals, downgrades or unrelated changes. Essential targets and sensitive kernel/boot/package-manager/core-service-manager packages are excluded. The exact name, prefix and source exclusions are `_SENSITIVE`, `_SENSITIVE_PREFIXES` and `_SENSITIVE_SOURCES` in [backends.py](../autoprotect/backends.py). Nonempty `Conflicts`, `Breaks` or `Replaces` fields also require external maintenance. An allowlist does not override these restrictions.
- Fixed native tools: `/usr/bin/dpkg-query`, `/usr/bin/dpkg`, `/usr/bin/apt-get`, `/usr/bin/python3`, `/usr/bin/gpgv` and `/usr/lib/apt/apt-helper`. The system Python must provide distribution `python3-apt` bindings (`apt`, `apt_pkg`, `apt_inst`); they are not application-interpreter dependencies. Armored `.asc` key files additionally need `/usr/bin/gpg`. Provisioning these prerequisites is a separately authorized operation, not part of the simulator.
- One to 64 explicit enabled HTTPS binary sources, parsed from `/etc/apt/sources.list` and `.list`/deb822 `.sources` files in `/etc/apt/sources.list.d`. Supported codenames are exactly `trixie`, `trixie-updates` and `trixie-security`, with `amd64` indexes. Supported components are `main`, `contrib`, `non-free` and `non-free-firmware`. Moving suite names alone do not authorize a source.
- Each source needs an explicit `.gpg` or `.asc` `Signed-By` file directly under `/usr/share/keyrings` or `/etc/apt/keyrings`. Plain HTTPS archive URLs cannot contain credentials, query strings, fragments, percent escapes or nonstandard ports. Unsupported source options, insecure trust/date overrides, redirected configuration and external includes are rejected. Supported dpkg configuration is limited to comments, `no-debsig` and `log /var/log/dpkg.log`. See [native prerequisites and limits](DESIGN.md#native-prerequisites-and-implemented-limits) and [the source/configuration parser](../autoprotect/_apt_probe.py).

### Review repository configuration and installed lineage separately

The administrator must review source identities, signing keys, APT configuration and hooks outside the application. Native configuration/key files and their checked directories must be root-owned, not group/world writable, and not symlinks. `allowed_origins` consists of exact `{origin, label, archive, codename, component, site}` tuples. A familiar mirror name or a feed link is not sufficient approval.

`approved_config_digest` must bind the independently reviewed configuration. The implementation fingerprints `/etc/apt`, `/etc/dpkg` and `/usr/share/keyrings`; the plan separately binds `target.metadata_digest` for `/var/lib/apt/lists` excluding `lock`, `partial` and `auxfiles`. These digests use the helper's canonical file-record algorithm, not a plain checksum of one source file. The CLI has **no configuration-digest bootstrap or approval command**. Establishing a reviewed value through a separately designed and verified provisioning procedure is an unresolved native rollout prerequisite. Do not copy an observed digest into policy merely because a candidate supplied it, and do not invoke the private helper as an undocumented trust bootstrap.

The backend verifies signed InRelease and Packages evidence and checks every contributing release's date/expiry against `max_repository_age`. It does not refresh indexes. Repository refresh is external, explicitly authorized maintenance; neither `poll` nor a planning command performs an implicit `apt-get update`. Changed configuration requires review and a new policy digest. Changed index/artifact state requires replanning and renewed authorization, not editing a stored plan.

Native planning/execution require `allow_maintainer_scripts`, `recovery_confirmed` and `trusted_installed_lineage` all to be true. Set them only after reviewing script effects, preparing an asset-specific recovery procedure, and independently establishing an unmodified Debian-managed installation. They are assertions, not verified backups or installed-byte authentication. Matching dpkg name/version fields do not prove repository origin or absence of compromise. Unknown or modified lineage calls for investigation or rebuilding from trusted artifacts, not setting the flag to silence a denial.

## Acquisition, inventory and coverage

These are command templates for an already configured private state. They do not establish native prerequisites or authorize a network request in an offline environment.

```bash
ap poll pwn
ap poll debian
```

`poll` makes one bounded HTTPS acquisition from a fixed endpoint: `pwn` uses `https://pwn.watch/incidents.json`; `debian` uses `https://security-tracker.debian.org/tracker/data/json`. There is no endpoint override. pwn is incident context and prioritization, not patch authority; Debian provides supported release/source assertions. Neither feed selects executable code, repositories or download URLs.

For offline investigation or simulation, use local source-format files instead. `feed_file` and `inventory_file` below are bounded regular JSON inputs, not acquisition envelopes:

```bash
ap import-feed debian "$feed_file"
ap inventory --import "$inventory_file"
ap triage "$asset_id"
ap export "$asset_id"
```

`import-feed pwn FILE` is also supported. Imports always have import provenance regardless of claimed URLs or collector labels. Importing Debian data into a native workflow replaces its current source head with imported evidence; a successful fixed-endpoint Debian poll is required before native remediation. Inventory imports similarly clear collection authority for that asset. Backend collection, without `--import`, is required for planning:

```bash
ap inventory
ap triage "$asset_id"
```

For a simulator this observes only synthetic state. For a native policy, `inventory` reads the real local identity/package database and records generation context; do not run it without authorization to collect that host. Collection does not need `--live`, but existing protected root-owned native generation state requires root access. Feed/import/queue/audit/triage/export commands defer backend construction and do not silently inventory the host. They can still create or update local SQLite state; `export` reruns triage and persists its affected findings.

Check both source health and finding reasons. `poll`/`import-feed` return health including `last_attempt`, `last_success`, `error`, `acquisition`, `endpoint` and `snapshot_id`; `export` exposes stored summaries under `sources`. There is no separate source-health command. A failed acquisition keeps the last good snapshot and success time and records an error. A successful conditional 304 refreshes contact time, not publisher dates. Identical snapshots are deduplicated. A current Debian error or stale success blocks remediation even if older good data exists. Refresh successfully, then triage and replan; do not replace the error with a synthetic successful import for native use.

Treat missing/stale/future-dated inventory, unsupported platforms/ecosystems, missing coverage, unsupported version semantics and temporary Debian identifiers as uncertainty. Each finding covers the advisories in its `advisory_ids` list. A package's affected advisories are grouped by Debian fixed version, so one finding (and one plan) covers every advisory that the same upgrade resolves; to check one CVE, search `advisory_ids`. `affected` without a supported fixed version is not executable. `not_affected` applies only to the listed supported assertions. `evidence_acquisition` shows whether verdicts came from fixed-endpoint HTTPS polling or an import; imported verdicts are investigation data and cannot authorize native execution. An empty result or a successful update is not evidence of universal safety. Stale pwn context may remain visible; it never substitutes for fresh Debian evidence. Incidents involving compromise, credentials or persistence need a separate incident-response procedure.

### External polling and alerting

No scheduler, retry daemon or service is installed. A proposed starting cadence is one poll of each source every 15 minutes, adjusted to reviewed freshness policy and operational needs. A future external timer must:

1. Serialize invocations for the same database, avoid overlap with long execution transactions, and keep a bounded retry budget with capped backoff and jitter. Retry acquisition failures, not remediation blindly.
2. Check exit codes **and** JSON health. Alert on sustained errors, time since `last_success` approaching/exceeding `max_feed_age`, missing inventory or unknown coverage, waiting approvals and `needs_attention`.
3. Keep failure history and last-good evidence; reconcile by a successful full/conditional refresh after an outage. Do not clear findings because a source failed.
4. Capture protected summaries and distinguish source lag, policy denials, execution duration and verification failure. Do not send private inventories to public monitoring services. The built-in feed requests do not upload inventories.

Polling fetches and parses without holding the SQLite write lock. If another import or poll changes the same source head meanwhile, the late response is discarded with exit status 1 and a `source-error` audit event; poll again. Scheduling, supervision, alert delivery and their failure tests must be supplied externally; this runbook does not install them or claim they work.

## Controlled rollout and execution

### Simulator first

Use [the manual and automatic examples](../examples/README.md) in separate disposable directories. They include exclusive `init-simulator --inventory FILE --catalog FILE`, synthetic feed import, collection and verification. Never adapt those synthetic origins/hashes into native trust. The self-contained `python3 -m autoprotect demo` accepts no state directory, policy or live flag and cleans its generated state on normal completion. Forced process/host death can leave temporary files. For a cache-free invoking interpreter, use `python3 -B -m autoprotect demo`; the demo already disables bytecode writes in its children.

### Conditional native sequence

Do not begin until the native qualification gates in this runbook are satisfied and an operator has separately authorized the exact target, maintenance window, recovery method and live operation. Start with observation, then one manually approved nonsensitive package on a disposable qualified target. Promotion to `auto` requires a separate policy decision after that evidence; it is not justified by simulator success.

1. Establish private state and independently reviewed policy, sources, keys, hooks, lineage and recovery prerequisites. Complete separately authorized index refresh. Stop if the configuration fingerprint cannot be established through a reviewed procedure.
2. Acquire fresh Debian evidence, collect the selected backend's actual inventory and triage its returned asset ID. Investigate unknowns and select an affected finding with a supported fix.
3. After the observation phase, provision the reviewed manual policy before creating the plan you intend to execute. A plan made under `observe` cannot be reused after changing mode. Create and inspect the immutable plan:

   ```bash
   ap plan "$finding_id"
   ap queue
   ```

4. Under a manual policy, approve that exact plan after inspecting the target and bindings:

   ```bash
   ap approve "$plan_id" --actor "$actor_label"
   ```

5. Execute only in a separately authorized effective-root invocation, with all operational options before `execute`:

   ```bash
   python3 -m autoprotect --state-dir "$state_dir" \
     --policy "$policy_file" --live execute "$plan_id"
   ```

   `--live` is mandatory for native `execute`, `recovery-status`, `recover` and `resolve-recovery`. It is rejected for simulation. For the simulator, use `ap execute "$plan_id"` without it. Auto mode omits step 4, not the checks in steps 1–3 or execution-time authorization.

6. Inspect the execution JSON, then `ap queue`, `ap audit`, `ap inventory` and `ap triage "$asset_id"`. Require `status=succeeded` and `result.verified=true` from execution for package-state success. If output was lost, investigate persisted queue/audit and recovery state before deciding what happened; do not replay the plan to obtain output.

Execution rechecks the current policy, evidence, approval/plan deadlines, generation, full inventory and exact repository target. It downloads only the pinned authenticated artifact into private staging, checks its hash/size/identity, then uses fixed `dpkg --force-confdef --force-confold --install` arguments under native locking. Conffile handling takes the default answer and preserves local changes when no default is available. This is not a promise that scripts cannot alter services or data.

Successful verification compares the full package inventory with exactly the authorized single-package binary/source-version change. It does **not** prove the updated binary is running, an application is healthy, a kernel is active, installed bytes are authentic, or compromise is removed. Service checks, restarts, reboot decisions and incident response require separately reviewed procedures; there is no generic health-command facility.

## Exit codes and durable outcomes

Successful command output is JSON with escaped control/non-ASCII characters, except plain-text help/version. Errors are bounded JSON on stderr as `{"error":{"code":"...","message":"..."}}` when stderr is usable. Do not equate a process exit with the execution outcome.

| Exit | Meaning and next action |
| --- | --- |
| `0` | The requested CLI operation returned successfully. Only execution's verified `succeeded` result establishes its package-state outcome. Successful `recover` may return `needs_attention`; successful `resolve-recovery` has `verified=false`. |
| `1` | Application, local I/O/state or output failure; a poll health error; or an execution result other than `succeeded`. Inspect the structured result/error. Output failure can occur after a committed action; query queue/audit and recovery state before any retry. |
| `2` | Argument error. Check `--help`, required arguments and global-option position. No operational dispatch occurred. |
| `130` | Interruption. Inspect queue and recovery state; do not assume mutation never started. |

| Queue status | Interpretation and clearing action |
| --- | --- |
| `pending`, `approved` | Not final; still subject to fresh authorization. A retained gate can exist even here after interrupted publication/claim. Inspect recovery state if blocked. |
| `executing` | Claimed; not a success verdict. If the worker disappeared, follow recovery after excluding surviving processes. |
| `succeeded` | Full expected package-state delta was verified and committed. A gate-clearing failure can still require explicit resolution. Runtime health remains separate. |
| `failed` | Confirmed pre-mutation failure. Inspect the cause, collect fresh state and make a new plan; the final plan cannot be replayed. |
| `needs_attention` | Mutation, verification or recovery requires operator attention. Retain the gate until explicit resolution. |
| `stale` | Bound inputs, collection generation or time constraints changed. Refresh/collect, triage, plan and authorize again; do not edit the old record. |

Policy denials are not successful remediation. Some occur before any Engine audit event; others append `action-denied`. Inspect the actual error and available persisted evidence rather than treating any nonzero exit as a particular safety check.

## Interruption and recovery

A durable target gate is published before claiming a plan and before mutation. It prevents new execution until the prior uncertainty is resolved; it has no expiry lease. Native coordination is independent of `--state-dir`:

- `/var/lib/autoprotect/targets/local.lock`
- `/var/lib/autoprotect/targets/local.gate`
- `/var/lib/autoprotect/targets/local.generation`

Changing databases does not escape a native gate. Execution holds the target lock and `/var/lib/dpkg/lock-frontend` through checking, installation and verification. Native recovery also takes `/var/lib/dpkg/lock` to exclude a surviving package-manager child. Never unlink lock/gate/generation files to clear a busy target. Do not restart execution from a different database.

The recovery commands below are conditional native templates with the same root/live prerequisites as execution. In a simulator, use the corresponding `ap` subcommand without `--live`.

1. Stop external automatic dispatch for this target. Inspect queue/audit from the database that owns the affected plan and establish whether any worker or package-manager process is still active. A successful lock acquisition is a prerequisite, not proof that script side effects were repaired. Do not clear a gate while work survives.
2. Read the gate evidence for a known stored plan:

   ```bash
   python3 -m autoprotect --state-dir "$state_dir" \
     --policy "$policy_file" --live recovery-status "$plan_id"
   ```

   The result contains `plan_id`, `asset_id`, `status`, `gate`, `generation` and `prior_plan_identity_verified`. It writes no outcome or audit event, but it takes recovery locks, performs native observation and may clean an unpublished preparation alias. It is not an entirely side-effect-free file viewer.
3. For abandoned `executing` work with the valid matching gate, record uncertainty:

   ```bash
   python3 -m autoprotect --state-dir "$state_dir" \
     --policy "$policy_file" --live recover "$plan_id"
   ```

   This records `needs_attention` with `result.verified=false` and **retains** the gate. It neither retries installation nor declares success. It is only for `executing`; pending/approved gates, final outcomes and malformed gates need the explicit resolution path after investigation.
4. Inspect and repair the package/application state using the separately authorized asset-specific recovery procedure. Preserve evidence. Autoprotect has no rollback command and does not automatically downgrade or repair dpkg. Recovery may require restoring data/configuration or replacing the host, not another package operation.
5. Resolve the retained gate only after that investigation and recovery decision. `recovery_reason` must be a nonempty printable ASCII explanation, at most 2,048 characters, without surrounding whitespace or secrets:

   ```bash
   python3 -m autoprotect --state-dir "$state_dir" \
     --policy "$policy_file" --live resolve-recovery "$plan_id" \
     --actor "$actor_label" --reason "$recovery_reason"
   ```

   Require `gate_cleared=true` and a changed `target_generation` in the successful result. `verified=false` is intentional: this records an operator attestation, never a new successful-remediation verdict. Nonfinal work becomes `needs_attention`; existing final outcomes are not upgraded to success.
6. Check queue/audit and recovery status again. Collect actual backend inventory, triage and create a new plan; manual mode needs a new approval. Resolution rotates the target-wide generation **before** removing the gate, invalidating all pre-resolution collection contexts and plans across databases, even in the same clock second. An import cannot supply the required fresh collection context. Old queue rows in another database need not change immediately, but cannot gain authority from their old approval.

### Match the evidence, not just the command name

| `gate` evidence | Permitted handling |
| --- | --- |
| `{"plan_id": "ID"}` matching the selected plan | `prior_plan_identity_verified=true`. Use `recover` only for abandoned `executing` work, then explicit resolution after inspection. A gate can also remain with a pending/approved/final plan; resolve it explicitly without inventing an execution result. |
| Valid gate for a different plan | Stop. Locate the matching plan and its database. An override cannot clear another valid plan's gate. There is no CLI recovery without a stored plan; missing owning state requires external recovery investigation. |
| `null` | No unresolved gate was found. Neither `recover` nor resolution can fabricate one or finalize a plan through it. Investigate any disagreement with queue/audit; do not manufacture a gate. |
| `{"malformed": true, "digest": "RAW_SHA256"}` | A bounded regular gate was readable but its contents were invalid. Prior-plan identity is unverified. Investigate the relevant stored plan/asset and explicitly attest this exact evidence using the procedure below. |
| Unreadable/unsafe/oversized gate or invalid generation state | Stop and inspect protected filesystem state externally. The digest override does not bypass unsafe files, unrelated links, ownership failures or malformed generation records. |

For the malformed case only, set `malformed_digest` to the exact digest just returned by `recovery-status`, review the unverified identity, and explicitly request:

```bash
python3 -m autoprotect --state-dir "$state_dir" \
  --policy "$policy_file" --live resolve-recovery "$plan_id" \
  --actor "$actor_label" --reason "$recovery_reason" \
  --malformed-digest "$malformed_digest"
```

The current raw digest must still match. `recover` has no malformed override; it requires a valid matching gate. A successful malformed resolution reports `prior_plan_identity_verified=false`, preserves that distinction in audit, and still rotates generation. Never guess a digest, rewrite the gate into valid-looking JSON, or use the override for a valid gate. If resolution itself is interrupted or persistence is uncertain, inspect gate/generation/queue/audit again; it may have rotated generation or removed the gate before the last event/output was delivered.

Gate publication can leave a reserved hardlink alias after a crash. The backend recognizes only its own same-inode publication alias, not arbitrary extra links. Leave that cleanup to the locked protocol. Physical power-loss durability was not tested; abrupt-process tests do not establish it.

## Troubleshooting without weakening authorization

| Symptom | Clearing action |
| --- | --- |
| Policy/input/state path rejected | Confirm the intended path, all ancestors, owner, restrictive modes, single regular-file link and separation from reserved names. Correct provisioning deliberately; do not use symlinks, alternate slash spellings or broad permissions as a workaround. |
| Debian source stale, missing or in error | Repair network/source availability or the input format, complete a successful fixed-endpoint poll for native use, then triage/replan. Keep last-good evidence. Do not disable freshness or relabel an import. |
| Missing/stale collection context or changed generation | Run actual selected-backend `inventory`, not `--import`, then triage and create/authorize a new plan. |
| Expired approval/plan, changed policy, source or target | Review the changed evidence, recollect as needed, then replan and authorize. Do not extend stored expiry timestamps or alter hashed bodies. |
| No supported candidate, dependency transaction, relationship fields or sensitive package | Keep the finding unresolved and use separately authorized external maintenance. Do not expand this backend's transaction by altering allowlists or using advisory commands. |
| Configuration/lineage mismatch or missing native prerequisite | Independently inspect approved sources, keys, hooks, tools and installed lineage. Review legitimate configuration changes and provision a new policy through the external process; otherwise repair/rebuild. Do not auto-approve observed fingerprints. |
| Target or native package-manager lock busy | Identify the owning operation, wait for its legitimate completion or follow its separate interruption procedure, then inspect recovery state. Never delete a lock file. |
| SQLite busy/state error | Another transaction may be polling or executing. Serialize work and inspect queue/recovery before retrying. Check storage and compatible schema; do not delete the database to obtain a clean queue. |
| Timeout, lost output, interrupted execution or verification mismatch | Use the recovery procedure. A transport/process error is not evidence that installation never started. |
| Schema mismatch or immutable-body hash failure | Preserve state, stop execution and investigate corruption/compatibility. Schema 1 has no automatic migration; do not recreate or hand-edit the store to reuse approvals. |

## Persistence, concurrency and cleanup limits

SQLite schema 3 uses explicit transactions, foreign keys, `synchronous=FULL` and a five-second busy timeout. Opening a schema-2 store migrates it in place without removing records. Execution holds a write transaction from post-claim validation through preparation, installation, verification and outcome commit, so other writing commands (`poll`, `import-feed`, `inventory`, `triage`, `plan`, `approve`) can fail with `state_error` until it finishes. `queue`, `audit` and `recovery-status` read without the write lock and remain usable during execution. This is a local serialized store, not a fleet queue or distributed lock service.

Evidence retention is automatic. Replacing a source head or recording triage deletes source snapshots, findings sets and inventories that nothing retained references, and records an `evidence-pruned` audit event with counts. Snapshots, findings and inventories bound to any plan are kept, as are current heads; plans, approvals, outcomes and audit rows are never deleted. A real Debian snapshot is about 50 MiB, so the steady-state database holds roughly one snapshot per source plus plan evidence. An audit event can name a pruned evidence ID. SQLite reuses freed pages; run `VACUUM` deliberately, with no other command running, if the file itself must shrink.

Content hashes and append-only audit rows help bind actions and detect corruption, but a trusted database writer can subvert them. There is no externally immutable audit sink, backup/restore command, compaction service or tamper-proof approval identity. Establish a separately tested backup/restore procedure before native rollout. Preserve the database, policy and target coordination evidence together; do not restore an old database or generation token and assume old approvals remain usable. A restored system must be reconciled with actual package state before fresh collection/planning.

The runner uses fixed executable paths, argument arrays, a minimal environment and process groups, not shell interpolation. Default combined output is capped at 16 MiB. Native probe/transaction commands have 120-second deadlines, download preparation 300 seconds and installation 900 seconds; these are per-operation bounds, not a total plan deadline. Freshness/approval checks run again before installation. A socket-operation limit of 10 seconds and a 60-second worker deadline bound feed acquisition after worker startup. See [acquisition limits](DESIGN.md#acquisition-and-source-health) and [runner limitations](DESIGN.md#debian-aptdpkg).

Native spawn/exec startup itself is not forcibly time-bounded. Cleanup depends on Python unwinding and working OS controls; SIGKILL, host/interpreter crashes, some custom signal handlers or deliberately detached descendants can escape it. External supervision is needed for a hard wall-clock limit. Expiring a supervisor timer must trigger uncertainty handling, not automatic replay.

Budget disk and memory separately: feed caps are 8 MiB (`pwn`) and 128 MiB (`debian`), while JSON decoding retains whole snapshots and intermediates. Native artifacts are capped at 256 MiB, uncompressed package indexes at 512 MiB, configuration hashing at 32 MiB and aggregate index hashing at 2 GiB. These are input/operation limits, not a whole-process memory or disk quota.

Native downloads use a fresh private `download-` directory under `/var/lib/autoprotect/targets`; signature work uses private `autoprotect-gpg-` directories under `/tmp`. Normal cleanup is attempted, but native download cleanup errors are suppressed so they do not replace the installation outcome; forced death can leave either kind of scratch data. Never reuse leftover downloads. Investigate surviving processes and retain recovery evidence before separately authorized removal of positively identified scratch files. Do not sweep coordination files or operator inputs. Simulator/demo cleanup does not demonstrate native cleanup after a crash.

**There is no universal rollback.** A downgrade cannot reliably reverse maintainer scripts, configuration/data migrations, service effects, removed files or unavailable old artifacts. Backups, replacement deployment and application-specific recovery remain operational prerequisites rather than features certified by `recovery_confirmed`.

## Investigation exports and remaining production gates

`export ASSET_ID` returns `kind=untrusted-advisory-data`, `trusted=false`, a warning, private inventory, source health and findings. It is investigation data, not a shell script, administrator prompt or action envelope. Jouzu or another coding assistant may explain it or propose changes, but cannot use it to select executables, alter policy, create native provenance or approve itself. Optional TextGuard findings do not make cleaned text authoritative. Neither tool is installed or invoked by this runtime.

Before native deployment, qualify the real system-Python bindings, signatures/indexes, authenticated downloads, native frontend/database lock protocol, installation and package verification on a separately authorized disposable Debian target. Include interruption, partial state, failed verification, recovery and storage-loss exercises. The absence of a reviewed native fingerprint-provisioning procedure is a blocker, not permission to invent one during execution.

Production/fleet controls remain proposed work: authenticated operators and asset enrollment, separated collector/planner/minimal-executor roles, signed time-bound action envelopes, least-privilege accounts, protected central audit and tested backups, secret handling/rotation, replay and cloned-identity handling, distributed coordination, maintenance windows, canaries and blast-radius limits, source/coverage alerts, per-service health and activation checks, and incident containment. Application/container updates need their own approved artifact and deployment-controller workflows. See [production evolution](DESIGN.md#deployment-and-proposed-production-evolution); none of these controls is established by a passing simulation.
