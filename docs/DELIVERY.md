# Delivery checklist

This checklist tracks the original assignment: research security feeds and patch information, design the system, build a working proof of concept, and independently review it. Checking a box requires implementation or research evidence, not a plan.

Sections before **Ubuntu LTS retargeting** record the completed baseline and its historical checks. Their test counts and review outcomes do not qualify the Ubuntu migration; current acceptance is tracked separately below.

## Baseline

- [x] Inspect the repository and inherited instructions. The repository had no application files, no commits, and no applicable `AGENTS.md` on inspection. Preserve the existing `.pi/` task state.
- [x] Inspect available runtimes and adjacent harnesses. Python 3.12.13, Node.js 24.16.0, `uv`, `pytest`, and Docker commands are available. Availability does not establish Docker daemon access.
- [x] Discover agent roles. The configured `astra-xhigh` role is available; the session permits eight concurrent children. Use that role for delegated work requested by the user.
- [x] Establish explicit development boundaries. Do not modify live packages, services, firewall rules, remote machines, credentials, or sibling repositories. Do not publish, deploy, or create external resources as part of this development assignment.
- [x] Inspect `hipEngine`, `jouzu-dev`, and `shisad` development conventions. Adopt shared-main coordination, immutable per-unit worklog entries, validated logical commits, and paired functional/security tests; do not inherit unrelated product rules.
- [x] Write `AGENTS.md` and Git ignore/line-ending rules. Work on `main`; no worktrees. Parent integration owns commits while children edit disjoint assigned paths.
- [x] Implement and test `scripts/worklog.py`, `worklog/README.md`, and `tests/test_worklog.py`; record the initial immutable entry and include it in the setup commit. The 20 isolated tests and staged-entry check passed.

## Research — `docs/SOURCES.md`

- [x] Fetch and inspect `https://pwn.watch/`, `/feed.xml`, `/incidents.json`, and `/llms.txt`. Separate the quoted incident claims from verified evidence.
- [x] Compare authoritative vulnerability and patch sources: CISA Known Exploited Vulnerabilities, OSV, GitHub advisories, NVD/CVE, vendor or distribution advisories, and EPSS exploitation probability.
- [x] Record each source's purpose, access method, identity/version semantics, limitations, and trust level. Do not treat news or severity scores as patch instructions.
- [x] Describe host, application dependency, container, and fleet inventory options, including distribution backports and stale inventory.

## Design — `docs/DESIGN.md`

- [x] Define requirements, non-goals, threat model, trust boundaries, and supported proof-of-concept scope.
- [x] Specify ingestion, provenance, normalization, deduplication, persistence, inventory, applicability matching, prioritization, and triage states.
- [x] Specify remediation plans, immutable approval binding, stale-plan rejection, policy modes, locking, bounded execution, verification, rollback limits, and audit records.
- [x] Define deployment and fleet evolution, polling, outage behavior, credentials, package-source trust, and observability.
- [x] Define advisory-only Jouzu integration and optional TextGuard inspection. Model output and cleaned text must never grant execution authority.
- [x] Mark every proposed production capability separately from implemented behavior.

## Implementation — Python package, CLI, and examples

- [x] Provide installable project metadata and a documented CLI. Module/console commands, offline wheel/source build and both example workflows pass; independent CLI/demo repair re-reviews closed all findings.
- [x] Persist feeds, normalized incidents or advisories, inventories, findings, plans, approvals, execution results, and audit events as appropriate to the implemented design. Schema-2 Store/Engine APIs pass focused and integrated offline tests and independent re-review.
- [x] Ingest pwn.watch data and at least one authoritative applicability source with bounded network requests and deterministic offline fixtures. Python acquisition/parser APIs, durable source health and CLI integration are verified offline.
- [x] Import system inventories and implement a read-only local collector. Keep unsupported ecosystems and uncertain matches visible rather than declaring them safe. Native collection is checked with synthetic identity files and fake dpkg output; no private host inventory was taken.
- [x] Implement evidence-based applicability triage and risk ranking. Feed text cannot supply commands or silently select patch targets. Public parser-to-matcher tests and 1,028 native dpkg comparison cases pass.
- [x] Build a remediation queue with validated, structured plans, explicit manual approval, policy-controlled automation, and revalidation before execution. Python APIs and user-facing commands pass actual simulator and fake-native integration.
- [x] Provide a runnable end-to-end simulation that changes only disposable fixture state and demonstrates successful verification and failed-update handling. Module and installed-console demos pass 101 commands across four scenarios; independent re-review closed denial-evidence and child-cache findings.
- [x] Implement a narrowly scoped real remediation backend with deterministic fake-runner tests of command construction, authorization, preconditions, execution, and verification. Native prerequisites are explicit; all seven runtime findings are closed after independent re-review. The integrated API suite passes 367 tests. No live patching occurred; real Python-APT resolution/download, native lock handoff and privileged execution remain untested.
- [x] Provide an advisory export usable by a coding harness without giving feed content executable authority. CLI emits an untrusted data envelope with escaped JSON; example/demo checks and independent boundary review pass.

## Verification and review — tests and `docs/REVIEW.md`

- [x] Run deterministic offline unit and integration tests. `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v`: 452 passed, no skips, in 20.165 seconds.
- [x] Run the documented end-to-end demo from a clean temporary state directory. Direct module and fresh installed-console runs passed all 101 commands and verified cleanup.
- [x] Exercise hostile feed content, malformed payloads, source spoofing, unsupported version comparisons, duplicate ingestion, stale inventory and approvals, denied policy, command injection, concurrent execution, and failure/rollback behavior as applicable. Evidence and honest recovery limits are recorded in `docs/REVIEW.md`.
- [x] Independently review security boundaries and correctness with `astra-xhigh`; record findings, fixes, and unresolved limitations. All implementation findings are closed; real privileged deployment remains untested.
- [x] Re-run affected checks after fixes and perform an integration review of all delegated changes. Parent suite/demo/package checks and original-reviewer rechecks pass; reviewed candidate hashes match.
- [x] Inspect final changes for secrets, accidental state, unintended sibling edits, and unsupported claims. Parent reviewed tracked/proposed paths and content, scanned private-key markers and state/build/cache extensions, preserved ignored session state, and verified disjoint repository-only edits. Final independent documentation audit found no actionable claims or command defects.

## Operator documentation and handoff

- [x] Write `README.md` with verified installation, demo, feed polling, inventory, triage, queue, approval, execution, and test commands. README metadata build/install check passed after the final edit; live polling is explicitly distinguished from offline verification.
- [x] Write `docs/OPERATIONS.md` with rollout, recovery, approval boundaries, scheduling, and production-readiness gates. Commands/fields match implementation; parent and independent link/syntax/help audits pass. Native procedures are conditional, not deployment evidence.
- [x] Clearly disclose network-dependent checks and privileged execution not tested here. README, OPERATIONS and REVIEW distinguish dated research retrievals and offline injected transports from untested real APT/download/lock/install and native trust provisioning.
- [x] Reconcile this checklist against evidence and report delivered files, passing checks, and remaining limitations. `docs/REVIEW.md` and the final delivery worklog record the complete 452-test, module/installed 101-command and independent-review evidence.
- [x] Final external action: none. No push, publication, live deployment, privileged patching or fleet enrollment was performed; those require separately supplied targets and operational authorization.

## Post-delivery review remediation (2026-10-23)

- [x] Critically review the earlier native-backend candidate and record findings in the immutable worklog. These historical observations do not qualify Ubuntu execution.
- [x] Bound triage output and verification cost; prune unreferenced evidence; keep inspection usable during execution (`bc6eb4e`).
- [x] Support reviewed package configuration and package states; provide a read-only configuration review observation (`27ed6ee`). Ubuntu APT/install qualification remains untested.
- [x] Refuse root execution of code other users can modify (`2905d87`, extended by the review follow-up).
- [x] Tighten gate lifecycle edges and runner descendant handling (`ca43e85`, corrected by the review follow-up).
- [x] Independently review the remediation, then resolve or reject each finding with evidence. 485 tests pass on Python 3.12 and 3.14; the package check passes.

## Ubuntu LTS retargeting

The supported target is Ubuntu 24.04 LTS (`noble`) on `amd64`. Canonical release-specific evidence determines applicability; approved Ubuntu APT repositories determine installable artifacts. Ubuntu Pro/ESM repositories are outside automatic remediation scope. An unsupported release, repository, or missing advisory remains unknown or blocked, not safe.

Acceptance for this change:

- [x] Verify the Canonical feed contract and document source identity, release/source-package matching, missing evidence, and Pro/ESM limitations. See `docs/research/UBUNTU.md`: Canonical USN JSON is notice-based missing-update evidence, not a complete CVE database.
- [x] Replace the advisory adapter and matching semantics; cover valid, malformed, wrong-release, and unsupported-pocket evidence with offline tests.
- [x] Retarget native inventory, APT origins/suites/keyrings, release freshness, policy and backend identifiers to Ubuntu; preserve execution safeguards and test both success and denial paths.
- [x] Update active source files, scripts, filenames, fixtures, examples, CLI commands, README and every active document. Preserve immutable worklog entries and Git history. Retain only the existing debconf noninteractive protocol variable and its test as the closeout exception; no compatibility aliases or alternative distribution support remain.
- [x] Reject incompatible persisted state without discarding history or reusing previous approvals. Schema 4 rejects prior schemas before writes; fresh state is required.
- [x] Run the full deterministic suite, module demo, packaging/installed-console checks, worklog checks and whitespace checks. **507 tests passed in 25.515 seconds**; both 101-command demos, both simulator walkthroughs and 1,028 disposable Ubuntu dpkg comparisons passed. Real CLI polling and refresh also succeeded. Active-content audit found only the runner's required debconf protocol variable and its test; the naming exception is retained on user-directed closeout.
- [x] Obtain independent integrated review, resolve findings, and record exact verification evidence and untested native boundaries. R1 (engine intake limits) was repaired with a shared decoder and regression tests; independent re-review closed it with no new findings. See `docs/REVIEW.md`.
- [x] Commit the validated change and its worklog entry. No push, release, deployment or live package modification is authorized.

## Context for implementation

The sibling projects `../textguard` and `../jouzu` were inspected read-only. TextGuard's documented Python API provides `scan`, `clean`, and `TextGuard`, with optional semantic backends; it does not prove that arbitrary text is safe. Jouzu's documented harness supports agents, scheduling, and local content scanning; those are investigation and workflow capabilities, not an independent authorization service.

Use Python for the proof of concept, with a small dependency surface, SQLite persistence, and offline test fixtures. The detailed module contracts and supported package ecosystems are decided in the design stage. Default execution must not change the host. Treat advisory feeds, inventory imports, URLs, and model responses as untrusted input.
