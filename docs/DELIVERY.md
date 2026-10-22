# Delivery checklist

This checklist tracks the original assignment: research security feeds and patch information, design the system, build a working proof of concept, and independently review it. Checking a box requires implementation or research evidence, not a plan.

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

- [ ] Provide installable project metadata and a documented CLI.
- [ ] Persist feeds, normalized incidents or advisories, inventories, findings, plans, approvals, execution results, and audit events as appropriate to the implemented design.
- [x] Ingest pwn.watch data and at least one authoritative applicability source with bounded network requests and deterministic offline fixtures. Python acquisition/parser APIs are verified; durable source health and CLI integration remain below.
- [x] Import system inventories and implement a read-only local collector. Keep unsupported ecosystems and uncertain matches visible rather than declaring them safe. Native collection is checked with synthetic identity files and fake dpkg output; no private host inventory was taken.
- [x] Implement evidence-based applicability triage and risk ranking. Feed text cannot supply commands or silently select patch targets. Public parser-to-matcher tests and 1,028 native dpkg comparison cases pass.
- [ ] Build a remediation queue with validated, structured plans, explicit manual approval, policy-controlled automation, and revalidation before execution.
- [ ] Provide a runnable end-to-end simulation that changes only disposable fixture state and demonstrates successful verification and failed-update handling.
- [ ] Implement a narrowly scoped real remediation backend with deterministic fake-runner tests of command construction, authorization, preconditions, execution, and verification. An unavailable implementation prerequisite is a blocker, not completion. Never run live patching during development; disclose live execution as untested.
- [ ] Provide an advisory export usable by a coding harness without giving feed content executable authority.

## Verification and review — tests and `docs/REVIEW.md`

- [ ] Run deterministic offline unit and integration tests. Record the exact command and results.
- [ ] Run the documented end-to-end demo from a clean temporary state directory.
- [ ] Exercise hostile feed content, malformed payloads, source spoofing, unsupported version comparisons, duplicate ingestion, stale inventory and approvals, denied policy, command injection, concurrent execution, and failure/rollback behavior as applicable.
- [ ] Independently review security boundaries and correctness with `astra-xhigh`; record findings, fixes, and unresolved limitations.
- [ ] Re-run affected checks after fixes and perform an integration review of all delegated changes.
- [ ] Inspect final changes for secrets, accidental state, unintended sibling edits, and unsupported claims.

## Operator documentation and handoff

- [ ] Write `README.md` with verified installation, demo, feed polling, inventory, triage, queue, approval, execution, and test commands.
- [ ] Write `docs/OPERATIONS.md` with rollout, recovery, approval boundaries, scheduling, and production-readiness gates.
- [ ] Clearly disclose network-dependent checks and privileged execution not tested here.
- [ ] Reconcile this checklist against evidence and report delivered files, passing checks, and remaining limitations.
- [ ] Final external action: none. Live deployment, privileged patching, and fleet enrollment require separately supplied targets and operational authorization.

## Context for implementation

The sibling projects `../textguard` and `../jouzu` were inspected read-only. TextGuard's documented Python API provides `scan`, `clean`, and `TextGuard`, with optional semantic backends; it does not prove that arbitrary text is safe. Jouzu's documented harness supports agents, scheduling, and local content scanning; those are investigation and workflow capabilities, not an independent authorization service.

Use Python for the proof of concept, with a small dependency surface, SQLite persistence, and offline test fixtures. The detailed module contracts and supported package ecosystems are decided in the design stage. Default execution must not change the host. Treat advisory feeds, inventory imports, URLs, and model responses as untrusted input.
