# Delivery checklist

Tracks implementation and verification for Ubuntu, Arch/CachyOS, conda/mamba, uv and npm environments. Development history is recorded in the worklog.

## Required workflow

- [x] Explicit local/SSH environment list, including OS, prefix or project path.
- [x] Collection and update discovery for Ubuntu, Arch, CachyOS, conda, mamba, uv and npm; test each adapter.
- [x] Cached Canonical USN, Arch tracker and OSV evidence. Exact package/source matching where supported; explicit conda-native, CachyOS, pre-patch and other coverage gaps.
- [x] Readable and JSON status, first/last-seen findings, changes and cursor history; failures retain prior evidence and remain queryable.
- [x] Saved human-reviewed preview, explicit approval, fixed environment-wide package-manager commands, no replay after interruption, post-update collection and runtime caveats.
- [x] SQLite storage for inventories, observations, previews, outcomes, evidence cache and event history. Reject incompatible old state without deleting it.

## Removal and verification

- [x] Remove obsolete runtime, fixtures, tests, policy examples and documents; retain only reusable version comparison and worklog tooling/history.
- [x] Replace README, design and repository guidance with actual implemented behavior. No claim of exact-transaction authorization or comprehensive vulnerability coverage.
- [x] Run deterministic tests, ordinary CLI demo, packaging/installed demo, worklog checks and whitespace check. Verify every adapter's command and matching boundary; report application LOC. **47 tests pass; 905 application lines, including demo and version comparator.** Public-source smoke checks and README registration/query checks also pass.
- [x] Self-review parsing, SSH quoting, approval, interrupted operations and failed-source handling. No independent review: the user explicitly prohibited subagents.
- [x] Record results/limitations in an append-only worklog entry; stage exact files, commit, inspect final status. No push, deployment, private inventory collection or real package changes.

## Project rename and licensing

- [x] Rename the package, module, CLI, metadata, documentation and test references to `netwatch`; keep Git/worklog history unchanged.
- [x] Use `~/.local/state/netwatch/state.db` by default without moving or deleting existing databases. Existing schema-10 state remains usable through `--db`; keep the previous local-data ignore rule for safety.
- [x] Add the unmodified Apache License 2.0 text and SPDX `Apache-2.0` metadata. Include the license in wheel/source distributions and link it from README.
- [x] Run 47 tests, renamed module/demo and installed packaging checks, including license bytes and metadata. Record the worklog and commit; no publication or remote-repository change.

## Public publication

- [x] Audit all reachable history before publication: 16 commits, 116 historical paths and 241 unique file versions, plus commit metadata. Gitleaks and targeted manual checks found no credential, private-key, database, private-inventory or harness-state exposure. Ordinary authorship and development history are intentionally retained; scans are not a guarantee.
- [x] Recheck 47 tests, installed packaging/demo, Apache 2.0 artifacts and worklog integrity.
- [x] Create public [`lhl/netwatch`](https://github.com/lhl/netwatch), publish main only, and verify visibility, Apache-2.0 recognition and remote/local commit equality. Preserve history; no force push.

## End-user documentation

- [x] Rewrite README with a short description, concrete feature bullets, quick start and usage examples; place License last.
- [x] Move command/reference details into `docs/USAGE.md`; remove defensive boilerplate and obsolete implementation history from active prose.
- [x] Apply clear-writing and anti-slop passes using the supplied writing guidance. Verify 12 shell blocks, 23 CLI examples and 8 local links/anchors, plus the simulated workflow and installed package demo.

## Output improvements from the local check

- [x] Compare Arch/CachyOS fixed versions with target `vercmp`; batch remote comparisons and keep uncertain/foreign-package coverage visible.
- [x] Summarize affected packages, review notices and update versions; provide `--all` and complete JSON output.
- [x] Record matching-rule changes as reassessment, preserve old scans, and avoid duplicate finding events on unchanged checks.
- [x] Pass 56 tests, module/installed demos, packaging and synthetic native-version comparisons. Rerun the authorized local check without applying updates; keep private inventory outside Git.

## Terminal output and operating manual

- [x] Add Rich terminal styling with text labels for affected/review/update status; preserve plain pipes, `NO_COLOR`, dumb-terminal and JSON output.
- [x] Show source severity separately from applicability and label updates that overlap findings without claiming they fix them.
- [x] Pin runtime dependencies with hashes; verify dependency installation and include the lock in source distributions.
- [x] Link the operating manual from AGENTS and make it cover installation, registration, checks, queries, updates and recovery.
- [x] Pass 61 tests, package/dependency checks and a cached local pseudo-terminal check. No new inventory or update operations.

- [x] Improve wide-terminal hierarchy with a summary panel, finding/update tables and a separate reported-severity column; retain stacked narrow output. All 62 tests and package checks pass; cached local output inspected through a pseudo-terminal.

## Optional security context

- [x] Add opt-in `check --context` with cve.now lookup for existing CVE references and pwn.watch live incident leads matched locally. Keep context separate from package applicability, fixed-version evidence and update commands.
- [x] Cache bounded public requests, preserve source/model/license attribution and observation times, retain failed/skipped context, and record changes separately. Allow only the same-CVE HTTPS storage redirect used by cve.now.
- [x] Document privacy, lookup caps, tag-matching limits, incomplete exit status and unchanged conda/CachyOS coverage. Pass 23 context tests, all 85 tests, module/installed demos, packaging checks and public-only smoke requests using synthetic package names. No registered-target checks or real updates.

## Before using live updates

Test package-manager commands, credentials, project layouts and recovery on disposable targets before enabling updates on working systems. Live updates have not been tested. Conda-native vulnerability matching and authoritative CachyOS matching remain unimplemented; inventory and update discovery are supported.
