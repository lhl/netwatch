# Delivery checklist: small replacement

The user directed replacement of the previous implementation with the simplest useful Python/SQLite system, covering actual Ubuntu, Arch/CachyOS, conda/mamba, uv and npm environments. No subagents, services or plugin framework. Historical delivery and review evidence remains in Git and immutable worklog entries, not as claims about this replacement.

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

## Operational qualification still required

No actual machine list/access was supplied for operations. Fixture coverage is not a live rollout. Before use for updates, qualify each applicable package-manager version, credentials, project layout and recovery procedure on explicitly authorized disposable systems. Conda-native advisory coverage and authoritative CachyOS matching are not implemented; those environments still support inventory and update workflows with visible uncertainty.
