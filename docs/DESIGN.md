# Minimal replacement contract

This replaces the previous runtime, not its Git/worklog history. One Python CLI and one private SQLite database manage explicit local or SSH environments: Ubuntu, Arch/CachyOS, conda/mamba, uv and npm. Adapters are plain functions selected by a dictionary, not plugins or services.

Required loop: register → inventory → cached advisory/update check → query changes → preview → explicitly approve/apply → recollect and report. Store every attempt and retain previous findings on failure. Reports distinguish affected, investigation required, missing coverage, available updates, and verified package changes. An empty advisory result is not proof of safety.

Use Canonical USNs for Ubuntu noble; Arch tracker records as limited evidence (CachyOS rebuilds stay uncertain); OSV exact-version queries for installed PyPI/npm packages. Conda-native packages have unknown advisory coverage; their update availability remains useful. Do not map conda names to PyPI by guesswork. Network queries disclose package names/versions and are explicit through `check`; `--offline` requires fresh cached evidence.

Update the whole selected environment through its package manager, never execute feed text or feed-selected versions. Human approval binds a stored preview, target and inventory; changed inventory invalidates it. Arch uses full system upgrades, not partial package updates. Log start before execution and never automatically replay an interrupted attempt. Failed/partial updates need operator attention. Package-manager scripts run with the operator's authority; this is not a sandbox or a privilege-separation service. Agent accounts should only have read/collection access; an agent with administrator credentials cannot be constrained by this CLI.

No live system changes during development. Verify with injected command/network runners, synthetic fixtures, temporary SQLite files and a CLI demo. No subagents. Keep application code small; use standard library where practical. Proposed adapters do not count as implemented until collection, update discovery, preview and apply paths have tests.
