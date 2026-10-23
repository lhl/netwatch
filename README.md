# Autoprotect

A small Python CLI and SQLite database for **tracking maintained environments, checking relevant security advisories and available updates, and recording human-approved updates**. No server, resident host agent, plugin framework or model dependency.

Register a machine's OS, a conda prefix, a uv project or an npm project. Check it locally or through an existing SSH alias. Query the cached status and changes without reconnecting. Preview an environment-wide update, explicitly approve it, then inspect the post-update findings.

## Install and try without touching any machines

Python 3.12+ is required on the control machine. Runtime dependencies: standard library only. SSH targets need their package tools, not this application or a remote Python agent.

```bash
python3 -m pip install .
autoprotect demo
```

The demo uses temporary SQLite state and a fake package manager. It demonstrates an affected package, denied execution without approval, an approved update, recollection and change history. It performs no network requests or real package operations.

## Register your environments

These examples **only register targets**; substitute your actual SSH aliases and absolute paths. A single machine can have several environments.

```bash
autoprotect add server-os ubuntu --host my-server
autoprotect add workstation-os cachyos --host my-workstation
autoprotect add arch-os arch --host my-arch-host
autoprotect add training mamba --host my-server --path /opt/conda/envs/training
autoprotect add analysis conda --path /home/me/miniconda3/envs/analysis
autoprotect add api uv --host my-server --path /srv/api
autoprotect add frontend npm --path /home/me/projects/frontend
autoprotect list
```

`local` is the default host. Host values are explicit SSH aliases or `user@host`, never discovered addresses. SSH uses batch mode and normal configured host-key checking. Paths are safely quoted. Registered names cannot be overwritten; use a new name when replacing an environment so its history stays separate.

## Check and query

```bash
autoprotect check server-os           # collect inventory, advisories and updates
autoprotect check                     # check every registered environment independently
autoprotect check server-os --refresh # force a fresh advisory fetch
autoprotect status                    # cached reports; no connections
autoprotect --json status server-os   # full report for an agent
autoprotect --json history --since 0  # events and the next cursor
```

Reports contain installed packages, affected or uncertain findings, advisory links/fix versions, available package-manager updates, evidence timestamps, coverage warnings, collection status and pending/uncertain update attempts. Findings retain first/last-seen times. Changes are logged separately from routine checks. `history` returns at most 1,000 events; pass its `next_cursor` to read the next page. Reads are non-destructive: the agent keeps its own cursor and can retry a read.

Advisory responses are cached for one hour. The first Ubuntu fetch downloads the full publisher database (about 354 MB at the checked snapshot); only Noble matching fields are retained locally (about 7 MB). Decoding that first response needs substantially more memory than the cache size. `--refresh` bypasses the cache once per source/package query in that check. `check NAME --offline` still collects inventory (including SSH) but requires fresh cached advisories and skips update discovery; it reports update availability as unrefreshed. Previous update observations keep their original timestamp. `status` is the genuinely connection-free lookup.

A collection failure preserves the previous report and marks the last attempt failed. An advisory failure retains prior findings as unknown. Findings that disappear after a successful check are recorded as **no longer detected**, not proof of complete safety. An unavailable environment does not prevent checking the others. `check` exits 1 if collection, advisory checking or update discovery was incomplete; a nonzero exit is not an empty result.

### What each adapter actually supports

| Environment | Inventory and update discovery | Vulnerability evidence | Apply scope |
| --- | --- | --- | --- |
| Ubuntu | dpkg inventory; APT candidates from existing indexes | Canonical Ubuntu Security Notices for **24.04 noble amd64** and explicit standard-security binary/source matches | Refresh APT indexes, then `apt-get upgrade`; includes related packages, not a single binary |
| Arch | pacman inventory; `checkupdates` from pacman-contrib | Arch tracker: exact published affected-version matches with recognized status; other name matches require investigation | Full `pacman -Syu`; never partial upgrades |
| CachyOS | Same tools as Arch | Tracker names are hints only; rebuilt packages remain unknown | Full `pacman -Syu` using the machine's configured repositories |
| conda / mamba | Prefix-specific inventory; solver dry-run for updates | OSV for explicitly pip/PyPI-origin entries only; **conda-native coverage unknown** | Update all conda-managed packages in that prefix; pip packages are not upgraded |
| uv | Installed packages in the project's default `.venv`; outdated versions | OSV exact-version queries for PyPI | Upgrade the project lock within its constraints, then sync default groups |
| npm | Installed dependency tree, including transitive packages; outdated versions | OSV exact-version queries for npm | `npm update --ignore-scripts` within project constraints |

No adapter declares an environment universally safe. The Arch tracker may lag current releases. Ubuntu notices describe published fixes, not all unpatched vulnerabilities. Conda package names are not guessed to be PyPI names. Source forks, custom uv environment locations, uninstalled lockfile dependencies, containers, Snap and Flatpak are outside these collectors. npm/uv constraints, held OS packages or pip packages inside conda may leave findings unresolved after an update.

**Network disclosure:** `check` sends collected PyPI/npm package names and versions to `https://api.osv.dev/v1/query`. Ubuntu and Arch use downloaded public feeds. Inventories and command results stay locally, but package queries can disclose private dependency names. Use `--offline` with already-populated cache when network queries are inappropriate; missing cache remains unknown. Feed content is evidence, not commands.

## Preview, approve and apply

**This is an operator tool, not a privilege-separation service.** The database owner, project files, package-manager configuration and installed tools are trusted. Keep an agent's account read/collection-only, including read-only project permissions and no administrator credentials. An agent with administrator access or write access to this database cannot be restrained by an `--actor` label or a CLI flag; there is no such claim here.

```bash
autoprotect preview server-os
# Read the returned plan ID, commands, observed updates and scope.
autoprotect apply 1 --yes   # replace 1 with the plan ID you reviewed
autoprotect status server-os
autoprotect history --name server-os
```

Approval covers **updating the entire named environment**, not an immutable list of exact versions. Repository state can change between preview and execution, and Ubuntu refreshes indexes at apply time. Packages, dependencies, scripts and services may change. If you require exact transaction approval, inspect and perform the package-manager operation manually instead. This tool does not provide exact artifact pinning, a sandbox, rollback or automatic restart orchestration.

The preview expires after one hour. Changed installed inventory or target/command definitions require another preview. Apply records approval/start and the invoking local user ID before commands, refuses replay, and recollects afterwards. `applied` means commands completed and package state was observed; the result separately shows whether packages changed, remaining findings and advisory-check success. It does not mean every vulnerability was fixed. Service runtime is explicitly unverified; Ubuntu's reboot-required marker is reported where available. Inspect service/restart/reboot needs yourself.

OS updates use `sudo -n`; the invoking administrator must already have suitable noninteractive privileges, locally or on the SSH target. Do not give those privileges to the read-only agent account. Application updates run as the invoking account; uv builds and conda scripts can execute project/package code. npm scripts are disabled, so packages requiring build scripts may need separately reviewed follow-up. Back up environments, lockfiles and application state first.

If a command fails, times out or verification cannot collect inventory, the plan becomes `needs_attention`. Abrupt process death leaves it `running`; disconnecting SSH does not prove remote work stopped. New updates to that registered environment are blocked until you inspect the actual processes and package state:

```bash
autoprotect resolve 1 --note 'Confirmed update stopped; inspected and repaired package state'
```

Resolution is your recovery attestation, not a rollback or success verdict. Make a fresh preview before another attempt. Registering the same actual machine through multiple aliases does not coordinate updates; use one canonical alias and serialize operator maintenance. The application does not protect against another administrator changing a target concurrently.

## Local storage and extension

Default database: `~/.local/state/autoprotect/state.db`, mode 600. Use `--db /absolute/path/state.db` **before** the command to select another. It stores targets, scans, findings, update previews/results, cursor events and cached evidence. SQLite transactions make local event/claim writes atomic. Raw subprocess output is not retained because it can contain credentials; command names, outcomes and relevant normalized observations are recorded. The database can contain private inventories: protect and back it up. History is local recordkeeping, not tamper-proof auditing. No automatic retention or pruning is performed yet.

The replacement uses schema 10 and refuses older application databases. Keep old databases separately; use a new path. Git and the immutable [worklog](worklog/README.md) retain development history. The previous custom executor, policy framework and demos have been removed, not silently migrated.

To add an ecosystem, add a collection function to `autoprotect/adapters.py`, an update-discovery branch and a fixed command list; add advisory matching in `sources.py` only if a reliable source exists. Add fixture tests for success and failure. There is no registration framework or inheritance hierarchy.

## Verification

```bash
python3 -B -m unittest discover -s tests -v
python3 -B -m autoprotect --json demo
python3 -B scripts/check_package.py
python3 -B scripts/worklog.py check
python3 -B scripts/worklog.py render
git diff --check
```

Tests exercise fake package tools and network responses in disposable state. They are not evidence that updates ran on your actual machines. No machine inventory or live package change was performed during this rewrite. See [delivery checks](docs/DELIVERY.md) and the short [design contract](docs/DESIGN.md).
