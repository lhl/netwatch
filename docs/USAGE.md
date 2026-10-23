# Usage guide

[Install and quick start](../README.md#quick-start)

## Environments

| Kind | Package tools | Advisory coverage |
| --- | --- | --- |
| `ubuntu` | dpkg, APT; Ubuntu 24.04 noble amd64 | Canonical notices for published standard-security fixes; excludes Pro/ESM and pre-patch vulnerabilities. |
| `arch` | pacman, `checkupdates` from pacman-contrib | Exact affected-version matches with a `Vulnerable` or `Fixed` tracker status are flagged. Other matches need investigation; the tracker may lag releases. |
| `cachyos` | pacman, `checkupdates` | Arch advisory names provide leads; applicability to rebuilt packages is unknown. |
| `conda`, `mamba` | The named tool and an existing prefix | OSV for pip/PyPI-origin entries only. Conda-native coverage is unknown. |
| `uv` | uv and an installed project `.venv` | OSV for installed PyPI packages. |
| `npm` | npm and installed dependencies | OSV for installed npm packages, including transitive dependencies. |

Additional registration examples:

```bash
netwatch add desktop arch --host my-desktop
netwatch add workstation cachyos --host my-workstation
netwatch add analysis conda --path /opt/conda/envs/analysis
```

Custom uv environment locations, uninstalled lockfile dependencies, containers, Snap and Flatpak are not scanned. Source forks need separate assessment. Held packages and project constraints can prevent an update from reaching an advisory's fixed version.

## Cache and network

| Command | Behavior |
| --- | --- |
| `check NAME` | Collect inventory and discover updates; use advisory cache up to one hour old. |
| `check NAME --refresh` | Also fetch fresh advisories. |
| `check NAME --offline` | Still collect inventory, including over SSH. Use fresh cached advisories and skip update discovery. |
| `status NAME` | Read stored results without connecting. |

Ubuntu and Arch checks download public feeds. Python/npm checks query `api.osv.dev` with package names and versions. Package managers may contact their repositories during update discovery.

The Ubuntu feed was about 354 MB at the 2026-10-23 check. netwatch caches about 7 MB of Noble data, but download and decoding need more memory than the cache size.

`check` exits 1 when collection, advisory checking or update discovery is incomplete, including when `--offline` skips update discovery. Earlier findings and update observations are retained with their timestamps; the report identifies the failed or skipped step.

## History

```bash
netwatch --json history --since 0
netwatch history --name server
```

Each page contains up to 1,000 events and a `next_cursor`. Save that cursor after processing the page. Reads do not consume events.

Findings have first/last-seen times. History records new or changed findings, failed checks and update attempts. Findings absent from a successful check produce `finding_no_longer_detected` events.

## Updates

`preview` saves the update commands, observed candidates and inventory. It expires after one hour; inventory changes require another preview. Approval covers the environment-wide operation, so repository changes can change the versions installed.

| Kind | Apply commands |
| --- | --- |
| Ubuntu | `sudo -n apt-get update`, then `sudo -n apt-get upgrade -y` |
| Arch/CachyOS | `sudo -n pacman -Syu --noconfirm` |
| conda/mamba | `conda update --all --yes --prefix PATH` or its `mamba` equivalent |
| uv | `uv lock --upgrade`, then `uv sync --locked` |
| npm | `npm update --ignore-scripts` |

- Arch/CachyOS always perform a full system upgrade.
- Conda/mamba leave pip-installed packages unchanged.
- uv updates within project constraints and syncs default groups.
- npm skips scripts; packages needing build scripts may require follow-up.
- Package scripts and builds can run code and affect services.

Use the package manager directly if you need to approve an exact list of versions.

### After an update

The result includes `package_state_changed`, `remaining_findings` and `advisory_check_ok`. Ubuntu also reports its reboot-required marker. Check service health and restart requirements yourself; netwatch does not restart services or roll back changes.

### After a failure

A failed or interrupted update leaves `needs_attention` or `running`, blocking another update to that registration.

Inspect the target and confirm the update process has stopped—an SSH disconnect alone does not establish that. Repair package state if needed, then record your action:

```bash
netwatch resolve PLAN_ID --note 'Confirmed update stopped; repaired package state'
```

Replace `PLAN_ID` and the note with the attempt you inspected. `resolve` clears the block; it does not undo changes. Create a fresh preview before retrying.

## Storage

Default: `~/.local/state/netwatch/state.db`, created with mode 600.

```bash
netwatch --db /path/to/state.db status
```

Back up this file to preserve inventories and update history. Records are not automatically pruned. Existing schema-10 databases work at their existing paths; older schemas are refused without migration.
