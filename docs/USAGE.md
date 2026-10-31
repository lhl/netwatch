# Usage guide

## Install and try

Requires Python 3.12+ and Git. Install into a virtual environment:

```bash
git clone https://github.com/lhl/netwatch.git
cd netwatch
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --require-hashes -r requirements.lock
python3 -m pip install .
netwatch demo
```

The demo uses synthetic data and a simulated package manager. From a checkout, `python3 -m netwatch` runs the same CLI as `netwatch`.

## Daily workflow

Replace the example SSH alias with your target. Registration saves a name; `check` collects installed versions, advisory evidence and available updates.

```bash
netwatch add server ubuntu --host my-server
netwatch check server
netwatch status server
netwatch list
```

Use `--path /absolute/project/path` for a project or conda prefix. Omit `--host` for local use. `check` without a name checks all registrations; `status` without a name shows their cached reports.

For an update, review the commands and environment-wide scope returned by `preview`, then substitute its ID for `PLAN_ID`:

```bash
netwatch preview server
netwatch apply PLAN_ID --yes
netwatch status server
```

OS updates require `sudo -n` access. Application updates use the invoking account. `apply` updates the whole selected environment, including dependencies. Live updates have not been tested; start on a disposable target. See [update behavior and recovery](#updates).

## Agent and script queries

```bash
netwatch --json list
netwatch --json status server
netwatch --json history --since 0
```

Global flags (`--json`, `--db`) go before the command. Status returns the saved report, last collection attempt and pending update plans. History returns events and `next_cursor`; pass that value as `--since` on the next request. These queries do not contact targets. Keep agent permissions read-only and use an operator account to apply updates.

## Environments

| Kind | Package tools | Advisory coverage |
| --- | --- | --- |
| `ubuntu` | dpkg, APT; Ubuntu 24.04 noble amd64 | Canonical notices for published standard-security fixes; excludes Pro/ESM and pre-patch vulnerabilities. |
| `arch` | pacman, `vercmp`, `checkupdates` from pacman-contrib | Exact affected-version matches with a `Vulnerable` or `Fixed` tracker status are flagged. Other matches need investigation; the tracker may lag releases. |
| `cachyos` | pacman, `vercmp`, `checkupdates` | Arch advisory names provide leads; applicability to rebuilt packages is unknown. |
| `conda`, `mamba` | The named tool and an existing prefix | OSV for pip/PyPI-origin entries only. Conda-native coverage is unknown. |
| `uv` | uv and an installed project `.venv` | OSV for installed PyPI packages. |
| `npm` | npm and installed dependencies | OSV for installed npm packages, including transitive dependencies. |

For repository packages on Arch/CachyOS, `vercmp` filters out notices whose fixed version is at or below the installed version. This removes historical matches; it does not verify CachyOS patch contents. Foreign packages and notices without usable fix versions remain for review. A missing or failed `vercmp` makes the advisory check incomplete.

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
| `check NAME --context` | Also fetch/cache cve.now context and locally match pwn.watch incidents. |
| `status NAME` | Read stored results without connecting. |

Ubuntu and Arch checks download public feeds. Python/npm checks query `api.osv.dev` with package names and versions. Package managers may contact their repositories during update discovery.

The Ubuntu feed was about 354 MB at the 2026-10-23 check. netwatch caches about 7 MB of Noble data, but download and decoding need more memory than the cache size.

`check` exits 1 when collection, advisory checking or update discovery is incomplete, including when `--offline` skips update discovery. Requested context that fails or reaches its lookup limit also causes exit 1, independently of `advisory_check_ok`. Earlier findings and update observations are retained with their timestamps; the report identifies the failed or skipped step.

## Optional security context

Add `--context` to a check to use both supplementary sources. It is opt-in for each invocation; it does not register another target or change package matching.

```bash
netwatch check server --context
netwatch check server --context --refresh
netwatch status server --all
netwatch --json status server
```

| Source | What netwatch uses | What leaves your machine |
| --- | --- | --- |
| [cve.now](https://cve.now/) | Source-reported CVSS, CISA Known Exploited Vulnerabilities (KEV) listing, Exploit Prediction Scoring System (EPSS) threshold-reached dates, public-exploit indicators, upstream attribution and labeled model summaries. | CVE IDs referenced by existing findings; no inventory or lockfile upload. |
| [pwn.watch](https://pwn.watch/) | Live patch and supply-chain incidents overlapping finding/advisory IDs or package/source names and product tags. | A request for the public incident catalog; relevance is matched locally. |

cve.now is queried once per distinct CVE, in sorted-ID order, up to 20 IDs per environment per check. No new CVE lookup starts once 60 seconds have elapsed; an in-flight request can finish afterward. Omitted IDs and failed lookups leave context marked `incomplete`. EPSS threshold dates are not current probability scores. An absent exploitation signal does not establish safety. Model summaries are explanatory text, attributed to the named model and cve.now under CC-BY-4.0; upstream records retain their listed licenses.

pwn.watch leads always have `state: review`. Matching uses lowercased exact package/source names, with PyPI punctuation normalization, and fixed aliases: `nodejs` → `node`, `bind9` → `bind`, and `linux-lts`/`linux-zen`/`linux-hardened` → `linux`. A `linux` tag match additionally requires a product name beginning with `Linux kernel`. Broad tags can still produce unrelated leads; missing tags, other aliases and uncollected software can hide relevant incidents. Breach-only, closed and example incidents are excluded. Its `cveIds` field can contain non-CVE advisory IDs; these are preserved without inventing CVE identities.

Neither source can mark a package affected or fixed, clear an advisory finding, supply an update command, or establish conda/CachyOS patch applicability. A notice-level CVE reference is not a per-package CVE determination. A source's `patched` incident label is not evidence that your installation is patched. netwatch links to incident details but does not import their remediation commands or follow their links.

Context uses the one-hour cache and honors `--refresh` and `--offline`. Failed source checks retain earlier context with its original observation times and `retained: true`; a successful source check replaces that source's context. A later check without `--context`, including the post-update check from `apply`, marks saved context `skipped` and retains it for reference. It does not claim that retained incidents still apply. `status` and `history` remain network-free.

JSON reports store this data separately under `report.context.cve_now` and `report.context.pwn_watch`, each with `status`, `items`, `errors` and fetch `evidence`. Items include `fetched_at`; pwn.watch also records catalog generation time and overlap reasons. Changes produce `context_changed` history events, not package-finding events. Default text output shows five records per source; `--all` and JSON expose all saved records.

Context requests accept only the fixed public endpoints. cve.now entry lookups may make one HTTPS redirect to a `*.public.blob.vercel-storage.com` host at the exact same CVE's `/public/entries/ID.json` path, without credentials, ports, queries or fragments. Other redirects are refused. Responses are bounded to 2 MiB per cve.now entry and 20 MiB for the pwn.watch catalog, with a 10-second socket timeout and a 20-second elapsed-read check. These limits do not make the feeds authoritative or guarantee availability.

## Report output

`check` and `status` group findings by package, separate affected packages from notices needing review, and show installed-to-candidate update versions. The default view shows five package groups per category and ten updates. Optional context appears in separate, labeled sections.

```bash
netwatch status server --all   # expand every row
netwatch --json status server  # complete records, including evidence and inventory
```

Color terminals at least 90 columns wide show a summary panel and aligned finding/update tables. Narrower terminals use a stacked layout. The reported-severity column is separate from finding status; empty finding sections remain visible as counts in the summary.

Color terminals show affected findings in red, review findings in yellow and ordinary updates in cyan. Updates marked `[affected]` or `[review]` have an associated finding; the marker does not establish that the candidate fixes it. Source-reported severity is shown separately where available. Pipes and redirected files use plain text. Set `NO_COLOR=1` to disable styling; `--json` always emits plain JSON.

The summary includes observation times, failed checks and the count of historical notices filtered out. Packages with available updates appear first in finding groups; updates for affected packages appear first, followed by review matches and other updates.

## History

```bash
netwatch --json history --since 0
netwatch history --name server
```

Each page contains up to 1,000 events and a `next_cursor`. Save that cursor after processing the page. Reads do not consume events.

Findings have first/last-seen times. History records new or changed findings, failed checks and update attempts. Findings absent from a successful check produce `finding_no_longer_detected` events. When a matching-rule change removes findings, one `findings_reassessed` event records the count and links to the previous scan; it does not report package updates.

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
