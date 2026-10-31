# Design

netwatch runs package tools locally or over SSH and stores observations in SQLite.

| Module | Responsibility |
| --- | --- |
| `adapters.py` | Collect installed packages, discover available updates and define update commands. |
| `sources.py` | Fetch/cache advisory data and match installed packages; separately fetch optional cve.now context and pwn.watch incident leads. |
| `store.py` | Store registrations, scans, findings, events and update attempts. |
| `workflow.py` | Check environments, save previews, apply approved updates and record results. |
| `cli.py` | Parse commands and present text or JSON results. |

## Behavior to preserve

- Collect only registered environments. Commands come from adapter definitions; advisory text cannot supply commands or repositories.
- Match Ubuntu notices using Noble source versions and binary membership. Use OSV for installed PyPI/npm packages. Keep uncertain Arch/CachyOS matches and missing conda-native coverage visible.
- Retain earlier findings when collection or advisory requests fail. Record changes separately from routine checks.
- `check --context` enriches existing CVE references through cve.now and locally matches pwn.watch live patch/supply-chain incidents by advisory IDs or exact package/source tags with fixed aliases. Keep both sources outside applicability, fix-version and command selection. No inventory is sent to either source.
- Cache and record context independently of findings. Failed context sources retain prior records with their observation times; checks that omit context, including `apply` recollection, mark it skipped. Context changes have separate history events, and incomplete requested context makes `check` exit 1 without changing `advisory_check_ok`.
- Bound context requests and validate identities before caching. Allow only the cve.now-to-storage redirect for the same CVE path; never follow advisory links.
- A preview binds the target, inventory and environment-wide command list. Changed inventory or an expired preview requires a new preview. Repository candidates can change before execution.
- Record approval and start before running updates. Recollect afterward and report remaining findings separately from command completion.
- Block another attempt while an update is running or needs attention. Recovery records the operator's note and invalidates outstanding previews.
- Operator filesystem and SSH permissions control access. Keep agent accounts read-only.

## Development checks

Use injected command runners, synthetic responses and temporary databases for tests. Test each adapter's collection, update discovery and apply paths. Live operations require explicit target authorization.
