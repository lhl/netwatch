# Design

netwatch runs package tools locally or over SSH and stores observations in SQLite.

| Module | Responsibility |
| --- | --- |
| `adapters.py` | Collect installed packages, discover available updates and define update commands. |
| `sources.py` | Fetch and cache advisory data; match it against installed packages. |
| `store.py` | Store registrations, scans, findings, events and update attempts. |
| `workflow.py` | Check environments, save previews, apply approved updates and record results. |
| `cli.py` | Parse commands and present text or JSON results. |

## Behavior to preserve

- Collect only registered environments. Commands come from adapter definitions; advisory text cannot supply commands or repositories.
- Match Ubuntu notices using Noble source versions and binary membership. Use OSV for installed PyPI/npm packages. Keep uncertain Arch/CachyOS matches and missing conda-native coverage visible.
- Retain earlier findings when collection or advisory requests fail. Record changes separately from routine checks.
- A preview binds the target, inventory and environment-wide command list. Changed inventory or an expired preview requires a new preview. Repository candidates can change before execution.
- Record approval and start before running updates. Recollect afterward and report remaining findings separately from command completion.
- Block another attempt while an update is running or needs attention. Recovery records the operator's note and invalidates outstanding previews.
- Operator filesystem and SSH permissions control access. Keep agent accounts read-only.

## Development checks

Use injected command runners, synthetic responses and temporary databases for tests. Test each adapter's collection, update discovery and apply paths. Live operations require explicit target authorization.
