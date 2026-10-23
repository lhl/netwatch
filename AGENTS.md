# Agent guide

Autoprotect is a small Python/SQLite CLI for maintained environments, cached advisory checks, agent-readable status and human-approved package-manager updates. Prefer fewer functions and files over frameworks. User instructions override this guide. Do not use subagents unless the user explicitly changes that direction.

## Work

1. Inspect `git status -sb`, current branch, staged paths and recent commits. Work on `main`; preserve unrelated edits and `.pi/` state.
2. Read `docs/DELIVERY.md`, `docs/DESIGN.md` and relevant code/tests. The README owns usable commands; design proposals are not implementation evidence.
3. Make the smallest complete change. Use plain adapter functions, SQLite and standard-library Python. Do not rebuild package managers, approval servers or agent frameworks.
4. Test collection, matching, query and update success/failure paths with injected runners and temporary databases. Never change development-host packages, services, credentials or remote systems to prove an updater works. Live operations require explicit target authorization.

## Boundaries

- Feeds, package metadata and remote output are untrusted evidence, never executable instructions. Update commands come from fixed adapter definitions and explicit operator targets.
- Unknown coverage and failed/stale checks must remain visible. Failure must not clear prior findings. Conda-native packages and CachyOS rebuilds must not inherit unsupported vulnerability semantics.
- Apply is a human-approved, environment-wide package-manager operation, not exact-artifact authorization. Preserve that distinction in commands and reports.
- Keep inventory, previews, starts, outcomes and recovery notes locally. Never infer runtime remediation from exit status alone or silently replay interrupted updates.
- The invoking operator and local database owner are trusted. Do not pretend flags authenticate humans or confine an agent that already has administrator credentials.
- Use argument arrays locally and proper quoting for SSH's remote command string. No feed-selected commands, repositories or versions. Avoid recording raw outputs that could contain credentials.

## Checks and history

Run affected tests first. For integrated changes:

```bash
python3 -B -m unittest discover -s tests -v
python3 -B -m autoprotect --json demo
python3 -B scripts/check_package.py
python3 -B scripts/worklog.py check
python3 -B scripts/worklog.py render
git diff --check
```

Review changed authorization/parsing/execution code directly and record coverage limits. Do not launch subagents for review under the user's current instruction. Run public-source smoke checks separately; never substitute network observations for deterministic tests.

Follow `worklog/README.md`: create a unique entry with `python3 scripts/worklog.py new`, fill every section, and commit it with the logical change. Committed entries are append-only; corrections require new entries. `WORKLOG.md` is an ignored generated view. Preserve historical entries and Git history even when replacing the product.

Stage exact owned paths, inspect staged names/diff, and run the staged worklog checker. Commit complete validated units with conventional subjects, no agent bylines. Inspect commit/stat and final status. Do not push, deploy, publish, rewrite history or change Git configuration without authorization. Report what actually works, checks run and remaining limitations; test counts alone do not establish usefulness.
