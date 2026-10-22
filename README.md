# Autoprotect

Autoprotect is a local security-advisory triage and remediation proof of concept. It polls fixed advisory sources, compares them with package inventory, creates immutable remediation plans, and executes them under manual approval or explicit automatic policy.

**Start with the offline simulator.** The native backend is implemented for one-package updates on Debian 13 (`trixie`), `amd64`, but real APT downloads, native package-lock handoff and privileged installation have not been tested. This is not a production-ready unattended patch service.

## What it does

- Imports or polls pwn.watch incident discovery and Debian Security Tracker assertions. Incident prose and reported fixed versions cannot select installation commands.
- Matches Debian **source-package versions**, including distribution backports. Unsupported ecosystems, incomplete evidence and unmatched packages remain `unknown`, not implicitly safe.
- Stores source health, inventories, findings, plans, approvals, outcomes and audit events in SQLite.
- Supports `observe`, `manual` and `auto` policies. Execution rechecks policy, evidence, inventory, exact repository artifacts and expiry; automatic mode does not bypass those checks.
- Verifies the complete expected package-state change, retains a target-wide gate after uncertain execution, and requires explicit recovery followed by fresh collection and a new plan.
- Exports untrusted advisory data for a coding harness to investigate, without granting administrative authority to a model or feed.

The research in [SOURCES.md](docs/SOURCES.md) distinguishes incident claims from verified evidence and compares additional sources. OSV, GitHub advisories, Known Exploited Vulnerabilities, exploitation prediction, fleet agents and application/container rollout are **not implemented adapters**.

## Run the demo

Use Linux and **Python 3.12 or newer** from the repository root. The package has no third-party Python runtime dependencies. No network access, installation or administrator privilege is needed for this command:

```bash
python3 -B -m autoprotect demo
```

The demo runs **101 ordinary commands** against generated private simulator state, then removes that state. Its JSON summary verifies:

| Scenario | Expected result |
| --- | --- |
| Manual approval | Unapproved execution denied; approved execution succeeds; repeat execution denied |
| Automatic policy | Execution succeeds without manual approval; repeat execution denied |
| Failure before writing | `failed`, package state unchanged, gate cleared |
| Failure after writing | `needs_attention`, changed package state, gate retained |
| Explicit recovery | `verified=false`; generation changes; old plans stay stale; fresh collection and a newly approved plan succeed |

Denial checks require the expected error reason and, where emitted, a newly appended matching audit event. A generic I/O error cannot stand in for a policy denial. `-B` disables cache writes by the invoking interpreter; demo children also use `-B`. Normal completion and Python unwinding remove temporary state; forced process or host death can leave scratch files.

For individual commands, follow the tested [manual and automatic simulator walkthrough](examples/README.md). It demonstrates setup, import, inventory, triage, planning, approval, execution, audit and advisory export using the files in `examples/`.

## Install locally

The application requires Python `>=3.12` (Debian 13 ships 3.13). Building from source requires **setuptools 83.0.0**; virtual-environment creation requires Python's `venv` and `ensurepip` support. Native system prerequisites are separate from these Python dependencies.

With that build backend already available in your Python environment, build and install without consulting a package index:

```bash
python3 -c "from setuptools.build_meta import build_wheel; build_wheel('dist')"
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --no-deps dist/autoprotect-0.1.0-py3-none-any.whl
.venv/bin/autoprotect --version
PYTHONDONTWRITEBYTECODE=1 .venv/bin/autoprotect demo
```

These commands intentionally create `dist/`, build metadata and `.venv/` in your checkout. Provision the pinned build prerequisite separately if it is absent; the commands above do not install it. The installed `autoprotect` command and `python -m autoprotect` expose the same interface. The demo in the installed wheel does not depend on repository tests or example files.

To verify building and installed execution without leaving build or virtual-environment state in the checkout:

```bash
python3 -B scripts/check_package.py
```

This check copies runtime sources to a temporary directory, builds a wheel and source distribution offline, installs the wheel into a new temporary environment, checks both entry points outside the repository, runs the installed demo, validates its scenario summary, and reports only after cleanup.

## Command workflow

Operational commands require a private policy file and an explicit state directory. Put global options **before** the command. The policy selects the backend; no command-line option can replace it. Use `init-simulator` first for new simulator state, as shown in the walkthrough.

For reference, define `STATE` and `POLICY` as your existing private state directory and policy file, and `ASSET_ID`, `FINDING_ID`, and `PLAN_ID` from the preceding JSON results. These commands do not add `--live`:

```bash
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" queue
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" inventory
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" triage "$ASSET_ID"
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" plan "$FINDING_ID"
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" approve "$PLAN_ID" --actor operator-label
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" execute "$PLAN_ID"
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" audit
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" export "$ASSET_ID"
```

`inventory` collects from the selected backend. `inventory --import FILE` instead imports untrusted JSON and cannot establish native provenance. `operator-label` is an audit label, not an authenticated identity. Under an `auto` policy, omit `approve`; all substantive execution checks still apply. Changing the policy after planning invalidates the plan rather than reusing its approval.

Feed commands use the same global options:

```bash
# Offline: explicit import, never authenticated acquisition provenance.
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" import-feed debian examples/debian-synthetic.json

# Network-dependent: one request to each fixed HTTPS endpoint.
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" poll pwn
python3 -B -m autoprotect --state-dir "$STATE" --policy "$POLICY" poll debian
```

`pwn` uses `https://pwn.watch/incidents.json`; `debian` uses `https://security-tracker.debian.org/tracker/data/json`. Polling failures preserve last-good data and expose source errors. A successful poll does **not** trigger triage or execution; an external scheduler must invoke the required workflow. The final CLI polling path was tested with injected transport results, not live network requests. Earlier dated source retrievals are recorded separately in the research.

Do not mix synthetic inputs with a native deployment. Importing a feed after polling changes its current acquisition provenance back to `import`; it cannot authorize native execution.

### Results and recovery

JSON output escapes control and non-ASCII characters. Help and version are plain text. Ordinary errors are bounded JSON on stderr; failed execution outcomes are JSON on stdout. Exit codes are `0` for a completed command, `1` for application errors or failed polling/execution, `2` for argument errors, and `130` for interruption. If output fails after an operation, inspect persisted state before retrying; an output error does not prove the operation did nothing.

A recovery command can complete with exit `0` while the original plan remains `needs_attention` and `verified=false`. Use `recovery-status`, `recover` and `resolve-recovery` as described in the [operator runbook](docs/OPERATIONS.md). Do not delete a gate, retry a final plan, or interpret gate resolution as rollback. Recovery invalidates prior collection context and plans, including native plans in other databases.

## Native execution boundary

Native mutation and recovery-lock commands require explicit `--live`, effective root, protected root-owned policy/state, fresh native inventory, HTTPS-acquired Debian assertions, exact package/asset/repository allowlists and a reviewed APT configuration fingerprint. `autoprotect native-config` prints the host's configuration digest, sources, key-file digests and signed origins as read-only input to that review; it approves nothing. Policies must explicitly acknowledge maintainer scripts, recovery preparation and trusted installed lineage. These are administrator assertions, not verified backups or authentication of installed bytes.

Only a single-package, increasing-version transaction with no extra package changes is supported. Sensitive packages, unsupported repositories, dependency changes, holds and uncertain package states are rejected. Do not loosen these checks to make an unsupported update execute. See [native prerequisites and rollout gates](docs/OPERATIONS.md) before considering a separately authorized disposable-Debian exercise.

Package-state verification is **not** service health, kernel activation, rollback, absence of compromise or complete vulnerability coverage. Feeds and exported text remain untrusted. Local content hashes and audit rows do not protect against the trusted database owner or root.

## Verify and develop

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
python3 -B -m autoprotect demo
python3 -B scripts/check_package.py
python3 scripts/worklog.py check
python3 scripts/worklog.py render
git diff --check
```

The integrated candidate passes **452 offline tests** with no skips, including fake-native execution, actual simulator processes, recovery, hostile inputs and failure paths. Synthetic signature tests use local GnuPG tools when available; they are not live Debian repository tests. Check details and review disposition are in [REVIEW.md](docs/REVIEW.md).

Read [DESIGN.md](docs/DESIGN.md) for implemented contracts and separately marked production work, [DELIVERY.md](docs/DELIVERY.md) for acceptance status, and [AGENTS.md](AGENTS.md) for development rules. Development history is stored in immutable [worklog entries](worklog/README.md), not in the product instructions. No live deployment or privileged host update was performed for this delivery.
