# Review and verification record

## Scope and completion status

This record covers the reviewed local proof of concept: source research, design, intake, protected-file and backend/lifecycle APIs, packaged CLI, disposable command demo and operator documentation. All implementation findings are resolved and independently re-reviewed; the final documentation audit found no actionable issues. [DELIVERY.md](DELIVERY.md) records the completed scope. Earlier sections retain the evidence and scope at each milestone. This acceptance does not qualify real privileged deployment. A later [post-delivery critical review](#post-delivery-critical-review-2026-10-23) found scale, native-compatibility and privilege defects; their resolution and independent re-review are recorded there.

Reviewers used the configured `astra-xhigh` role with separate review assignments. They did not edit the candidates. Parent integration inspected delegated files, added regression tests and ran the integrated offline suite. Review findings and exact unit handoffs are retained under `worklog/entries/`.

## Design baseline

Commit `1431d78` established the architecture and shared validation core after independent review. Corrections required full package-state delta verification, a host-wide durable recovery gate, repository codename/freshness checks and an explicit installed-lineage trust assumption. Final clarification placed the durable gate before the database executing transition. Shared exceptions distinguish confirmed pre-mutation failures from uncertain mutation; `IndeterminateError` is not a subclass of `BackendError`.

These are runtime implementation requirements, not evidence that the pending executor already enforces them.

## Task-5 findings and resolution

| Finding | Correction and evidence | Status |
| --- | --- | --- |
| Missing imported Debian source metadata could confuse binary rebuilds with source fixes. | Debian imports require explicit source name/version; native dpkg source fields retain their native semantics. Inventory regressions reject missing source identity instead of guessing. | Fixed; independently reviewed |
| Epochs above native dpkg's supported integer range could produce a false not-affected finding. | `core.version` rejects epochs greater than `2147483647`; matcher treats invalid advisory boundaries as unknown. Native comparison script and regression tests include the boundary. | Fixed; regression verified |
| Repeated incident CVE IDs multiplied correlations and output. | Deduplicate incident IDs before correlation; enforce cumulative association and serialized-output limits in addition to the finding count. | Fixed; regression verified |
| Parser and matcher differed on temporary Debian advisory IDs and maximum identifier length. | Preserve well-formed `TEMP-*` records only as unknown; use the same 128-character ID bound. Public parser-to-matcher tests cover source fixes, open/no-fix, missing-release and temporary records. Independent review also exercised 65- and 128-character IDs. | Fixed; independently reviewed |
| Raw JSON validation expanded a width-sized stack before checking node budgets. | Use iterator frames proportional to nesting depth. Red-first raw-input tests failed with `MemoryError` under 128 MiB; both small and production node budgets now reject with `ValidationError`. Independent re-review checked 954 node/depth cases, 106 canonical/hash identities and 11 malformed/cyclic cases. | Fixed; independently re-reviewed |
| Standard-library chunked trailers bypassed header budgets and accepted incomplete termination. | Enforce separate trailer field/byte limits, complete framing and metadata restrictions using the real response reader. Valid chunked bodies still work; malformed trailers fail without returning partial data. | Fixed; independently re-reviewed |
| A successful fetch-worker start followed by interruption skipped cleanup because a flag had not been assigned. | Inspect actual process state instead of a caller-maintained flag. Real-process and persistent-live fake regressions cover interruption, termination escalation and bounded joins. | Fixed; independently re-reviewed |
| Interruption during command startup leaked a child and released the frontend lock too early; handshake errors could be misclassified as definite pre-mutation failure. | Own the process object before initialization, protect startup and cleanup, defer SIGINT through sensitive transitions, kill/reap before lock release, and classify unconfirmed startup conservatively as indeterminate. Real synthetic process tests cover PID registration, constructor return, handshake errors, repeated SIGINT and a process-group creation race. | Fixed; independently re-reviewed |

No additional concrete inventory defect was found in the independent review. Imported collector labels cannot grant native provenance. Unsupported platforms/ecosystems, stale or incomplete inventory, non-ready package states and absent advisory coverage remain visible as unknown rather than safe.

## Verification evidence

The integrated candidate was checked on Python 3.12.13:

```bash
python3 -m unittest discover -s tests -v
```

Result: **146 tests passed**, no skips, in 8.726 seconds. The suite includes 11 core, 4 comparator, 36 feed, 26 inventory, 1 raw-memory regression, 16 matching, 30 runner, 2 public source-pipeline and 20 worklog tests. The memory test has two subprocess subcases and is Linux-only; the core traversal tests are portable.

An additional comparison check was run before the subsequent transport/runner-only repairs:

```bash
python3 scripts/check_debian_versions.py \
  --image debian@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
```

Result: **1,028 comparisons passed** against native `dpkg` in a disposable container, without network, host mounts or package installation. This validates comparator behavior for those cases, not a real update. The Docker image pull changed only the local image cache.

Earlier supplementary public feed probes observed 719 pwn.watch incidents and 77,341 Debian assertions, including 797 temporary identifiers. These dated observations are not offline test inputs or proof of ongoing feed availability. The parent inspected the reports without repeating the bulk downloads; tracked fixtures are synthetic.

Focused independent re-reviews confirmed closure without further findings. The feed reviewer ran 36 tests in 2.823 seconds and additional real-`HTTPResponse` probes covering the original failures and valid single/multi-chunk and zero-body responses. The runner reviewer ran 30 tests in 1.440 seconds and independently injected SIGINT, `ValueError` and `SubprocessError` after a real child had executed; cleanup reaped the child and closed its pipes before temporary frontend-lock release. Neither review performed host inventory or native package operations.

CLI/demo verification is a later delivery gate, not replaced by helper/API tests.

## Packaging and protected local files

`pyproject.toml` defines a standard-library package for Python 3.12, with a pinned build backend. An offline temporary snapshot of the stable intake modules and `local_files.py` built both a wheel and source distribution. The wheel installed without dependencies in a fresh temporary virtual environment; isolated imports, version and the public pwn parser passed. Console commands and final integrated packaging remain later gates.

`local_files.py` validates bounded regular-file imports and private policy/SQLite paths. Independent review found that early `abspath` normalization removed `..` and skipped canceled ancestors. Red-first regressions reproduced four invalid-ancestor cases. The repair preserves parent components until descriptor-relative validation and normalizes returned state paths afterward. All **17 focused tests passed**. Independent re-review closed the finding with five additional temporary-directory tests covering both APIs, relative/absolute paths, valid multiple-parent traversal and rejection without creating state at either possible location.

Ownership variants were checked with synthetic metadata, not cross-user privileged execution. The invoking user and root remain trusted; checks detect observed changes during reads but do not claim atomic snapshots against those owners. These verified helpers do not establish that the pending CLI reloads policy or protects its state correctly.

## Backend/lifecycle API acceptance

The first integrated candidate passed `python3 -m unittest discover -s tests -v`: **302 tests**, no skips, in 9.034 seconds. This included 12 Store, 58 Engine, 37 backend, 27 APT probe, 17 protected-file and five public Simulator/Engine pipeline tests, alongside the 146-test intake baseline. This result predates the additional native pipeline and path regressions below; it is not final product acceptance.

The parent then added five actual DebianApt/Engine integration tests in `tests/test_native_pipeline.py`. All passed. They use real lifecycle/backend classes, but substitute every native command, inventory observation, clock, root check and lock location. They verify approved success, corrupt-download failure without installation, unrelated package drift retaining the recovery gate, approval expiry after download, and import invalidation of previously HTTPS-acquired authority. No network or native package command runs in these tests.

Parent inspection found early simulator path normalization skipped symlink/missing/non-directory/writable ancestors followed by `..`; a private simulator directory under a writable ancestor was also accepted. Nine failing regression cases reproduced these gaps. Backend directories now reuse the protected descriptor-relative traversal from `local_files.py`, normalizing only after validation. Valid parent traversal remains supported. After repair, focused checks passed: **39 backend tests**, **12 source/runtime/native pipeline tests**, and **17 protected-file tests**. The native directory durability check still verifies the identity and order of actual directory `fsync` operations.

Three independent review assignments covered lifecycle authorization/persistence, backend execution/locks/integration, and APT metadata/acquisition. The backend reviewer confirmed the parent path repair with independent probes. The seven additional findings and their closure status are:

| Finding | Required repair | Status |
| --- | --- | --- |
| Final authorization used clock/policy values read before expensive matching; expiry or revocation during that work still allowed mutation. | Engine performs a bounded final policy/clock check after expensive validation. Independent later-boundary probes closed the lifecycle finding. Actual Engine/backend tests and consumer re-review confirmed the final repository time check. | Fixed; independently re-reviewed |
| Resolving uncertainty left older approved plans in other databases executable. | Store schema 2 records collection context; plans bind target generation. Independent same-second cross-database manual/auto probes require collection and new plans; actual Simulator/Engine tests and backend re-review pass too. | Fixed; independently re-reviewed |
| A wrong recovery plan ID was finalized before its gate mismatch was rejected. | Exact gate validation precedes outcomes. Independent wrong/absent/malformed/override probes preserve valid plans, outcome absence, audit and generation. Actual Simulator/Engine regression passes. | Fixed; independently re-reviewed |
| Interrupted exclusive gate creation left truncated JSON that blocked explicit recovery too. | Complete exclusive hard-link publication, recognized two-link crash state, successful-publication authorization marker, and exact malformed-digest recovery. Independent actual Engine interruption probes never reached mutation and permitted recovery and later authorized success. | Fixed; independently re-reviewed |
| A simulator named `sim.json.lock` could replace another simulator's held lock inode. | Initialization/opening reserve hidden names and `.lock`, `.gate`, `.generation` suffixes. Independent original/legacy-file collision probes and traversal regressions pass. | Fixed; independently re-reviewed |
| Accepted armored `.asc` keys could not be consumed by the fixed `gpgv --keyring` invocation. | Bounded isolated conversion preserves binary-key verification. Independent real-tool checks verified both formats and a 4 MiB child-output limit without changing parent limits or inherited trust state. | Fixed; independently re-reviewed |
| Origin deduplication discarded earlier contributing release dates/expiry constraints. | Probe retains all distinct constraints; backend validates exact origin membership/coverage and every date/expiry. Producer-to-consumer tests and independent limit/permutation/callback probes pass. | Fixed; independently re-reviewed |

Parent inspected the repaired candidates and reran their focused tests: **15 Store**, **72 Engine**, **62 backend** and **39 probe** tests passed, with no skips. All eight actual Simulator/Engine cases pass, including same-second cross-database generation invalidation, mandatory new collection/planning/approval, wrong-ID non-consumption and explicit malformed-gate attestation.

The lifecycle re-review closed all three original findings within Store/Engine. Independent probes changed policy/deadlines after the last approval read, and instrumentation found no expensive work after the final clock read. Same-second manual/auto recovery probes required fresh collection and new plans. Abrupt exits after attestation, generation rotation and gate removal preserved attestation and invalidated old cross-database work. A schema-1 rejection preserved the database bytes. Native backend generation/gate compliance was separately re-reviewed below.

The APT probe re-review closed armored-key handling and verified complete release evidence in all six orderings of expired/current/future constraints, with exact-duplicate deduplication. Consumer re-review also closed the freshness-loss finding. It ran 17 selected release/backend/native tests without skips and independently checked six valid permutations across two origins, expired records at positions 0, 511 and 1023 of the 1,024-record limit, and maximum-age/clock-reversal changes during the actual Engine callback. Each invalid case stopped before installation. Backend re-review also closed both original findings and confirmed integrated generation/recovery behavior. It ran **78 focused tests** without skips: 62 backend, eight runtime, six native and two release pipeline tests. Independent actual Simulator/Engine probes injected file-fsync failure, publication-alias cleanup interruption and directory-fsync failure; none reached `apply`. Retained complete gates allowed explicit recovery and later authorized success. Absent gates preserved approved plans, and malformed-gate results/audit consistently reported unverified prior identity.

### Repaired integrated candidate

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Result: **367 tests passed**, no skips, in 14.277 seconds. This combines the 146-test intake baseline, 17 protected-file, 15 Store, 72 Engine, 62 backend, 39 probe, eight runtime pipeline, six native pipeline and two release pipeline tests. `git diff --check` passed. The new `tests/test_release_pipeline.py` passes the actual probe's output unchanged to the actual backend consumer through fake native interfaces. The sixth native pipeline test crosses repository expiry during the final Engine matching pass while every other deadline remains valid; it confirms no installation occurs. No live command ran. All seven review findings are closed for these APIs. CLI and final delivery gates remain open.

The lifecycle reviewer additionally observed one winning claim across four processes and safe retained gates after abrupt exits before claim and after mutation. The APT reviewer reproduced armored/binary key behavior using temporary synthetic signatures and reproduced the freshness loss using two same-origin records. No review performed real APT/dpkg operations. Repair tests and original-reviewer rechecks closed all seven findings before API acceptance.

## CLI and disposable command candidate

The command unit adds `cli.py`, the multiprocessing-safe `__main__.py`, `demo.py`, console metadata, synthetic examples and `scripts/check_package.py`. Separate CLI and demo/package reviews and their repair re-reviews are complete. Final operator documentation was verified in the final audit below. The initial results below precede the repaired candidate's acceptance.

Parent inspected both handoffs and ran:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_cli.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_demo.py' -k DemoCLIIntegration -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_package.py
PYTHONDONTWRITEBYTECODE=1 python3 -m autoprotect demo
```

Results: **41 CLI tests passed** in 1.314 seconds; the real-process demo integration passed in 5.340 seconds; the full candidate passed **434 tests**, no skips, in 17.559 seconds. This adds 41 CLI and 26 demo tests to the 367-test runtime baseline. The earlier parent demo Unit selection passed 25 tests in 1.662 seconds. Native and polling tests use mocks; no private host inventory or live package operation ran.

The offline package check built `autoprotect-0.1.0-py3-none-any.whl` and `autoprotect-0.1.0.tar.gz` in a temporary source snapshot using the locally available pinned backend. The wheel installed without an index or dependencies into a fresh temporary virtual environment. Module and console help/version passed outside the repository. The installed console demo and direct module demo both completed **91 ordinary commands**, reported the four expected scenarios and removed their temporary state. The manual/automatic examples in `examples/README.md` were executed verbatim (automatic variant substituted its policy and omitted approval); both returned verified success, the expected updated package version, untrusted export and confirmed temporary-directory removal.

The CLI tests cover every command, policy reload/backend binding, changed inputs, root/live restrictions through fake interfaces, import provenance, null-import rejection, protected paths, fixed-path collisions, error escaping and exit codes, success/denial, failed/uncertain outcomes and recovery. During implementation, a red-first regression found that a policy at the gate-publication alias could be treated as disposable backend state. Both fixed simulator publication aliases are now reserved; the candidate's collision tests pass. Parent integration then reproduced the same omission for native coordination: a caller file at the native gate-publication alias passed CLI validation and was deleted by actual temporary target-lock entry. The repair reserves native lock/gate/generation and gate-publication paths independently of `--state-dir`. Twelve red-first policy/inventory/feed subcases reproduced acceptance; after repair all **42 CLI tests passed** in 1.533 seconds. Native operations were replaced with temporary paths and fake inventory/package locks. Independent re-review has confirmed closure of the simulator/native reservation fixes, including equivalent Linux path spellings.

Independent review returned four additional defects. All four repairs pass focused/integrated checks and original-reviewer re-review:

| Finding | Reproduction and required correction | Status |
| --- | --- | --- |
| Equivalent `/tmp/...` and `//tmp/...` paths bypass string collision checks and can delete a caller policy at a gate-publication alias. | Reviewer reproduced deletion through actual Simulator recovery-status and bypass of native reservations. A comparison-only key now equates leading-slash spellings while preserving original-component traversal. Both-direction simulator/native regressions preserve input bytes; 30 subcases failed before repair. | Fixed; independently re-reviewed |
| Closed stdout is retried during interpreter shutdown, leaking raw `BrokenPipeError` text and exit 120. | Explicit write/flush and closure of failing interpreter-owned streams prevent shutdown retry. Actual module/entry-function subprocesses check queue/help/version, closed stderr and exact exits; caller-owned captures remain open. Ten subprocess subcases failed before repair. | Fixed; independently re-reviewed |
| Demo denial claims accept unrelated pre-dispatch I/O errors. | Exact category/reason/schema plus newly appended audit evidence where emitted replace generic failure acceptance. Pre-dispatch unrelated and exact-looking but unaudited failures now reject. Retained-gate checks use actual backend error and queue/gate evidence. | Fixed; independently re-reviewed |
| Demo child interpreters write bytecode outside their temporary state. | Every child uses `-B`. A real cold-copy test verifies successful initialization/inventory, unchanged package bytes and no cache writes. Parent startup flags remain a documented caller responsibility. | Fixed; independently re-reviewed |

No runtime authorization bypass was established by these findings. The CLI reviewer additionally exercised actual CLI/Engine/Store/DebianApt with fake native interfaces: manual and automatic success, missing-live rejection and unrelated-package drift with retained gate and unverified resolution. These are offline integration results, not privileged execution.

The demo/package reviewer found no additional packaging blocker. Parent also adopted the reviewer's optional check-strengthening suggestion: `scripts/check_package.py` now validates required scenario/cleanup fields instead of accepting any dictionary, and prints its summary only after temporary cleanup completes. Three focused `test_package_check.py` tests pass; the updated installed package check also passes after stable repair handoffs.

The demo checks persisted queue, audit, full inventory fingerprints, exact recovery evidence and generation invalidation rather than interpreting exit status alone for successful execution. Its unit tests reject forged success evidence, unrelated denial errors, absent new denial audit evidence and cleanup failure. Synthetic package state is not runtime health, installed-byte authentication or rollback evidence.

### Repaired command integration evidence

Parent inspected both repair handoffs and ran these checks with no active implementation writers:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_cli.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_demo.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_package.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m autoprotect demo
```

Results: **49 CLI tests passed** in 1.977 seconds; **33 demo tests passed** in 8.836 seconds, including real subprocess integration and cold-package preservation. The integrated suite passed **452 tests**, no skips, in 20.165 seconds: the 367-test runtime baseline plus 49 CLI, 33 demo and three package-summary tests. Both direct module and freshly installed console demos completed **101 commands** and reported every required outcome and temporary-state removal. The additional ten commands read before/after audit evidence for five Engine-audited denials. Wheel/source builds, runtime inclusion, offline install and module/console help/version all passed outside the repository. Both original-reviewer rechecks confirmed closure before command acceptance.

The CLI re-review closed both findings and the parent's native reservation fix without new findings. It reran all 49 CLI tests in 2.032 seconds and independently repeated both original alias repros, eight native reservation probes, subsequent normal recovery, failed caller-stream flushes and simultaneous closed output descriptors. Caller files remained intact, caller streams remained open, and exact error exits were preserved. No native operation ran.

## Command acceptance

The demo/package re-review closed both findings without new defects. It independently reran all 33 demo tests in 8.698 seconds, including the real 101-command demo, cold-copy preservation and denial fault injection, plus all three package-summary tests. A disposable harness exercised actual packaging-check control flow with stubbed commands: valid results printed only after removal; empty results, cleanup exceptions and retained temporary roots emitted no success summary. It ran no installation or native commands.

Parent compared all six reviewed CLI/demo/package implementation and test file hashes to the independent reviewers' hashes; all matched. The 452-test suite and installed/direct demo evidence therefore apply to the accepted command candidate. Final documentation review is separate from these completed code reviews.

## Final documentation and delivery audit

The implementation was committed as `213a423`. Final integration added `README.md`, `docs/OPERATIONS.md` and README package metadata without changing runtime or tests. The existing 452-test result therefore remains the final runtime evidence. After the metadata change, `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_package.py` again passed offline wheel/source builds, fresh installation, both entrypoints and the installed 101-command demo, including temporary-state cleanup.

Parent inspected the operations handoff and verified 32 local Markdown links/anchors and 24 Bash blocks across the seven product/design/delivery documents; shell templates were parsed, not executed. Tracked/proposed file inspection found no local database/build/cache artifacts or private-key markers; public signature fixtures and synthetic examples are intentional. Existing ignored session state and caches were preserved. Sibling repositories were read-only references.

The final independent `astra-xhigh` audit accepted the README and runbook with no actionable findings or unassigned in-scope deliverables. It checked 23 local links/anchors, parsed 19 Bash blocks, and ran 17 safe invocations: version, top-level help and all 15 command helps. Code/test inspection checked policy, protected paths, provenance, command exits, native restrictions, coordination and recovery fields. It verified installation claims against metadata/checker code and confirmed documentation hashes remained unchanged. It did not repeat the parent suite, demos or builds and performed no native or network operation.

The delivery checklist is complete for this proof of concept. Native qualification remains separate: a reviewed configuration-fingerprint provisioning procedure, authorized disposable-Debian testing of real APT/download/lock/install/recovery, application-specific health checks and production controls are not delivered evidence.

## Limits and deployment gates

- Feed parsing still decodes the whole JSON snapshot before structural validation. Input byte limits do not establish a hard parser-memory limit.
- Trailer validation depends on a private CPython response hook; the real-response regressions pass on Python 3.12 and 3.14. Python 3.13, Debian 13's interpreter, was not run. Chunk grammar remains the standard library's responsibility; there is no aggregate wire-byte cap on chunk overhead.
- Worker network deadlines start after spawn. Interruption before multiprocessing publishes the handle, another interruption during cleanup, forced parent death and OS-delayed termination remain process-supervision concerns.
- Runner execution/output limits do not forcibly bound native spawn/exec handshake time. Graceful SIGINT cleanup is not crash containment, and process groups do not contain deliberately detached descendants. Other custom raising signal handlers are not guarded during native spawn. Any uncertain mutation must retain the lifecycle's recovery gate.
- No private development-host inventory, privileged package update, real APT repository resolution/download, native dpkg frontend-lock handoff or installed-state verification was performed. Native collection tests use synthetic files and fake dpkg output; lock/cleanup tests use temporary files and synthetic Python subprocesses.
- Fixed-source HTTPS acquisition alone is not durable provenance. The reviewed Engine/Store records acquisition and health separately from imported body claims; CLI provenance regressions preserve that boundary.
- The local proof-of-concept delivery is complete. Production scheduling, fleet enrollment, authenticated operators, externally protected audit and real privileged qualification remain separate deployment work. `native-config` supplies a read-only observation for configuration review; the independent review it requires is an operator procedure, not a product guarantee.

## Post-delivery critical review (2026-10-23)

A critical review of `73e27d7` used the real Debian tracker export (86 MB; 77,414 trixie records) and a disposable `debian:trixie-slim` image. It found these defects, fixed in `bc6eb4e`, `27ed6ee`, `2905d87` and `ca43e85`:

| Severity | Defect | Resolution |
| --- | --- | --- |
| High | Native backend could not pass the probe on stock Debian 13: base-files/keyring symlinks, `.pgp` keys, HTTP mirrors, `rc`/multiarch packages; Python pinned below trixie's 3.13 | In-root symlink fingerprinting, key aliases, signed HTTP sources, settled-state readiness, Python `>=3.12`, read-only `native-config` |
| High | Whole-host triage exceeded its 64 MiB bound for five `linux`-source binaries, blocking all planning | Findings grouped by package, status, fixed version and explanation with `advisory_ids`; worst case 1,760 rows/2 MB |
| Medium | `execute` 83 s and `plan` 20 s (repeated snapshot hashing and whole-host rematching under the write lock); inspection commands blocked during execution | Targeted `verify_affected`, verified-text cache, deferred read views, polling outside the write lock; `execute` 2 s, `plan` 0.6 s |
| Medium | Immutable findings sets and polled snapshots accumulated without bound | Schema 3, v2 migration, transactional pruning of unreferenced evidence; only affected findings persisted |
| Medium | Root could execute user-writable code (checkout venv, `python3 -m` current directory, adjacent probe) | Root invocations require root-owned package and module search path |
| Low | Gate retained after a pre-commit claim failure; malformed-gate override could finalize an unrelated plan; runner timed out on pipe-holding descendants and killed maintainer-script services; stable-suite freshness undocumented | Gate `cancel`, unclaimed-gate `recover`, malformed scope limited to `executing`, pipe grace and `keep_descendants` for successful installs, freshness guidance |

An independent read-only reviewer then examined `73e27d7..HEAD` and found no authorization bypass. It confirmed that `verify_affected` derives exactly what `match` derives, that prune retains everything referenced by plans and outcomes, and that the v2 migration, cache, poll race, symlink containment, cancel/recover ordering and runner return codes are correct. Its findings and their dispositions:

1. Medium, valid: `keep_descendants` also kept descendants after a nonzero `dpkg` exit. Now only a zero exit keeps them. Regression added.
2. Medium-low, valid: arbitrary dpkg `path-exclude` could leave vulnerable files while the version verified as fixed. Filters are now limited to documentation-like trees with no `..`.
3. Low, rejected with evidence: the claim that stock Debian `/usr/local` Python directories are `root:staff 2775`. A fresh trixie `python3-minimal` install in a disposable container showed `root:root 0755`. Upgraded hosts may differ; this is documented, and the check fails closed.
4. Low, valid: missing `sys.path` entries were skipped, and root `native-config`/`demo` ran before the check. Missing entries now require a trusted nearest ancestor, and every effective-root invocation is checked. `.pth` files, ACLs and module contents inside root-owned directories remain uninspected; this is documented.
5. Low, valid: HTTP allows replay of an older stable-suite Release within `max_repository_age`. Documented, with a recommendation for HTTPS mirrors.
6. Low, valid: the deadline could fire during the pipe grace after a timely exit. Exit now takes precedence; the descendant regression was updated accordingly.
7. Low, rejected: multiarch `same` skew is already refused by the APT simulation singleton check during planning. The malformed wrong-plan edge predates this change and is documented.
8. Low, valid: the verified-text cache is reduced to two entries.

Evidence: `python3 -m unittest discover -s tests` passes 485 tests on Python 3.12.13 and on `/usr/bin/python3.14`; `python3 -B scripts/check_package.py` passes. Real APT resolution, signatures against Debian keys, downloads, lock handoff, installation and recovery on Debian remain untested.
