# Review and verification record

## Scope and completion status

This record covers the reviewed design, intake, protected-file and backend/lifecycle APIs. It is not a review of a completed remediation product. The packaged CLI, end-to-end command demo, final integration review and operator documentation remain open in [DELIVERY.md](DELIVERY.md).

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

## Limits and remaining gates

- Feed parsing still decodes the whole JSON snapshot before structural validation. Input byte limits do not establish a hard parser-memory limit.
- Trailer validation depends on a private CPython response hook tested on Python 3.12. Other supported runtimes need the real-response regressions. Chunk grammar remains the standard library's responsibility; there is no aggregate wire-byte cap on chunk overhead.
- Worker network deadlines start after spawn. Interruption before multiprocessing publishes the handle, another interruption during cleanup, forced parent death and OS-delayed termination remain process-supervision concerns.
- Runner execution/output limits do not forcibly bound native spawn/exec handshake time. Graceful SIGINT cleanup is not crash containment, and process groups do not contain deliberately detached descendants. Other custom raising signal handlers are not guarded during native spawn. Any uncertain mutation must retain the lifecycle's recovery gate.
- No private development-host inventory, privileged package update, real APT repository resolution/download, native dpkg frontend-lock handoff or installed-state verification was performed. Native collection tests use synthetic files and fake dpkg output; lock/cleanup tests use temporary files and synthetic Python subprocesses.
- Fixed-source HTTPS acquisition alone is not durable provenance. The reviewed Engine/Store records acquisition and health separately from imported body claims; final CLI integration must preserve that boundary.
- Final acceptance still requires packaged user-facing CLI, disposable end-to-end command demo, final integrated security review and operator documentation.
