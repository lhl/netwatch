# Review and verification record

## Scope and completion status

This record covers the design baseline and task-5 feed acquisition, inventory, matching and command-runner APIs. It is not a review of a completed remediation product. SQLite provenance/source health, policy and approval enforcement, remediation backends, recovery lifecycle, packaging, CLI and end-to-end demo remain pending in [DELIVERY.md](DELIVERY.md).

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

## Limits and remaining gates

- Feed parsing still decodes the whole JSON snapshot before structural validation. Input byte limits do not establish a hard parser-memory limit.
- Trailer validation depends on a private CPython response hook tested on Python 3.12. Other supported runtimes need the real-response regressions. Chunk grammar remains the standard library's responsibility; there is no aggregate wire-byte cap on chunk overhead.
- Worker network deadlines start after spawn. Interruption before multiprocessing publishes the handle, another interruption during cleanup, forced parent death and OS-delayed termination remain process-supervision concerns.
- Runner execution/output limits do not forcibly bound native spawn/exec handshake time. Graceful SIGINT cleanup is not crash containment, and process groups do not contain deliberately detached descendants. Other custom raising signal handlers are not guarded during native spawn. Any uncertain mutation must retain the future lifecycle's recovery gate.
- No private development-host inventory, privileged package update, real APT repository resolution/download, native dpkg frontend-lock handoff or installed-state verification was performed. Native collection tests use synthetic files and fake dpkg output; lock/cleanup tests use temporary files and synthetic Python subprocesses.
- Fixed-source HTTPS acquisition is not itself durable provenance or source-health enforcement. Those are pending Engine/Store responsibilities; an imported body cannot promote itself to trusted acquisition.
- Final acceptance still requires the real backend's fake-runner tests, persistent authorization/concurrency/recovery tests, packaged user-facing CLI, disposable end-to-end demo, integrated security review and operator documentation.
