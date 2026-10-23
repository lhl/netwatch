# Review and verification record

## Ubuntu acceptance status

The active target is **Ubuntu 24.04 LTS (`noble`), `amd64`**, with the `ubuntu` advisory source and `ubuntu-apt` backend. Canonical's USN database at `https://usn.ubuntu.com/usn-db/database.json` provides notice-based missing-update evidence, not complete CVE coverage. Ubuntu Pro and Expanded Security Maintenance (ESM), realtime and FIPS pockets are outside assessment/remediation scope; approved native archive pockets remain noble, noble-updates and noble-security.

The [source research](research/UBUNTU.md) records a complete bounded retrieval on 2026-10-23: 354,359,354 bytes, 8,131 notices and 1,614 Noble entries, with sampled source/binary fixes corroborated against published notices. `feeds.py` and `matching.py` implement USN identities, notice-level CVEs used only for correlation, explicit standard-security source/binary evidence and unknown coverage. The fetch/import/parser budget is 512 MiB with 32,000,000 JSON nodes and depth 32. These observations and implementation facts do not establish final integrated verification.

**No privileged Ubuntu qualification has been performed.** The current deterministic suite passes 507 tests, including native freshness and shared feed-budget regressions. Independent review found an engine intake-limit mismatch; the shared-decoder repair passed re-review with no new findings. [DELIVERY.md](DELIVERY.md) owns the complete acceptance checklist.

Historical reviews, test counts, container observations and performance measurements remain in the immutable [worklog](../worklog/README.md). They are not Ubuntu evidence. Their detailed milestone narratives are intentionally omitted from this active record rather than relabelled as validation of a different target.

## Ubuntu verification results

Parent integration reported these results for the Ubuntu candidate:

| Check | Observed result and scope |
| --- | --- |
| Full deterministic offline suite | **507 passed in 25.515 seconds**, including native freshness and shared feed-budget regressions. |
| Module demo | **101 commands passed** through the ordinary CLI and disposable simulator. |
| Packaging and installed demo | Wheel and source distribution builds passed; the installed-console demo passed **101 commands**. |
| Manual and automatic walkthroughs | Both Bash procedures in [examples/README.md](../examples/README.md) executed successfully, returning verified execution and the expected USN `not_affected` result. |
| Real Canonical CLI polling | Two `poll ubuntu` commands in fresh disposable state succeeded with HTTPS provenance, no source error, the same snapshot/ETag and refreshed source health. No host inventory or package execution occurred. |
| Native version comparison | `scripts/check_package_versions.py` passed **1,028 cases** against dpkg in a disposable Ubuntu 24.04 image. This checked synthetic version ordering, not inventory or installation. |

The Ubuntu image was pulled before the comparison and identified by digest `sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac`. The comparison ran without network access or host mounts. Image acquisition and isolated comparison are distinct operations; neither establishes native APT execution or privileged qualification.

The independent reviewer inspected the integrated candidate, reported R1, and closed it after the repair. The reviewer did not run tests or perform privileged operations; runtime evidence above was collected during integration.

## Remaining acceptance and evidence

The migration's committed worklog records closeout and the retained debconf protocol-variable exception. The current full suite has no skipped tests. A documentation syntax check is not a runtime test.

| Gate | Required evidence | Status |
| --- | --- | --- |
| Canonical source contract | Fixed USN JSON endpoint, USN/source identity, notice-level CVE correlation, Noble security-pocket binary membership, unknown coverage and bounded parsing | Verified source contract in [UBUNTU.md](research/UBUNTU.md); offline suite passed at the recorded candidate |
| Feed command integration | Poll provenance/source health and import admission consistent with the 512 MiB adapter budget; no partial snapshot accepted | Recorded offline suite, synthetic imports and real fixed-endpoint CLI polling passed |
| Ubuntu inventory and version matching | Exact noble/amd64 identity, source/binary version separation, distribution backports, epochs, unknown coverage and stale observations | Recorded offline suite and 1,028-case Ubuntu dpkg comparison passed |
| Standard archive boundary | Exact approved Ubuntu origins and noble pockets; no Pro/ESM remediation; reject unsupported repositories, entitlement-dependent fixes and unsafe transactions | Latest native regressions passed: 8 native-pipeline and 5 Release-pipeline tests; independent review complete |
| Repository freshness | Reconcile observed Release dates and missing expiry with bounded policy and replay protection, without weakening checks to force a candidate through | Inventory/inspection stay usable; older base versions do not block newer security candidates, while stale same-version contributors reject the target. No universal age bound recommended |
| Authorization and recovery | Manual and automatic successes; denied policy, imported provenance, stale approvals, changed inputs, concurrent claims, interruption, failed verification and target-wide recovery generation | Recorded suite and both 101-command demos passed; independent review complete |
| State compatibility | Schema 4 rejects previous schemas and preserves their records; require fresh state, acquisition, collection and authorization, without bypassing native target gates | Recorded offline suite passed; independent review complete |
| CLI and examples | Module and installed entry points; both simulator walkthroughs; actual demo outcomes and cleanup | Module/installed demos and both documented workflows passed |
| Packaging | Offline wheel/source build, isolated install and installed demo | Passed |
| Independent review | Read-only review of integrated acquisition, matching, command construction, persistence, authorization and recovery; resolve valid findings and rerun affected checks | R1 resolved and independently re-reviewed; no new findings in the repair |
| Product documentation | Commands, identifiers, links, restrictions and claims match the integrated runtime; no inherited platform-specific observations presented as Ubuntu results | Documentation rewrite, local-link/shell-block checks and final content audit complete; protocol-variable exception retained on user-directed closeout |

Baseline commands from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
python3 -B -m autoprotect demo
python3 -B scripts/check_package.py
python3 scripts/worklog.py check
python3 scripts/worklog.py render
git diff --check
```

The comparator result above applies to the identified Ubuntu image and those 1,028 cases. It does not authorize further image pulls or host package operations, nor qualify privileged installation.

The examples use `examples/ubuntu-synthetic.json`, whose `example-app` source/binary and `1.0-1ubuntu0.24.04.1` fix match the simulator inventory/catalog. `tests/fixtures/feeds/ubuntu.json` remains the broader parser fixture. Both procedures passed using this example input; the broader parser fixture was not substituted for it.

## Independent review finding

R1 identified a functional failure: the engine retained 128 MiB / 8,000,000-node decoding limits although the actual Canonical response exceeded both. `feeds.decode_source()` now supplies the same source-specific limits to standalone parsing and engine import/poll, preserving provenance-envelope rejection. Red-first regression tests demonstrated the missing shared decoder call; import/poll budget and retention tests now pass. Independent re-review closed R1 with no new findings. A subsequent real CLI poll and refresh both succeeded in disposable state.

## Security boundaries to preserve

- **Evidence is not authority.** Feed text, imported inventory, model responses and exports remain untrusted. Only fixed-source acquisition can establish the evidence provenance required for native execution. Imports cannot claim that provenance.
- **USN coverage is limited.** Findings/plans bind notices, not individual CVEs. `cve_ids` correlate incidents without inventing a source/CVE cross product. Assessment needs exact binary membership and standard `security`-pocket source/fix evidence; absent notices, unsupported pockets and missing fixes remain unknown. Meeting a notice fix is not proof of complete vulnerability coverage.
- **Installed versions are not upstream versions.** Match exact Ubuntu release and source-package identity, preserve the binary version used for installation, and use the package comparator. Missing or unsupported evidence stays unknown.
- **Repository metadata selects artifacts.** An advisory fix is a comparison boundary, never a repository URL or executable argument. Bind the artifact hash, size, source identity, exact origins and reviewed configuration to the plan.
- **Approval is bound and temporary.** Recheck current policy, inventory, source health, target, generation and expiry. Manual approval and automatic policy both retain these checks.
- **A single target does not imply a single change.** Reject dependency transactions, removals, downgrades, sensitive packages and unsafe package relationships. Verify the complete expected package-state delta after execution.
- **Uncertain execution requires recovery.** Publish the target-wide gate before mutation, retain it after indeterminate outcomes, and require explicit evidence-bound resolution followed by fresh collection and a new plan. Gate resolution is not rollback or successful remediation.
- **Local ownership is a trust boundary.** Effective-root commands require protected code and module search paths as well as policy/state. Root and the trusted database owner remain trusted; content hashes and local audit rows are not tamper-proof storage or authenticated operator identity.

## Limits and deployment gates

No real Ubuntu APT resolution/download, Ubuntu archive signature/index qualification, native package-lock handoff, privileged installation or recovery exercise has been established by this documentation work. Synthetic native runners do not establish system-Python compatibility or actual package-manager behavior. Collection tests must not be described as private-host observations unless that collection was separately authorized and performed.

A separately authorized disposable Ubuntu target must qualify the system `python3-apt` bindings, reviewed configuration report, signed repository metadata, authenticated downloads, frontend/database locks, installation, complete package-state verification and recovery. Include interrupted execution, partial package state, failed verification and storage-loss exercises. Keep approval of that exercise distinct from approval of any production host.

Other limits remain material:

- Whole-document decoding can require substantially more memory than the 512 MiB Ubuntu raw/decoded feed budget. The node and byte limits are not a process memory quota or parser deadline. Compression is rejected, not transparently decompressed.
- HTTP chunk-trailer handling depends on a private CPython response hook. Run its real-response regressions on supported Python versions; do not infer compatibility from a different runtime.
- Network-worker deadlines start after spawn. Native process startup/exec handshake is not forcibly time-bounded. Cleanup depends on Python unwinding and working OS controls; abrupt process/host death and deliberately detached descendants require supervision and retained recovery evidence.
- Package database verification does not establish service health, active kernel state, installed-byte integrity or absence of compromise. Script effects, restarts, reboot decisions and application recovery need separate procedures.
- Root-owned module search paths do not inspect every third-party module, `.pth` file or access-control list. Those contents remain a provisioning trust assumption.
- The native metadata investigation observed base noble Release `Date` 2024-04-25 and no `Valid-Until` in the inspected noble, noble-updates and noble-security metadata. Only contributing metadata for the exact candidate version is subject to age checks during planning/execution; old metadata does not block inventory or configuration inspection. No universal `max_repository_age` value is recommended; refreshing local indexes does not renew the publisher's date. HTTP additionally permits observation, withholding and replay within accepted age bounds.
- Local SQLite serialization is not fleet coordination. Scheduling, authenticated operators, enrollment, protected central audit, tested backups, maintenance windows, canaries and application/container deployment controls remain proposed work.

The [operator runbook](OPERATIONS.md) describes conditional procedures and clearing actions. Passing offline checks will not by itself close the privileged qualification or production gates.
