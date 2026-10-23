# Inventory and package authority

## Scope and evidence

The active target is **Ubuntu 24.04 LTS (`noble`), `amd64`**, including architecture-independent (`all`) packages where applicable. This reference separates the required inventory and remediation contract from research observations. It does not authorize host collection or package changes. **No privileged Ubuntu qualification has been performed.**

The `ubuntu` source consumes Canonical's Ubuntu Security Notice (USN) JSON database at `https://usn.ubuntu.com/usn-db/database.json`. The verified [Ubuntu source contract](UBUNTU.md) records the 2026-10-23 retrieval, source/binary mapping, supported pockets and limits. It supplies notice-based missing-update evidence, not complete CVE coverage. The recorded Ubuntu offline baseline and simulator workflows passed; verification of later native regressions and independent-review approval remain open.

The broader inventory and platform references were inspected on 2026-10-22. Their research scope does not establish that a collector, executor or fleet integration is implemented. Historical runtime observations remain in the [worklog](../../worklog/README.md), not as Ubuntu acceptance evidence here. The implementation contract is in [DESIGN.md](../DESIGN.md); current qualification gates are in [REVIEW.md](../REVIEW.md).

## Keep applicability, targets and authorization separate

1. **Applicability:** supported Noble USN evidence determines whether an installed source version is below or meets a published fix, with exact binary membership required. Missing or unsupported evidence is unknown. This is not complete coverage of vulnerabilities without published fixes.
2. **Target selection:** local APT policy identifies an exact available binary version from administrator-approved authenticated repositories. A fixed version in an advisory is a comparison boundary, not a URL or installation command.
3. **Authorization:** deterministic policy or an unexpired approval permits the immutable transaction on this asset. Feed text, imports, models and successful simulation grant no such permission.

Start with exact allowlists and one-package transactions that change no other packages. Kernels, boot components, package managers, essential packages, dependency transitions and unsupported service effects require external maintenance rather than weakening the executor. The runtime backend is `UbuntuApt`, selected as `ubuntu-apt`; simulator origins remain synthetic.

Native origin tuples require `origin=Ubuntu`, `label=Ubuntu`, `codename=noble`, with `archive` exactly `noble`, `noble-updates` or `noble-security`. Site and component must match reviewed policy too. **Backports, Ubuntu Pro and Expanded Security Maintenance (ESM) are excluded from remediation.** Local entitlement does not widen this contract, and an ESM-only fixed version must not become a standard-archive target.

## Ubuntu inventory and matching rules

### Platform identity

Read OS identity as data from `/etc/os-release`, with `/usr/lib/os-release` as fallback. Do not merge the files or source them as shell code. The format supports a data parser without a shell.[1] For native Ubuntu qualification, verify the exact Ubuntu release and architecture; a family hint in `ID_LIKE`, a similar package name or a reused machine image cannot establish support.

Retain stable asset identity, observation time, collector version, completeness and failures. Native identity derives from the local machine identity under the implementation contract; imported asset IDs remain claims. Cloned identifiers require operational handling rather than silently merging machines. Distinguish a host, image and application scope before comparing inventory.

The normalized runtime identity is `os=ubuntu`, `release=noble`, `architecture=amd64`, with package `ecosystem=deb`. Keep binary architecture separately. Foreign-architecture records may be present in a settled inventory, but only a uniquely installed, unheld `amd64` or `all` target is eligible for the first executor.

### Source and binary identity

Preserve installed binary name/version, source name/version, architecture, full package state and holds. One source can build many binaries. A source-version fix must be compared with the installed source version, not a guessed transformation of the binary name/version. Distribution backports can fix an older-looking upstream version, while a similar version from another lineage may not have the fix.

Native collection uses dpkg's `${source:Package}` and `${source:Version}` virtual fields. Imported Ubuntu records must supply source identity/version explicitly; they cannot gain native provenance or installed-lineage assurance from their fields. Unknown source metadata, local rebuilds or unsupported versions remain unresolved.

The native query shape is fixed by the collector, not supplied by an advisory:

```text
/usr/bin/dpkg-query --show --showformat='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Status}\n'
/usr/bin/dpkg --print-architecture
```

The show format is one argument. Use a fixed argument array, controlled environment and no shell. Bound output and duration; validate every identity, version, status and field length. Do not parse a human-oriented package listing or execute package binaries, application imports, build hooks or shell profiles to discover versions.

Keep holds, removed-with-configuration records, partial installation and errors visible. A settled package database can contain installed/held/marked-for-removal or removed-with-configuration records. Unpacked, half-installed/configured, trigger-pending and reinstall-required states block mutation. The target itself must be fully installed and unheld. A successful package query is not proof that collection was complete or race-free; native execution must recollect under the appropriate locks.

`dpkg-query` observes the package database, not file integrity or authenticated installed origin. A matching candidate name/version does not prove where installed bytes came from. `trusted_installed_lineage=true` is an administrator assertion, not a collector capability. Unknown lineage requires investigation or rebuilding from trusted artifacts, not a provenance field supplied by an import.

### Package versions and advisory states

Use Ubuntu's dpkg package-version ordering: optional epoch, upstream part and packaging revision, with native numeric/non-numeric ordering and tilde semantics. Preserve full versions; do not strip epochs/revisions or substitute lexical/semantic-version sorting. Keep source and binary versions separate even when they usually coincide.

`autoprotect/versions.py` owns the comparator. Offline fixtures cover epochs, tildes, numeric runs, missing revisions, packaging suffixes, binary/source differences and unsupported syntax. Parent integration ran `scripts/check_package_versions.py` against a disposable Ubuntu 24.04 image: 1,028 native dpkg comparison cases passed, with no network or host mounts during comparison. The [verification record](../REVIEW.md#ubuntu-verification-results) identifies the image digest. This is ordering evidence, not a package installation or privileged qualification.

Synthetic ordering examples: `1:1.0-1` is newer than `2.0-1`; `1.0~rc1-1` is older than `1.0-1`; `1.0-0ubuntu1.2` is newer than `1.0-0ubuntu1.1`. These are comparator examples, not claims about real Ubuntu fixes or available packages.

The adapter accepts `parse_ubuntu(data, release="noble")` for decoded JSON and `parse_source("ubuntu", raw)` for UTF-8 JSON bytes/text. The numeric database key and inner notice `id` must agree. Source fixes come only from `releases.noble.sources[NAME].version`. The Noble `allbinaries` map must explicitly link the installed binary to that source; `binaries` alone does not supply a usable source mapping.

Every linked binary must have a valid nonzero non-ESM version and explicit `security` pocket, and the source fix must also have valid nonzero non-ESM syntax. Missing or mixed evidence, Pro/ESM, realtime and FIPS pockets remain unknown. `fixed_version="0"` does not mean safe. Sources mentioned only under another release produce Noble unknowns without an inherited fix or binary mapping. Unlisted binaries and ESM-labelled installed versions remain unknown even when other source fields appear usable.

Normalized identity is `(source_name, release, USN ID)`. A notice with multiple sources creates one assertion per source, not a source/CVE cross product. Notice-level `cve_ids` are sorted/deduplicated references used only for incident correlation. Findings and plans bind USN IDs; a CVE reference does not establish that every source or release in the notice is affected.

For supported assertions, an installed source version below the fix is `affected` in the application's missing-update model; meeting it is `not_affected` by that notice's update requirement. This does not establish that every older version contains every referenced CVE, that running code has loaded the fix or that the host is uncompromised. A package without a notice remains unknown. Holds do not hide applicability but still block remediation.

The USN database has no authoritative severity field, so normalized urgency is `unknown`. Incident severity may raise investigation priority without changing applicability. Action prose, artifact URLs and checksums remain untrusted and are not retained as installation targets. An available candidate must come from separately authenticated approved APT metadata and meet the source-version boundary.

Ubuntu raw and decoded feed budgets are **512 MiB**, with 32,000,000 JSON nodes and depth 32. The parser also bounds notices, assertions, binary entries, CVE references and strings as specified in [UBUNTU.md](UBUNTU.md#bounds-and-operational-limits). It retains the whole JSON object; the budgets are not a memory reservation or parsing deadline. HTTP content compression is rejected.

Canonical distinguishes CVE OVAL vulnerability triage from USN OVAL missing-patch checks.[2] OVAL means Open Vulnerability and Assessment Language; it is an alternative, not an implemented adapter. Any future OVAL path must evaluate complete logical criteria with safe XML parsing rather than extract version-looking strings. Canonical's notice repository warns that its internal USN/LSN JSON can change.[3] The selected database therefore needs bounded failure handling and schema regressions, not an assumption of permanent format stability.

## Exact APT remediation contract

Here **index refresh** means `apt-get update`; **package update** means installation of an explicitly selected newer artifact. Neither belongs in a read-only collector. The implementation details below are a contract to verify on Ubuntu, not evidence of privileged execution.

1. **Establish the trusted base.** Require a healthy local noble amd64 asset, complete native inventory, independently reviewed installed lineage, standard archive policy and asset-specific recovery preparation. Inventory and investigation remain useful when execution is denied.
2. **Refresh separately.** Index refresh writes metadata and can invoke configured hooks. Obtain separate operational authorization; do not hide it in collection/planning. Restrict sources, keys, pockets, configuration and hooks, and surface partial/failed refreshes. An advisory cannot add a repository or key.
3. **Review effective configuration.** Require protected explicit Signed-By keys, exact origins and a reviewed `approved_config_digest`. Reject insecure trust/date overrides, redirected configuration, unsupported includes and unsafe package-manager options. `native-config` provides read-only evidence labelled `approved: false`; observing a digest is not approving it.
4. **Authenticate and bound metadata.** Verify source-specific InRelease signatures, matching Packages hashes and each contributing Release date/expiry. `max_repository_age` applies even without `Valid-Until`. The native investigation observed base noble Release `Date` 2024-04-25 and no `Valid-Until` in the inspected noble, noble-updates and noble-security metadata. Inventory and configuration inspection remain usable. Planning/execution apply age checks to every Release contributing the exact candidate version, not older base versions; a stale same-version origin still blocks the target. No universal age bound is recommended. Refreshing indexes does not change the publisher's date, and a larger accepted age widens replay acceptance where no earlier expiry applies.
5. **Discover candidates locally.** Follow native APT candidate policy, pinning and holds, not the numerically greatest version or a feed URL. Require exact binary/source identity, increasing binary version, sufficient source fix, approved origin, artifact hash/size and unambiguous same-version metadata. Missing, excluded or unsupported candidates remain unresolved; do not add another pocket or repository to manufacture a fix.
6. **Authorize the complete transaction.** Simulate the pinned request and reject new packages, dependencies, unrelated upgrades, removals, downgrades and held-package changes. Reject unsafe `Conflicts`, `Breaks` and `Replaces`. A singleton command argument does not prove a singleton package-state change or absence of script effects.
7. **Revalidate and serialize.** Bind the immutable plan to inventory, policy, evidence, exact artifact, configuration/index digests and expiry. Claim once; hold target/native locks and recheck all bindings. Download through the authenticated APT path into new private staging, then verify actual hash, size and binary/source identity. Keep the frontend lock through the final callback and installation.
8. **Install and verify.** The native backend uses a fixed local-artifact `dpkg` invocation rather than a second unconstrained resolver. Recollect and require the full expected singleton state delta. A timeout, interruption, partial state or mismatch retains the recovery gate and needs attention. Do not infer success from exit zero.

The install-command shape, for a **separately authorized** native operation, is:

```text
["/usr/bin/dpkg", "--force-confdef", "--force-confold", "--install", "VERIFIED_LOCAL_ARTIFACT"]
```

`VERIFIED_LOCAL_ARTIFACT` stands for the private backend-created path after authenticated download and identity checks. It is not a feed field or a user-supplied command fragment. Conffile handling takes the default answer and preserves local changes when no default is available; it does not promise that scripts cannot change services or data.

Use fixed absolute tools, a minimal environment, bounded output/time and no shell interpolation. Respect native package locks; simulation does not reserve a transaction. Do not add general `upgrade`, `full-upgrade`, automatic repair, downgrade, held-package override or unauthenticated-install paths to this backend. Scripts, triggers and external effects are not reversed reliably by reinstalling an older version. Backup/replacement and application-specific recovery remain prerequisites.

Required acceptance cases include wrong release/architecture/source identity, epochs/backports, unsupported or absent advisories, Pro/ESM-only fixes, backports/third-party origins, stale feed/inventory, unsettled or held packages, competing same-version artifacts, untrusted/expired metadata, insufficient fix, extra transaction changes, changed approvals, concurrency, failed download, interrupted installation and failed verification. Both authorized manual and automatic successes must pass with fake runners before any separately authorized native exercise.

## Installed software is not necessarily active software

Keep installed kernel packages, running kernel and livepatch observations separate. Installing a fixed kernel does not activate it. A livepatch can change exposure without changing ordinary package-version evidence; unsupported livepatch state remains unknown and is not part of this remediation backend. A running kernel release string is not a package version.

Processes can retain old executable/library mappings after an update. Restart diagnostics are evidence of activation needs, not proof that every workload is healthy. Do not install or invoke another privileged tool merely to improve inventory. Future runtime observation must have a reviewed implementation, minimal privileges and explicit scope.

Restart/reboot authorization needs availability policy, dependencies, maintenance windows, workload drain and post-action health checks. Package presence does not establish external exposure; absence of a listener does not exclude local or file-processing vulnerabilities. Package verification alone cannot close an incident involving compromise.

## Broader inventory options

These are research directions, not supported runtime adapters. CSAF is the Common Security Advisory Framework; VEX is Vulnerability Exploitability eXchange; SBOM is a software bill of materials.

| Scope | Evidence and collector options | Important boundary |
| --- | --- | --- |
| Other operating systems | Vendor/product/release-specific advisories and native package/update inventories; Red Hat CSAF/VEX, Alpine secdb, Microsoft Security Update Guide, Apple security releases | Do not apply Ubuntu package ordering or release assumptions to another ecosystem. Product, support stream and artifact lineage matter. |
| Containers | Image-bound SBOM, distribution/application evidence, immutable registry digest and platform-specific manifest | A tag can move; an updated image is not proof running replicas have been replaced. Host-kernel exposure is separate. |
| Applications | Lockfiles, build-generated SPDX/CycloneDX SBOMs, dependency graphs and environment metadata | Manifest ranges are not installed versions; a repository lockfile is not proof of the deployed artifact. |
| Existing management | Approved management inventory with enrolled identity, original observation time and completeness | Exports may omit source versions/architecture. Extend collection rather than silently infer fields. |

### Logical identity schema

This is a research schema, not a replacement for the runtime API in [DESIGN.md](../DESIGN.md). Package URL (PURL) helps interchange but is not a signature or a substitute for release/origin context.[4]

| Record | Minimum information |
| --- | --- |
| Collection | Schema/version, stable asset ID, host/image/application scope, collector identity/version, observation/receipt time, completeness/errors, inventory digest and evidence origin |
| Platform | Exact OS/release, native/package architectures, support channel, host/container scope and any separately authorized boot identity |
| Package | Ecosystem/version scheme, binary name/full version/architecture, source identity/version, state/errors/holds, optional PURL |
| Provenance | Local/imported/management source, original artifact/SBOM digest where available, known origin or explicit unknown reason |
| Candidate | Exact binary/source versions, approved origins, signing-key policy, authenticated metadata and freshness, hash/size and complete transaction |
| Applicability | Advisory identity/revision/digest, release/product scope, comparison inputs, verdict/reason, ordinary fix boundary and uncertainty |
| Runtime/recovery | Installed versus active state, observation method, restart/reboot needs, service/deployment health and recovery prerequisites |

Do not collect secrets, unrestricted process environments or arbitrary home directories. Public vulnerability queries disclose package names/versions; make egress a deliberate policy decision and support local evidence. Imported asset IDs and authenticated transport still cannot prove the truth of a compromised host's report.

### Containers and applications

Bind container findings and SBOMs to immutable image digests, recording the selected OS/architecture manifest for multi-platform images. Kubernetes distinguishes mutable tags from content-identifying digests.[5] Use restricted registry/orchestrator interfaces or offline inspection, not an unrestricted container-engine socket or execution of an untrusted image.

Inspect the final filesystem and application components, separating deleted layers, build-only dependencies, runtime mounts and mutable changes. An SBOM declares a subject and scope; it does not guarantee completeness. Validate schema, provenance and artifact binding.[6] Remediate by rebuilding approved artifacts, testing and rolling out a new digest through the deployment controller. Verify actual replicas, not just desired configuration. Publication and rollout require separate authorization.

Application collection should retain exact resolved versions/commits, integrity hashes, dependency edges, environment/platform markers and production/development scope. npm's lockfile documents resolved dependency trees and integrity fields.[7] `pip inspect` exposes environment inventory, but does not justify running an arbitrary project's interpreter on the collector.[8] Prefer offline parsing for untrusted artifacts; do not execute install/build hooks or application imports merely to inventory them. Dependency changes belong in the application's build/test/release process, not a host APT command.

### Fleet collection

| Approach | Useful properties | Costs and trust boundary |
| --- | --- | --- |
| SSH agentless | Bounded on-demand queries; existing collectors such as Ansible `package_facts`[9] | Requires host-key checks, credential controls, fixed collectors, explicit privilege and bounded concurrency. Agentless still executes code. |
| Enrolled agent | Outbound reports suit intermittent endpoints; osquery documents enrollment and authenticated transport[10] | Requires installation/upgrades, key rotation/revocation and resource controls. Separate read-only reporting from privileged execution. |
| Existing management | Reuses identities and operational ownership; systems such as AWS Systems Manager expose application/service/custom inventory[11] | Schema, coverage, freshness, access and licensing depend on deployment. Preserve original times/provenance and fill missing source metadata explicitly. |

Record per-asset failures, stale observations and unknown coverage. Encrypt transport/storage, isolate tenants and define retention. Never infer permission to scan a network or publish raw inventories from permission to inspect one project.

## Limits and escalation

- **VEX is contextual evidence.** Accept an approved issuer's statement only for the exact product/component/version or digest, configuration and revision. Retain conflicts, expiry and supersession. A signature identifies the claimant, not truth; a product statement cannot suppress unrelated library copies.[12]
- **Missing metadata is uncertainty.** Local builds, vendored/static code, stripped package databases, absent source identity, stale feeds and incomplete inventories remain unknown. A negative result covers only supported checks and evidence.
- **Backports require vendor semantics.** Older upstream-looking software can contain vendor fixes; Red Hat's documented practice independently illustrates why generic upstream comparisons fail.[13] That observation does not establish another platform's exact fixed boundary.
- **Unsupported or end-of-life software needs another path.** Check release and package-specific support. Preserve unresolved findings and assign investigation, migration, replacement or compensating controls; do not weaken signature/expiry checks or enable excluded support channels automatically.
- **Active scanning requires separate authorization.** Banners may be incomplete or misleading. Nmap documents that some version probes can affect devices, such as printers.[14] Require explicit targets, windows, limits and exclusions; inventory does not authorize exploit probing.
- **Compromise exceeds patching.** A hostile machine can falsify inventory; a compromised archive or signing key can distribute malicious software. Preserve evidence and use separately authorized containment, credential rotation and trusted rebuilds. NIST treats response/recovery as broader activities, not synonymous with updates.[15]

The historical source research collected no customer/development-host inventory and performed no privileged package operation. The Canonical USN contract has its own dated verification in [UBUNTU.md](UBUNTU.md); final integrated runtime evidence and real native lock/install/recovery qualification remain separate. Source research is not implementation acceptance.

## Research references

These references were inspected in the general research dated 2026-10-22. They are not Ubuntu runtime tests. The selected USN database and later source observations are documented separately in [UBUNTU.md](UBUNTU.md). Mutable pages and repository branches may change; source onboarding must recheck contracts, terms and access behavior.

1. systemd, [`os-release`](https://www.freedesktop.org/software/systemd/man/latest/os-release.html).
2. Canonical, [Ubuntu OVAL data](https://ubuntu.com/security/oval), distinguishing CVE and USN OVAL.
3. Canonical, [Ubuntu Vulnerability Data repository README](https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/README.md), formats and internal JSON warning. Its stated CC BY-SA 4.0 terms apply to that repository, not unrelated package payloads.
4. Package-URL project, [PURL introduction](https://www.packageurl.org/docs/purl/introduction).
5. Kubernetes, [Images](https://kubernetes.io/docs/concepts/containers/images/).
6. CycloneDX, [Software Bill of Materials](https://cyclonedx.org/capabilities/sbom/).
7. npm CLI 11, [`package-lock.json`](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).
8. Python Packaging Authority/pip, [`pip inspect`](https://pip.pypa.io/en/stable/cli/pip_inspect/).
9. Ansible, [`ansible.builtin.package_facts`](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/package_facts_module.html).
10. osquery, [Remote Settings](https://osquery.readthedocs.io/en/stable/deployment/remote/).
11. Amazon Web Services, [Systems Manager Inventory](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-inventory.html).
12. CycloneDX, [Vulnerability Exploitability eXchange](https://cyclonedx.org/capabilities/vex/).
13. Red Hat, [Security Backporting Practice](https://access.redhat.com/security/updates/backporting).
14. Nmap, [Service and Version Detection](https://nmap.org/book/man-version-detection.html).
15. NIST, [SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), published 2025-04-03; landing page/abstract inspected in the research, not the full report.

Public access does not establish unlimited use, availability or redistribution permission. Cache bounded responses, use conditional retrieval where supported, honor retry guidance and keep last-good evidence visibly stale during outages. Canonical source licensing, service guarantees and redistribution terms were not established by verifying the USN schema and sample fixes; see the [source research limits](UBUNTU.md#primary-source-observations).
