# Inventory and distribution patch authority

**Research reference, accessed 2026-10-22.** This document recommends a design; it does not describe implemented collectors or authorize live scanning or patching. No host or customer inventory was collected. Official documentation and public feed samples were inspected; command examples below were not run against the development host's package database.

## Recommendation

Start with a read-only `dpkg` collector and an exact-version APT executor for **one explicitly supported Debian release and architecture**. Debian 13 (`trixie`) on `amd64`, with architecture-independent (`all`) packages, is a feasible initial target; Debian identifies 13 as stable on the access date.[1] Import synthetic inventories for the demo, use fake command runners for executor tests, and require a fresh local collection before any later authorized live execution. Do not infer Ubuntu or derivative support from `ID_LIKE=debian`.

Keep three decisions separate:

1. **Applicability:** distribution-specific evidence says whether the installed source/binary package in this release is affected, fixed, not affected, or unknown.
2. **Target selection:** the native package manager identifies an exact available binary version from administrator-approved, authenticated repositories. An advisory's fixed version is a comparison boundary, not a download instruction.
3. **Authorization:** deterministic policy or an unexpired approval permits the complete transaction on this asset. Neither feed text, an imported inventory, a model response, nor a successful simulation grants this permission.

Begin automatic execution with an explicit allowlist of low-risk packages and transactions that change no other packages. Route kernels, boot components, package managers, essential packages, service-impacting updates and dependency transitions to review until their operational handling is implemented. This leaves a usable automatic path without claiming that all updates are safe or reversible.

## Source and collector matrix

OVAL means Open Vulnerability and Assessment Language; USN is an Ubuntu Security Notice; CSAF is the Common Security Advisory Framework; VEX is Vulnerability Exploitability eXchange; SBOM is a software bill of materials.

| Scope | Official applicability / fixed-version evidence | Inventory and candidate authority | Important boundary |
| --- | --- | --- | --- |
| Debian | Security Tracker JSON: source package → CVE → release; release-specific status, fixed version and repository versions. Security Team documentation explains release overrides, unfixed, no-advisory and end-of-life states.[2–4] | `dpkg-query`: installed binary/source names and versions, architecture and status. APT: authenticated archive metadata, candidate policy and full transaction.[5–10] | Match the exact release and source version; never reuse an upstream threshold or `sid` fix for stable. A repository's resolved status is not the host's installed status. |
| Ubuntu | Canonical CVE OVAL describes vulnerability triage; USN OVAL describes published updates/missing patches. Release-specific compressed XML is linked from the official OVAL page.[11] | `dpkg`/APT plus Ubuntu release, archive pocket, architecture and support/entitlement context. | Ubuntu is not Debian for vulnerability matching. USNs alone do not cover vulnerabilities without a published patch. Canonical warns that its internal USN/LSN JSON format can change at any time.[12] |
| Red Hat | CSAF advisories describe security fixes; per-CVE VEX describes affected, not-affected and fixed products/components. OVAL patch streams remain available but are in maintenance mode.[13–15] | RPM binary name, epoch/version/release, architecture, source RPM, product/repository/module stream; native DNF resolution and update information.[16–18] | A larger RPM version from a different product or Extended Update Support stream need not be more secure. Resolve CSAF product relationships, not just matching package names. |
| Alpine | `secdb.alpinelinux.org/<branch>/<repository>.json`: package entries with `secfixes` mapping fixed APK versions to CVEs.[19] | APK installed package name/version/architecture and source `origin`; configured branch/repository and native APK resolution/comparison.[20–22] | Preserve `-rN`, source/subpackage mapping and branch. Absence from a fixes database is not an explicit not-affected verdict. Do not use its `apkurl` template as execution authority. |
| Containers | Distribution evidence for image OS packages; ecosystem evidence for application components; image-bound SBOM and scoped VEX.[23–25] | Registry/repository, immutable image digest, platform-specific manifest digest, runtime instance and deployment revision. | A tag is mutable. A rebuilt/patched image is not proof that running workloads have been replaced. Host-kernel exposure is separate from image packages. |
| Applications | Ecosystem-specific advisories, interpreted against the actual dependency graph; separate work covers those feed integrations. | Lockfiles, build-produced SPDX/CycloneDX SBOMs and environment inventory; bind to artifact digest/commit and runtime environment.[24,26–27] | A manifest range is not an installed version. A lockfile is not proof of what was deployed, and a host package database misses bundled/static/vendor code. |
| Windows / macOS | Microsoft Security Update Guide/API; Apple security releases.[31,34] | Windows Update Agent and OS build/product information; Apple device-management OS/build queries.[32–35] | Future adapters only. Neither platform should be reduced to Debian-like version comparisons or a list of missing CVE numbers. |

## Distribution matching rules

### Debian: source packages, releases and special states

The JSON endpoint is `https://security-tracker.debian.org/tracker/data/json`. A bounded live prefix confirmed nested source-package and CVE keys, then `releases`, `status`, `repositories`, `fixed_version` and `urgency`. For example, the sampled `389-ds-base` records contained distinct `bookworm`, `trixie` and `sid` objects. This was a structural sample, not a completeness or schema-stability test.[2]

Use these rules:

- Join installed **source name and source version** to the release-specific tracker entry. One source package can produce several differently named binary packages. Preserve the binary name/version too: that is the package APT installs. Debian's `Source` field can carry a version different from the binary version; binary-only rebuilds are one reason not to substitute the binary version blindly.[5]
- Prefer `dpkg-query`'s `${source:Package}` and `${source:Version}` virtual fields. If parsing control records instead, Debian Policy permits omitted `Source` only when source and binary name/version coincide, and an omitted source version means the binary version. Apply that documented fallback, not a guessed name transformation.[5–6]
- Select a codename such as `trixie`, not a moving alias such as `stable`. Keep repository pockets such as `trixie-security` separate from the release identity. The Security Team documents that the base tracker data primarily targets `sid`; release tags and advisory data alter the result for stable/oldstable.[3]
- `status=resolved` concerns the distribution's tracked package state. Compare the actual installed source version against the applicable ordinary fixed version; an old host may still be vulnerable after the archive is fixed.
- `fixed_version="0"` is a special not-affected marker, not an installable version: the tracker source renders it as “(not affected)”. Missing or unrecognized fixed-version data must not become a guessed target.[4]
- Preserve unresolved/undetermined and support states. `<no-dsa>` means an issue does not warrant an immediate Debian Security Advisory, not that it is fixed; `<ignored>`, `<postponed>` and `<end-of-life>` also need explicit handling.[3] Do not flatten these into a boolean `safe`.
- A source-level match may conservatively implicate binaries that do not contain the vulnerable code. Keep that granularity visible; stronger binary-specific evidence can refine it. Debian triage does not establish the status of modified packages or software outside Debian.[3]

**Comparison contract:** Debian versions have `[epoch:]upstream_version[-debian_revision]`. Compare epoch numerically, then the remaining components using Debian's alternating digit/non-digit rules; `~` sorts before even the end of a component. Do not use lexical sorting, generic semantic-version libraries, or strip the epoch/revision. Use `dpkg --compare-versions` or a verified implementation of the same rules.[5]

Synthetic examples: `1:1.0-1` is newer than `2.0-1`; `1.0~rc1-1` is older than `1.0-1`; `1.0-1+deb13u2` is newer than `1.0-1+deb13u1`. These demonstrate ordering only, not actual vulnerability fixes.

### Ubuntu: evaluate criteria, not XML string matches

Canonical documents two different questions: CVE OVAL evaluates vulnerability status; USN OVAL evaluates missing published patches. Preserve their distinction. The documented USN feed naming pattern is `com.ubuntu.<codename>.usn.oval.xml.bz2` under `https://security-metadata.canonical.com/oval/`; there is also separate official-cloud-image OVAL.[11]

A future adapter should evaluate the complete release/package criteria, including nested logical tests and relevant support context, rather than extract the first version-looking string. Record whether the applicable update is available in the asset's configured standard or extended-security-maintenance repositories. Feed access does not establish package entitlement. Use bounded decompression and XML parsing with external entities/network retrieval disabled.

USN pages remain useful review evidence. Canonical's official notice repository offers USN/LSN, OSV and OpenVEX formats, but explicitly discourages reliance on the changeable internal USN/LSN JSON format.[12] Reusing Debian's inventory mechanics does not authorize reusing Debian's vulnerability verdicts.

### Red Hat: preserve product and stream identity

Use the published CSAF provider metadata to discover advisory and VEX collections. Retain document revision, product tree, relationships, architecture and `product_status`. Red Hat's guidance explains that fixed components carry versions, while some unfixed source-level components do not; it also warns that source-to-binary expansion can differ between advisory and VEX records, especially for older products.[13–14]

OVAL patch streams detect missing **released** security updates, not all vulnerabilities without fixes. Red Hat explicitly explains that RPM versions across incompatible product/repository streams cannot establish patch ordering; its OVAL tests also check Red Hat package signatures to distinguish locally rebuilt or upstream packages. Those tests are not an integrity audit of the host.[15]

RPM ordering uses **epoch, version, release (EVR)**, with an omitted epoch treated as zero and RPM-specific segment, `~` and `^` rules. Use the target's supported RPM comparator; retain name and architecture separately. Do not compare EVRs across unrelated products, module streams or support channels.[16] DNF's documented `updateinfo` queries can enumerate security updates; resolution still depends on enabled repositories and policy, including repository priorities.[17–18] Audit configured keys and package-authentication settings, and verify the chosen artifacts; an update listing alone is not authentication evidence.

Red Hat's backporting documentation gives direct counterevidence to upstream-only matching: older upstream software can contain vendor-applied fixes, and scanners using only upstream versions can report false positives.[36] A vendor version is meaningful only within the vendor's own package lineage.

### Alpine: fixes and source origins

A live `v3.22/main.json` sample contained `distroversion`, `reponame`, `archs`, `packages[].pkg.name` and `secfixes`; for example, the `amavis` entry mapped `2.13.1-r0` to `CVE-2024-28054`.[19] This demonstrates the fixed-version shape, not a recommendation to install that version or adopt that branch.

APK documents `origin` as the source package name. Preserve it alongside each installed subpackage name and use it when matching source-level secdb entries.[20] Preserve the full APK version including package revision. `apk version -t VERSION1 VERSION2` compares two versions without consulting the installed database and returns `<`, `=` or `>`.[21] Do not substitute Debian or RPM ordering. Resolve actual targets from approved APK repositories for the same branch/architecture, not from secdb URLs. Mixing stable and edge repositories is explicitly discouraged by Alpine.[22]

## Recommended package-identity schema

This is a proposed logical schema, not an existing API. Keep observations, applicability and executable plans in separate records. Package URL (PURL) is useful for interchange but is not a signature or a substitute for release/origin context.[37]

| Record | Minimum fields | Reason |
| --- | --- | --- |
| Collection | `schema_version`, `asset_id`, `scope_kind` (`host`, `image`, `application`), collector/version, collection start/end, receive time, completeness/errors, canonical inventory digest, evidence origin and trust classification | Distinguishes a current authenticated collection from a stale import, failed collection or partial view. An empty failed scan is not a clean asset. |
| Platform | OS `ID`, `VERSION_ID`, `VERSION_CODENAME`; native/package architectures; distribution/support channel; root/container scope; boot identity where authorized | `ID_LIKE` is a family hint, not proof that another distribution's advisories apply. Cloned hostnames/machine IDs must not silently merge assets. |
| Installed package | ecosystem/version scheme; binary name, full raw version, architecture; source name/version or source RPM / APK `origin`; install status/error/wanted state; held state; optional PURL | Preserves native identity and source-to-binary mapping without lossy normalization. Keep normalization rules versioned. |
| Provenance | local/imported/management source, collection identity, original artifact or SBOM digest where available, repository identity if known, unknown-provenance reason | `Maintainer`, `Homepage`, package name and a version string do not prove where installed bytes came from. Do not invent installed origin from a matching candidate. |
| Candidate | binary name/version/architecture; candidate source name/version; approved repository URI identifier, origin/label/codename/component; signing-key policy; authenticated metadata digest and freshness; artifact hash; full resolved transaction | Allows the candidate's source version to satisfy the advisory threshold while binding execution to exact binary artifacts. Redact repository credentials. |
| Applicability | advisory ID/revision/digest, distribution/product scope, comparison scheme and inputs, verdict, reason, fixed boundary if ordinary, uncertainty and evidence | Separate `affected`, `fixed`, `not_affected`, `unknown`, `unsupported` and `stale`; retain conflicting evidence rather than silently pick the reassuring source. |
| Runtime / recovery | running kernel, installed kernels, restart/reboot requirements and observation method; service/deployment health; recovery prerequisites | An installed update is not necessarily active, and an active update is not evidence of incident recovery. |

Bind an approval or automatic-policy decision to the immutable plan digest, authenticated asset identity, complete package-change set, inventory digest, repository/configuration evidence, policy revision and expiry. An imported `asset_id` is a claim, not authentication. Use a locally provisioned or enrolled identity and revalidate on the target.

### Minimal read-only Linux `dpkg` inventory

A baseline collector needs only:

- Parsed `/etc/os-release`, falling back to `/usr/lib/os-release`; do not merge or source them as shell code. The specification allows a data parser without a shell.[38]
- Native and configured foreign package architectures; an explicit host/image/application scope; collection timestamps and errors.
- The following fields for each package. `${Status}` preserves desired state, errors and installation state; only fully installed, healthy entries qualify for automatic update. Keep held and partial states visible rather than dropping them.
- A separate running-kernel observation, such as `uname -r`, recorded as a kernel release string, **not** a Debian package version. Failure to observe runtime state must remain explicit.

Illustrative query, fixed by the collector rather than supplied by an advisory:

```text
/usr/bin/dpkg-query --show --showformat='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Status}\t${Essential}\n'
/usr/bin/dpkg --print-architecture
/usr/bin/dpkg --print-foreign-architectures
/usr/bin/apt-mark showhold
/usr/bin/uname -r
```

The quoted format is one argument; an implementation should pass an argument array directly, with a controlled locale/environment and no shell. Do not parse the human-oriented `dpkg -l` table.[6] Bound output, duration and field lengths; validate names, versions, architectures and statuses; reject unexpected control characters and malformed rows. Do not collect descriptions, maintainer contacts, environment variables, command-line secrets or arbitrary home directories by default.

`dpkg-query` supplies package database evidence, not file integrity or authenticated installed origin. A collector can run without root for baseline package metadata, while stronger process/runtime evidence may require separate privileges. Record collection races: hash/check the package-state inputs before and after, retry boundedly or mark inconsistent, and always recollect during execution preflight.

## Safe exact APT update contract for the first backend

Here **metadata refresh** means `apt-get update`; **package update** means installing an explicitly selected newer package version. Neither is part of the read-only collector.

1. **Establish the trusted base.** Require a healthy, administrator-approved Debian asset, supported release/architecture and known repository policy. Unknown or local/custom package provenance stays review-only. Inventory is still useful when execution is denied.
2. **Refresh under separate authorization.** `apt-get update` writes package indexes and can run configured update hooks; it is not a read-only probe.[7,39] Permit only preapproved sources, codename/pockets, keys and configuration. Do not let an advisory add a repository, key, URL or option. Require authentication/date/expiry checks, a successful bounded refresh with `--error-on=any` (or a tested equivalent), and explicit freshness limits even if an archive omits `Valid-Until`.[7–9]
3. **Verify effective configuration.** Use restricted `Signed-By` keys. Reject `trusted=yes`, insecure/weak authentication overrides, disabled date/expiry checks, unreviewed hooks and environment-supplied APT configuration. APT configuration lists are not cleared merely by assigning an empty scalar; its manual specifies `#clear` for lists/scopes.[8–9,40] Treat root-owned repository/configuration state as an explicit trust assumption, not something an imported inventory can certify.
4. **Discover candidates locally.** Inspect APT candidate policy and the exact candidate's metadata, including binary/source versions and origin. `apt-cache policy`, `apt-cache show --no-all-versions` and native APT library interfaces can support discovery. Cached metadata can be stale; these queries alone do not prove a fresh authenticated download.[10] Do not select the numerically greatest version independently of pinning or holds. If the candidate is below the fix, absent, ambiguous or unsupported, queue investigation; do not add another release or third-party repository to obtain it.
5. **Bind artifacts as well as versions.** APT preferences select versions, not a particular repository's copy of an identical version. When several sources offer that version, APT can choose the earlier source.[8] Restrict usable sources and verify the selected package hash against authenticated metadata. Origin/label strings without the signature chain are insufficient.
6. **Resolve and authorize the entire transaction.** Use native Debian comparison to require a target binary version strictly newer than the installed version and a candidate source version meeting the release-specific fix. Simulate the exact request under the same configuration. Reject removals, downgrades, new packages, held-package changes, unrelated upgrades, broken/partial package states and unsupported outputs. The first backend can require the change set to contain only the allowlisted target; later designs may explicitly approve a dependency closure.
7. **Execute only after revalidation.** Claim the plan once, serialize the target, recheck inventory/configuration/candidate/approval freshness, respect native package locks and abort on drift. `apt-get --simulate` disables locking and therefore does not reserve the plan.[7] Coordinate with other package-management automation. A pre-install transaction gate or native transaction API must reject any resolved change outside the approved set before unpacking; a simulation followed by an unchecked install is insufficient.
8. **Verify installed and active state.** Requery exact package versions and healthy configuration status, then perform approved service/workload health checks. Report `installed_pending_restart` or `installed_pending_reboot` when appropriate; do not claim full remediation from an exit code. A timeout/interruption is indeterminate until state is inspected, not permission to rerun automatically.

Command construction shape for a **later authorized** executor, not an instruction to run here:

```text
["/usr/bin/apt-get", "--assume-yes", "--no-remove", "--only-upgrade",
 "--no-install-recommends", "install", "--", "NAME:ARCH=EXACT_BINARY_VERSION"]
```

`NAME`, `ARCH` and `EXACT_BINARY_VERSION` are placeholders derived from validated inventory and authenticated candidate records, not from prose. Match exact known package identities; reject paths, expressions, option-like input and extra selectors. Do not use `upgrade`, `dist-upgrade`, `full-upgrade`, `autoremove`, `--fix-broken`, forced downgrades, held-package overrides, or unauthenticated-install switches in this backend. `--only-upgrade` and `--no-remove` are defense-in-depth, **not proof that only the named package changes**: dependencies, configuration and maintainer scripts still matter.[7]

Use a controlled noninteractive environment, bounded output and time, and a defined configuration-file conflict policy; do not silently overwrite operator changes. Debian package installation runs maintainer scripts, so there is no universal “no service effects” guarantee.[5] Approve packages and maintenance windows accordingly. Backups/snapshots and an application recovery runbook are prerequisites where the impact warrants them. Installing an older package cannot reliably undo scripts, migrations or external effects.

**Implementation acceptance cases:** source/binary mismatch; epoch, tilde and binary-rebuild versions; `fixed_version="0"`; unresolved/no-advisory states; wrong release; absent/stale feed; stale/partial inventory; held or broken package; same version from competing repositories; expired or untrusted metadata; candidate below fix; additional dependency/removal; approval drift; concurrent executor; download failure; interrupted install; failed installed-state/health verification. Include authorized manual and automatic successes with fake runners. No privileged execution is claimed by this research.

## Installed software is not necessarily running software

Maintain separate evidence for installed kernels, the running kernel, and any livepatch mechanism. Installing a fixed kernel does not replace the running kernel automatically. Conversely, a livepatch may change exposure without changing the ordinary package/version observation; require vendor-specific livepatch evidence or leave the result unknown. Map the running kernel to its actual package/build rather than comparing its `uname` string with a package version.

Processes can retain old executable/library mappings after files are upgraded. Debian's `needrestart` explicitly checks daemons needing restart and offers obsolete-kernel/library checks and list-only mode.[41] Treat such output as restart evidence, not proof that every workload is healthy or that every language runtime has been inspected. Any future integration should use a supported, reviewed version with approved configuration and a minimal privilege boundary; do not install or invoke it automatically merely to collect inventory.

A restart or reboot needs separate availability policy: dependencies, maintenance windows, workload drain, redundant instances and post-action checks. A package's presence does not prove that it is listening or externally reachable; lack of a listening port does not rule out local or file-processing exposure.

## Containers and application dependencies

**Containers:** collect desired and observed image references separately. Bind findings and SBOMs to a digest; record the selected OS/architecture-specific manifest when a multi-platform index is used. Kubernetes documents that tags can move while digests identify fixed image content.[23] Collect through a restricted orchestrator/registry interface or offline image analysis, not by granting a collector an unrestricted container-engine socket or executing an untrusted image.

Inspect the final image filesystem and application components as well as the base image. Keep deleted layers, build-only dependencies, runtime-mounted content and mutable container changes distinct. An SBOM's component list is evidence about its declared subject and scope, not guaranteed completeness. Prefer trusted build-generated SPDX/CycloneDX documents bound to the produced artifact; validate schema, identity and provenance and record unsupported/missing components.[24]

Remediate by rebuilding from approved sources, testing, publishing a new approved image and rolling out its digest through the existing deployment controller—not by patching a transient running container. Verify that all relevant replicas actually run the new digest. Publication and rollout require separate operational authorization; none is performed here. Image patching does not update the host kernel or container runtime.

**Applications:** collect lockfiles and build SBOMs from explicitly authorized project/artifact roots. Preserve ecosystem, package namespace, exact resolved version or commit, integrity hash, dependency edges, optional/platform markers and production/development scope. Examples include `package-lock.json`, `Cargo.lock`, and pinned Python lockfiles; an unpinned requirements file is not an exact inventory. npm documents lockfile versions, exact resolved trees, integrity fields and installation-script metadata.[26]

Cross-check build artifacts or deployed environments rather than assume repository state equals production. `pip inspect` provides JSON environment inventory; its existence does not authorize executing an arbitrary project's Python interpreter on the collector.[27] Prefer offline metadata parsing for untrusted artifacts. Do not run install/build hooks, source shell files, import application modules or execute package binaries simply to discover their versions. Changes to application dependencies should go through the application's build, tests and release process, not a host APT command.

## Fleet collection choices

These are deployment options, not implemented features. Start with local read-only collection/import; prefer an existing approved management integration before introducing another privileged service.

| Approach | Useful properties | Costs and trust boundary | Recommendation |
| --- | --- | --- | --- |
| SSH agentless | No permanent new daemon; bounded on-demand queries for reachable Linux servers. Ansible's `package_facts` is an existing installed-package collector.[28] | Requires host-key verification, credential management, network reachability and explicit privilege rules. Remote commands/modules still execute; “agentless” is not “no code runs.” Offline endpoints remain stale. | Use a fixed allowlisted collector, least-privilege account, no agent forwarding, pinned host identity, time/output limits and bounded concurrency. Do not construct remote shell commands from advisory text. |
| Enrollment agent | Outbound collection suits intermittently connected endpoints; scheduled snapshots and local runtime observations. osquery documents enrollment and authenticated configuration/log transport.[29] | Adds installation, upgrades, key rotation/revocation, backend security and resource costs. Enrollment authenticates the sender, not the truth of a compromised host's observations. | Separate read-only collection from privileged execution. Use per-device credentials and replay/freshness checks; never expose arbitrary administrative commands through the inventory channel. |
| Existing management | Reuses enrolled identities, access controls and operational ownership. AWS Systems Manager Inventory documents managed-node application, service and custom metadata collection.[30] | Coverage/schema and freshness may not meet source-package matching needs; vendor exports can omit source versions or architecture. Access and licensing depend on the actual deployment. | Import with original collection time, completeness and provenance. Extend the existing collector for missing fields rather than silently infer them; verify before execution. |

For every option, preserve per-asset failures, unknown coverage, last successful collection and expiry. Limit collected data to security-relevant metadata, redact credentials, encrypt transport/storage and apply tenant isolation and retention rules. Do not publish raw inventories in worklogs or advisory exports. Do not scan unowned address ranges to discover a fleet.

## Limits and escalation

- **VEX is contextual evidence, not authorization.** Accept a statement only from an approved issuer for the exact product/component/version or digest and configuration, retaining revision, justification and supersession. A signature establishes who made a claim, not that the claim is correct. Conflicting, expired, unmatched or under-investigation statements remain visible. A `not_affected` statement for a vendor product cannot suppress unrelated copies of the library elsewhere.[14,25]
- **Missing metadata is not a clean bill of health.** Missing package source, unsupported comparator, stripped image databases, vendored/static code, local builds, stale feeds, partial collections and unavailable repositories must produce an explicit unknown/unsupported state. A negative result means only that the supported checks found no applicable entry within their evidence scope.
- **End-of-life and abandoned software need a migration path.** Check release, repository and package-specific support, not just the OS name. A feed may retain historical data after fixes stop; an upstream EOL version may still receive vendor backports, while a package may lose security coverage before its distribution does.[1,3,22,36] Queue replacement, supported-platform migration, isolation or compensating controls with an owner and deadline; never disable signature/expiry checks merely to make an old archive usable.
- **Network scanning is a separate authorization.** Banner/probe results can be incomplete, hidden behind proxies or inconsistent with backported packages. Active probes have effects: Nmap excludes port 9100 from version detection by default because some printers print the probes.[42] Require explicit target ranges, ownership, scan windows, traffic limits and exclusions; do not equate “scan” in the product UI with permission to send exploit probes.
- **Compromise and supply-chain incidents exceed patching.** A hostile host can falsify its package database and inventory. A signed repository can still distribute malicious software if the archive or signing key is compromised; APT explicitly excludes those cases from its protection.[9] Suspected compromise should trigger incident handling: preserve evidence, assess scope, isolate as authorized, rotate exposed credentials, validate build/source integrity, and restore/rebuild from trusted material. Patching alone does not evict an attacker or recover stolen secrets. NIST's incident-response reference covers response and recovery as broader activities.[43]

## Evidence review and remaining uncertainties

| Material claim | Status / confidence | Primary evidence and qualification |
| --- | --- | --- |
| Debian source identity and native ordering are required | Verified / high | Debian Policy §§5.6.1, 5.6.12 and `dpkg-query`; explicit source/binary distinction and epoch/tilde/revision rules.[5–6] |
| Distribution fixed versions differ from upstream versions | Verified / high | Debian release-tag documentation and Red Hat's concrete backporting explanation independently support this distinction.[3,36] |
| Fixed-version data needs release/product scope and special-state handling | Verified / high | Sampled Debian/Alpine data, Debian tracker source, Ubuntu OVAL documentation and Red Hat product/stream documentation.[2–4,11,14–15,19] Samples do not establish complete coverage. |
| APT version pinning alone cannot bind a safe exact transaction | Verified / high | APT documents dependencies, simulation without locks and same-version repository selection.[7–8] The proposed execution gate still requires implementation and tests. |
| SBOM/VEX and enrollment solve host integrity | Refuted as a general claim / high | Their documented roles are inventory, contextual statements and transport identity—not integrity of a potentially compromised host.[24–25,29] |
| First-backend operational safety | Not tested | No live inventory, repository refresh, package installation, service action, reboot, fleet enrollment or container rollout was performed. A synthetic `dpkg --compare-versions` check could not run because `/usr/bin/dpkg` is absent in this development environment; ordering examples were checked against Debian Policy instead. |

The Alpine wiki returned a temporary-unavailability notice when fetched; APK's official source manuals and the live secdb sample supplied the package identity/version evidence instead. Guessed Ubuntu USN-documentation and Red Hat OVAL URLs returned 404; canonical pages/repositories were found and cited below. No implementation is blocked by those failed URLs, but parsers still need versioned fixtures and error-path tests.

**Terms and access:** Red Hat's security-data page explicitly states CC BY 4.0 for its linked data resources, and Canonical's notice repository states CC BY-SA 4.0 for that repository.[12–13] Do not extend those terms to unrelated pages or package payloads. Debian tracker and Alpine secdb redistribution terms were not verified here; Alpine exposes a `license.txt` link, but its scope was not reviewed. Published numeric rate limits, availability guarantees and bulk-use permissions were **not verified** for these services. Public access is not evidence of unlimited use. Cache bounded responses, use conditional requests when supported, honor server retry guidance and keep old evidence visibly stale during outages.

## Official references

All references below were accessed **2026-10-22**. Manuals are versioned where the URL specifies `bookworm`; these establish the documented behavior, not a claim that every later APT/dpkg release has been tested. Feed samples and `main`/`master` source links are mutable snapshots. Publication dates not stated here were not independently established.

1. Debian, [Debian Releases](https://www.debian.org/releases/).
2. Debian Security Tracker, [JSON export](https://security-tracker.debian.org/tracker/data/json). Inspected an 8 KiB prefix with a bounded HTTPS read, not the complete feed.
3. Debian Security Team, [Security Tracker guide](https://security-team.debian.org/security_tracker.html), especially About, Distribution tags, Issues not warranting a security advisory, and end-of-life packages.
4. Debian Security Tracker source, [`bin/tracker_service.py`](https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/bin/tracker_service.py), rendering `fixed_version == "0"` as not affected.
5. Debian, [Policy Manual: control fields](https://www.debian.org/doc/debian-policy/ch-controlfields.html), §§5.6.1 Source and 5.6.12 Version; [Package maintainer scripts and installation procedure](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html), §§6.1–6.4.
6. Debian, [`dpkg-query(1)`](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html) and [`apt-mark(8)`](https://manpages.debian.org/bookworm/apt/apt-mark.8.en.html).
7. Debian/APT, [`apt-get(8)`](https://manpages.debian.org/bookworm/apt/apt-get.8.en.html), install, simulate, only-upgrade, no-remove and error-on options.
8. Debian/APT, [`apt_preferences(5)`](https://manpages.debian.org/bookworm/apt/apt_preferences.5.en.html), candidate priorities and same-version instance selection.
9. Debian/APT, [`apt-secure(8)`](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html) and [`sources.list(5)`](https://manpages.debian.org/bookworm/apt/sources.list.5.en.html), trust chain, Signed-By and validity checks.
10. Debian/APT, [`apt-cache(8)`](https://manpages.debian.org/bookworm/apt/apt-cache.8.en.html).
11. Canonical, [Ubuntu OVAL data](https://ubuntu.com/security/oval), CVE versus USN OVAL and feed naming.
12. Canonical, [Ubuntu Vulnerability Data repository README](https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/README.md).
13. Red Hat, [Security Data](https://access.redhat.com/security/data) and [CSAF provider metadata](https://security.access.redhat.com/data/csaf/v2/provider-metadata.json).
14. Red Hat Product Security, [CSAF/VEX Overview](https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/), product relationships and binary expansion.
15. Red Hat, [Red Hat and OVAL compatibility](https://access.redhat.com/articles/221883), patch-only coverage and product-version streams.
16. RPM project, [`rpm-version(7)`](https://rpm.org/docs/latest/man/rpm-version.7).
17. Red Hat Enterprise Linux 9, [Identifying security updates](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_and_monitoring_security_updates/identifying-security-updates_managing-and-monitoring-security-updates).
18. DNF project, [Configuration Reference](https://dnf.readthedocs.io/en/latest/conf_ref.html), repository priorities, module filtering and cache behavior.
19. Alpine Linux, [secdb index](https://secdb.alpinelinux.org/) and [v3.22 main JSON](https://secdb.alpinelinux.org/v3.22/main.json), inspected prefix.
20. Alpine Linux/apk-tools, [`apk-package(5)` source manual](https://raw.githubusercontent.com/alpinelinux/apk-tools/master/doc/apk-package.5.scd), version and origin fields.
21. Alpine Linux/apk-tools, [`apk-version(8)` source manual](https://raw.githubusercontent.com/alpinelinux/apk-tools/master/doc/apk-version.8.scd).
22. Alpine Linux, [Working with the Alpine Package Keeper](https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html), branches, repositories and support scope.
23. Kubernetes, [Images](https://kubernetes.io/docs/concepts/containers/images/), tags, digests and image updates.
24. CycloneDX, [Software Bill of Materials](https://cyclonedx.org/capabilities/sbom/).
25. CycloneDX, [Vulnerability Exploitability eXchange](https://cyclonedx.org/capabilities/vex/).
26. npm CLI 11, [`package-lock.json`](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).
27. Python Packaging Authority/pip, [`pip inspect`](https://pip.pypa.io/en/stable/cli/pip_inspect/).
28. Ansible, [`ansible.builtin.package_facts`](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/package_facts_module.html).
29. osquery, [Remote Settings](https://osquery.readthedocs.io/en/stable/deployment/remote/), enrollment and remote authentication.
30. Amazon Web Services, [Systems Manager Inventory](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-inventory.html).
31. Microsoft, [Security Updates API repository README](https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/master/README.md), linking the Security Update Guide and API documentation.
32. Microsoft, [`IUpdateSearcher::Search`](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search), configured search and update identity/revision.
33. Microsoft, [`Get-HotFix`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.5) and [`Win32_QuickFixEngineering`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering). The latter returns only Component Based Servicing updates, so a hotfix list is not complete software/update inventory.
34. Apple, [Apple security releases](https://support.apple.com/en-us/100100).
35. Apple, [Operating system queries for Apple devices](https://support.apple.com/guide/deployment/operating-system-queries-dep8b8b23369/web), OS/build and background security improvement queries.
36. Red Hat, [Security Backporting Practice](https://access.redhat.com/security/updates/backporting).
37. Package-URL project, [PURL introduction](https://www.packageurl.org/docs/purl/introduction).
38. systemd project, [`os-release`](https://www.freedesktop.org/software/systemd/man/latest/os-release.html).
39. Debian/APT source, [`apt-pkg/update.cc`](https://raw.githubusercontent.com/Debian/apt/main/apt-pkg/update.cc), `APT::Update::Pre-Invoke` and post-invoke hooks.
40. Debian/APT, [`apt.conf(5)`](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html), configuration precedence, `#clear` and command hooks.
41. Debian/needrestart, [`needrestart(1)`](https://manpages.debian.org/bookworm/needrestart/needrestart.1.en.html).
42. Nmap, [Service and Version Detection](https://nmap.org/book/man-version-detection.html).
43. NIST, [SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final), published 2025-04-03; landing page/abstract inspected, not the full report.
