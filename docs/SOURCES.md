# Security feeds, patch intelligence, and inventory

Research checked on **2026-10-22**. This document recommends sources and adapter behavior; it does not claim that application adapters have been implemented. Detailed references cover [authoritative advisory sources](research/ADVISORIES.md) and [distribution patch data and inventory](research/INVENTORY.md).

## Assessment

Use **pwn.watch for incident discovery**, **ecosystem or vendor advisories for applicability**, and **the target's approved package repositories for installable versions**. These are separate decisions. A feed saying “patched” means a fix reportedly exists, not that our systems are patched. A CVSS score measures vulnerability severity; it does not establish that an asset is affected, reachable, or compromised.

The initial system should combine:

1. pwn.watch JSON for incidents, including breaches and supply-chain events without CVEs.
2. CISA's Known Exploited Vulnerabilities (KEV) catalog and FIRST's Exploit Prediction Scoring System (EPSS) for prioritization signals, with their observation dates.
3. OSV or reviewed GitHub advisories for supported application packages, and distribution-specific advisories for operating-system packages.
4. Local package-manager metadata to resolve exact, available remediation targets from approved repositories.
5. Fresh inventories tied to stable asset identities, deployment artifacts, and package ecosystems.

News, model-generated advice, source links, CVSS, and package availability alone cannot authorize an administrative action.

## pwn.watch: verified interfaces

The publisher's [llms.txt](https://pwn.watch/llms.txt) describes static files rebuilt on content changes, no authentication, and “no rate limits on our side.” That is a publisher statement, not a service-level or unlimited-use guarantee. The five machine-readable endpoints below returned HTTP 200 in bounded requests at approximately `2026-10-22T19:24:38Z`. The [homepage](https://pwn.watch/) and a [full incident record](https://pwn.watch/i/gitlab-cve-2026-110264-regex-rce.json) were also fetched successfully through the readable-web tool.

| Endpoint | Observed contract | Recommended use |
| --- | --- | --- |
| [`/incidents.json`](https://pwn.watch/incidents.json) | Object containing `site`, `generatedAt`, `updatedAt`, `live`, and `incidents`. Observed 719 incident summaries, including 38 live incidents, in 943,050 bytes. | Primary discovery input and periodic full reconciliation. Do not ingest only the live subset. |
| [`/feed.xml`](https://pwn.watch/feed.xml) | RSS 2.0; 50 items, each with title, link, GUID, publication date, category, and escaped HTML description. The publisher says an item's date advances when the incident changes. | Human subscriptions or a recent-update signal, not a complete historical feed. |
| [`/llms.txt`](https://pwn.watch/llms.txt) | Markdown-like text containing endpoint documentation, tags, and incident summaries; observed 215,225 bytes. | Documentation and bounded investigation context, not an execution contract or full prompt to an administrator agent. |
| [`/changes.json`](https://pwn.watch/changes.json) | Object with `site`, `generatedAt`, and `changes`; observed 1,267 changes. A sampled change has incident identity, date, title, source URL, and status fields, but no dedicated immutable event ID. | Additional update discovery; retain content hashes and reconcile incident records rather than trusting a date-only cursor. |
| [`/tags.json`](https://pwn.watch/tags.json) | Object with 463 tag descriptors at observation time. Descriptors include tag IDs, groups, counts, and endpoint URLs. | Search/filter convenience. Tags are not an asset applicability test. |
| `/i/{slug}.json` | A sampled record contains summary fields plus `timeline`, `sources`, `tweets`, `notes`, `sections`, and `agentBrief`. | Fetch changed or relevant incident details, from the configured origin and a validated slug. |

The publisher also advertises per-incident RSS and JSON Feed 1.1, and per-tag JSON, RSS, and `llms.txt`. Those variants were **not individually probed** in this research. The summary JSON is sufficient for the first discovery adapter; those advertised variants need their own fixtures before support is claimed.

### Important schema facts

Observed summary fields include `slug`, `title`, `url`, `json`, `status`, `severity`, `patchStatus`, `product`, `stacks`, `tags`, `cveIds`, `affectedVersions`, `fixedVersions`, `startedAt`, `closedAt`, `updatedAt`, `summary`, `xPost`, and `isExample`.

- `cveIds` is not strictly a list of CVEs. The observed feed also includes `GHSA-…` and `MAL-…` identifiers. Preserve advisory identifiers with their namespaces; send only syntactically valid CVEs to CVE-specific enrichment services.
- `affectedVersions` and `fixedVersions` are lists of **free-form strings**, not a standardized version-range language. Records contain prose, branch-specific fixes, mitigation instructions, safe downgrade pins, and non-package actions. Do not interpret the first fixed-version string as an installation argument.
- `product`, tags, and stacks are discovery hints, not normalized package identities. “Python,” “GitLab,” and “Linux” do not identify a particular installation or package origin.
- Observed severities were `critical`, `high`, `medium`, `low`, and `unknown`; observed patch states were `patched`, `partial`, `unpatched`, and `no-fix-needed`. Preserve unknown future values as unresolved data rather than silently coercing them to safe states.
- All 719 observed rows had distinct slugs; none had `isExample` set true. An adapter should still exclude or visibly segregate example records when present.
- Dates have different precision. A start date can be date-only; update timestamps include offsets. Normalize timestamps to UTC without inventing a time of day for date-only fields. Preserve the original value for explanation.
- Full records' `agentBrief` contains Markdown and can include shell commands. It is untrusted third-party prose even when a suggested command looks reasonable. Do not run it, use it as a system prompt, or let it change policy.

### Caching, access, and provenance

The JSON and RSS endpoints returned `ETag`, `Cache-Control: public, max-age=60, must-revalidate`, and `Access-Control-Allow-Origin: *`. `llms.txt` returned `max-age=0, must-revalidate`. No `Last-Modified` header was observed. A conditional request to `/incidents.json` with the observed `If-None-Match` returned **304**, establishing that conditional retrieval worked for that snapshot.

Recommendation: begin with a configurable 15-minute poll, conditional requests, a bounded retry budget with backoff and jitter, and a full reconciliation after missed polls. This is our proposed cadence, not a publisher requirement. Bound request duration, response bytes, decompressed bytes, record count, and text length. A successful 304 refreshes the contact time, not the advisory's publication date. Keep `last_attempt`, `last_success`, publisher timestamps, payload digest, parser version, and error state separate.

No content license or redistribution permission was found in the fetched `llms.txt`; public accessibility and CORS do not establish either. Do not redistribute a bulk mirror as a product asset without checking terms. Keep only minimal synthetic fixtures in the repository. A plain `urllib` request to the homepage returned 403, while the readable-web fetch and explicitly identified machine-endpoint requests succeeded. An adapter must surface access failures rather than treating them as an empty feed.

The [observation metadata](research/PWN-WATCH-SNAPSHOT.json) records sizes, digests, and schema observations without copying the incident corpus. It is evidence of a dated retrieval, not a durable mirror or a signature from the publisher.

## Source roles and patch authority

| Role | Sources to evaluate | What it can establish | What it cannot establish alone |
| --- | --- | --- | --- |
| Broad incident discovery | pwn.watch, vendor incident notices, selected security news | A reported event, affected-product hints, references, and changing incident context. | Exact package applicability, trusted installation commands, or local remediation completion. |
| Confirmed exploitation signal | CISA KEV, explicit vendor exploitation statements | That the source reports exploitation of the referenced vulnerability. | Exploitation on our asset; completeness of all exploited vulnerabilities. |
| Exploitation probability | FIRST EPSS | A dated probability estimate for a published CVE, for the model's stated horizon. | Severity, asset exposure, or a finding that a low-scoring vulnerability is safe. |
| Application package applicability | OSV, reviewed GitHub advisories, vendor release/security advisories | Package ecosystem, identity, affected ranges or versions, fixed events, withdrawal/correction metadata where provided. | Dependency reachability, compatible upgrades, or trustworthy artifacts merely because a version is listed. |
| Distribution package applicability | Debian security tracker, Ubuntu OVAL/USN, Red Hat CSAF/OVAL, Alpine secdb | Distribution/release-specific status and fixed package versions. | That the candidate is in our configured repositories or that a new kernel is running. |
| CVE identity and enrichment | CVE List V5, NVD | Published/rejected identifiers, descriptions, references, scores, and product-matching data where available. | A complete package patch list or authoritative distribution backport comparison. |
| Product-specific status exchange | CSAF and VEX documents from an authenticated publisher | Structured product and vulnerability status scoped to a particular document and product identity. | Universal safety for every artifact sharing a product name; a trustworthy suppression without publisher and scope checks. |
| Installable remediation target | Approved, authenticated package repositories and local package-manager policy | Available candidate, origin, architecture, dependency resolution, and package authentication status. | That an update fixes the finding or is operationally safe without advisory evidence and verification. |

Official endpoints, API limits, terms, and semantic details are in [ADVISORIES.md](research/ADVISORIES.md) and [INVENTORY.md](research/INVENTORY.md). Do not flatten these sources into one undifferentiated “trusted feed.” Keep each assertion's origin, record ID, modification time, and evidence type.

## Inventory and matching recommendations

An asset record should carry a stable enrolled identity, collector identity/version, observation time, operating system and release, architecture, environment or service ownership, and explicitly recorded exposure. Package records should carry ecosystem, exact name and installed version, installation scope, and origin when known. Distribution packages additionally need source-package identity/version and architecture; container and application records need an immutable image/artifact digest or lockfile hash.

Prefer read-only package databases, build artifacts, lockfiles, and software bills of materials (SBOMs) over banner guessing or exploit probes. Query remote fleets through explicitly enrolled hosts or existing management, not an inferred address range. Never collect secrets or send complete inventories to public APIs by default. Public vulnerability queries disclose package names and versions; make that egress a configured decision and support local imported advisories.

Matching must return at least `affected`, `not_affected`, and `unknown`, with reasons and source evidence. Add explicit unresolved states for stale inventory, withdrawn or conflicting advisories, incomplete collection, unsupported ecosystems, and unavailable fixes. “No matching advisory in this dataset” is not proof of universal safety. Correlate advisory aliases without erasing differences in source assertions or treating advisory counts as independent vulnerabilities.

Do not compare arbitrary version strings lexically. Use the ecosystem's comparator or a vetted scanner. Distribution backports are the decisive counterexample: an old-looking upstream version may contain the fix, while a newer-looking package from another origin may not. Package installation and runtime activation are distinct: kernel and service findings may require reboot/restart and a new runtime observation.

The first real backend should be narrow enough to test thoroughly: read-only Debian-family package inventory, release-specific vulnerability evidence, and exact-version APT remediation from approved repositories. Scope supported distribution releases explicitly in the design. Handle application and container findings through their own evidence paths; do not install a PyPI or npm version into a system package merely because names resemble each other.

## Claim checks and limitations

| Claim | Status | Evidence and confidence |
| --- | --- | --- |
| pwn.watch offers usable RSS, JSON, and `llms.txt`. | Verified for the observed snapshot. | Successful fetches, parsed payloads, and the publisher's endpoint documentation. High confidence in interface availability at retrieval time, not future uptime. |
| The global RSS feed is a complete incident inventory. | Refuted. | RSS contained 50 items; summary JSON contained 719 incidents. Publisher explicitly describes the RSS as the latest 50 updated incidents. High confidence. |
| pwn.watch fixed-version fields can directly drive package installation. | Refuted as a general rule. | Observed prose and non-package mitigations in those fields; the sampled full record provides an untrusted executable-looking brief rather than a machine policy. High confidence. |
| A representative pwn.watch GitLab record is backed by a primary vendor advisory. | Verified for the bounded release/severity/range claim. | GitLab's [October 21 patch release](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/) confirms CVE-2026-110264, CVSS 3.1 score 10.0, affected branches, and the listed fixed releases. This does not validate all pwn.watch records or establish exposure in our fleet. High confidence. |
| “There were 4 CVSS-10 security incidents over the past 24 hours.” | Not checked as a dated historical claim. | The supplied quotation has no attribution timestamp or four identifiers. A live feed cannot reconstruct its intended 24-hour window. No design assumption depends on the count. |
| “One of them is the worst incident I’ve seen in my life.” | Subjective assessment, not a technical input. | Prioritization should use applicability, exploitation evidence, exposure, impact, and remediation constraints. |
| CVSS alone measures our operational risk. | Refuted. | FIRST's [CVSS v4 user guide](https://www.first.org/cvss/v4.0/user-guide) explicitly distinguishes Base severity from risk and calls for threat/environmental context. High confidence. |

The strongest case for automation is timely detection joined to reliable inventory and verified vendor fixes. The strongest limitation is that many incidents are not package-update problems: stolen credentials, a compromised release pipeline, persistence on a host, and tenant-side breaches require containment, evidence preservation, key rotation, or rebuilding. A successful upgrade does not remove an established compromise. Route those incidents to a separate response queue rather than marking them resolved by a package change.

No customer or development-host inventory was collected during this research. No exploit probes, updates, restarts, credential rotations, or remote enrollment were performed. Primary-source access failures and unverified licensing or rate limits are recorded in the detailed references. Production source onboarding must recheck those terms and endpoint contracts.
