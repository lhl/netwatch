# Advisory and exploitation-intelligence sources

Retrieved **2026-10-22 UTC**. This is an adapter-design reference, not a claim that Autoprotect implements these integrations. Primary documentation, schemas, and selected public records were fetched; no host or customer inventory was collected or submitted. Distribution-specific package authorities and pwn.watch are covered by separate research.

**Recommendation:** use OSV or GitHub for supported application-package applicability, CISA KEV and FIRST EPSS for prioritization, and CVE/NVD for identifiers and supplemental evidence. Use vendor CSAF/VEX only within an explicitly trusted publisher and product scope. None of these feeds grants permission to patch. An upstream fixed version is evidence for planning, not proof that a compatible, trusted installation target exists.

## Source matrix

Limits and terms below are those stated in the cited primary sources on the retrieval date, not availability guarantees. “Not verified” does not mean unrestricted use.

| Source and official access | Useful fields | Matching and patch-authority boundary | Synchronization, limits, and terms |
| --- | --- | --- | --- |
| **OSV.dev**: JSON `POST https://api.osv.dev/v1/query`, `POST /v1/querybatch`, `GET /v1/vulns/{id}`. [API][osv-api], [query][osv-query], [batch][osv-batch], [schema][osv-schema]. | `id`, `aliases`, `upstream`, `related`, `modified`, `published`, `withdrawn`; `affected[].package`, `ranges`, `versions`; severity and references. Batch returns **IDs and modification times only**, in input order. | Identify a package by ecosystem/name or package URL (PURL), or query a Git commit. The query API documents fuzzy version matching: preserve the submitted identity and returned evidence. Range types require different comparison rules. Fixed events describe upstream/ecosystem fixes, not authorized repository targets. | Follow `next_page_token`; batch pagination is **per query**. Docs state no API rate limit; HTTP/1.1 responses have a 32 MiB limit. This is not a service-level commitment. Aggregate data redistribution terms and maximum request batch size were not verified. |
| **GitHub global advisories**: JSON `GET https://api.github.com/advisories` and `/advisories/{ghsa_id}`; public requests need no authentication. [REST reference][gh-api], [database definition][gh-about]. | `ghsa_id`, nullable `cve_id`, `identifiers`, `type`, `github_reviewed_at`, `withdrawn_at`, `published_at`, `updated_at`; `vulnerabilities[].package`, `vulnerable_version_range`, nullable `first_patched_version`; references and severity. | `affects=package@version` plus `ecosystem` supports package queries. Reviewed records are mapped to supported packages; unreviewed records are imported from NVD without that review. Malware is a separate category, not a normal “upgrade to fixed version” case. Patch versions remain advisory evidence. | Default listing selects reviewed, non-malware records. Select `type` explicitly; process withdrawal updates. `modified` filters publication **or** updates; `updated` filters updates. Cursor pagination uses `Link` headers and `before`/`after`; maximum `per_page=100`, `affects` accepts up to 1,000 packages subject to URL length. General REST limits: 60 requests/hour unauthenticated, normally 5,000/hour for authenticated users; secondary limits also apply. [Limits][gh-limits]. Database README specifies **CC-BY 4.0**. [Terms statement][gh-repo]. |
| **CISA Known Exploited Vulnerabilities (KEV)**: full [JSON snapshot][kev-json], [JSON schema][kev-schema], and CSV linked from the [catalog][kev]. | Catalog `catalogVersion`, `dateReleased`, `count`; record `cveID`, `dateAdded`, `vendorProject`, `product`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, optional `cwes` and `forensicTriage`. | Join on CVE ID, not prose product names. Catalog membership is CISA's evidence of exploitation in the wild; it does not establish exposure of a particular asset. No structured affected-version or installable-target fields are defined in the fetched schema. `requiredAction` is text, not executable authority. | Snapshot format, not a paginated API. `dateAdded` is not a per-record modification time; compare complete snapshots to detect corrections. Ransomware `Unknown` means CISA lacks confirmation, not “No.” License is **CC0 1.0**; linked third-party material retains its own terms. No numeric fetch quota verified. [License][kev-license]. |
| **FIRST Exploit Prediction Scoring System (EPSS)**: JSON `GET https://api.first.org/data/v1/epss?cve=…`; [endpoint reference][epss-api], [data access][epss-data]. | `cve`, `epss`, `percentile`, score `date`; response `total`, `offset`, `limit`. Daily CSV includes model-version/date metadata for modern files. | CVE-level, daily probability of observed exploitation in the **next 30 days**, not severity, asset exposure, or confirmed exploitation. Percentile is relative rank, not probability. No package identity or patch target. [Meaning][epss], [use and limitations][epss-use]. | API is intended for single/small-batch lookup, **not bulk synchronization**; use the daily CSV linked by FIRST for bulk. `cve` parameter maximum 2,000 characters; date lookup and `scope=time-series` supported. Global API permits `limit` up to 10,000 with zero-based `offset`; public limit 1,000 requests/minute, with abuse blocking. These limits do not override the lookup-only guidance. [Global API][first-api]. Scores are free with no registration; redistribution license not verified. |
| **NIST National Vulnerability Database (NVD)**: JSON `GET https://services.nvd.nist.gov/rest/json/cves/2.0`; [CVE API][nvd-api], [operational guidance][nvd-start]. | `id`, `sourceIdentifier`, `published`, `lastModified`, `vulnStatus`; source-labelled metrics, weaknesses, references; CPE `configurations`; optional `affected`, Stakeholder-Specific Vulnerability Categorization (SSVC), and KEV-derived fields. | Common Platform Enumeration (CPE) applicability expressions have AND/OR/negation and version bounds, not just names. CVE-supplied affected data and NVD configurations are distinct evidence. Missing enrichment is not an unaffected result. Neither CPE nor a patch reference selects a package-manager target. | `cveIds` accepts up to 100 IDs; `cveId` is documented as deprecated. Offset pagination: `startIndex`, `resultsPerPage` ≤2,000, `totalResults`. Modified-date windows require both endpoints and span ≤120 days. Limits: 5 requests/30 seconds without a key, 50 with an `apiKey` header. NIST recommends updates no more often than every two hours and six-second request spacing. NIST requests its non-endorsement notice in applications. |
| **Common Vulnerabilities and Exposures (CVE) Program — CVE List V5**: official [repository and download contract][cve-list]; Git updates or daily baseline/hourly delta release archives. [Record schema][cve-schema], [version rules][cve-versions]. | `dataVersion`, `cveMetadata.cveId`, `state`, `datePublished`, `dateUpdated`; `containers.cna` and `containers.adp[]`, each retaining provider metadata; affected products, versions, references, metrics. Version 5.2 adds versionless `packageURL`. | Authoritative CVE record identity and publisher assertions, not uniform package coverage. Process CNA (CVE Numbering Authority) and ADP (Authorized Data Publisher) containers separately. Version status can be `affected`, `unaffected`, or `unknown`; rejected records need lifecycle handling. A CNA assertion is not universal installation authority. | README says updates approximately every seven minutes. Archive deltas are relative to the daily baseline; use Git/release checkpoints rather than treating publication dates as a complete change log. No repository-specific numeric rate limit verified. CVE license permits copying/derivatives/distribution subject to retaining MITRE's copyright designation and license. [Terms][cve-terms]. |
| **OASIS Common Security Advisory Framework (CSAF) / Vulnerability Exploitability eXchange (VEX)**: publisher-hosted JSON, not a central vulnerability API. [CSAF 2.0 specification][csaf], particularly §§3, 4.5, 7. | Publisher identity; `document.tracking` ID/version/release dates/revision history/status; `product_tree`; vulnerability CVE/other IDs, `product_status`, `remediations`, `flags`, and `threats`. | Product IDs are document-local references; resolve product-tree identities and relationships, using helpers such as PURL, CPE, or hashes where supplied. VEX reports product-specific affectedness, not exploitation probability. A trusted vendor can supply product/fix evidence; the format itself grants no publisher trust or execution permission. | Discover `provider-metadata.json` through documented mechanisms such as `security.txt` or `/.well-known/csaf/provider-metadata.json`. Directory distribution uses `index.txt` and `changes.csv`; Resource-Oriented Lightweight Information Exchange (ROLIE) is an alternative feed mechanism. Validate schema and mandatory semantic tests; the trusted-provider workflow includes hash/signature verification. Publisher quotas, redistribution terms, and deployment-specific trust keys require separate verification. |

## Semantics adapters must preserve

### OSV ranges, pagination, and identity

The [OSV schema][osv-schema] fetched identifies itself as **1.9.2 (2026-10-13)**. Its evaluation checks the union of enumerated `affected[].versions` and matching ranges for the identified package:

- `SEMVER` uses Semantic Versioning (SemVer) 2.0 ordering. `ECOSYSTEM` requires the ecosystem's ordering; never silently substitute lexical or generic SemVer comparison. `GIT` needs repository ancestry, not hash ordering.
- `introduced` is inclusive; `fixed` is exclusive. `introduced: "0"` means before all versions. `last_affected` is inclusive and does **not** identify a fixed release. `limit` is an exclusive scope boundary, not proof of a fix. Git branches and cherry-picked fixes can require multiple events.
- The query body uses either `{ "package": { "name": "jinja2", "ecosystem": "PyPI" }, "version": "2.4.1" }` or a PURL. Do not combine a versioned PURL with top-level `version`; docs specify HTTP 400. Name/ecosystem and PURL are alternative identity forms; requests are case-sensitive. [Query contract][osv-query].
- `/query` may paginate after approximately 1,000 results or 20 seconds. A page can contain **only a token**: keep fetching until the token disappears, subject to a client safety budget. `/querybatch` can paginate after approximately 1,000 results per item or 3,000 overall; retain each item's original association when resubmitting unfinished queries. Fetch full records by ID and cache against `modified`. [Query][osv-query], [batch][osv-batch].

`aliases` declares the same vulnerability and is symmetric/transitive in the schema. `upstream` is directional and transitive; `related` is symmetric but not transitive. The schema explicitly says downstream distribution advisories should use `upstream`, not aliases, for upstream vulnerabilities. **Recommendation:** keep typed, source-attributed edges and separate package findings; do not merge every CVE mention into an equivalence class. A distribution advisory may cover several upstream vulnerabilities. [Identity fields][osv-schema].

### Revisions, withdrawals, and enrichment gaps

GitHub review and withdrawal are independent dimensions. Preserve both `type`/review timestamps and `withdrawn_at`; do not require a CVE or a fixed version. Explicit `is_withdrawn=true` retrieves withdrawn records. GitHub's OSV repository warns that its `database_specific` fields can change without notice; prefer the documented REST fields for a review-state contract. [REST][gh-api], [repository warning][gh-repo].

NVD's `lastModified` is not a universal change clock: its API documentation says an initial transition to “Undergoing Analysis” and a change to an associated CPE record do not change it. If implementing CPE-based matching, synchronize CPE/match-criteria data separately. NIST's **2026-04-15** update says it now prioritizes specific CVE classes for enrichment, while other records are not scheduled for immediate enrichment; the backlog was not cleared. Consequently, waiting for NVD configurations can delay or prevent an applicability decision. NIST also reported additive affected-data/SSVC support and widespread modification-time changes on **2026-06-17**. [API behavior][nvd-api], [dated NIST updates][nvd-news].

CVE List records can use different format versions: select validation from `dataVersion`, not publication date. Keep container/provider provenance instead of overwriting CNA facts with ADP facts. For version matching, `lessThan` is exclusive, `lessThanOrEqual` inclusive, and `changes[].at` changes status within a range. Unmatched versions use `defaultStatus`, which defaults to `unknown`; `versionType: custom` does not define an executable comparison algorithm. The repository documents historical timestamp corrections, so retain transport checkpoints and periodically reconcile. [Repository][cve-list], [schema][cve-schema], [version rules][cve-versions].

### Exploitation signals and VEX are not interchangeable

KEV answers whether CISA has catalogued known exploitation; EPSS forecasts observed exploitation activity across its data partners. EPSS does not know local presence, reachability, controls, or consequence. Neither KEV absence nor a low/missing EPSS score proves safety. Record score date and distinguish a missing score from zero; model-version changes can shift scores without a change in the vulnerability. [KEV][kev], [EPSS interpretation][epss-use], [model/date history][epss-data].

CSAF VEX's core states are `known_affected`, `known_not_affected`, `fixed`, and `under_investigation`. The profile requires justification for `known_not_affected` and an action statement for `known_affected`; permitted actions include `no_fix_planned` and `none_available`. Thus an affected record need not have a patch. **Recommendation:** accept a not-affected assertion only for an authorized publisher, exact matching product/version/configuration, and applicable revision; absence of an assertion stays unknown. [CSAF §4.5][csaf].

## Adapter recommendations

These are proposed Autoprotect design choices, not provider guarantees or implemented behavior.

1. **Separate evidence roles.** Start with OSV batch applicability for explicitly supported application ecosystems, KEV snapshot enrichment, and EPSS small-batch lookup. Add GitHub/CVE/NVD as source-specific evidence, not redundant votes that increase confidence merely because mirrors agree.
2. **Preserve provenance before normalization.** Store configured source identity, fetch URL/time, content hash, source record ID, source modification time, parser/schema version, and original payload. Keep original publisher/container attribution and source-specific licenses through exports.
3. **Deduplicate records without losing claims.** Upsert by `(source, record_id)`; use validated explicit aliases to group vulnerability identities. Keep upstream/related links separate. Preserve conflicting affectedness/version claims for triage rather than choosing the newest timestamp across unrelated publishers.
4. **Treat synchronization as a completed transaction.** Advance a checkpoint only after every page validates and persists. Use overlapping modified-time windows and idempotent upserts; hash whole KEV snapshots. Retain prior good data and mark freshness/coverage degraded on timeouts, malformed records, or exhausted pagination budgets.
5. **Make lifecycle changes visible.** Refresh known records as well as discovering new ones. Keep withdrawn/rejected records and their provenance; invalidate dependent findings/plans for reevaluation rather than deleting history. Do not use NVD's `noRejected` filter in a mirror that must observe rejections.
6. **Bound all untrusted input.** Cap compressed/decompressed bytes, nesting, records, pages, and request duration; reject malformed identities. Honor rate-limit headers and bounded retries. Do not follow arbitrary reference URLs or run commands from descriptions, `requiredAction`, remediations, or model explanations.
7. **Keep matching conservative and ecosystem-specific.** Support exact package identity and tested comparator types first. Unknown comparators, unresolved CPE/product mappings, fuzzy-query ambiguity, unsupported ecosystems, or missing inventory produce explicit uncertainty—not a clean scan. Do not transpose upstream fixes into distribution package versions.
8. **Keep prioritization explainable.** Store KEV membership/date, EPSS probability/percentile/date, severity source/vector, and local exposure separately. Local policy can prioritize known exploitation without treating severity or a probability threshold as execution authorization.
9. **Resolve patches through trusted package sources.** Advisory evidence may propose a fixed boundary. A separate backend must resolve an available exact target, validate package source/system compatibility, bind approval to the immutable plan and current inputs, execute only policy-authorized actions, and verify installed state. Missing fixes or ambiguous VEX must leave investigation usable without inventing a remediation.

For NVD-consuming applications, the fetched guidance asks for this notice: “This product uses data from the NVD API but is not endorsed or certified by the NVD.” [NIST guidance][nvd-start].

## Retrieval evidence and unverified items

All source links in this reference were read on 2026-10-22, except generic endpoint templates whose contracts are cited. Large specifications were inspected in relevant sections, not audited exhaustively. Confidence is **high** for the bounded documented contracts and observed response shapes; completeness of advisory coverage, matching accuracy, and service reliability were **not measured**.

Selected public-data checks used bounded requests and JSON parsing, not local inventories:

| Check | Observed outcome |
| --- | --- |
| OSV `/query` and `/querybatch` for the documented `PyPI/jinja2@2.4.1` example | Both HTTP 200; 18 records versus 18 ID/modified entries. No pagination was triggered; pagination behavior is documentation-backed only. |
| [GitHub reviewed + withdrawn listing][gh-check], `per_page=1`, API version header `2026-03-10` | HTTP 200; returned `GHSA-p3hm-x653-5rc6` with review/withdrawal timestamps, `cve_id: null`, and `first_patched_version: null`. |
| [CISA JSON snapshot][kev-json] | HTTP 200; version `2026.10.21`; declared and parsed counts both 1,754. Schema and license also HTTP 200. |
| [FIRST lookup for CVE-2021-44228][epss-check] | HTTP 200; one dated score, `date: 2026-10-22`. Numeric score values were JSON strings. The endpoint documentation's scope table says `created`, but its example and the live record use `date`; preserve the actual score date. |
| [NVD lookup for CVE-2021-44228][nvd-check] | HTTP 200; one record, including `affected` and `configurations`. No full mirror or CPE matching was exercised. |
| [CVE List record for CVE-2021-44228][cve-check] | HTTP 200; `dataVersion: 5.1`, CNA and ADP containers, and a `custom` version range—concrete evidence that a uniform generic version comparator is insufficient. |

Access issues and boundaries:

- `https://www.first.org/epss/api` and `/epss/api.html` returned **HTTP 404**. FIRST's current data page links to the working [API reference][epss-api].
- Static extraction returned no readable NVD API/start-page content and only a title for CVE terms. Browser rendering recovered all three with HTTP 200. These were extraction failures, not evidence the APIs were down.
- The generic CSAF 2.0 URL returned the Errata 01 document; the versioned [base specification][csaf] was fetched separately. This reference does not claim CSAF 2.0 is the latest version.
- No load/rate-limit, authenticated-access, withdrawal transition, multi-page synchronization, full archive import, publisher-signature, or real patch execution tests were run. No particular vendor CSAF deployment or trust key was evaluated.
- OSV aggregate redistribution terms, FIRST score redistribution license, CISA numeric fetch quota, CVE repository-specific quotas, and individual CSAF publisher terms remain **not verified**. Verify these before bulk redistribution or production polling; do not infer them from public access or a schema's software license.

[osv-api]: https://google.github.io/osv.dev/api/
[osv-query]: https://google.github.io/osv.dev/post-v1-query/
[osv-batch]: https://google.github.io/osv.dev/post-v1-querybatch/
[osv-schema]: https://ossf.github.io/osv-schema/
[gh-api]: https://docs.github.com/en/rest/security-advisories/global-advisories
[gh-about]: https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/github-advisory-database
[gh-limits]: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
[gh-repo]: https://raw.githubusercontent.com/github/advisory-database/main/README.md
[kev]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
[kev-json]: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
[kev-schema]: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
[kev-license]: https://www.cisa.gov/sites/default/files/licenses/kev/license.txt
[epss]: https://www.first.org/epss/
[epss-api]: https://api.first.org/epss/
[epss-data]: https://www.first.org/epss/data.html
[epss-use]: https://www.first.org/epss/using-epss.html
[first-api]: https://api.first.org/
[nvd-api]: https://nvd.nist.gov/developers/vulnerabilities
[nvd-start]: https://nvd.nist.gov/developers/start-here
[nvd-news]: https://www.nist.gov/itl/nvd
[cve-list]: https://raw.githubusercontent.com/CVEProject/cvelistV5/main/README.md
[cve-schema]: https://raw.githubusercontent.com/CVEProject/cve-schema/main/schema/docs/CVE_Record_Format_bundled.json
[cve-versions]: https://raw.githubusercontent.com/CVEProject/cve-schema/main/schema/docs/versions.md
[cve-terms]: https://www.cve.org/Legal/TermsOfUse
[csaf]: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.md
[gh-check]: https://api.github.com/advisories?type=reviewed&is_withdrawn=true&per_page=1
[epss-check]: https://api.first.org/data/v1/epss?cve=CVE-2021-44228
[nvd-check]: https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-2021-44228
[cve-check]: https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/44xxx/CVE-2021-44228.json
