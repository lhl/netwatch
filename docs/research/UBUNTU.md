# Ubuntu 24.04 LTS advisory evidence

Autoprotect's `ubuntu` source uses Canonical's Ubuntu Security Notice (USN) JSON database at the fixed endpoint **`https://usn.ubuntu.com/usn-db/database.json`**. Applicability is limited to Ubuntu **24.04 LTS (`noble`) on `amd64`**, including architecture-independent `all` packages. This is notice-based missing-update evidence, not a complete CVE affected-version database.

Ubuntu Pro, Expanded Security Maintenance (ESM), realtime and FIPS pockets are outside remediation scope. A Noble release name alone does not establish standard-support coverage. Missing or unsupported evidence produces `unknown`, never a safe verdict or an executable fix.

## Primary-source observations

Checked on **2026-10-23** using bounded HTTPS requests with normal certificate verification. No private inventory was collected or sent, and no package commands were run.

| Source | Observed evidence | Interpretation and limits |
| --- | --- | --- |
| [Canonical USN database](https://usn.ubuntu.com/usn-db/database.json) | HTTP 200, `application/json`, 354,359,354 bytes; ETag `"6ada7ad0-151f183a"`; Last-Modified `Thu, 22 Oct 2026 21:06:24 GMT`. A complete bounded retrieval contained 8,131 notices, of which 1,614 had a `noble` release entry. | Verified publisher-hosted notice, source-version and pocket fields. These counts describe one response, not complete vulnerability coverage or future availability. |
| [Ubuntu Security Notices](https://ubuntu.com/security/notices?format=md) | Canonical states that developers issue a USN when a security issue is fixed in an official Ubuntu package. | Supports interpreting a notice as published update evidence. It does not establish every vulnerable version or local repository availability. |
| [USN-6801-1](https://ubuntu.com/security/notices/USN-6801-1?format=md) | Published 2024-05-30. Noble fix for `python3-pymysql` is `1.0.2-2ubuntu1.1`; source package `python-pymysql`; CVE-2024-36039. The database gives that source version and `security`-pocket binary records. | The human notice corroborates the sampled raw source/binary/version relationship. The `all` architecture is present in this notice's artifact metadata. |
| [USN-6803-1](https://ubuntu.com/security/notices/USN-6803-1?format=md) | Noble FFmpeg fix is `7:6.1.1-3ubuntu5+esm1`, explicitly labelled Ubuntu Pro. The database gives `pocket="esm-apps"`. | Refutes treating every Noble USN fix as an ordinary security-archive update. This evidence must not authorize this backend. |
| [Ubuntu OVAL documentation](https://ubuntu.com/security/oval?format=md) and [published OVAL index](https://security-metadata.canonical.com/oval/) | Canonical distinguishes CVE vulnerability definitions from USN missing-patch definitions, and documents release-specific compressed XML. The index lists Noble CVE, package and USN datasets. | OVAL is a valid alternative, but is not parsed by this implementation. Its additional evaluation semantics must not be approximated by extracting version strings. |
| [CVE JSON API sample](https://ubuntu.com/security/cves.json?limit=1) | Returned a `cves` list with nested source-package `statuses`, plus `offset`, `limit` and `total_results=84297`. A release-filtered probe timed out. | A single page is not a complete snapshot. Pagination and tracker-state interpretation are not implemented. |

The retrieved database SHA-256 was `72d2d9ea856c3d9fb822975267099ab28e93f521e66346cfea35086b5b958132`. This is a dated observation, not a publisher signature. The raw corpus is not committed or redistributed. A record-by-record diagnostic counted 14,809,951 JSON nodes within the notices, excluding the outer map and its keys.

Three details required explicit compatibility tests: the raw `cves` lists also contain HTTP(S) reference URLs; some inner IDs include `USN-` (for example the `5185-1` key has `id="USN-5185-1"`); and some notices contain hundreds of CVE references (USN-7019-1 had 429). An `is_hidden` field is also present, including the string `"false"` in USN-5185-1. The adapter accepts booleans and the exact strings `"true"`/`"false"`; other types or spellings reject the snapshot. Hidden notices remain unknown, not actionable.

Across Noble notices, the observed pocket counts were: `security` 1,288, `esm-apps` 264, `realtime` 68, and `fips-updates` 39. Counts overlap because a notice can contain more than one pocket. One Noble notice lacked `allbinaries`. These observations are why pocket and missing-evidence checks are required, not optional feed cleanup.

Confidence is high for the observed JSON shape and the two corroborated package fixes. Coverage completeness, service guarantees and redistribution terms were not established. No inference of universal safety depends on them.

## Raw input contract

`parse_ubuntu(data, release="noble")` accepts a decoded JSON object. `parse_source("ubuntu", raw)` accepts UTF-8 JSON bytes or text. The synthetic fixture at `tests/fixtures/feeds/ubuntu.json` follows the observed format:

```json
{
  "10001-1": {
    "id": "10001-1",
    "description": "Synthetic notice, not instructions.",
    "cves": ["CVE-2026-10001"],
    "releases": {
      "noble": {
        "sources": {
          "example-source": {"version": "1:1.0-1ubuntu0.24.04.2"}
        },
        "allbinaries": {
          "libexample1": {
            "source": "example-source",
            "version": "1:1.0-1ubuntu0.24.04.2",
            "pocket": "security"
          }
        }
      }
    }
  }
}
```

The database key and inner `id` must agree after removing an optional `USN-` prefix from the inner ID. The normalized identifier always includes `USN-`. Source versions come only from `releases.noble.sources[NAME].version`; a version from another release cannot become a Noble fix. `allbinaries` supplies explicit binary-to-source and pocket evidence. `binaries` alone lacks the required source mapping and is not a fallback.

The misleadingly named raw `cves` list contains both CVE identities and HTTP(S) reference URLs. Only syntactically valid CVEs enter `cve_ids`. URLs are bounded, never fetched and omitted from the normalized assertions; they are not invented CVE identities. Malformed CVE strings and unsupported reference types reject the snapshot.

The publisher also includes `title`, `timestamp`, `summary`, `action`, `archs`, artifact URLs and other fields. They remain untrusted data. Artifact URLs, checksums and action prose are not retained as installation targets. No links are followed, and no commands are extracted.

## Normalized assertion contract

Each assertion has these fields:

| Field | Meaning |
| --- | --- |
| `id` | USN identity, for example `USN-10001-1`. |
| `source_name` | Validated source-package name. |
| `release` | Always `noble`; only this parser release argument is accepted. |
| `status` | `resolved` means the source supplies a usable standard-security fix boundary. Otherwise `unknown`. It does not mean the installed package is fixed. |
| `fixed_version` | Source-version boundary or null. A retained unsupported value cannot authorize remediation. `"0"` has no special safe meaning. |
| `urgency` | `unknown`: this database does not supply an authoritative severity field. |
| `description` | Bounded notice prose, still untrusted. |
| `cve_ids` | Sorted, deduplicated notice-level CVE references, used only for incident correlation. |
| `pocket` | A single explicit binary pocket, or null for missing/mixed evidence. Only `security` is assessable. |
| `binary_packages` | Sorted binary names explicitly linked to this source in the Noble `allbinaries` map. |

The assertion identity is `(source_name, release, id)`. A notice covering several sources produces one assertion per source, **not** a source/CVE cross product: a notice-level CVE list does not identify which source or release each CVE affects. Findings and plans bind USN IDs. Incident matching can correlate either the USN identity or its CVE references; that correlation changes ordering and investigation context, not applicability authority.

For notices without a Noble entry, source names observed in other releases are retained as Noble `unknown` assertions with no inherited fix or binary evidence. Sources that cannot be named produce no invented assertion; an inventory package with no evidence still gets an unknown-coverage finding.

## Matching and authorization boundary

An unhidden source assertion is assessable only when all linked binary entries have an explicit `security` pocket and valid nonzero, non-ESM versions, and the Noble source fix has valid nonzero, non-ESM version syntax. Missing, mixed or special-pocket evidence remains unknown. The matcher repeats pocket, source-version and binary-membership checks rather than trusting `status="resolved"` alone.

Matching requires a fresh complete Noble `amd64` inventory, a fully installed `deb` package of architecture `amd64` or `all`, the exact source identity, and explicit coverage for that binary. Installed ESM-labelled versions remain unknown. Holds do not conceal applicability, but remain a remediation blocker.

`autoprotect/versions.py` compares the **installed source version**, not an upstream version or the binary's rebuild suffix. Below the notice's fix means `affected` in this application's missing-update model; meeting the boundary means `not_affected` by that notice's update requirement. This does not prove that every older version contains every referenced CVE, that the running service loaded the fix, or that the host is uncompromised. A package without a notice, or a vulnerability without a published update, is not declared safe.

`verify_affected()` re-derives the exact grouped USN/fix decision for the bound package. Feed text never selects an executable, repository or artifact. The backend must separately resolve and revalidate a policy-approved available package with a sufficient source version. Imported JSON is still imported evidence, even if it repeats a Canonical URL or claims HTTPS acquisition. Only the fixed-endpoint fetch path can supply acquisition provenance through the engine.

## Bounds and operational limits

- Ubuntu raw and decoded feed budgets: **512 MiB**; JSON node budget: **32,000,000**; nesting depth: **32**. The initial production-parser smoke check rejected the actual response at the former 8,000,000-node bound, so the Ubuntu budget is separate from pwn's unchanged bound.
- At most 50,000 raw notices, 500,000 normalized assertions, 10,000 binary entries per Noble notice, 4,096 raw references or normalized CVE aliases per notice, and 65,536 characters per string, including ignored fields. Identity and version fields have smaller limits.
- Duplicate JSON keys, malformed identities, non-finite numbers, unsupported data types and oversized inputs reject the entire snapshot. Unsupported version semantics remain unknown rather than using lexical order.
- The existing transport uses fixed direct HTTPS, verified certificates, identity encoding, no redirects or environment proxies, bounded headers/trailers, ten-second socket-operation limits and a sixty-second fetch-worker deadline. A conditional 304 still requires a prior successful snapshot in the engine.
- The parser retains the full JSON object in memory. The byte/node caps are not a memory reservation or a parsing wall-clock deadline. The 354 MB response requires substantial additional memory during decoding and validation. Production deployment must budget that memory or add an isolated streaming parser; a smaller unsupported cap must fail visibly rather than silently truncate coverage.

## Verification evidence

The final production-API network check called `fetch_source("ubuntu")`, `parse_source("ubuntu", response["raw"])`, then `fetch_source("ubuntu", response["etag"])`:

- The full response was 354,359,354 bytes and matched the SHA-256 recorded above. Fetching took 41.94 seconds; fetching plus normalization took 69.41 seconds.
- Normalization returned **17,779 assertions**: **1,793 resolved fix boundaries** and **15,986 unknowns**. Unknowns include notices whose source packages have no Noble entry, missing evidence and unsupported pockets; a security-pocket label alone does not establish a usable source fix.
- Matching those assertions against a two-package **synthetic** Noble inventory reported `USN-6801-1` affected with source fix `1.0.2-2ubuntu1.1`, and `USN-6803-1` unknown with no actionable fix. No host inventory was used.
- The conditional request returned `not_modified=true` and `raw=None`, verifying HTTP 304 support for the observed ETag.

The focused offline checks passed:

```text
python3 -B -m unittest discover -s tests -p test_feeds.py -v             # 41 passed
python3 -B -m unittest discover -s tests -p test_matching.py -v          # 23 passed
python3 -B -m unittest discover -s tests -p test_source_pipeline.py -v   # 4 passed
python3 scripts/worklog.py check                                     # 29 indexed entries valid
```

Owned-file whitespace checks and the active-content/filename scan passed. The parent integration must use the same Ubuntu **512 MiB / 32,000,000-node** intake bounds in the engine and CLI; the adapter's larger bound cannot override a smaller upstream loader. Full integrated command/demo testing and independent security review belong to the parent milestone.

The feed fixture and focused tests exercise source-version backports, notice/CVE correlation, imported provenance, wrong releases and architectures, unlisted binaries, Pro/ESM and special pockets, hidden notices, missing evidence, hostile text, malformed identities, duplicate keys and resource bounds. Live package changes, native repository resolution, downloads and privileged installation are not part of this source-verification work.
