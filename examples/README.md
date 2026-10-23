# Disposable simulator examples

These files contain invented packages, advisory IDs, hashes and repository identities. They are not evidence of a real vulnerability and cannot authorize the native backend. The inventory timestamp is zero: `init-simulator` and later `inventory` commands collect current simulator state rather than treating that imported timestamp as a fresh host observation.

Use Python 3.12 or newer from the repository root. The synthetic target is Ubuntu 24.04 LTS (`noble`), `amd64`. No installation, network access or administrator privilege is needed. This Bash procedure creates a private directory and changes only files inside it. Run setup before any other command for that state directory; setup refuses existing database or simulator files.

The walkthrough uses `examples/ubuntu-synthetic.json`, which follows the [Canonical USN JSON contract](../docs/research/UBUNTU.md) and matches the simulator's `example-app` source/binary identity and `1.0-1ubuntu0.24.04.1` fix. It is synthetic, not a publisher snapshot. The broader parser test fixture is `tests/fixtures/feeds/ubuntu.json`, not the input for this workflow. Both procedures below were executed successfully during Ubuntu integration, producing verified execution and the expected USN `not_affected` result. See [verification evidence](../docs/REVIEW.md#ubuntu-verification-results).

```bash
set -euo pipefail
example_dir=$(mktemp -d /tmp/autoprotect-example.XXXXXXXX)
trap 'rm -rf -- "$example_dir"' EXIT
install -m 600 examples/simulator-policy.json "$example_dir/policy.json"
ap() {
  python3 -B -m autoprotect --state-dir "$example_dir/state" \
    --policy "$example_dir/policy.json" "$@"
}
ap init-simulator --inventory examples/simulator-inventory.json \
  --catalog examples/simulator-catalog.json
ap import-feed ubuntu examples/ubuntu-synthetic.json
ap inventory
finding_id=$(ap triage example-host | python3 -c \
  'import json,sys; print(next(x["id"] for x in json.load(sys.stdin) if x["status"] == "affected"))')
plan_id=$(ap plan "$finding_id" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
ap queue
ap approve "$plan_id" --actor tutorial-operator
ap execute "$plan_id"
ap inventory
ap triage example-host
ap audit
ap export example-host
```

Execution must return `status: succeeded` and `result.verified: true`; the collected `example-app` version must equal `1.0-1ubuntu0.24.04.1`, the exact `to_version` in `examples/simulator-catalog.json`. The finding whose `advisory_ids` lists `USN-10001-1` becomes `not_affected` by that notice's update requirement. Notice-level CVEs correlate incidents; they do not establish a package-by-CVE mapping or complete coverage. `tutorial-operator` is an audit label, not an authenticated identity. Exported advisory content remains untrusted data, even when its text looks like instructions.

For automatic execution, run the same procedure in a **new** temporary directory, copy `examples/simulator-auto-policy.json` instead, and omit `ap approve`. `ap execute` still performs policy, freshness, target and installed-state checks. Changing the policy after planning invalidates that plan; do not switch policies to reuse its approval.

For before-write failure, after-write uncertainty, explicit recovery and old-generation rejection, run the self-contained command demo:

```bash
python3 -B -m autoprotect demo
```

The module and installed-console demos each passed 101 ordinary commands over generated fixtures. The demo returns four scenario summaries and removes its own temporary state on normal completion. Expected denials require their specific error and, where emitted, a new matching audit event. The commands above use `-B` to prevent Python cache writes in the source tree; demo child interpreters also use it. The demo does not accept a caller state directory or policy. Forced process or host death can leave temporary files. Neither these examples nor the demo qualify privileged Ubuntu execution, real APT downloads, service health or removal of compromise. Ubuntu Pro and Expanded Security Maintenance (ESM) are outside the remediation scope.
