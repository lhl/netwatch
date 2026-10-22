# Disposable simulator examples

These files contain invented packages, advisory IDs, hashes and repository identities. They are not evidence of a real vulnerability and cannot authorize the native backend. The inventory timestamp is zero: `init-simulator` and later `inventory` commands collect current simulator state rather than treating that imported timestamp as a fresh host observation.

Use Python 3.12 from the repository root. No installation, network access or administrator privilege is needed. This Bash procedure creates a private directory and changes only files inside it. Run setup before any other command for that state directory; setup refuses existing database or simulator files.

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
ap import-feed debian examples/debian-synthetic.json
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

Execution must return `status: succeeded` and `result.verified: true`; the collected `example-app` version becomes `1.0-1+deb13u1`. The finding whose `advisory_ids` lists that advisory becomes `not_affected`, which is not a claim of complete security coverage. `tutorial-operator` is an audit label, not an authenticated identity. Exported advisory content remains untrusted data, even when its text looks like instructions.

For automatic execution, run the same procedure in a **new** temporary directory, copy `examples/simulator-auto-policy.json` instead, and omit `ap approve`. `ap execute` still performs policy, freshness, target and installed-state checks. Changing the policy after planning invalidates that plan; do not switch policies to reuse its approval.

For before-write failure, after-write uncertainty, explicit recovery and old-generation rejection, run the self-contained command demo:

```bash
python3 -B -m autoprotect demo
```

The demo runs 101 ordinary commands over generated fixtures, returns four scenario summaries, and removes its own temporary state on normal completion. Expected denials require their specific error and, where emitted, a new matching audit event. The commands above use `-B` to prevent Python cache writes in the source tree; demo child interpreters also use it. The demo does not accept a caller state directory or policy. Forced process or host death can leave temporary files. Neither these examples nor the demo verify real APT downloads, privileged package installation, service health or removal of compromise.
