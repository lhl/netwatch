#!/usr/bin/env python3
"""Cross-check Debian version ordering in an already-pulled disposable image.

Run from the repository root:
    docker pull debian:trixie-slim
    python3 scripts/check_debian_versions.py

The container has no network, host mounts, or extra privileges. It runs only
synthetic dpkg comparisons, not inventory collection or package installation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import runpy
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from autoprotect.debian import compare_versions  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="debian:trixie-slim", help="Previously pulled Debian image or digest")
    args = parser.parse_args()
    pairs = [(a, b) for a, b, _ in runpy.run_path(str(ROOT / "tests/test_debian.py"))["PAIRS"]]
    rng = random.Random(1729)
    versions = [
        f"{rng.randrange(4)}:{rng.randrange(4)}.{rng.randrange(12)}"
        f"{rng.choice(['', '~rc1', '+dfsg', 'a', '.001', '-extra'])}"
        f"-{rng.randrange(4)}{rng.choice(['', '+b1', '~bpo13+1', '+deb13u2'])}"
        for _ in range(100)
    ]
    pairs += [(rng.choice(versions), rng.choice(versions)) for _ in range(1000)]
    lines = ["set -eu"]
    for left, right in pairs:
        a, b = shlex.quote(left), shlex.quote(right)
        lines.append(
            f"if dpkg --compare-versions {a} lt {b}; then echo -1; "
            f"elif dpkg --compare-versions {a} gt {b}; then echo 1; "
            f"elif dpkg --compare-versions {a} eq {b}; then echo 0; else exit 3; fi"
        )
    result = subprocess.run(
        ["/usr/bin/docker", "run", "--rm", "--pull=never", "--network=none",
         "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
         "-i", args.image, "/bin/sh", "-s"],
        input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60,
    )
    if result.returncode:
        print(json.dumps({"error": "Disposable dpkg comparison failed", "exit_code": result.returncode,
                          "detail": result.stderr[:1000]}, ensure_ascii=True), file=sys.stderr)
        return 1
    actual = result.stdout.splitlines()
    expected = [str(compare_versions(left, right)) for left, right in pairs]
    if actual != expected:
        mismatch = next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), None)
        print(json.dumps({"error": "Debian ordering differs", "mismatch_index": mismatch,
                          "native_results": len(actual), "expected_results": len(expected)}), file=sys.stderr)
        return 1
    print(json.dumps({"image": args.image, "comparisons": len(pairs), "result": "passed"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
