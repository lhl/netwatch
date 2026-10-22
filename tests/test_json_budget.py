"""Raw feed regression: validation traversal must not duplicate the tree width."""

from pathlib import Path
import subprocess
import sys
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "uses Linux address-space limits")
class RawJsonBudgetTests(unittest.TestCase):
    def test_wide_raw_input_rejects_within_bounded_address_space(self):
        # Decode the full JSON normally, then enforce the same production feed
        # limits in a process with ample space for that tree but not an extra
        # width-sized stack of (child, depth) tuples. This is not a general
        # parser-memory guarantee: json.loads still retains the whole tree.
        script = """
import resource
import sys
from autoprotect import feeds
from autoprotect.core import ValidationError
resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
feeds._MAX_NODES = int(sys.argv[1])
raw = b'{"incidents":[],"ignored":[' + b'0,' * 2_000_000 + b'0]}'
try:
    feeds.parse_source("pwn", raw)
except ValidationError:
    print("bounded rejection")
else:
    raise AssertionError("wide hostile feed was accepted")
"""
        for node_limit in (10, 8_000_000):
            with self.subTest(node_limit=node_limit):
                result = subprocess.run(
                    [sys.executable, "-c", script, str(node_limit)],
                    cwd=Path(__file__).resolve().parents[1], capture_output=True,
                    text=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "bounded rejection\n")


if __name__ == "__main__":
    unittest.main()
