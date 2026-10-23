import unittest

from netwatch.core import ValidationError
from netwatch.versions import compare_versions


# Native dpkg differential verification uses the same cases, plus generated
# pairs, in the optional disposable-container check. This suite stays offline.
PAIRS = [
    ("1", "1-0", 0),
    ("0:1", "1", 0),
    ("00:1", "0:1", 0),
    ("1.001", "1.1", 0),
    ("1.0", "1.0-0", 0),
    ("1.0-01", "1.0-1", 0),
    ("1.0", "1.0-1", -1),
    ("1.9", "1.10", -1),
    ("1:0", "9999.0", 1),
    ("9:9", "10:0", -1),
    ("1~rc1", "1", -1),
    ("1~~", "1~", -1),
    ("1~", "1~a", -1),
    ("1.0~rc1-1", "1.0-1", -1),
    ("1.0-1", "1.0-1+b1", -1),
    ("1.0-1+b9", "1.0-1+b10", -1),
    ("1.0-1+u1", "1.0-1+u2", -1),
    ("1.0-1~backport1", "1.0-1", -1),
    ("1a", "1+", -1),
    ("1A", "1a", -1),
    ("1+", "1.", -1),
    ("1.0-a", "1.0-1", 1),
    ("1.0-1-1", "1.0-1", 1),
    ("1:1:2-3", "1:1:3-3", -1),
    ("1.0-1", "1.0-1.0", -1),
    ("1.000a", "1.0a", 0),
    ("2147483647:1", "2147483646:999", 1),
    ("0002147483647:1", "2147483647:1", 0),
]


class DpkgVersionTests(unittest.TestCase):
    def test_known_ordering_and_symmetry(self):
        for left, right, expected in PAIRS:
            with self.subTest(left=left, right=right):
                self.assertEqual(compare_versions(left, right), expected)
                self.assertEqual(compare_versions(right, left), -expected)
                self.assertEqual(compare_versions(left, left), 0)

    def test_long_numeric_runs(self):
        self.assertEqual(compare_versions("1." + "9" * 200, "1.1" + "0" * 200), -1)
        self.assertEqual(compare_versions("1." + "0" * 200 + "1", "1.1"), 0)

    def test_invalid_epoch_cannot_be_compared(self):
        for bad in ("2147483648:1", "0002147483648:1", "9" * 100 + ":1"):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                compare_versions(bad, "1")

    def test_invalid_versions_are_not_lexical_comparisons(self):
        for bad in ("unknown", "v1", "-1", "1;id", "1_2", "1/2", "1\n", "1-", None, 1):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                compare_versions(bad, "1")


if __name__ == "__main__":
    unittest.main()
