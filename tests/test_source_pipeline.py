"""Offline integration of public parsing, inventory normalization and matching."""

import copy
from pathlib import Path
import unittest

from autoprotect.core import canonical, digest
from autoprotect.feeds import parse_source
from autoprotect.inventory import normalize_inventory
from autoprotect.matching import match


FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


class SourcePipelineTests(unittest.TestCase):
    def inventory(self):
        return normalize_inventory({
            "schema_version": 1, "asset_id": "fixture-host", "observed_at": 1000,
            "os": "debian", "release": "trixie", "architecture": "amd64",
            "collector": "native", "complete": True,
            "packages": [{
                "ecosystem": "deb", "name": "libexample1", "version": "1:1.0-1+b8",
                "source_name": "example-source", "source_version": "1:1.0-1",
                "architecture": "amd64", "status": "installed", "held": False,
            }],
        })

    def findings(self, inventory):
        assertions = parse_source("debian", (FIXTURES / "debian.json").read_bytes())
        incidents = parse_source("pwn", (FIXTURES / "pwn.json").read_bytes())
        return match(inventory, assertions, incidents, inventory_id=digest(inventory),
                     source_digest=digest(assertions), now=1100, max_inventory_age=300)

    def test_real_shaped_fixtures_to_findings_with_no_provenance_promotion(self):
        inventory = self.inventory()
        self.assertEqual(inventory["collector"], "imported")
        results = self.findings(inventory)
        # CVE-2026-10004 and -10005 share one unresolved-evidence explanation.
        self.assertEqual(len(results), 6)
        by_advisory = {advisory: row for row in results if row["package"] for advisory in row["advisory_ids"]}
        self.assertEqual(by_advisory["CVE-2026-10001"]["status"], "affected")
        self.assertEqual(by_advisory["CVE-2026-10001"]["fixed_version"], "1:1.0-1+deb13u2")
        self.assertEqual(by_advisory["CVE-2026-10001"]["incident_ids"], ["example-open-incident"])
        self.assertEqual(by_advisory["CVE-2026-10002"]["status"], "not_affected")
        self.assertIsNone(by_advisory["CVE-2026-10002"]["fixed_version"])
        self.assertEqual(by_advisory["CVE-2026-10003"]["status"], "affected")
        self.assertIsNone(by_advisory["CVE-2026-10003"]["fixed_version"])
        for advisory in ("CVE-2026-10004", "CVE-2026-10005", "TEMP-0000000-ABCDEF"):
            self.assertEqual(by_advisory[advisory]["status"], "unknown")
        self.assertIs(by_advisory["CVE-2026-10004"], by_advisory["CVE-2026-10005"])
        self.assertIsNot(by_advisory["CVE-2026-10004"], by_advisory["TEMP-0000000-ABCDEF"])
        self.assertEqual(next(row for row in results if row["package"] is None)["priority"], 0)
        encoded = canonical(results)
        self.assertNotIn("never-execute", encoded)
        self.assertNotIn("\x1b", encoded)
        self.assertNotIn("trusted", results[0])
        self.assertEqual(results, self.findings(copy.deepcopy(inventory)))

    def test_updated_inventory_changes_applicability_and_identity(self):
        inventory = self.inventory()
        before = self.findings(inventory)
        inventory["packages"][0].update(version="1:1.0-1+deb13u2+b1", source_version="1:1.0-1+deb13u2")
        after = self.findings(inventory)
        first = next(row for row in before if "CVE-2026-10001" in row["advisory_ids"])
        fixed = next(row for row in after if "CVE-2026-10001" in row["advisory_ids"])
        self.assertEqual(fixed["status"], "not_affected")
        self.assertNotEqual(first["id"], fixed["id"])
        self.assertTrue(any(row["status"] == "unknown" for row in after))


if __name__ == "__main__":
    unittest.main()
