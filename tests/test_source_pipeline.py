"""Offline integration of public Canonical parsing, inventory and matching."""

import copy
from pathlib import Path
import unittest

from autoprotect.core import canonical, digest
from autoprotect.feeds import parse_source
from autoprotect.inventory import normalize_inventory
from autoprotect.matching import match, verify_affected


FIXTURES = Path(__file__).parent / "fixtures" / "feeds"


class SourcePipelineTests(unittest.TestCase):
    def inventory(self):
        return normalize_inventory({
            "schema_version": 1, "asset_id": "fixture-host", "observed_at": 1000,
            "os": "ubuntu", "release": "noble", "architecture": "amd64",
            "collector": "native", "complete": True,
            "packages": [{
                "ecosystem": "deb", "name": "libexample1", "version": "1:1.0-1+b8",
                "source_name": "example-source", "source_version": "1:1.0-1",
                "architecture": "amd64", "status": "installed", "held": False,
            }],
        })

    def assertions(self):
        return parse_source("ubuntu", (FIXTURES / "ubuntu.json").read_bytes())

    def findings(self, inventory, *, acquisition=None):
        assertions = self.assertions()
        incidents = parse_source("pwn", (FIXTURES / "pwn.json").read_bytes())
        return match(inventory, assertions, incidents, inventory_id=digest(inventory),
                     source_digest=digest(assertions), now=1100, max_inventory_age=300,
                     evidence_acquisition=acquisition)

    def test_real_shaped_fixtures_to_findings_with_no_provenance_promotion(self):
        inventory = self.inventory()
        self.assertEqual(inventory["collector"], "imported")
        results = self.findings(inventory, acquisition="import")
        by_notice = {advisory: row for row in results if row["package"] for advisory in row["advisory_ids"]}
        self.assertEqual(by_notice["USN-10001-1"]["status"], "affected")
        self.assertEqual(by_notice["USN-10001-1"]["fixed_version"], "1:1.0-1ubuntu0.24.04.2")
        self.assertEqual(by_notice["USN-10001-1"]["incident_ids"], ["example-open-incident"])
        self.assertEqual(by_notice["USN-10002-1"]["status"], "not_affected")
        self.assertIsNone(by_notice["USN-10002-1"]["fixed_version"])
        for advisory in ("USN-10003-1", "USN-10004-1", "USN-10005-1", "USN-10006-1"):
            self.assertEqual(by_notice[advisory]["status"], "unknown")
            self.assertIsNone(by_notice[advisory]["fixed_version"])
        self.assertEqual(next(row for row in results if row["package"] is None)["priority"], 0)
        encoded = canonical(results)
        self.assertNotIn("never-execute", encoded)
        self.assertNotIn("\x1b", encoded)
        self.assertNotIn("trusted", results[0])
        self.assertTrue(all(row["evidence_acquisition"] == "import" for row in results))
        self.assertEqual(results, self.findings(copy.deepcopy(inventory), acquisition="import"))

    def test_updated_inventory_changes_applicability_and_identity(self):
        inventory = self.inventory()
        before = self.findings(inventory)
        inventory["packages"][0].update(version="1:1.0-1ubuntu0.24.04.2+b1", source_version="1:1.0-1ubuntu0.24.04.2")
        after = self.findings(inventory)
        first = next(row for row in before if "USN-10001-1" in row["advisory_ids"])
        fixed = next(row for row in after if "USN-10001-1" in row["advisory_ids"])
        self.assertEqual(fixed["status"], "not_affected")
        self.assertNotEqual(first["id"], fixed["id"])
        self.assertTrue(any(row["status"] == "unknown" for row in after))

    def test_only_standard_security_evidence_passes_execution_time_recheck(self):
        inventory = self.inventory()
        args = dict(package=inventory["packages"][0], max_inventory_age=300)
        self.assertTrue(verify_affected(inventory, self.assertions(), **args,
                                       advisory_ids=["USN-10001-1"], fixed_version="1:1.0-1ubuntu0.24.04.2"))
        for row in self.assertions():
            if row["status"] == "unknown":
                self.assertFalse(verify_affected(inventory, self.assertions(), **args,
                                                advisory_ids=[row["id"]], fixed_version=row["fixed_version"]))

    def test_wrong_release_architecture_and_unlisted_binary_stay_unknown(self):
        for change in ({"release": "jammy"}, {"architecture": "arm64"}):
            inventory = self.inventory()
            inventory.update(change)
            self.assertTrue(all(row["status"] == "unknown" for row in self.findings(inventory)))
        inventory = self.inventory()
        inventory["packages"][0]["name"] = "libexample-unlisted"
        self.assertTrue(all(row["status"] == "unknown" for row in self.findings(inventory)))


if __name__ == "__main__":
    unittest.main()
