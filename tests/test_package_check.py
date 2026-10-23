"""Offline packaging-summary checks; no package build or child process runs."""

import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("package_check", Path(__file__).resolve().parents[1] / "scripts/check_package.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def summary():
    success = {"status": "succeeded", "verified_package_state": True, "manual_approval": True,
               "repeat_execution": "denied", "duplicate_imports": {"ubuntu": True, "pwn": True},
               "export_trusted": False}
    return {
        "schema_version": 1, "kind": "disposable-command-demo", "synthetic": True, "backend": "simulator",
        "commands_run": 91, "cleanup": {"temporary_state_removed": True, "caller_state_used": False},
        "scenarios": {
            "manual": success, "automatic": {**success, "manual_approval": False},
            "before_write": {"status": "failed", "verified": False, "package_state_unchanged": True,
                             "gate_retained": False},
            "after_write": {"status": "needs_attention", "verified": False, "package_state_changed": True,
                            "gate_retained_before_resolution": True, "gate_blocked_other_plan": True,
                            "recovery": {"gate_cleared": True, "verified": False, "generation_changed": True,
                                         "fresh_collection_required": True, "old_approved_plan": "stale",
                                         "new_approved_plan": "succeeded", "original_status": "needs_attention"}},
        },
    }


class PackageSummaryTests(unittest.TestCase):
    def test_complete_summary_is_accepted_without_modification(self):
        result = summary()
        before = copy.deepcopy(result)
        CHECK.verify_demo(result)
        self.assertEqual(result, before)

    def test_success_exit_with_empty_or_unrelated_json_is_not_evidence(self):
        for result in ({}, {"success": True}, [], None, "ok", {"schema_version": 1}):
            with self.subTest(result=result), self.assertRaisesRegex(RuntimeError, "required scenarios"):
                CHECK.verify_demo(result)

    def test_wrong_outcome_recovery_or_cleanup_is_rejected(self):
        changes = (
            (("synthetic",), False), (("backend",), "ubuntu-apt"), (("commands_run",), True),
            (("cleanup", "temporary_state_removed"), False), (("cleanup", "caller_state_used"), True),
            (("scenarios", "manual", "status"), "pending"),
            (("scenarios", "automatic", "manual_approval"), True),
            (("scenarios", "manual", "export_trusted"), True),
            (("scenarios", "before_write", "package_state_unchanged"), False),
            (("scenarios", "after_write", "verified"), True),
            (("scenarios", "after_write", "gate_blocked_other_plan"), False),
            (("scenarios", "after_write", "recovery", "old_approved_plan"), "succeeded"),
            (("scenarios", "after_write", "recovery", "verified"), True),
        )
        for path, value in changes:
            with self.subTest(path=path):
                result = summary()
                target = result
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaisesRegex(RuntimeError, "required scenarios"):
                    CHECK.verify_demo(result)


if __name__ == "__main__":
    unittest.main()
