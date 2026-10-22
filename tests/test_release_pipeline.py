"""APT probe-to-backend evidence integration with no native binding or command."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from autoprotect import backends
from autoprotect.backends import DebianApt
from autoprotect.core import BackendError
import test_apt_probe as probe_fixtures
import test_backends as backend_fixtures


class ReleasePipelineTests(unittest.TestCase):
    def setUp(self):
        # Reuse synthetic native bindings, not another test class's assertions.
        self.producer = probe_fixtures.ResolveProbeTests()
        self.producer.setUp()
        self.addCleanup(self.producer.doCleanups)
        self.runner = backend_fixtures.FakeNativeRunner()
        self.backend = DebianApt(self.runner)
        self.policy = backend_fixtures.policy("debian-apt")
        self.fresh = {"codename": "trixie", "date": backend_fixtures.CLOCK - 100,
                      "valid_until": backend_fixtures.CLOCK + 1000}
        for patcher in (
            patch.object(backends, "now", return_value=backend_fixtures.CLOCK),
            patch.object(backends, "collect_local", side_effect=lambda runner: copy.deepcopy(runner.inventory)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def resolve(self, constraints):
        self.producer.candidate._cand.file_list = [
            (SimpleNamespace(filename=f"/synthetic/repository-{i}/Packages"), i) for i in range(len(constraints))
        ]
        self.producer.verify.side_effect = [(probe_fixtures.ORIGIN, release) for release in constraints]
        evidence = self.producer.resolve()  # Actual probe producer, fake APT bindings.
        self.runner.target = evidence["target"]
        self.runner.evidence = evidence  # Consumer receives the unmodified producer envelope.
        installed = self.runner.inventory["packages"][1]
        installed.update(version="1:1.0-1", source_version="1:1.0-1")
        target = self.runner.target
        self.runner.simulation = (f"Inst widget [{target['from_version']}] ({target['to_version']} Debian:stable [amd64])\n"
                                  f"Conf widget ({target['to_version']} Debian:stable [amd64])\n")
        self.runner.events.clear()
        inventory = self.backend.inspect()
        finding = dict(backend_fixtures.finding(inventory), fixed_version="1:2.0-1")
        return self.backend.resolve(inventory, finding, self.policy)

    def test_fresh_same_origin_constraints_reach_the_actual_consumer(self):
        for constraints in ([self.fresh, dict(self.fresh, date=backend_fixtures.CLOCK - 200)],
                            [dict(self.fresh, date=backend_fixtures.CLOCK - 200), self.fresh]):
            with self.subTest(constraints=constraints):
                self.assertEqual(self.resolve(constraints), self.runner.target)
                self.assertEqual(len(self.runner.evidence["releases"]), 2)
                self.assertEqual(self.runner.events, ["resolve", "simulate"])

    def test_any_bad_contributing_constraint_blocks_before_simulation_in_either_order(self):
        for change in ({"date": backend_fixtures.CLOCK - self.policy["max_repository_age"] - 1},
                       {"date": backend_fixtures.CLOCK + 1}, {"valid_until": backend_fixtures.CLOCK}):
            bad = dict(self.fresh, **change)
            for constraints in ([bad, self.fresh], [self.fresh, bad]):
                with self.subTest(change=change, constraints=constraints):
                    with self.assertRaisesRegex(BackendError, "stale, future-dated or expired"):
                        self.resolve(constraints)
                    self.assertEqual(len(self.runner.evidence["releases"]), 2)
                    self.assertEqual(self.runner.events, ["resolve"])


if __name__ == "__main__":
    unittest.main()
