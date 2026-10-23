"""APT probe-to-backend evidence integration with no native binding or command."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from autoprotect import backends
from autoprotect.backends import UbuntuApt
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
        self.backend = UbuntuApt(self.runner)
        self.policy = backend_fixtures.policy("ubuntu-apt")
        self.fresh = {"codename": "noble", "date": backend_fixtures.CLOCK - 100,
                      "valid_until": backend_fixtures.CLOCK + 1000}
        for patcher in (
            patch.object(backends, "now", return_value=backend_fixtures.CLOCK),
            patch.object(backends, "collect_local", side_effect=lambda runner: copy.deepcopy(runner.inventory)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def resolve(self, constraints, *, origins=None):
        self.producer.candidate._cand.file_list = [
            (SimpleNamespace(filename=f"/synthetic/repository-{i}/Packages"), i) for i in range(len(constraints))
        ]
        origins = [probe_fixtures.ORIGIN] * len(constraints) if origins is None else origins
        self.producer.verify.side_effect = list(zip(origins, constraints))
        evidence = self.producer.resolve()  # Actual probe producer, fake APT bindings.
        self.runner.target = evidence["target"]
        self.runner.evidence = evidence  # Consumer receives the unmodified producer envelope.
        installed = self.runner.inventory["packages"][1]
        installed.update(version="1:1.0-1", source_version="1:1.0-1")
        target = self.runner.target
        self.runner.simulation = (f"Inst widget [{target['from_version']}] ({target['to_version']} Ubuntu:24.04/noble [amd64])\n"
                                  f"Conf widget ({target['to_version']} Ubuntu:24.04/noble [amd64])\n")
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

    def test_absent_valid_until_preserves_signed_date_age_limit(self):
        no_expiry = dict(self.fresh, valid_until=None)
        self.assertEqual(self.resolve([no_expiry]), self.runner.target)
        old = dict(no_expiry, date=backend_fixtures.CLOCK - self.policy["max_repository_age"] - 1)
        with self.assertRaisesRegex(BackendError, "max_repository_age"):
            self.resolve([old])
        self.assertEqual(self.runner.events, ["resolve"])

    def test_older_base_package_version_does_not_contribute_release_constraints(self):
        # The configured base repository supplies only a different, older
        # binary version. Its Release is not evidence for this target version.
        base = SimpleNamespace(version="1:1.0-1", architecture="amd64",
                               _cand=SimpleNamespace(file_list=[(SimpleNamespace(filename="/synthetic/base/Packages"), 0)]))
        self.producer.package.versions.append(base)
        sources = [probe_fixtures.SOURCES[0], dict(probe_fixtures.SOURCES[0], suite="noble-security")]
        self.producer.config.return_value = ("c" * 64, sources)
        security = dict(probe_fixtures.ORIGIN, archive="noble-security")
        self.policy["allowed_origins"].append(security)
        fresh = dict(self.fresh, valid_until=None)
        self.assertEqual(self.resolve([fresh], origins=[security]), self.runner.target)
        self.producer.verify.assert_called_once()
        self.assertEqual(self.runner.evidence["releases"], [dict(fresh, origin=security)])
        self.assertEqual(self.runner.target["origins"], [security])
        self.assertEqual(self.runner.events, ["resolve", "simulate"])

    def test_same_version_from_old_base_and_fresh_security_rejects_whole_target(self):
        security = dict(probe_fixtures.ORIGIN, archive="noble-security")
        self.policy["allowed_origins"].append(security)
        old = dict(self.fresh, date=backend_fixtures.CLOCK - 31_536_001, valid_until=None)
        fresh = dict(self.fresh, valid_until=None)
        evidence = [(probe_fixtures.ORIGIN, old), (security, fresh)]
        for ordering in (evidence, list(reversed(evidence))):
            with self.subTest(ordering=ordering), self.assertRaisesRegex(BackendError, "max_repository_age"):
                self.resolve([release for _, release in ordering], origins=[origin for origin, _ in ordering])
            self.assertEqual(len(self.runner.evidence["releases"]), 2)
            self.assertEqual(len(self.runner.target["origins"]), 2)
            self.assertEqual(self.runner.events, ["resolve"])

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
