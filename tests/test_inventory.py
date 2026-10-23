import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from autoprotect.core import BackendError, ValidationError
from autoprotect.inventory import collect_local, inventory_fingerprint, normalize_inventory
from autoprotect.runner import CommandResult


def example_inventory():
    return {
        "schema_version": 1,
        "asset_id": "synthetic-host",
        "observed_at": 1_790_000_000,
        "os": "ubuntu",
        "release": "noble",
        "architecture": "amd64",
        "collector": "native",
        "complete": True,
        "packages": [{
            "ecosystem": "deb", "name": "libexample1", "version": "2:1.0-1+b2",
            "source_name": "example", "source_version": "2:1.0-1",
            "architecture": "amd64", "status": "installed", "held": False,
        }],
    }


class NormalizationTests(unittest.TestCase):
    def test_import_cannot_claim_native_or_simulator_provenance(self):
        for label in ("native", "simulator", "imported", "https", None, {"trusted": True}):
            data = example_inventory()
            data["collector"] = label
            result = normalize_inventory(data)
            self.assertEqual(result["collector"], "imported")
            self.assertEqual(result["packages"], data["packages"])
        data.pop("collector")
        self.assertEqual(normalize_inventory(data)["collector"], "imported")

    def test_explicit_internal_collector_is_not_read_from_body(self):
        for collector in ("imported", "native", "simulator"):
            result = normalize_inventory(example_inventory(), collector=collector)
            self.assertEqual(result["collector"], collector)
        for collector in ("remote", None, True, []):
            with self.subTest(collector=collector), self.assertRaises(ValidationError):
                normalize_inventory(example_inventory(), collector=collector)

    def test_normalization_does_not_mutate_input_and_sorts_identity(self):
        data = example_inventory()
        data["packages"].extend([
            {**data["packages"][0], "name": "aaa", "architecture": "arm64"},
            {**data["packages"][0], "name": "aaa", "architecture": "amd64"},
            {**data["packages"][0], "ecosystem": "npm", "name": "@org/pkg", "version": "v1"},
        ])
        original = copy.deepcopy(data)
        result = normalize_inventory(data)
        self.assertEqual(data, original)
        keys = [(p["ecosystem"], p["name"], p["architecture"]) for p in result["packages"]]
        self.assertEqual(keys, sorted(keys))
        result["packages"][0]["held"] = True
        self.assertEqual(data, original)

    def test_duplicate_identity_rejected_even_if_version_differs(self):
        data = example_inventory()
        data["packages"].append({**data["packages"][0], "version": "9.0"})
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            normalize_inventory(data)

    def test_source_mapping_and_missing_deb_metadata_rejected(self):
        result = normalize_inventory(example_inventory())
        package = result["packages"][0]
        self.assertEqual(package["version"], "2:1.0-1+b2")
        self.assertEqual(package["source_name"], "example")
        self.assertEqual(package["source_version"], "2:1.0-1")
        for field in ("source_name", "source_version"):
            data = example_inventory()
            del data["packages"][0][field]
            with self.subTest(field=field), self.assertRaisesRegex(ValidationError, "supply source metadata"):
                normalize_inventory(data)
            data["packages"][0][field] = None
            with self.assertRaises(ValidationError):
                normalize_inventory(data)

    def test_unsupported_source_fields_use_binary_fallback(self):
        data = example_inventory()
        data["packages"][0].update(ecosystem="npm", name="@scope/Thing", version="v1.0")
        del data["packages"][0]["source_name"]
        del data["packages"][0]["source_version"]
        package = normalize_inventory(data)["packages"][0]
        self.assertEqual(package["source_name"], "@scope/Thing")
        self.assertEqual(package["source_version"], "v1.0")

    def test_unsupported_platforms_and_ecosystems_remain_data(self):
        data = example_inventory()
        data.update(os="macos", release="15.1", architecture="arm64")
        data["packages"] = [{
            "ecosystem": "npm", "name": "@scope/Thing", "version": "v2.0.0-beta+build",
            "architecture": "any", "status": "installed", "held": False,
        }, {
            "ecosystem": "pypi", "name": "Some_Package", "version": "release_candidate",
            "architecture": "any", "status": "unknown", "held": False,
        }]
        result = normalize_inventory(data)
        self.assertEqual(result["os"], "macos")
        self.assertEqual(result["packages"][0]["name"], "@scope/Thing")
        self.assertEqual(result["packages"][1]["version"], "release_candidate")

    def test_incomplete_held_and_non_ready_states_remain_visible(self):
        for state in ("installed", "half-configured", "reinstreq-installed", "unknown"):
            data = example_inventory()
            data["complete"] = False
            data["packages"][0].update(status=state, held=True)
            result = normalize_inventory(data)
            self.assertFalse(result["complete"])
            self.assertTrue(result["packages"][0]["held"])
            self.assertEqual(result["packages"][0]["status"], state)

    def test_strict_boolean_timestamp_and_schema_types(self):
        for field, values in (
            ("complete", (0, 1, "true", None)),
            ("observed_at", (True, 1.1, "123", -1, 2**63, None)),
            ("schema_version", (True, 1.0, "1", 0, 2)),
        ):
            for value in values:
                data = example_inventory()
                data[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    normalize_inventory(data)
        for held in (0, 1, "false", None):
            data = example_inventory()
            data["packages"][0]["held"] = held
            with self.subTest(held=held), self.assertRaises(ValidationError):
                normalize_inventory(data)

    def test_missing_required_fields_and_bad_shapes(self):
        data = example_inventory()
        for field in data.keys() - {"collector"}:
            bad = copy.deepcopy(data)
            del bad[field]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                normalize_inventory(bad)
        for value in (None, [], "{}", True):
            with self.assertRaises(ValidationError):
                normalize_inventory(value)
        for value in (None, {}, "packages", [None], [[]]):
            with self.assertRaises(ValidationError):
                normalize_inventory({**data, "packages": value})
        for field in data["packages"][0].keys() - {"source_name", "source_version"}:
            bad = copy.deepcopy(data)
            del bad["packages"][0][field]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                normalize_inventory(bad)

    def test_malformed_control_and_oversize_fields(self):
        for field in ("asset_id", "os", "release", "architecture"):
            for value in ("bad\n", "bad\x1b", "x" * 129, "../bad", "\ud800"):
                with self.subTest(field=field, value=repr(value)), self.assertRaises(ValidationError):
                    normalize_inventory({**example_inventory(), field: value})
        for ecosystem in ("deb", "npm"):
            for field in ("name", "version", "source_name", "source_version", "architecture", "status", "ecosystem"):
                for value in ("bad\n", "bad\x00", "bad\x7f", "bad\x85", "x" * 257, "\ud800"):
                    data = example_inventory()
                    data["packages"][0].update(ecosystem=ecosystem)
                    data["packages"][0][field] = value
                    with self.subTest(ecosystem=ecosystem, field=field, value=repr(value)), self.assertRaises(ValidationError):
                        normalize_inventory(data)
        for value in ("pkg;id", "pkg:amd64", "@scope/pkg"):
            data = example_inventory()
            data["packages"][0]["name"] = value
            with self.assertRaises(ValidationError):
                normalize_inventory(data)

    def test_package_count_bound(self):
        with patch("autoprotect.inventory.MAX_PACKAGES", 1):
            data = example_inventory()
            data["packages"].append({**data["packages"][0], "name": "other"})
            with self.assertRaises(ValidationError):
                normalize_inventory(data)

    def test_fingerprint_excludes_only_observation_time(self):
        data = normalize_inventory(example_inventory(), collector="native")
        before = inventory_fingerprint(data)
        self.assertEqual(len(before), 64)
        self.assertEqual(before, inventory_fingerprint({**data, "observed_at": data["observed_at"] + 1}))
        for field, value in (("asset_id", "other"), ("collector", "imported"), ("complete", False),
                             ("os", "linux"), ("release", "jammy"), ("architecture", "arm64"),
                             ("schema_version", 2), ("extra", True)):
            with self.subTest(field=field):
                self.assertNotEqual(before, inventory_fingerprint({**data, field: value}))
        for field, value in (("held", True), ("source_version", "2:1.0-2"), ("version", "2:1.0-2"),
                             ("status", "half-configured"), ("source_name", "other"), ("name", "other"),
                             ("ecosystem", "npm"), ("architecture", "all")):
            changed = copy.deepcopy(data)
            changed["packages"][0][field] = value
            with self.subTest(package_field=field):
                self.assertNotEqual(before, inventory_fingerprint(changed))


class FakeRunner:
    def __init__(self, rows=None, *, architecture="amd64\n", second_rows=None, returncode=0):
        self.rows = rows if rows is not None else (
            "libexample1\t2:1.0-1+b2\tamd64\texample\t2:1.0-1\tinstall ok installed\n"
            "held-example\t1.0-1\tall\theld-example\t1.0-1\thold ok installed\n"
            "partial-example\t1.0-1\tamd64\tpartial-example\t1.0-1\tinstall ok half-configured\n"
            "broken-example\t1.0-1\tamd64\tbroken-example\t1.0-1\tinstall reinstreq installed\n"
            "plain-example\t3.0-2\tamd64\t\t\tinstall ok installed\n"
        )
        self.architecture = architecture
        self.second_rows = second_rows
        self.returncode = returncode
        self.calls = []

    def run(self, argv, *, timeout=60, cwd=None):
        self.calls.append((argv, timeout, cwd))
        if argv == ["/usr/bin/dpkg", "--print-architecture"]:
            return CommandResult(0, self.architecture, "")
        expected = ["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\t${source:Version}\\t${Status}\\n"]
        if argv != expected:
            raise AssertionError(f"unexpected command: {argv!r}")
        rows = self.second_rows if len(self.calls) == 3 and self.second_rows is not None else self.rows
        return CommandResult(self.returncode, rows, "untrusted-error\x1b")


class NativeCollectionTests(unittest.TestCase):
    def setUp(self):
        self.machine = b"0123456789abcdef0123456789abcdef\n"
        self.files = {
            "/etc/os-release": b'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Synthetic Ubuntu"\n',
            "/etc/machine-id": self.machine,
        }
        self.reads = []

    def read_file(self, path, limit):
        self.reads.append((path, limit))
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def collect(self, runner=None):
        with patch("autoprotect.inventory._read_file", side_effect=self.read_file), \
             patch("autoprotect.inventory.now", return_value=1_790_000_123):
            return collect_local(FakeRunner() if runner is None else runner)

    def test_native_collection_preserves_states_source_mapping_and_identity(self):
        result = self.collect()
        self.assertEqual(result["collector"], "native")
        self.assertTrue(result["complete"])
        self.assertEqual(result["observed_at"], 1_790_000_123)
        self.assertEqual(result["asset_id"], "machine-" + hashlib.sha256(self.machine.strip()).hexdigest())
        self.assertNotIn(self.machine.strip().decode(), str(result))
        self.assertEqual((result["os"], result["release"], result["architecture"]), ("ubuntu", "noble", "amd64"))
        packages = {p["name"]: p for p in result["packages"]}
        self.assertTrue(all(p["ecosystem"] == "deb" for p in packages.values()))
        self.assertEqual(packages["libexample1"]["source_name"], "example")
        self.assertEqual(packages["libexample1"]["source_version"], "2:1.0-1")
        self.assertEqual(packages["libexample1"]["version"], "2:1.0-1+b2")
        self.assertTrue(packages["held-example"]["held"])
        self.assertEqual(packages["held-example"]["status"], "installed")
        self.assertEqual(packages["partial-example"]["status"], "half-configured")
        self.assertEqual(packages["broken-example"]["status"], "reinstreq-installed")
        self.assertEqual(packages["plain-example"]["source_name"], "plain-example")
        self.assertEqual(packages["plain-example"]["source_version"], "3.0-2")

    def test_only_fixed_read_only_commands_and_bounded_identity_files(self):
        runner = FakeRunner()
        self.collect(runner)
        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(runner.calls[0], (["/usr/bin/dpkg", "--print-architecture"], 60, "/"))
        self.assertEqual(runner.calls[1], runner.calls[2])
        self.assertEqual(runner.calls[1][1:], (60, "/"))
        self.assertEqual(self.reads, [("/etc/os-release", 65536), ("/etc/machine-id", 4096)])
        self.assertTrue(all(c[0][0] in ("/usr/bin/dpkg", "/usr/bin/dpkg-query") for c in runner.calls))
        self.assertNotIn("--install", str(runner.calls))
        self.assertNotIn("--version", str(runner.calls))

    def test_default_runner_can_be_replaced_without_native_files(self):
        fake = FakeRunner()
        with patch("autoprotect.inventory.Runner", return_value=fake), \
             patch("autoprotect.inventory._read_file", side_effect=self.read_file):
            self.assertEqual(collect_local()["collector"], "native")
        self.assertEqual(len(fake.calls), 3)

    def test_os_release_fallback_does_not_merge_sources(self):
        self.files["/usr/lib/os-release"] = b"ID=example\nVERSION_CODENAME=other\n"
        self.assertEqual(self.collect()["os"], "ubuntu")
        self.assertNotIn("/usr/lib/os-release", [path for path, _ in self.reads])
        del self.files["/etc/os-release"]
        result = self.collect()
        self.assertEqual((result["os"], result["release"]), ("example", "other"))

    def test_id_like_never_establishes_platform_identity(self):
        self.files["/etc/os-release"] = b"ID=custom\nID_LIKE=ubuntu\nVERSION_ID=24.04\n"
        result = self.collect()
        self.assertEqual((result["os"], result["release"]), ("custom", "24.04"))

    def test_os_release_is_data_not_shell_code(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-exist"
            self.files["/etc/os-release"] += (
                f'NAME="$(touch {marker})"\nEXTRA="`touch {marker}`"\n'
                'ESCAPES="a\\\"b\\\\c\\$HOME\\`literal\\`"\nSINGLE=\'literal $HOME\'\n'
            ).encode()
            self.assertEqual(self.collect()["os"], "ubuntu")
            self.assertFalse(marker.exists())
        for value in (b"ID=ubuntu;touch /bad\n", b"ID=$(id)\n", b"ID='ubuntu'\"other\"\n",
                      b"ID=ubuntu\nID=linux\n", b"ID=ubuntu\x00\n", b"ID=ubuntu\r\n",
                      b"ID=ubuntu\nNAME=\"unclosed\n", b"ID=\xff\n", b"ID=ubuntu\n. /bad\n"):
            self.files["/etc/os-release"] = value
            with self.subTest(value=value), self.assertRaises(BackendError):
                self.collect()

    def test_missing_or_malformed_identity_files_reject_collection(self):
        for machine in (b"", b"uninitialized\n", b"0" * 32 + b"\n", b"a" * 31,
                        b"a" * 33, b"a" * 32 + b"\nextra", b"a" * 32 + b"\x00", b"A" * 32):
            self.files["/etc/machine-id"] = machine
            with self.subTest(machine=machine), self.assertRaises(BackendError):
                self.collect()
        del self.files["/etc/machine-id"]
        with self.assertRaises(BackendError):
            self.collect()
        self.files["/etc/machine-id"] = self.machine
        del self.files["/etc/os-release"]
        with self.assertRaises(BackendError):
            self.collect()

    def test_file_and_command_output_limits(self):
        for path, size in (("/etc/os-release", 65537), ("/etc/machine-id", 4097)):
            original = self.files[path]
            self.files[path] = b"a" * size
            with self.subTest(path=path), self.assertRaises(BackendError):
                self.collect()
            self.files[path] = original
        with patch("autoprotect.inventory.MAX_QUERY_BYTES", 20):
            with self.assertRaises(BackendError):
                self.collect()

    def test_actual_file_reader_bounds_and_rejects_nonregular_files(self):
        from autoprotect.inventory import _read_file
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "synthetic"
            file.write_bytes(b"12345")
            self.assertEqual(_read_file(str(file), 5), b"12345")
            with self.assertRaises(BackendError):
                _read_file(str(file), 4)
            with self.assertRaises(BackendError):
                _read_file(directory, 10)
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(BackendError):
                _read_file(str(fifo), 10)

    def test_malformed_architecture_and_rows_do_not_become_empty_success(self):
        for architecture in ("amd64\narm64\n", "amd64\n\n", "amd64\x1b", "", "--bad\n"):
            with self.subTest(architecture=architecture), self.assertRaises(BackendError):
                self.collect(FakeRunner(architecture=architecture))
        good = "example\t1.0-1\tamd64\texample\t1.0-1\tinstall ok installed\n"
        for rows in ("", good.rstrip("\n"), good + "\n", good + good, good.replace("\t", " ", 1),
                     good.replace("example\t", "evil;id\t", 1), good.replace("1.0-1", "v1", 1),
                     good.replace("amd64", "amd64\x00"), good.replace("install ok", "install error"),
                     good.replace("installed", "invented"), good.replace("example\t", "example\x1b\t", 1)):
            with self.subTest(rows=repr(rows)), self.assertRaises(BackendError):
                self.collect(FakeRunner(rows))

    def test_query_failure_does_not_echo_subprocess_text(self):
        with self.assertRaises(BackendError) as caught:
            self.collect(FakeRunner(returncode=2))
        self.assertNotIn("untrusted-error", str(caught.exception))
        self.assertNotIn("\x1b", str(caught.exception))

    def test_query_race_rejects_changes_but_not_row_reordering(self):
        rows = FakeRunner().rows
        runner = FakeRunner(second_rows="\n".join(reversed(rows.rstrip("\n").split("\n"))) + "\n")
        self.assertTrue(self.collect(runner)["complete"])
        runner = FakeRunner(second_rows=rows.replace("2:1.0-1+b2", "2:1.0-1+b3"))
        with self.assertRaisesRegex(BackendError, "changed"):
            self.collect(runner)

    def test_non_default_desired_states_remain_non_ready(self):
        for desired in ("deinstall", "purge", "unknown"):
            rows = f"example\t1.0\tamd64\texample\t1.0\t{desired} ok installed\n"
            result = self.collect(FakeRunner(rows))
            self.assertEqual(result["packages"][0]["status"], desired + "-installed")


if __name__ == "__main__":
    unittest.main()
