"""Offline probe tests: fake APT bindings and public-only synthetic GPG fixtures."""

import base64
from contextlib import ExitStack
import copy
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from autoprotect import _apt_probe as probe

KEY = "/usr/share/keyrings/debian-archive-keyring.gpg"
SOURCE = f"deb [arch=amd64 signed-by={KEY}] https://deb.example.invalid/debian trixie main\n"
SOURCES = [{"uri": "https://deb.example.invalid/debian/", "suite": "trixie", "components": ["main"], "key": KEY}]
ORIGIN = {"origin": "Debian", "label": "Debian", "archive": "stable", "codename": "trixie", "component": "main", "site": "deb.example.invalid"}
RELEASE = {"codename": "trixie", "date": 1_800_000_000, "valid_until": None}
CONTROL = "Package: widget\nVersion: 1:2.0-1+b1\nArchitecture: amd64\nSource: widget-src (1:2.0-1)\n"
RECORD = CONTROL + "SHA256: " + "a" * 64 + "\nSize: 123\nFilename: pool/main/w/widget/widget_2.0-1+b1_amd64.deb\n"


class SourceTests(unittest.TestCase):
    def test_list_and_deb822_exact_signed_by_sources(self):
        self.assertEqual(probe.parse_sources(SOURCE, deb822=False), SOURCES)
        deb822 = ("# configured locally\nTypes: deb\nURIs: https://deb.example.invalid/debian\nSuites: trixie\n"
                  f"Components: main\nArchitectures: amd64\nSigned-By: {KEY}\n")
        self.assertEqual(probe.parse_sources(deb822, deb822=True), SOURCES)
        for content, format822 in ((SOURCE, False), (deb822, True)):
            with self.subTest(deb822=format822):
                self.assertEqual(probe.parse_sources(content.replace("keyring.gpg", "keyring.asc"), deb822=format822),
                                 [dict(SOURCES[0], key=KEY.replace(".gpg", ".asc"))])
        self.assertEqual(len(probe.parse_sources(deb822.replace("Suites: trixie", "Suites: trixie trixie-updates"), deb822=True)), 2)

    def test_reject_source_authentication_and_date_overrides(self):
        for option in ("trusted=yes", "allow-insecure=yes", "allow-weak=yes", "check-valid-until=no", "check-date=no", "arch=arm64"):
            with self.subTest(option=option), self.assertRaises(probe.ProbeError):
                probe.parse_sources(SOURCE.replace("]", " " + option + "]"), deb822=False)
        for extra in ("Trusted: yes", "Check-Valid-Until: no", "Allow-Insecure: yes", "Enabled: maybe", "Signed-By: /tmp/key.gpg"):
            content = f"Types: deb\nURIs: https://deb.example.invalid/debian\nSuites: trixie\nComponents: main\nSigned-By: {KEY}\n{extra}\n"
            with self.subTest(extra=extra), self.assertRaises(probe.ProbeError):
                probe.parse_sources(content, deb822=True)

    def test_reject_unsigned_remote_or_ambiguous_source_selectors(self):
        cases = [SOURCE.replace(f"[arch=amd64 signed-by={KEY}] ", ""), SOURCE.replace(KEY, "/tmp/key.gpg"),
                 SOURCE.replace(KEY, "/usr/share/keyrings/../key.gpg"), SOURCE.replace("https:", "ftp:"),
                 SOURCE.replace("invalid/", "invalid:8080/"), SOURCE.replace("https:", "http:").replace("invalid/", "invalid:443/"),
                 SOURCE.replace("keyring.gpg", "keyring.key"),
                 SOURCE.replace("trixie", "stable"), SOURCE.replace("trixie", "sid"), SOURCE.replace("deb [", "deb-src[ "),
                 SOURCE.replace("deb.example.invalid", "user:password@deb.example.invalid"),
                 SOURCE.replace("/debian trixie", "/debian?custom=yes trixie"),
                 SOURCE.replace(" main", " main;touch /tmp/unsafe"), SOURCE.replace("https:", "file:")]
        for content in cases:
            with self.subTest(content=content), self.assertRaises((probe.ProbeError, ValueError)):
                probe.parse_sources(content, deb822=False)

    def test_stock_trixie_sources_signed_http_pgp_keys_and_source_indexes(self):
        # The shape Debian 13 installs: plain HTTP mirrors (authenticated by
        # signed InRelease, not transport), a .pgp keyring and a comment.
        stock = ("Types: deb\n# http://snapshot.debian.org/archive/debian/20261020T213255Z\n"
                 "URIs: http://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main\n"
                 "Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp\n\n"
                 "Types: deb\nURIs: http://deb.debian.org/debian-security\nSuites: trixie-security\n"
                 "Components: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n")
        entries = probe.parse_sources(stock, deb822=True)
        self.assertEqual([(entry["uri"], entry["suite"]) for entry in entries], [
            ("http://deb.debian.org/debian/", "trixie"), ("http://deb.debian.org/debian/", "trixie-updates"),
            ("http://deb.debian.org/debian-security/", "trixie-security")])
        self.assertTrue(all(entry["key"].endswith(".pgp") for entry in entries))
        self.assertEqual(probe.parse_sources(SOURCE.replace("https:", "http:"), deb822=False)[0]["uri"],
                         "http://deb.example.invalid/debian/")
        self.assertEqual(probe.parse_sources(SOURCE.replace("deb [", "deb-src ["), deb822=False), [])
        both = stock.replace("Types: deb\n", "Types: deb deb-src\n", 1)
        self.assertEqual(probe.parse_sources(both, deb822=True), entries)
        disabled = stock.replace("Types: deb\n", "Types: deb\nEnabled: no\n", 1)
        self.assertEqual(len(probe.parse_sources(disabled, deb822=True)), 1)
        for types in ("Types: deb-src deb-src\n", "Types: rpm\n", "Types:\n"):
            with self.subTest(types=types), self.assertRaises(probe.ProbeError):
                probe.parse_sources(stock.replace("Types: deb\n", types, 1), deb822=True)

    def test_control_duplicate_casefold_and_malformed_data(self):
        for raw in ("Package: widget\npackage: other\n", " continuation\n", "Malformed\n", "Package: widget\x00\n"):
            with self.subTest(raw=raw), self.assertRaises(probe.ProbeError):
                probe._single(raw)

    def test_source_identity_fallback_and_binary_rebuild(self):
        exact = probe.control_identity(probe._single(CONTROL))
        self.assertEqual(exact["source_name"], "widget-src")
        self.assertEqual(exact["source_version"], "1:2.0-1")
        record = probe._single(CONTROL)
        record.pop("source")
        fallback = probe.control_identity(record)
        self.assertEqual(fallback["source_name"], "widget")
        self.assertEqual(fallback["source_version"], "1:2.0-1+b1")
        record["source"] = "widget-src"
        self.assertEqual(probe.control_identity(record)["source_version"], "1:2.0-1+b1")

    def test_relationship_and_protected_flags_are_not_dropped(self):
        for field in ("Conflicts", "Breaks", "Replaces"):
            parsed = probe.control_identity(probe._single(CONTROL + field + ": other\n"))
            self.assertEqual(parsed["relationships"][field], "other")
        for field in ("Essential", "Protected"):
            self.assertTrue(probe.control_identity(probe._single(CONTROL + field + ": yes\n"))["essential"])

    def test_release_dates_need_timezone_and_visible_expiry(self):
        fields = {"codename": "trixie", "date": "Thu, 15 Jan 2026 12:00:00 UTC", "valid-until": "Thu, 22 Jan 2026 12:00:00 UTC"}
        freshness = probe.release_freshness(fields)
        self.assertLess(freshness["date"], freshness["valid_until"])
        for date in (None, "tomorrow", "Thu, 15 Jan 2026 12:00:00"):
            with self.subTest(date=date), self.assertRaises(probe.ProbeError):
                probe.release_freshness(dict(fields, date=date))


class FakeConfig(dict):
    dirs = {"Dir": "/", "Dir::Etc": "/etc/apt/", "Dir::Etc::parts": "/etc/apt/apt.conf.d/",
            "Dir::Etc::sourceparts": "/etc/apt/sources.list.d/", "Dir::Etc::preferencesparts": "/etc/apt/preferences.d/",
            "Dir::Etc::trustedparts": "/etc/apt/trusted.gpg.d/", "Dir::State::lists": "/var/lib/apt/lists/"}
    files = {"Dir::Etc::main": "/etc/apt/apt.conf", "Dir::Etc::sourcelist": "/etc/apt/sources.list",
             "Dir::Etc::preferences": "/etc/apt/preferences", "Dir::Etc::trusted": "/etc/apt/trusted.gpg",
             "Dir::State::status": "/var/lib/dpkg/status"}

    def find(self, key):
        return self.get(key, "")

    def find_dir(self, key):
        return self.get(key, self.dirs.get(key, ""))

    def find_file(self, key):
        return self.get(key, self.files.get(key, ""))

    def set(self, key, value):
        self[key] = value


class ConfigurationTests(unittest.TestCase):
    def test_effective_defaults_and_explicit_safe_checks(self):
        probe.check_effective_config(FakeConfig())
        probe.check_effective_config(FakeConfig({"APT::Get::AllowUnauthenticated": "false", "Acquire::Check-Date": "true",
                                                 "Dir::Bin::dpkg": "/usr/bin/dpkg"}))

    def test_apt3_compiled_defaults_allow_absent_legacy_trusted_keyring(self):
        # APT 3.0.3 init.cc uses absolute list entries for these directories and
        # does not initialize the removed legacy trusted.gpg setting.
        config = FakeConfig({"Dir::Bin::solvers::": "/usr/lib/apt/solvers",
                             "Dir::Bin::planners::": "/usr/lib/apt/planners", "Dir::Etc::trusted": ""})
        probe.check_effective_config(config)

    def test_effective_insecure_and_redirected_configuration(self):
        cases = {"APT::Get::AllowUnauthenticated": "true", "Acquire::AllowInsecureRepositories": "1",
                 "Acquire::AllowWeakRepositories": "yes", "Acquire::AllowDowngradeToInsecureRepositories": "true",
                 "Acquire::Check-Date": "false", "Acquire::Check-Valid-Until": "0", "Acquire::https::Verify-Peer": "false",
                 "Acquire::https::evil.invalid::Verify-Host": "false", "DPkg::Options::": "--force-all",
                 "Dir::Bin::dpkg": "/tmp/dpkg", "APT::Solver": "custom", "Dir::State::status": "/tmp/status",
                 "Dir::Etc::trustedparts": "/tmp/keys", "Dir::Etc::sourcelist": "/tmp/sources", "Dir": "/tmp/"}
        for key, value in cases.items():
            with self.subTest(key=key), self.assertRaises(probe.ProbeError):
                probe.check_effective_config(FakeConfig({key: value}))

    def test_fingerprint_covers_file_bytes_paths_modes_and_keyrings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.write_bytes(b"one")
            config.chmod(0o600)
            # Test the real hasher and filesystem constraints as the invoking
            # user; ownership inspection itself is covered separately below.
            with patch.object(probe, "_safe_info", side_effect=lambda p, **kw: p.lstat()):
                first = probe._fingerprint_tree([root], limit=100)
                config.write_bytes(b"two")
                second = probe._fingerprint_tree([root], limit=100)
                config.rename(root / "keyring.gpg")
                third = probe._fingerprint_tree([root], limit=100)
                self.assertEqual(len({first, second, third}), 3)
                with self.assertRaises(probe.ProbeError):
                    probe._fingerprint_tree([root], limit=1)

    def test_unsafe_owner_writes_links_and_nonregular_files(self):
        for info in (SimpleNamespace(st_mode=0o100644, st_uid=1000, st_nlink=1),
                     SimpleNamespace(st_mode=0o100666, st_uid=0, st_nlink=1),
                     SimpleNamespace(st_mode=0o120600, st_uid=0, st_nlink=1),
                     SimpleNamespace(st_mode=0o100600, st_uid=0, st_nlink=2),
                     SimpleNamespace(st_mode=0o010600, st_uid=0, st_nlink=1)):
            with self.subTest(info=info), patch.object(Path, "lstat", return_value=info), self.assertRaises(probe.ProbeError):
                probe._safe_info(Path("/synthetic"))

    def test_external_include_and_dpkg_forcing_are_rejected(self):
        aptdir = Path("/etc/apt")
        files = {aptdir / "sources.list": SOURCE.encode(), Path(KEY): b"synthetic key",
                 aptdir / "apt.conf": b'#include "/tmp/unfingerprinted.conf";'}
        with patch.object(probe, "_fingerprint_tree", return_value="c" * 64), \
                patch.object(probe, "_resolve_key", side_effect=lambda key: key), \
                patch.object(Path, "exists", lambda p: p in files), \
                patch.object(probe, "_read", side_effect=lambda p, limit: files[p]):
            with self.assertRaisesRegex(probe.ProbeError, "includes"):
                probe._configuration()
            files[aptdir / "apt.conf"] = b"// reviewed local config"
            files[Path("/etc/dpkg/dpkg.cfg")] = b"force-all\n"
            with self.assertRaisesRegex(probe.ProbeError, "dpkg configuration"):
                probe._configuration()
            files[Path("/etc/dpkg/dpkg.cfg")] = b"# normal defaults\nno-debsig\nlog /var/log/dpkg.log\n"
            self.assertEqual(probe._configuration(), ("c" * 64, SOURCES))
            # Cloud images filter documentation payloads; that is not a force option.
            files[Path("/etc/dpkg/dpkg.cfg")] += b"path-exclude=/usr/share/doc/*\npath-include /usr/share/doc/*/copyright\n"
            self.assertEqual(probe._configuration(), ("c" * 64, SOURCES))
            for line in (b"path-exclude=relative\n", b"force-unsafe-io\n", b"admindir=/tmp\n"):
                with self.subTest(line=line), self.assertRaisesRegex(probe.ProbeError, "dpkg configuration"):
                    files[Path("/etc/dpkg/dpkg.cfg")] = line
                    probe._configuration()

    def test_distribution_symlinks_inside_checked_roots_are_fingerprinted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(probe, "_OWNER", os.geteuid()):
            root = Path(directory) / "etc"
            (root / "origins").mkdir(parents=True)
            root.chmod(0o755)
            (root / "origins").chmod(0o755)
            (root / "origins" / "debian").write_bytes(b"Vendor: Debian\n")
            (root / "origins" / "default").symlink_to("debian")
            (root / "keyring.pgp").write_bytes(b"key")
            (root / "keyring.gpg").symlink_to("keyring.pgp")
            (root / "linked-dir").symlink_to("origins")
            first = probe._fingerprint_tree([root], limit=1000)
            (root / "origins" / "default").unlink()
            (root / "origins" / "default").symlink_to("keyring-other")
            (root / "keyring-other").write_bytes(b"x")
            with self.assertRaisesRegex(probe.ProbeError, "inside the checked"):
                probe._fingerprint_tree([root], limit=1000)  # Dangling: origins/keyring-other does not exist.
            (root / "origins" / "default").unlink()
            (root / "origins" / "default").symlink_to("../keyring-other")
            self.assertNotEqual(probe._fingerprint_tree([root], limit=1000), first)
            outside = Path(directory) / "outside"
            outside.write_bytes(b"unchecked")
            (root / "escape").symlink_to(outside)
            with self.assertRaisesRegex(probe.ProbeError, "inside the checked"):
                probe._fingerprint_tree([root], limit=1000)
            (root / "escape").unlink()
            (root / "dangling").symlink_to("missing")
            with self.assertRaisesRegex(probe.ProbeError, "inside the checked"):
                probe._fingerprint_tree([root], limit=1000)
        with tempfile.TemporaryDirectory() as directory, patch.object(probe, "_OWNER", os.geteuid() + 1):
            root = Path(directory)
            root.chmod(0o755)
            (root / "target").write_bytes(b"x")
            (root / "link").symlink_to("target")
            with self.assertRaises(probe.ProbeError):
                probe._safe_link(root / "link", [root])

    def test_signed_by_alias_resolves_only_within_keyring_directories(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(probe, "_OWNER", os.geteuid()):
            keyrings, other = Path(directory) / "keyrings", Path(directory) / "other"
            keyrings.mkdir()
            other.mkdir()
            (keyrings / "archive.pgp").write_bytes(b"key")
            (keyrings / "archive.gpg").symlink_to("archive.pgp")
            (other / "evil.pgp").write_bytes(b"key")
            (keyrings / "evil.gpg").symlink_to(other / "evil.pgp")
            (keyrings / "renamed.gpg").symlink_to("archive.pgp.bak")
            (keyrings / "archive.pgp.bak").write_bytes(b"key")
            with patch.object(probe, "KEYRING_DIRECTORIES", (keyrings,)):
                self.assertEqual(probe._resolve_key(str(keyrings / "archive.gpg")), str(keyrings / "archive.pgp"))
                self.assertEqual(probe._resolve_key(str(keyrings / "archive.pgp")), str(keyrings / "archive.pgp"))
                for name in ("evil.gpg", "renamed.gpg"):
                    with self.subTest(name=name), self.assertRaises(probe.ProbeError):
                        probe._resolve_key(str(keyrings / name))


class ConfigReportTests(unittest.TestCase):
    def test_report_lists_reviewable_inputs_and_signed_origins_without_approval(self):
        config = FakeConfig()
        apt_pkg = SimpleNamespace(init_config=Mock(), config=config,
                                  uri_to_filename=lambda uri: uri.removeprefix("https://").replace("/", "_"))
        sources = [dict(SOURCES[0], components=["main", "contrib"]),
                   {"uri": "https://security.example.invalid/debian-security/", "suite": "trixie-security",
                    "components": ["main"], "key": KEY}]
        fields = {"origin": "Debian", "label": "Debian", "suite": "stable", "codename": "trixie",
                  "date": "Thu, 15 Jan 2026 12:00:00 UTC"}
        def signed(_apt_pkg, source):
            if source["suite"] == "trixie-security":
                raise FileNotFoundError("no local index yet")
            return fields
        with patch.object(probe, "_configuration", return_value=("c" * 64, sources)), \
                patch.object(probe, "_read", return_value=b"public key bytes"), \
                patch.object(probe, "_signed_release", side_effect=signed):
            report = probe._config_report(apt_pkg)
        self.assertEqual(set(report), {"config_digest", "sources", "origins"})
        self.assertEqual(report["config_digest"], "c" * 64)
        self.assertEqual(report["sources"][0]["key_sha256"], probe.hashlib.sha256(b"public key bytes").hexdigest())
        self.assertEqual(report["sources"][0]["release"], {"date": 1_768_478_400, "valid_until": None})
        self.assertIn("missing", report["sources"][1]["release"])
        self.assertEqual(report["origins"], sorted([dict(ORIGIN, component="contrib"), ORIGIN], key=probe._canonical))
        apt_pkg.init_config.assert_called_once()

    def test_report_rejects_unsafe_effective_configuration(self):
        apt_pkg = SimpleNamespace(init_config=Mock(), config=FakeConfig({"Acquire::AllowInsecureRepositories": "1"}))
        with patch.object(probe, "_configuration", return_value=("c" * 64, SOURCES)), self.assertRaises(probe.ProbeError):
            probe._config_report(apt_pkg)


class SignedIndexTests(unittest.TestCase):
    def setUp(self):
        self.filename = "deb.example.invalid_debian_dists_trixie_main_binary-amd64_Packages.lz4"
        self.package_file = SimpleNamespace(filename="/var/lib/apt/lists/" + self.filename, **{k: ORIGIN[k] for k in ("origin", "label", "archive", "component", "site")})
        self.apt_pkg = SimpleNamespace(uri_to_filename=lambda uri: uri.removeprefix("https://").replace("/", "_"))
        self.raw = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\nLabel: Debian\nSuite: stable\nCodename: trixie\n"
                    "Date: Thu, 15 Jan 2026 12:00:00 UTC\nSHA256:\n " + "a" * 64 + " 100 main/binary-amd64/Packages\n"
                    "-----BEGIN PGP SIGNATURE-----\nsynthetic, not a real signature\n-----END PGP SIGNATURE-----\n").encode()

    def test_signature_then_uncompressed_index_hash_and_origin(self):
        with patch.object(probe, "_safe_info"), patch.object(probe, "_read", return_value=self.raw), \
                patch.object(probe, "_command") as command, patch.object(probe, "_index_hash", return_value=("a" * 64, 100)):
            origin, freshness = probe._verified_index(self.apt_pkg, self.package_file, SOURCES)
        self.assertEqual(origin, ORIGIN)
        self.assertEqual(freshness["codename"], "trixie")
        command.assert_called_once()
        home = command.call_args.kwargs["home"]
        self.assertEqual(command.call_args.args[0], ["/usr/bin/gpgv", "--homedir", str(home), "--keyring", KEY,
                                                   "/var/lib/apt/lists/deb.example.invalid_debian_dists_trixie_InRelease"])
        self.assertFalse(home.exists())

    def test_bad_signature_index_hash_size_codename_or_origin(self):
        for change in ("signature", "hash", "size", "codename", "origin", "missing-hash"):
            raw = self.raw
            file = copy.copy(self.package_file)
            if change == "codename":
                raw = raw.replace(b"Codename: trixie", b"Codename: sid")
            if change == "origin":
                file.origin = "Unreviewed"
            if change == "missing-hash":
                raw = raw.replace(b"main/binary-amd64/Packages", b"other/binary-amd64/Packages")
            with self.subTest(change=change), patch.object(probe, "_safe_info"), patch.object(probe, "_read", return_value=raw), \
                    patch.object(probe, "_command", side_effect=probe.ProbeError("bad signature") if change == "signature" else None), \
                    patch.object(probe, "_index_hash", return_value=("b" * 64 if change == "hash" else "a" * 64,
                                                                     101 if change == "size" else 100)), \
                    self.assertRaises(probe.ProbeError):
                probe._verified_index(self.apt_pkg, file, SOURCES)

    def test_release_envelope_duplicate_checksums_and_unmapped_indexes(self):
        cases = [self.raw.replace(b"-----BEGIN PGP SIGNED MESSAGE-----", b"unsigned"),
                 self.raw.replace(b"Codename: trixie", b"Codename: trixie\nCodename: sid"),
                 self.raw.replace(b"-----BEGIN PGP SIGNATURE-----", b" " + b"a" * 64 + b" 100 main/binary-amd64/Packages\n-----BEGIN PGP SIGNATURE-----")]
        for raw in cases:
            with patch.object(probe, "_safe_info"), patch.object(probe, "_read", return_value=raw), \
                    patch.object(probe, "_command"), patch.object(probe, "_index_hash", return_value=("a" * 64, 100)), \
                    self.assertRaises(probe.ProbeError):
                probe._verified_index(self.apt_pkg, self.package_file, SOURCES)
        self.package_file.filename = "/tmp/unapproved_Packages"
        with patch.object(probe, "_safe_info"), self.assertRaises(probe.ProbeError):
            probe._verified_index(self.apt_pkg, self.package_file, SOURCES)

    def test_signature_command_and_index_decompression_are_fixed_and_bounded(self):
        result = SimpleNamespace(returncode=0)
        with patch.object(probe.subprocess, "run", return_value=result) as run:
            probe._command(["/usr/bin/gpgv", "--keyring", KEY, "/fixed/InRelease"], home=Path("/private/home"))
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertEqual(run.call_args.kwargs["stdout"], probe.subprocess.DEVNULL)
        process = Mock()
        process.stdout = io.BytesIO(b"synthetic index")
        process.wait.return_value = 0
        process.poll.return_value = 0
        with patch.object(probe.subprocess, "Popen", return_value=process) as popen:
            checksum, size = probe._index_hash(Path("/synthetic/Packages.lz4"))
        self.assertEqual(size, 15)
        self.assertEqual(len(checksum), 64)
        self.assertEqual(popen.call_args.args[0], ["/usr/lib/apt/apt-helper", "cat-file", "/synthetic/Packages.lz4"])
        process.stdout = io.BytesIO(b"too big")
        with patch.object(probe.subprocess, "Popen", return_value=process), patch.object(probe, "MAX_INDEX", 2), self.assertRaises(probe.ProbeError):
            probe._index_hash(Path("/synthetic/Packages.lz4"))


class KeyConversionTests(unittest.TestCase):
    def setUp(self):
        self.homes = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.read = self.stack.enter_context(patch.object(probe, "_read", return_value=b"synthetic armor"))
        self.run = self.stack.enter_context(patch.object(probe.subprocess, "run", side_effect=self.success))

    def success(self, argv, **kwargs):
        home = Path(kwargs["cwd"])
        self.homes.append(home)
        self.assertEqual(home.stat().st_mode & 0o777, 0o700)
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(home), "GNUPGHOME": str(home)})
        self.assertEqual(kwargs["timeout"], 30)
        for stream in ("stdin", "stdout", "stderr"):
            self.assertEqual(kwargs[stream], probe.subprocess.DEVNULL)
        self.assertTrue(kwargs["close_fds"])
        self.assertFalse(kwargs["check"])
        if argv[0] == "/usr/bin/gpg":
            armored, binary = home / "archive.asc", home / "archive.gpg"
            self.assertEqual(argv, ["/usr/bin/gpg", "--no-options", "--homedir", str(home), "--batch", "--no-tty",
                                   "--no-autostart", "--no-default-keyring", "--no-auto-key-retrieve", "--no-auto-key-import",
                                   "--output", str(binary), "--dearmor", str(armored)])
            self.assertEqual(armored.read_bytes(), b"synthetic armor")
            self.assertEqual(armored.stat().st_mode & 0o777, 0o600)
            self.assertIs(kwargs["preexec_fn"], probe._keyring_output_limit)
            binary.write_bytes(b"synthetic binary key")
        else:
            self.assertEqual(argv[0], "/usr/bin/gpgv")
            self.assertIsNone(kwargs["preexec_fn"])
            self.assertEqual(argv[1:3], ["--homedir", str(home)])
            self.assertEqual(argv[-1], "/fixed/InRelease")
        return SimpleNamespace(returncode=0)

    def assert_cleaned(self):
        self.assertTrue(self.homes)
        self.assertTrue(all(not home.exists() for home in self.homes))

    def test_conversion_is_bounded_isolated_then_verified_and_cleaned(self):
        with patch.dict(os.environ, {"GNUPGHOME": "/untrusted", "HOME": "/untrusted", "LD_PRELOAD": "/untrusted",
                                     "TMPDIR": "/nonexistent", "GPG_AGENT_INFO": "/untrusted"}):
            probe._verify_release(KEY.replace(".gpg", ".asc"), Path("/fixed/InRelease"))
        self.read.assert_called_once_with(Path(KEY.replace(".gpg", ".asc")), 4 * 1024 * 1024)
        self.assertEqual([call.args[0][0] for call in self.run.call_args_list], ["/usr/bin/gpg", "/usr/bin/gpgv"])
        keyring = Path(self.run.call_args_list[1].args[0][-2])
        self.assertEqual(keyring, self.homes[0] / "archive.gpg")
        self.assertEqual(self.homes[0], self.homes[1])
        self.assert_cleaned()

    def test_binary_key_does_not_require_gpg_or_conversion(self):
        def no_gpg(argv, **kwargs):
            if argv[0] == "/usr/bin/gpg":
                raise FileNotFoundError("gpg intentionally unavailable")
            return self.success(argv, **kwargs)
        self.run.side_effect = no_gpg
        probe._verify_release(KEY, Path("/fixed/InRelease"))
        self.read.assert_not_called()
        self.run.assert_called_once()
        self.assertEqual(self.run.call_args.args[0][-2], KEY)
        self.assert_cleaned()

    def test_conversion_error_timeout_missing_gpg_and_interrupt_fail_closed_and_clean_up(self):
        for failure in (SimpleNamespace(returncode=2), FileNotFoundError("missing gpg"),
                        probe.subprocess.TimeoutExpired("gpg", 30), KeyboardInterrupt()):
            def fail(argv, **kwargs):
                self.success(argv, **kwargs)  # leave partial output to clean
                if isinstance(failure, BaseException):
                    raise failure
                return failure
            self.run.reset_mock()
            self.run.side_effect = fail
            with self.subTest(failure=type(failure).__name__), self.assertRaises(
                    KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else probe.ProbeError):
                probe._verify_release(KEY.replace(".gpg", ".asc"), Path("/fixed/InRelease"))
            self.run.assert_called_once()
            self.assert_cleaned()

    def test_signature_failure_after_conversion_still_rejects_and_cleans_up(self):
        def fail(argv, **kwargs):
            result = self.success(argv, **kwargs)
            return SimpleNamespace(returncode=2) if argv[0] == "/usr/bin/gpgv" else result
        self.run.side_effect = fail
        with self.assertRaises(probe.ProbeError):
            probe._verify_release(KEY.replace(".gpg", ".asc"), Path("/fixed/InRelease"))
        self.assertEqual(self.run.call_count, 2)
        self.assert_cleaned()

    def test_empty_oversized_or_missing_conversion_output_cannot_reach_gpgv(self):
        for size in (0, probe.MAX_KEYRING + 1, None):
            def invalid_output(argv, **kwargs):
                result = self.success(argv, **kwargs)
                keyring = Path(kwargs["cwd"]) / "archive.gpg"
                if size is None:
                    keyring.unlink()
                else:
                    with keyring.open("wb") as stream:
                        stream.truncate(size)
                return result
            self.run.reset_mock()
            self.run.side_effect = invalid_output
            with self.subTest(size=size), self.assertRaises((probe.ProbeError, OSError)):
                probe._verify_release(KEY.replace(".gpg", ".asc"), Path("/fixed/InRelease"))
            self.run.assert_called_once()
            self.assert_cleaned()

    def test_oversized_armored_input_is_rejected_before_conversion(self):
        # Use the actual bounded reader, only substituting ownership for this
        # unprivileged temporary fixture. No native process is invoked.
        self.stack.close()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.asc"
            with path.open("wb") as stream:
                stream.truncate(probe.MAX_KEYRING + 1)
            with patch.object(probe, "_safe_info", side_effect=lambda p: p.lstat()), \
                    patch.object(probe.subprocess, "run") as run, self.assertRaisesRegex(probe.ProbeError, "size limit"):
                probe._verify_release(str(path), Path("/fixed/InRelease"))
            run.assert_not_called()

    def test_conversion_output_rlimit_is_child_only_and_respects_lower_inherited_hard_limit(self):
        for inherited, expected in ((probe.resource.RLIM_INFINITY, probe.MAX_KEYRING), (1024, 1024)):
            with self.subTest(hard=inherited), patch.object(probe.resource, "getrlimit", return_value=(inherited, inherited)), \
                    patch.object(probe.resource, "setrlimit") as limit:
                probe._keyring_output_limit()
                limit.assert_called_once_with(probe.resource.RLIMIT_FSIZE, (expected, expected))


class RealSignatureTests(unittest.TestCase):
    """Exercise gpgv with fixtures, not the host's APT files or signing keys."""

    def setUp(self):
        SignedIndexTests.setUp(self)

    @unittest.skipUnless(os.access("/usr/bin/gpg", os.X_OK) and os.access("/usr/bin/gpgv", os.X_OK),
                         "synthetic signature verification requires /usr/bin/gpg and /usr/bin/gpgv")
    def test_real_binary_and_armored_keys_verify_the_same_signed_release(self):
        fixtures = Path(__file__).resolve().parent / "fixtures" / "apt-probe"
        raw = (fixtures / "InRelease").read_bytes()
        armored = (fixtures / "archive-public.asc").read_bytes()
        # Decode the public fixture without invoking gpg so the binary case is
        # independent of the conversion implementation under test.
        body = armored.split(b"\n\n", 1)[1].split(b"\n=", 1)[0]
        binary = base64.b64decode(body)
        command = probe._command
        def local_command(argv, **kwargs):
            if argv[0] == "/usr/bin/gpgv":
                argv = [*argv[:-1], str(fixtures / "InRelease")]
            return command(argv, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            keys = [Path(directory) / "archive.gpg", Path(directory) / "archive.asc"]
            keys[0].write_bytes(binary)
            keys[1].write_bytes(armored)
            for key in keys:
                with self.subTest(suffix=key.suffix), patch.object(probe, "_safe_info"), \
                        patch.object(probe, "_read", side_effect=lambda p, limit: raw if p.name.endswith("InRelease") else p.read_bytes()), \
                        patch.object(probe, "_command", side_effect=local_command), \
                        patch.object(probe, "_index_hash", return_value=("a" * 64, 100)):
                    origin, freshness = probe._verified_index(self.apt_pkg, self.package_file, [dict(SOURCES[0], key=str(key))])
                self.assertEqual(origin, ORIGIN)
                self.assertEqual(freshness["date"], 1_768_478_400)


    @unittest.skipUnless(os.access("/usr/bin/gpg", os.X_OK) and os.access("/usr/bin/gpgv", os.X_OK),
                         "synthetic signature verification requires /usr/bin/gpg and /usr/bin/gpgv")
    def test_real_bad_armor_signature_and_unrelated_key_never_fall_back_to_user_trust(self):
        fixtures = Path(__file__).resolve().parent / "fixtures" / "apt-probe"
        armored = (fixtures / "archive-public.asc").read_bytes()
        binary = base64.b64decode(armored.split(b"\n\n", 1)[1].split(b"\n=", 1)[0])
        signed = (fixtures / "InRelease").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inherited = root / "user-home"
            inherited.mkdir(mode=0o700)
            (inherited / "gpg.conf").write_text("invalid-user-config-option\n")
            (inherited / "trustedkeys.gpg").write_bytes(binary)
            for case in ("armor", "signature", "key"):
                key = root / ("archive.gpg" if case == "key" else "archive.asc")
                key.write_bytes(b"not a key" if case in ("armor", "key") else armored)
                release = root / "InRelease"
                release.write_bytes(signed.replace(b"Label: Debian", b"Label: Forged") if case == "signature" else signed)
                with self.subTest(case=case), patch.dict(os.environ, {"HOME": str(inherited), "GNUPGHOME": str(inherited)}), \
                        patch.object(probe, "_safe_info", side_effect=lambda p: p.lstat()), self.assertRaises(probe.ProbeError):
                    probe._verify_release(str(key), release)
            self.assertEqual(sorted(p.name for p in inherited.iterdir()), ["gpg.conf", "trustedkeys.gpg"])


class ResolveProbeTests(unittest.TestCase):
    def setUp(self):
        self.files = [SimpleNamespace(filename="/synthetic/Packages")]
        self.candidate = SimpleNamespace(version="1:2.0-1+b1", architecture="amd64", _cand=SimpleNamespace(file_list=[(self.files[0], 1)]))
        installed = SimpleNamespace(version="1:1.0-1", architecture="amd64", source_name="widget-src")
        self.package = SimpleNamespace(candidate=self.candidate, installed=installed, essential=False,
                                       is_now_broken=False, is_inst_broken=False, versions=[self.candidate])
        self.cache = Mock()
        self.cache.broken_count = 0
        self.cache.__getitem__ = Mock(return_value=self.package)
        self.records = SimpleNamespace(lookup=Mock(return_value=True), record=RECORD)
        self.source_list = SimpleNamespace(read_main_list=Mock(), find_index=Mock(return_value=SimpleNamespace(is_trusted=True)))
        self.apt = SimpleNamespace(Cache=Mock(return_value=self.cache))
        self.apt_pkg = SimpleNamespace(init_config=Mock(), init_system=Mock(), config=FakeConfig(),
                                       PackageRecords=Mock(return_value=self.records), SourceList=Mock(return_value=self.source_list))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.config = self.stack.enter_context(patch.object(probe, "_configuration", return_value=("c" * 64, SOURCES)))
        self.metadata = self.stack.enter_context(patch.object(probe, "_metadata_digest", return_value="d" * 64))
        self.verify = self.stack.enter_context(patch.object(probe, "_verified_index", return_value=(ORIGIN, RELEASE)))

    def resolve(self):
        return probe._resolve(self.apt, self.apt_pkg, "widget", "amd64")[0]

    def test_resolve_complete_target_uses_apt_policy_not_highest_version(self):
        result = self.resolve()
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["target"], {"name": "widget", "architecture": "amd64", "from_version": "1:1.0-1",
                                           "to_version": "1:2.0-1+b1", "source_name": "widget-src", "source_version": "1:2.0-1",
                                           "sha256": "a" * 64, "size": 123, "origins": [ORIGIN],
                                           "config_digest": "c" * 64, "metadata_digest": "d" * 64})
        self.assertEqual(self.apt_pkg.config["Dir::Cache::pkgcache"], "")
        self.assertIs(probe._resolve(self.apt, self.apt_pkg, "widget", "amd64")[2], self.cache)
        self.assertEqual(self.apt_pkg.config["Dir::Cache::srcpkgcache"], "")
        self.cache.__getitem__.assert_called_with("widget:amd64")
        newer = SimpleNamespace(version="9.0", architecture="amd64", _cand=SimpleNamespace(file_list=[]))
        self.package.versions.append(newer)
        self.assertEqual(self.resolve()["target"]["to_version"], "1:2.0-1+b1")

    def test_reject_untrusted_missing_candidate_essential_broken_and_wrong_source(self):
        for attribute in ("essential", "is_now_broken", "is_inst_broken"):
            setattr(self.package, attribute, True)
            with self.subTest(attribute=attribute), self.assertRaises(probe.ProbeError):
                self.resolve()
            setattr(self.package, attribute, False)
        self.source_list.find_index.return_value.is_trusted = False
        with self.assertRaises(probe.ProbeError):
            self.resolve()
        self.source_list.find_index.return_value.is_trusted = True
        self.package.installed.source_name = "different"
        with self.assertRaises(probe.ProbeError):
            self.resolve()
        self.package.candidate = None
        with self.assertRaises(probe.ProbeError):
            self.resolve()

    def test_reject_candidate_relationships_missing_hash_size_and_filename(self):
        for record in (RECORD + "Conflicts: other\n", RECORD + "Breaks: other\n", RECORD + "Replaces: other\n",
                       RECORD + "Protected: yes\n", RECORD.replace("SHA256:", "SHA1:"), RECORD.replace("Size: 123", "Size: 999999999"),
                       RECORD.replace("pool/main/w/widget/widget_2.0-1+b1_amd64.deb", "../../tmp/evil.deb")):
            self.records.record = record
            with self.subTest(record=record), self.assertRaises(probe.ProbeError):
                self.resolve()

    def test_same_version_ambiguity_across_indexes(self):
        self.candidate._cand.file_list.append((self.files[0], 2))
        def lookup(position):
            self.records.record = RECORD if position[1] == 1 else RECORD.replace("a" * 64, "b" * 64)
            return True
        self.records.lookup.side_effect = lookup
        with self.assertRaisesRegex(probe.ProbeError, "ambiguous"):
            self.resolve()
        self.records.lookup.side_effect = None
        self.records.record = RECORD
        self.assertEqual(self.resolve()["target"]["sha256"], "a" * 64)

    def test_same_origin_retains_distinct_release_constraints_in_any_order(self):
        # Identical candidate bytes/identities from different paths on one
        # hostname must not let a fresh Release hide another constraint.
        for change in ({"date": RELEASE["date"] - 1_000_000},
                       {"date": RELEASE["date"] + 1_000_000},
                       {"valid_until": RELEASE["date"] - 1},
                       {"valid_until": RELEASE["date"] + 10_000}):
            different = dict(RELEASE, **change)
            for constraints in ([different, RELEASE], [RELEASE, different]):
                with self.subTest(change=change, first=constraints[0]):
                    self.candidate._cand.file_list = [(SimpleNamespace(filename=f"/synthetic/path-{i}/Packages"), i)
                                                      for i in range(2)]
                    self.verify.side_effect = [(ORIGIN, value) for value in constraints]
                    result = self.resolve()
                    expected = [dict(value, origin=ORIGIN) for value in constraints]
                    self.assertEqual(result["target"]["origins"], [ORIGIN])
                    self.assertEqual(result["releases"], sorted(expected, key=probe._canonical))

    def test_release_constraints_cover_origins_and_only_exact_duplicates_deduplicate(self):
        other = dict(ORIGIN, site="mirror.example.invalid")
        constraints = [(ORIGIN, RELEASE), (other, RELEASE), (ORIGIN, dict(RELEASE))]
        results = []
        for ordering in (constraints, list(reversed(constraints))):
            self.candidate._cand.file_list = [(self.files[0], i) for i in range(len(ordering))]
            self.verify.side_effect = ordering
            results.append(self.resolve())
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]["target"]["origins"], sorted([ORIGIN, other], key=probe._canonical))
        self.assertEqual(results[0]["releases"], sorted([dict(RELEASE, origin=o) for o in (ORIGIN, other)], key=probe._canonical))

    def test_release_constraint_bound_rejects_overflow_without_truncation(self):
        for count in (1024, 1025):
            self.candidate._cand.file_list = [(self.files[0], i) for i in range(count)]
            self.verify.side_effect = [(ORIGIN, dict(RELEASE, date=RELEASE["date"] + i)) for i in range(count)]
            if count == 1024:
                self.assertEqual(len(self.resolve()["releases"]), count)
            else:
                with self.assertRaisesRegex(probe.ProbeError, "release.*limit"):
                    self.resolve()
        # Repeated identical constraints do not consume the distinct bound.
        self.verify.side_effect = None
        self.assertEqual(self.resolve()["releases"], [dict(RELEASE, origin=ORIGIN)])

    def test_configuration_or_metadata_drift_rejects_resolution(self):
        self.config.side_effect = [("c" * 64, SOURCES), ("e" * 64, SOURCES)]
        with self.assertRaisesRegex(probe.ProbeError, "changed"):
            self.resolve()
        self.config.side_effect = None
        self.metadata.side_effect = ["d" * 64, "e" * 64]
        with self.assertRaisesRegex(probe.ProbeError, "changed"):
            self.resolve()


class DownloadAndArtifactTests(unittest.TestCase):
    def test_download_pins_fingerprints_disallows_unauthenticated_and_sets_file_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory)
            target = {"to_version": "2.0", "sha256": "a" * 64, "size": 123, "config_digest": "c" * 64, "metadata_digest": "d" * 64}
            candidate = Mock()
            def fetch(destination, *, progress, allow_unauthenticated):
                self.assertFalse(allow_unauthenticated)
                progress.current_bytes = 123
                self.assertTrue(progress.pulse(None))
                progress.current_bytes = 124
                self.assertFalse(progress.pulse(None))
                path = Path(destination) / "synthetic.deb"
                path.write_bytes(b"fake deb")
                return str(path)
            candidate.fetch_binary.side_effect = fetch
            args = ["widget", "amd64", "2.0", "a" * 64, "123", "c" * 64, "d" * 64, str(staging)]
            with patch.object(probe, "_resolve", return_value=({"target": target}, candidate, object())), \
                    patch.object(probe, "_safe_info", side_effect=lambda p, **kw: p.lstat()), \
                    patch.object(probe.resource, "setrlimit") as limit, \
                    patch.dict(sys.modules, {"apt.progress.base": SimpleNamespace(AcquireProgress=object)}):
                self.assertEqual(probe._download(None, None, args), {"downloaded": True})
            limit.assert_called_once_with(probe.resource.RLIMIT_FSIZE, (123, 123))
            self.assertEqual((staging / "package.deb").stat().st_mode & 0o777, 0o600)

    def test_download_refuses_changed_fingerprints_before_fetch(self):
        target = {"to_version": "2.0", "sha256": "a" * 64, "size": 123, "config_digest": "c" * 64, "metadata_digest": "d" * 64}
        candidate = Mock()
        with patch.object(probe, "_resolve", return_value=({"target": target}, candidate, object())), self.assertRaises(probe.ProbeError):
            probe._download(None, None, ["widget", "amd64", "2.0", "a" * 64, "123", "e" * 64, "d" * 64, "/unused"])
        candidate.fetch_binary.assert_not_called()

    def test_artifact_reads_only_bounded_control_without_payload_extraction(self):
        control = Mock()
        member = SimpleNamespace(name="./control", size=len(CONTROL), isfile=lambda: True)
        control.go.side_effect = lambda callback, *, extract_data: callback(member, None)
        control.extractdata.return_value = CONTROL.encode()
        apt_inst = SimpleNamespace(DebFile=Mock(return_value=SimpleNamespace(control=control)))
        result = probe._artifact(apt_inst, "/private/package.deb")
        self.assertEqual(result["source_version"], "1:2.0-1")
        self.assertEqual(control.go.call_args.kwargs, {"extract_data": False})
        control.extractall.assert_not_called()
        member.size = probe.MAX_CONTROL + 1
        with self.assertRaises(probe.ProbeError):
            probe._artifact(apt_inst, "/private/package.deb")

    def test_duplicate_or_link_control_member_rejected(self):
        member = SimpleNamespace(name="control", size=10, isfile=lambda: True)
        control = Mock()
        def duplicate(callback, *, extract_data):
            callback(member, None)
            callback(member, None)
        control.go.side_effect = duplicate
        apt_inst = SimpleNamespace(DebFile=Mock(return_value=SimpleNamespace(control=control)))
        with self.assertRaises(probe.ProbeError):
            probe._artifact(apt_inst, "/private/package.deb")
        member.isfile = lambda: False
        with self.assertRaises(probe.ProbeError):
            probe._artifact(apt_inst, "/private/package.deb")
        control.extractdata.assert_not_called()

    def test_missing_native_binding_is_bounded_failure_not_import_failure(self):
        output = io.StringIO()
        with patch.dict(sys.modules, {"apt": None, "apt_pkg": None, "apt_inst": None}), patch.object(sys, "stderr", output):
            self.assertEqual(probe.main(["resolve", "widget", "amd64"]), 1)
        self.assertIn("APT prerequisite", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())


if __name__ == "__main__":
    unittest.main()
