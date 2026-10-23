"""Local-file boundary tests use private temporary files, never host state."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from autoprotect.core import ValidationError
from autoprotect.local_files import prepare_database, read_bytes, require_trusted_code


class LocalFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, name="policy.json", body=b"{}", mode=0o600):
        path = self.root / name
        path.write_bytes(body)
        path.chmod(mode)
        return path

    def test_regular_import_and_exact_limit(self):
        path = self.file(body=b"1234", mode=0o644)
        self.assertEqual(read_bytes(path, max_bytes=4), b"1234")
        with self.assertRaises(ValidationError):
            read_bytes(path, max_bytes=3)
        self.assertEqual(read_bytes(self.file("empty", b""), max_bytes=1), b"")

    def test_limit_argument_is_strict(self):
        path = self.file()
        self.assertEqual(read_bytes(path, max_bytes=512 * 1024 * 1024), b"{}")
        for cap in (0, -1, True, 1.5, 512 * 1024 * 1024 + 1):
            with self.subTest(cap=cap), self.assertRaises(ValidationError):
                read_bytes(path, max_bytes=cap)

    def test_private_policy_requires_private_mode_without_repair(self):
        for mode in (0o644, 0o620, 0o601):
            path = self.file(mode=mode)
            with self.subTest(mode=mode), self.assertRaises(ValidationError):
                read_bytes(path, max_bytes=100, private=True)
            self.assertEqual(path.stat().st_mode & 0o777, mode)
        self.assertEqual(read_bytes(self.file(), max_bytes=100, private=True), b"{}")

    def test_symlink_leaf_and_directory_are_rejected(self):
        path = self.file()
        leaf = self.root / "alias"
        leaf.symlink_to(path)
        parent = self.root / "linked"
        parent.symlink_to(self.root, target_is_directory=True)
        for candidate in (leaf, parent / path.name):
            with self.subTest(candidate=candidate), self.assertRaises(ValidationError):
                read_bytes(candidate, max_bytes=100)

    def test_hardlink_fifo_and_directory_are_rejected_without_blocking(self):
        path = self.file()
        link = self.root / "link"
        os.link(path, link)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for candidate in (path, link, fifo, self.root):
            with self.subTest(candidate=candidate), self.assertRaises(ValidationError):
                read_bytes(candidate, max_bytes=100)

    def test_unprotected_parent_disallows_policy_but_import_is_data(self):
        public = self.root / "public"
        public.mkdir(mode=0o777)
        public.chmod(0o777)
        path = public / "policy"
        path.write_bytes(b"{}")
        path.chmod(0o600)
        self.assertEqual(read_bytes(path, max_bytes=100), b"{}")
        with self.assertRaises(ValidationError):
            read_bytes(path, max_bytes=100, private=True)

    def test_missing_and_malformed_paths_use_bounded_errors(self):
        for value in (self.root / "missing-secret", "a\0secret", "", self.root / ".." / "no-such-autoprotect-file"):
            with self.subTest(value=value), self.assertRaises(ValidationError) as caught:
                read_bytes(value, max_bytes=100)
            self.assertNotIn("secret", str(caught.exception))

    def test_live_requires_root_before_access(self):
        path = self.file()
        with patch("autoprotect.local_files.os.geteuid", return_value=12345):
            with self.assertRaisesRegex(ValidationError, "root"):
                read_bytes(path, max_bytes=100, live=True)
            with self.assertRaisesRegex(ValidationError, "root"):
                prepare_database(self.root / "state", live=True)
        self.assertFalse((self.root / "state").exists())

    def test_database_creation_is_private_idempotent_and_preserves_bytes(self):
        directory = self.root / "state"
        database = prepare_database(directory)
        self.assertEqual(database, directory / "state.sqlite3")
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(database.stat().st_mode & 0o777, 0o600)
        database.write_bytes(b"private saved data")
        self.assertEqual(prepare_database(directory), database)
        self.assertEqual(database.read_bytes(), b"private saved data")

    def test_database_creation_requires_existing_parent(self):
        with self.assertRaises(ValidationError):
            prepare_database(self.root / "missing" / "state")
        self.assertFalse((self.root / "missing").exists())

    def test_existing_state_directory_mode_is_not_silently_repaired(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValidationError):
            prepare_database(self.root)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)
        self.assertFalse((self.root / "state.sqlite3").exists())

    def test_database_and_sidecars_reject_unsafe_existing_files(self):
        for suffix in ("", "-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                directory = self.root / ("state" + suffix)
                directory.mkdir(mode=0o700)
                entry = directory / ("state.sqlite3" + suffix)
                target = self.file("outside" + suffix)
                entry.symlink_to(target)
                with self.assertRaises(ValidationError):
                    prepare_database(directory)
                self.assertTrue(entry.is_symlink())
                self.assertEqual(target.read_bytes(), b"{}")
                entry.unlink()
                entry.write_bytes(b"existing")
                entry.chmod(0o644)
                with self.assertRaises(ValidationError):
                    prepare_database(directory)
                self.assertEqual(entry.read_bytes(), b"existing")

    def test_database_sidecars_with_private_regular_files_are_allowed(self):
        database = prepare_database(self.root)
        for suffix in ("-wal", "-shm", "-journal"):
            path = Path(str(database) + suffix)
            path.touch(mode=0o600)
        self.assertEqual(prepare_database(self.root), database)

    def test_changed_file_during_read_is_rejected(self):
        path = self.file(body=b"initial")
        original = os.read
        changed = False

        def changing(fd, count):
            nonlocal changed
            data = original(fd, count)
            if not changed:
                changed = True
                path.write_bytes(b"replacement")
            return data

        with patch("autoprotect.local_files.os.read", side_effect=changing):
            with self.assertRaisesRegex(ValidationError, "changed"):
                read_bytes(path, max_bytes=100, private=True)

    def test_parent_components_cannot_cancel_invalid_ancestors(self):
        self.file("policy", b"root policy")
        other = self.root / "other"
        (other / "child").mkdir(parents=True)
        (other / "policy").write_bytes(b"other policy")
        link = self.root / "link"
        link.symlink_to(other / "child", target_is_directory=True)
        ordinary = self.file("ordinary")
        public = self.root / "public"
        public.mkdir()
        public.chmod(0o777)
        for ancestor in (link, self.root / "missing", ordinary, public):
            with self.subTest(ancestor=ancestor):
                with self.assertRaises(ValidationError):
                    read_bytes(ancestor / ".." / "policy", max_bytes=100, private=True)
                with self.assertRaises(ValidationError):
                    prepare_database(ancestor / ".." / "state")
                self.assertFalse((self.root / "state").exists())

    def test_parent_traversal_through_valid_directories_still_works(self):
        child = self.root / "child"
        child.mkdir(mode=0o700)
        self.file("policy", b"valid")
        self.assertEqual(read_bytes(child / ".." / "policy", max_bytes=100, private=True), b"valid")
        self.assertEqual(prepare_database(child / ".." / "state"), self.root / "state" / "state.sqlite3")

    def test_relative_paths_are_returned_absolute_without_resolving_symlinks(self):
        directory = self.root / "state"
        relative = os.path.relpath(directory)
        self.assertEqual(prepare_database(relative), directory / "state.sqlite3")


class TrustedCodeTests(unittest.TestCase):
    """Uses the invoking user as the trusted owner; live mode requires root."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.package = self.root / "site" / "autoprotect"
        (self.package / "__pycache__").mkdir(parents=True)
        for path in (self.root / "site", self.package, self.package / "__pycache__"):
            path.chmod(0o755)
        for name in ("cli.py", "_apt_probe.py", "__pycache__/cli.cpython-313.pyc"):
            (self.package / name).write_bytes(b"# code")
            (self.package / name).chmod(0o644)
        self.owner = os.geteuid()

    def check(self, search_path=(), owner=None):
        require_trusted_code(self.package, [str(self.root / "site"), *search_path],
                             owner=self.owner if owner is None else owner)

    def test_owner_controlled_package_and_search_path_are_accepted(self):
        archive = self.root / "python313.zip"
        archive.write_bytes(b"zip")
        archive.chmod(0o644)
        self.check([str(archive), str(self.root / "missing"), str(self.root / "missing" / "deeper")])

    def test_missing_entry_under_a_writable_parent_is_rejected(self):
        writable = self.root / "shared"
        writable.mkdir()
        writable.chmod(0o777)
        # Another user could create this directory after the check.
        with self.assertRaises(ValidationError):
            self.check([str(writable / "created_later")])

    def test_writable_or_linked_code_and_untrusted_owners_are_rejected(self):
        cases = [
            lambda: (self.package / "_apt_probe.py").chmod(0o666),
            lambda: (self.package / "__pycache__" / "cli.cpython-313.pyc").chmod(0o664),
            lambda: (self.package / "__pycache__").chmod(0o777),
            lambda: self.package.chmod(0o775),
            lambda: (self.package / "extra.py").symlink_to(self.root / "elsewhere.py"),
        ]
        for mutate in cases:
            with self.subTest(case=cases.index(mutate)):
                self.setUp()
                mutate()
                with self.assertRaises(ValidationError):
                    self.check()
        self.setUp()
        with self.assertRaises(ValidationError):
            self.check(owner=self.owner + 1)  # This tree is not owned by that user.
        writable = self.root / "writable-site"
        writable.mkdir()
        writable.chmod(0o777)
        with self.assertRaises(ValidationError):
            self.check([str(writable)])
        (self.root / "linked-site").symlink_to(self.root / "site")
        with self.assertRaises(ValidationError):
            self.check([str(self.root / "linked-site")])
        with patch("autoprotect.local_files.os.getcwd", return_value=str(writable)), self.assertRaises(ValidationError):
            self.check([""])


if __name__ == "__main__":
    unittest.main()
