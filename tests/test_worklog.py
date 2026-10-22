"""Worklog integration tests. All Git writes happen in temporary repositories."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "worklog.py"
spec = importlib.util.spec_from_file_location("worklog", SCRIPT)
worklog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worklog)


class WorklogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="worklog-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("GIT_", "WORKLOG_"))
        }
        self.env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(self.root / "no-hooks"),
            "GIT_CONFIG_KEY_1": "commit.gpgSign",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_AUTHOR_NAME": "Test Worker",
            "GIT_AUTHOR_EMAIL": "worklog@example.invalid",
            "GIT_COMMITTER_NAME": "Test Worker",
            "GIT_COMMITTER_EMAIL": "worklog@example.invalid",
        })
        self.git("init", "--initial-branch=main")
        (self.root / ".gitignore").write_text("/WORKLOG.md\n/.WORKLOG.md.*.tmp\n", encoding="utf-8")

    def git(self, *args, input=None, ok=True):
        result = subprocess.run(
            ["git", *args], cwd=self.root, env=self.env, input=input,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result

    def cli(self, *args, ok=True, env=None, explicit_root=True):
        command = [sys.executable, str(SCRIPT)]
        if explicit_root:
            command += ["--root", str(self.root)]
        command += list(args)
        result = subprocess.run(
            command, cwd=self.root, env=self.env if env is None else env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def create(self, title="Implement worklog", worker="agent-one", status="completed"):
        result = self.cli("new", "--worker", worker, "--title", title, "--status", status)
        return self.root / result.stdout.strip()

    def complete(self, path):
        text = path.read_text(encoding="utf-8")
        text = text.replace("<required>", "Recorded concrete work and test results.")
        text = text.replace("<next-or-none>", "None.")
        path.write_text(text, encoding="utf-8")
        return text

    def stage(self, path):
        self.git("add", "--", str(path.relative_to(self.root)))

    def committed_entry(self):
        path = self.create()
        text = self.complete(path)
        self.stage(path)
        self.git("commit", "-m", "test: record first worklog entry")
        return path, text

    def test_unborn_check_render_and_completed_template(self):
        self.assertIn("0 valid indexed entries", self.cli("check").stdout)
        self.cli("render")
        self.assertIn("No committed worklog entries", (self.root / "WORKLOG.md").read_text())
        self.git("check-ignore", "WORKLOG.md")
        path = self.create(title="First commit: useful outcome")
        text = path.read_text()
        self.assertIn("base_commit: unborn\n", text)
        self.assertIn("branch: main\n", text)
        self.assertIn("title: First commit: useful outcome\n", text)
        self.assertRegex(text, r"timestamp: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
        self.assertIn("<required>", text)
        self.stage(path)
        self.assertIn("placeholders", self.cli("check", ok=False).stderr)
        self.complete(path)
        self.stage(path)
        self.assertIn("1 valid indexed entries", self.cli("check").stdout)
        self.git("commit", "-m", "test: first entry on unborn main")
        self.cli("check")
        self.cli("render")
        self.assertIn("First commit: useful outcome", (self.root / "WORKLOG.md").read_text())

    def test_base_commit_branch_environment_and_explicit_root(self):
        self.committed_entry()
        head = self.git("rev-parse", "HEAD").stdout.decode().strip()
        env = dict(self.env, WORKLOG_ROOT=str(self.root), WORKLOG_WORKER="environment-worker")
        result = self.cli("new", "--title", "Environment selection", env=env, explicit_root=False)
        text = (self.root / result.stdout.strip()).read_text()
        self.assertIn(f"base_commit: {head}\n", text)
        self.assertIn("worker: environment-worker\n", text)
        env["WORKLOG_ROOT"] = str(self.root / "does-not-exist")
        self.cli("check", env=env)  # Explicit --root takes precedence.
        self.git("checkout", "--detach", "HEAD")
        path = self.create(title="Detached context")
        self.assertIn(f"branch: detached-{head}\n", path.read_text())
        self.complete(path)
        self.stage(path)
        self.cli("check")

    def test_untracked_drafts_are_ignored(self):
        self.committed_entry()
        draft = self.create(title="Other worker draft", worker="agent-two")
        (draft.parent / "not-even-an-entry.txt").write_bytes(b"\xffinvalid draft")
        (draft.parent / "draft-link.md").symlink_to(draft)
        self.assertIn("1 valid indexed entries", self.cli("check").stdout)
        self.cli("render")
        self.assertNotIn("Other worker draft", (self.root / "WORKLOG.md").read_text())

    def test_actual_staged_bytes_are_validated_in_unborn_repo(self):
        path = self.create()
        self.stage(path)  # Stage the unfinished template.
        self.complete(path)  # A valid working copy must not hide the bad index.
        self.assertIn("placeholders", self.cli("check", ok=False).stderr)
        self.stage(path)
        self.cli("check")
        text = path.read_text()
        path.write_text(text.replace("None.", "<next-or-none>"))
        self.assertIn("differs from staged", self.cli("check", ok=False).stderr)
        path.unlink()
        self.cli("check", ok=False)

    def test_malformed_staged_entries_and_metadata_mismatches(self):
        path = self.create()
        good = self.complete(path)
        changes = {
            "opening delimiter": good.replace("---", "bad", 1),
            "missing field": good.replace("worker: agent-one\n", ""),
            "duplicate field": good.replace("worker: agent-one\n", "worker: agent-one\nworker: agent-two\n"),
            "unknown field": good.replace("worker: agent-one\n", "worker: agent-one\nunknown: value\n"),
            "worker mismatch": good.replace("worker: agent-one", "worker: other-worker"),
            "timestamp mismatch": good.replace("timestamp: 20", "timestamp: 19", 1),
            "bad timestamp": good.replace("timestamp: ", "timestamp: not-a-date", 1),
            "base hash": good.replace("base_commit: unborn", "base_commit: abcdef"),
            "status": good.replace("status: completed", "status: pending"),
            "title metadata mismatch": good.replace("title: Implement worklog", "title: Other title"),
            "body title mismatch": good.replace("# Implement worklog", "# Other title"),
            "missing section": good.replace("## Changes", "### Changes"),
            "duplicate section": good + "\n## Summary\nExtra summary.\n",
            "reordered sections": good.replace("## Summary", "## Changes", 1),
            "empty section": good.replace("## Next\n\nNone.", "## Next\n\n- "),
            "inline placeholder": good.replace("None.", "Next step: <required>"),
            "conflict marker": good.replace("None.", "<<<<<<< HEAD\nconflict\n=======\nother\n>>>>>>> topic"),
        }
        for label, bad in changes.items():
            with self.subTest(label=label):
                path.write_text(bad, encoding="utf-8")
                self.stage(path)
                path.write_text(good, encoding="utf-8")
                self.cli("check", ok=False)
        path.write_bytes(b"\xffinvalid UTF-8")
        self.stage(path)
        path.write_text(good)
        self.cli("check", ok=False)
        self.stage(path)
        self.cli("check")
        renamed = path.with_name("invalid-name.md")
        path.rename(renamed)
        self.git("add", "-A", "--", "worklog/entries")
        self.assertIn("filename", self.cli("check", ok=False).stderr)

    def test_committed_index_edit_rejected_even_when_working_copy_restored(self):
        path, original = self.committed_entry()
        path.write_text(original.replace("None.", "Changed follow-up."))
        self.stage(path)
        path.write_text(original)
        self.assertIn("immutable; index modification or deletion", self.cli("check", ok=False).stderr)

    def test_committed_index_deletion_rejected_with_intact_working_copy(self):
        path, _ = self.committed_entry()
        self.git("rm", "--cached", "--", str(path.relative_to(self.root)))
        self.assertTrue(path.is_file())
        self.assertIn("immutable; index modification or deletion", self.cli("check", ok=False).stderr)

    def test_committed_working_copy_edits_deletion_and_mode_rejected(self):
        path, original = self.committed_entry()
        self.git("update-index", "--assume-unchanged", str(path.relative_to(self.root)))
        path.write_text(original.replace("None.", "Unstaged edit."))
        self.assertIn("immutable; working-copy modification", self.cli("check", ok=False).stderr)
        path.write_text(original)
        path.chmod(0o755)
        self.assertIn("executable", self.cli("check", ok=False).stderr)
        path.chmod(0o644)
        self.cli("check")
        path.unlink()
        self.cli("check", ok=False)

    def test_committed_rename_is_rejected(self):
        path, _ = self.committed_entry()
        self.git("mv", str(path.relative_to(self.root)), str(path.relative_to(self.root)) + ".renamed")
        self.assertIn("immutable", self.cli("check", ok=False).stderr)

    def test_symlinks_in_index_and_working_copy_are_rejected(self):
        path = self.create()
        text = self.complete(path)
        target = self.root / "target.md"
        target.write_text(text)
        path.unlink()
        path.symlink_to(target)
        self.stage(path)
        path.unlink()
        path.write_text(text)
        self.assertIn("symlink", self.cli("check", ok=False).stderr)
        self.stage(path)
        self.git("commit", "-m", "test: normal entry")
        path.unlink()
        path.symlink_to(target)
        self.assertIn("symlink", self.cli("check", ok=False).stderr)

    def test_symlink_entry_directory_is_rejected_without_external_writes(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "worklog").symlink_to(outside, target_is_directory=True)
        self.assertIn("symlink", self.cli("new", "--title", "Unsafe directory", ok=False).stderr)
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlink_parent_of_committed_entry_is_rejected(self):
        path, _ = self.committed_entry()
        directory = path.parent
        moved = self.root / "moved-entries"
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        self.assertIn("symlink", self.cli("check", ok=False).stderr)

    def test_render_uses_head_bytes_not_dirty_staged_or_untracked_entries(self):
        path, original = self.committed_entry()
        self.cli("render")
        output = self.root / "WORKLOG.md"
        expected = output.read_bytes()
        path.write_text(original.replace("None.", "STAGED CONTENT MUST NOT RENDER"))
        self.stage(path)
        path.write_text("DIRTY INVALID CONTENT MUST NOT RENDER")
        added = self.create(title="Staged addition must not render")
        self.complete(added)
        self.stage(added)
        self.create(title="Untracked draft must not render")
        self.cli("render")
        self.assertEqual(output.read_bytes(), expected)
        path.unlink()
        self.git("rm", "--cached", "--", str(path.relative_to(self.root)))
        self.cli("render")
        self.assertEqual(output.read_bytes(), expected)

    def test_render_invalid_committed_entry_preserves_previous_output(self):
        path = self.create()
        self.stage(path)
        self.git("commit", "-m", "test: intentionally malformed historical entry")
        output = self.root / "WORKLOG.md"
        output.write_text("previous view\n")
        self.assertIn("placeholders", self.cli("render", ok=False).stderr)
        self.assertEqual(output.read_text(), "previous view\n")

    def test_render_refuses_symlink_and_tracked_output(self):
        output = self.root / "WORKLOG.md"
        target = self.root / "outside-view"
        target.write_text("do not replace\n")
        output.symlink_to(target)
        self.assertIn("symlink", self.cli("render", ok=False).stderr)
        self.assertEqual(target.read_text(), "do not replace\n")
        output.unlink()
        output.write_text("tracked file\n")
        self.git("add", "--force", "WORKLOG.md")
        self.assertIn("tracked", self.cli("render", ok=False).stderr)
        self.assertEqual(output.read_text(), "tracked file\n")

    def test_atomic_replace_failure_preserves_output_and_cleans_temporary_file(self):
        output = self.root / "WORKLOG.md"
        output.write_text("old content\n")
        with mock.patch.object(worklog.os, "replace", side_effect=OSError("simulated replacement failure")):
            with self.assertRaisesRegex(OSError, "simulated replacement failure"):
                worklog.atomic_write(output, "new content\n")
        self.assertEqual(output.read_text(), "old content\n")
        self.assertEqual(list(self.root.glob(".WORKLOG.md.*.tmp")), [])
        worklog.atomic_write(output, "new content\n")
        self.assertEqual(output.read_text(), "new content\n")

    def test_concurrent_creation_produces_unique_complete_files(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            paths = list(pool.map(lambda _: self.create(title="Same logical title"), range(18)))
        self.assertEqual(len(set(paths)), 18)
        for path in paths:
            self.complete(path)
            self.stage(path)
        self.assertIn("18 valid indexed entries", self.cli("check").stdout)

    def test_exclusive_create_retries_without_overwriting_existing_file(self):
        args = argparse.Namespace(title="Collision test", worker="agent", status="completed")
        fixed = worklog.datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=worklog.timezone.utc)
        with mock.patch.dict(os.environ, self.env, clear=True):
            repo = worklog.Repository(self.root)
            with mock.patch.object(worklog, "datetime") as clock:
                clock.now.return_value = fixed
                with mock.patch.object(worklog.secrets, "token_hex", side_effect=["0" * 16, "0" * 16, "1" * 16]):
                    first = self.root / worklog.new_entry(repo, args)
                    first.write_text("existing draft owned by another worker\n")
                    second = self.root / worklog.new_entry(repo, args)
                self.assertNotEqual(first, second)
                self.assertEqual(first.read_text(), "existing draft owned by another worker\n")
                with mock.patch.object(worklog.secrets, "token_hex", return_value="0" * 16):
                    with self.assertRaisesRegex(worklog.WorklogError, "after 10 attempts"):
                        worklog.new_entry(repo, args)

    def test_new_rejects_multiline_metadata_and_accepts_unicode(self):
        self.cli("new", "--title", "Title\n## Injected", ok=False)
        self.cli("new", "--title", "Title", "--worker", "worker\nstatus: blocked", ok=False)
        path = self.create(title="検証結果", worker="担当者")
        self.complete(path)
        self.stage(path)
        self.cli("check")

    def test_unmerged_index_entries_are_rejected(self):
        path, _ = self.committed_entry()
        rel = path.relative_to(self.root).as_posix()
        oid = self.git("rev-parse", f"HEAD:{rel}").stdout.decode().strip()
        records = f"0 {'0' * 40}\t{rel}\n100644 {oid} 1\t{rel}\n100644 {oid} 2\t{rel}\n"
        self.git("update-index", "--index-info", input=records.encode())
        self.assertIn("unresolved index conflict", self.cli("check", ok=False).stderr)


if __name__ == "__main__":
    unittest.main()
