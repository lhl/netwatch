#!/usr/bin/env python3
"""Create, check, and render immutable per-unit worklog entries (stdlib only)."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ENTRY_DIR = "worklog/entries"
FIELDS = ("timestamp", "worker", "branch", "base_commit", "status", "title")
SECTIONS = ("Summary", "Changes", "Validation", "Next")
STATUSES = ("completed", "checkpoint", "decision", "blocked", "handoff")
PLACEHOLDERS = ("<required>", "<next-or-none>")
HASH_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


class WorklogError(ValueError):
    """An entry or repository does not satisfy the worklog rules."""


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:48].rstrip("-") or "entry"


def single_line(value: str) -> bool:
    return bool(value) and value == value.strip() and all(c.isprintable() for c in value)


def filename_prefix(fields: dict[str, str]) -> str:
    stamp = fields["timestamp"].replace("-", "").replace(":", "")
    return f"{stamp}-{slug(fields['worker'])}-{slug(fields['title'])}-"


def parse_entry(path: str, data: bytes) -> tuple[dict[str, str], str]:
    """Validate named bytes, without consulting a working-copy file."""
    text = data.decode("utf-8")
    if any(marker in text for marker in PLACEHOLDERS):
        raise WorklogError("replace all template placeholders")
    if re.search(r"(?m)^(?:<{7}|={7}|>{7}|\|{7})(?: |$)", text):
        raise WorklogError("Git conflict marker present")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise WorklogError("missing opening metadata delimiter")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise WorklogError("missing closing metadata delimiter") from exc
    fields: dict[str, str] = {}
    for line in lines[1:end]:
        key, separator, value = line.partition(": ")
        if not separator or not single_line(value) or key in fields:
            raise WorklogError(f"invalid or duplicate metadata field: {line!r}")
        fields[key] = value
    if tuple(fields) != FIELDS:
        raise WorklogError("metadata fields must appear once, in order: " + ", ".join(FIELDS))
    if not TIME_RE.fullmatch(fields["timestamp"]):
        raise WorklogError("timestamp must use UTC YYYY-MM-DDTHH:MM:SS.ffffffZ")
    try:
        datetime.strptime(fields["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise WorklogError("invalid timestamp") from exc
    if fields["status"] not in STATUSES:
        raise WorklogError("unsupported status: " + fields["status"])
    if fields["base_commit"] != "unborn" and not HASH_RE.fullmatch(fields["base_commit"]):
        raise WorklogError("base_commit must be unborn or a full lowercase Git commit hash")
    expected = re.escape(f"{ENTRY_DIR}/{filename_prefix(fields)}") + r"[0-9a-f]{16}\.md"
    if not re.fullmatch(expected, path):
        raise WorklogError("filename does not match timestamp, worker, and title metadata")

    body = lines[end + 1:]
    while body and not body[0].strip():
        body.pop(0)
    if not body or body[0] != "# " + fields["title"]:
        raise WorklogError("body title does not match title metadata")
    headings = [(i, line[3:]) for i, line in enumerate(body) if line.startswith("## ")]
    if tuple(name for _, name in headings) != SECTIONS:
        raise WorklogError("required sections must appear once, in order: " + ", ".join(SECTIONS))
    if any(line.startswith("# ") for line in body[1:]):
        raise WorklogError("only one level-one title is allowed")
    for index, (start, name) in enumerate(headings):
        stop = headings[index + 1][0] if index + 1 < len(headings) else len(body)
        content = "\n".join(body[start + 1:stop]).strip()
        if not content or not content.strip("-*+ \t\n"):
            raise WorklogError(f"{name} section is empty")
    return fields, text


class Repository:
    def __init__(self, root: Path):
        self.root = root.resolve()
        top = Path(os.fsdecode(self.git("rev-parse", "--show-toplevel").stdout).strip()).resolve()
        if top != self.root:
            raise WorklogError("--root must name the Git repository root")

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(
            ["git", *args], cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )
        if check and result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise WorklogError(f"git {' '.join(args)} failed: {detail}")
        return result

    def head(self) -> str | None:
        result = self.git("rev-parse", "--verify", "--quiet", "HEAD^{commit}", check=False)
        if result.returncode == 0:
            return result.stdout.decode("ascii").strip()
        symbolic = self.git("symbolic-ref", "--quiet", "HEAD", check=False)
        if symbolic.returncode == 0:
            ref = symbolic.stdout.decode("utf-8").strip()
            if self.git("show-ref", "--verify", "--quiet", ref, check=False).returncode == 1:
                return None
        raise WorklogError("cannot resolve HEAD; expected a commit or an unborn branch")

    def entries(self, head: str | None = None, *, index: bool = False) -> dict[str, tuple[str, str]]:
        if index:
            data = self.git("ls-files", "--stage", "-z", "--", ENTRY_DIR).stdout
        elif head:
            data = self.git("ls-tree", "-r", "-z", "--full-tree", head, "--", ENTRY_DIR).stdout
        else:
            return {}
        entries = {}
        for record in data.split(b"\0"):
            if not record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            first, second, third = metadata.decode("ascii").split()
            path = os.fsdecode(raw_path)
            if index:
                if third != "0":
                    raise WorklogError(f"{path}: unresolved index conflict")
                mode, oid = first, second
            else:
                mode, oid = first, third
            entries[path] = (mode, oid)
        return entries

    def blob(self, oid: str) -> bytes:
        return self.git("cat-file", "blob", oid).stdout

    def working_bytes(self, path: str) -> bytes:
        target = self.root
        parts = PurePosixPath(path).parts
        for part in parts[:-1]:
            target /= part
            if not stat.S_ISDIR(target.lstat().st_mode):
                raise WorklogError("entry parent must be a real directory, not a symlink")
        target /= parts[-1]
        mode = target.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise WorklogError("entry must be a regular file, not a symlink")
        if mode & 0o111:
            raise WorklogError("entry must not be executable")
        return target.read_bytes()


def new_entry(repo: Repository, args: argparse.Namespace) -> Path:
    worker = args.worker or os.environ.get("WORKLOG_WORKER") or os.environ.get("USER") or "worker"
    title = args.title
    if not single_line(worker) or not single_line(title):
        raise WorklogError("worker and title must be nonempty single lines without surrounding whitespace")
    if any(marker in worker or marker in title for marker in PLACEHOLDERS):
        raise WorklogError("worker and title must not contain template placeholders")
    head = repo.head()
    branch_result = repo.git("symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    if branch_result.returncode not in (0, 1):
        raise WorklogError("cannot read branch name")
    branch = branch_result.stdout.decode("utf-8").strip() if branch_result.returncode == 0 else f"detached-{head}"
    fields = dict(zip(FIELDS, (
        datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        worker, branch, head or "unborn", args.status, title,
    )))
    text = "---\n" + "".join(f"{key}: {value}\n" for key, value in fields.items())
    text += f"---\n\n# {title}\n"
    for section in SECTIONS:
        placeholder = "<next-or-none>" if section == "Next" else "<required>"
        text += f"\n## {section}\n\n{placeholder}\n"
    directory = repo.root
    for part in PurePosixPath(ENTRY_DIR).parts:
        directory /= part
        directory.mkdir(exist_ok=True)
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise WorklogError("entry directory must not be a symlink")
    for _ in range(10):
        path = directory / f"{filename_prefix(fields)}{secrets.token_hex(8)}.md"
        try:
            handle = path.open("x", encoding="utf-8", newline="\n")
        except FileExistsError:
            continue
        with handle:
            handle.write(text)
        return path.relative_to(repo.root)
    raise WorklogError("could not allocate a unique entry path after 10 attempts")


def check_entries(repo: Repository) -> int:
    head_entries = repo.entries(repo.head())
    index_entries = repo.entries(index=True)
    errors = []
    for path, identity in head_entries.items():
        if index_entries.get(path) != identity:
            errors.append(f"{path}: committed entry is immutable; index modification or deletion")
        try:
            if repo.working_bytes(path) != repo.blob(identity[1]):
                raise WorklogError("committed entry is immutable; working-copy modification")
        except (OSError, WorklogError) as exc:
            errors.append(f"{path}: {exc}")
    for path, (mode, oid) in index_entries.items():
        try:
            if mode != "100644":
                raise WorklogError("index entry must be a non-executable regular file, not a symlink")
            data = repo.blob(oid)
            parse_entry(path, data)
            if repo.working_bytes(path) != data:
                raise WorklogError("working copy differs from staged entry; finish and stage this entry again")
        except (OSError, UnicodeError, WorklogError) as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise WorklogError("\n".join(errors))
    return len(index_entries)


def atomic_write(path: Path, text: str) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(text)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def render(repo: Repository) -> int:
    entries = []
    for path, (mode, oid) in repo.entries(repo.head()).items():
        if mode != "100644":
            raise WorklogError(f"{path}: committed entry must be a non-executable regular file")
        try:
            fields, text = parse_entry(path, repo.blob(oid))
        except (UnicodeError, WorklogError) as exc:
            raise WorklogError(f"{path}: {exc}") from exc
        entries.append((fields["timestamp"], path, text))
    entries.sort()
    lines = [
        "# Worklog", "",
        "> Generated from committed HEAD entries in `worklog/entries/`.",
        "> Do not edit; run `python3 scripts/worklog.py render`.", "",
    ]
    if not entries:
        lines.append("No committed worklog entries yet.")
    for _, path, text in entries:
        lines.extend([f"<!-- source: {path} -->", "", text.rstrip(), "", "---", ""])
    output = repo.root / "WORKLOG.md"
    if output.is_symlink():
        raise WorklogError("WORKLOG.md must not be a symlink")
    if repo.git("ls-files", "-z", "--", "WORKLOG.md").stdout:
        raise WorklogError("WORKLOG.md is tracked; keep the generated view ignored and untracked")
    atomic_write(output, "\n".join(lines).rstrip() + "\n")
    return len(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(os.environ.get("WORKLOG_ROOT") or Path(__file__).resolve().parents[1]),
        help="repository root (default: WORKLOG_ROOT or this script's repository)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    new = commands.add_parser("new", help="create a unique, unfinished entry template")
    new.add_argument("--title", required=True, help="one-line description of the logical unit")
    new.add_argument("--worker", help="worker/session ID (default: WORKLOG_WORKER, USER, or worker)")
    new.add_argument("--status", choices=STATUSES, default="completed")
    commands.add_parser("check", help="validate staged bytes and reject committed entry changes")
    commands.add_parser("render", help="atomically rebuild WORKLOG.md from committed HEAD bytes")
    args = parser.parse_args(argv)
    try:
        repo = Repository(args.root)
        if args.command == "new":
            print(new_entry(repo, args))
        elif args.command == "check":
            print(f"worklog: {check_entries(repo)} valid indexed entries")
        else:
            print(f"worklog: rendered {render(repo)} committed entries to WORKLOG.md")
        return 0
    except (OSError, UnicodeError, WorklogError) as exc:
        print(f"worklog: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
