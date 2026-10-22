# Immutable worklog

Track one Markdown file per logical unit under `worklog/entries/`. Each file has a unique name so agents sharing `main` do not append to the same journal. Commit the entry with the work it records. Once committed, never edit, rename, or delete it; write a new entry that names the earlier path and explains the correction.

The root `WORKLOG.md` is an ignored, generated reading view. It is not the journal and must not be staged. Entries are tracked; the view is disposable.

## Record a logical unit

Use Python 3 and Git. Run commands from the repository root unless you supply `--root`.

1. Create a draft for a completed unit, checkpoint, decision, blocker, or handoff:

   ```bash
   python3 scripts/worklog.py new \
     --worker agent-one \
     --status completed \
     --title "Implement immutable worklog checks"
   ```

   The command prints the new relative path. Names contain a UTC timestamp, worker and title slugs, and a random suffix. Exclusive creation prevents an existing file from being overwritten, including when workers create entries concurrently.

2. Edit only that draft. Replace every `<required>` and `<next-or-none>` placeholder. Keep these headings in order:

   - `## Summary`: the requirement and outcome, including decisions or blockers.
   - `## Changes`: changed paths, behavior, or interfaces.
   - `## Validation`: exact commands and outcomes; state anything not tested.
   - `## Next`: concrete remaining work, or `None.`

   Keep the generated metadata and title consistent with the filename. Choose a useful title before creation. Do not include credentials, private inventories, tokens, or secret-bearing command output.

3. Have the integration owner stage the completed entry and the exact files belonging to that unit. Replace `ENTRY_PATH` with the path printed by `new`:

   ```bash
   git add -- ENTRY_PATH
   python3 scripts/worklog.py check
   git diff --staged --name-only
   git diff --staged
   ```

   Do not stage other workers' drafts or use a blanket `git add`. The shared index still needs one integration owner; unique journal paths do not make concurrent staging and committing safe.

4. Commit the reviewed unit under the repository's Git rules, then refresh the reading view:

   ```bash
   python3 scripts/worklog.py render
   ```

An untracked draft is deliberately outside `check`'s scope. To validate a finished entry for a commit, stage it first. Edit drafts only before their first commit. Correct committed mistakes with another entry, not a history rewrite.

## Commands and metadata

`new`, `check`, and `render` are the only commands. They do not stage, commit, install hooks, or change Git configuration.

`new` requires `--title`. It accepts `--worker` and `--status`. Worker defaults, in order, are `WORKLOG_WORKER`, `USER`, and `worker`; supply a stable worker/session ID explicitly when agents share a checkout. The default status is `completed`; alternatives are `checkpoint`, `decision`, `blocked`, and `handoff`. All statuses require completed sections before staging, even though `new` always creates an unfinished template.

The fixed metadata fields, in order, are:

| Field | Meaning |
| --- | --- |
| `timestamp` | Creation time in UTC, as `YYYY-MM-DDTHH:MM:SS.ffffffZ`. |
| `worker` | Worker or session that records the unit. |
| `branch` | Creation branch, or `detached-` followed by the full HEAD commit hash. |
| `base_commit` | Full HEAD commit hash at creation; `unborn` before the repository's first commit. |
| `status` | One of the five statuses listed above. |
| `title` | One-line title, also used as the entry's `#` heading. |

Metadata is a small `key: value` format between `---` lines, not general YAML. Do not add fields or quote values as YAML strings. Worker and title must be nonempty single lines without surrounding whitespace. The checker matches the timestamp and normalized worker/title against the filename and checks the body title against metadata. Branch and base commit record creation context: they do not have to match the branch or HEAD at a later check. Base hashes are checked for full lowercase SHA-1 or SHA-256 syntax, not independently authenticated provenance.

For another repository or an isolated test, put the global option before the command:

```bash
python3 scripts/worklog.py --root /path/to/repository check
WORKLOG_ROOT=/path/to/repository python3 scripts/worklog.py render
```

`--root` takes precedence over `WORKLOG_ROOT`. Without either, the root is the directory containing this script's `scripts/` directory, not the shell's current directory. The selected path must be a Git repository root.

## What validation enforces

`check` reads actual Git index objects, not just working-copy files. It rejects malformed staged entries, remaining template placeholders, conflict markers, duplicate or missing metadata, mismatched filenames or titles, missing or empty sections, and unresolved index conflicts.

For every entry in committed HEAD, it independently checks that:

- The index has the same path, mode, and object. Staged edits, deletions, and renames fail even if the working copy has been restored.
- The working copy still has the committed bytes. Unstaged changes and missing files fail, including files hidden from ordinary Git status by `assume-unchanged`.

Indexed entries must be non-executable regular files, not symlinks. Their working files must match the staged bytes exactly, and their parent directories must not be symlinks. A valid staged entry followed by another working-copy edit fails: finish the draft and stage it again. A committed entry cannot be fixed by restaging the edit; restore its original content and record the correction in a new entry.

Untracked files under `worklog/entries/`, including other workers' unfinished drafts, are ignored. This is not a scanner of every file on disk.

## Generated view and limits

`render` captures HEAD, reads its committed entry bytes directly from Git, validates those entries, and sorts them by timestamp and path. Dirty or missing working files, staged additions or deletions, and untracked drafts do not change the view. An unborn repository renders an empty-history message. Malformed committed entries make rendering fail without replacing an existing view.

The renderer writes a temporary file beside `WORKLOG.md`, then atomically replaces the view. It refuses a tracked or symlinked `WORKLOG.md`. The repository's `/WORKLOG.md` ignore rule keeps this generated view out of commits. Rendering does not modify ignore rules or enforce that the rule exists in a different repository; configure the same ignore rule there. An interrupted process can leave a `.WORKLOG.md.*.tmp` file; it is not an entry and must not be committed.

These commands enforce workflow checks, not tamper-proof storage. They do not prevent someone from bypassing `check`, rewriting Git history, or changing the index after validation. Coordinate commits, run `check` after staging, and do not treat metadata as authenticated identity. Rendering is a snapshot of the HEAD it captured; rerun it after a later commit.

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_worklog.py' -v
```

Tests create disposable repositories and isolate Git configuration and hooks. They never modify the development repository's index or history. Coverage includes unborn HEAD, completed templates, untracked drafts, staged/working-copy disagreement, immutable history changes, symlinks, HEAD-only rendering, atomic replacement failures, and concurrent filename creation.
