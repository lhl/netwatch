# netwatch

netwatch tracks vulnerabilities and available updates across your machines and development environments, then lets you review and apply updates.

- Checks Ubuntu, Arch/CachyOS, conda/mamba, uv and npm environments locally or over SSH.
- Matches installed packages against Canonical, Arch and OSV advisories.
- Stores findings and history in SQLite, with text and JSON output for you or your agent.

## Quick start

Requires Python 3.12+ and Git.

```bash
git clone https://github.com/lhl/netwatch.git
cd netwatch
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
netwatch demo
```

The demo checks and updates a synthetic package in temporary state without making network requests or changing your installed software.

## Usage

### Check a machine or project

For an Ubuntu **24.04 LTS, amd64** machine, replace `my-server` with your SSH alias:

```bash
netwatch add server ubuntu --host my-server
netwatch check server
```

For local projects and environments:

```bash
netwatch add api uv --path /srv/api
netwatch add frontend npm --path /srv/frontend
netwatch add training mamba --path /opt/conda/envs/training
netwatch check
```

uv checks the project's `.venv`; npm checks installed dependencies. Remote targets need their package tools available over SSH.

Reports show affected packages, advisory links, fix versions, available updates and failed checks.

Ubuntu matching covers published Noble fixes and excludes Pro/ESM. Conda-native packages lack vulnerability matching; CachyOS findings need investigation. See [environment support](docs/USAGE.md#environments).

Python/npm checks send package names and versions to OSV.

### Read status and history

```bash
netwatch list                   # registered environments
netwatch status                 # cached reports; no connections
netwatch history --name server  # changes and update attempts
netwatch check server --refresh # fetch fresh advisories
```

Advisories are cached for one hour. Failed checks preserve earlier findings and appear in the report. The default report groups findings by package and shows a short update list; add `--all` to `status` or `check` to expand it. Color terminals highlight affected findings in red, review findings in yellow and other updates in cyan. Use `NO_COLOR=1` for plain output.

### Apply updates

`apply` updates the **whole selected environment**, including dependencies, so review its scope and back up before running it. Live updates have not been tested; start with a disposable environment.

```bash
netwatch preview server
```

Review the commands and scope. Replace `PLAN_ID` with the returned ID:

```bash
netwatch apply PLAN_ID --yes
netwatch status server
```

OS updates need `sudo -n` access. After applying, netwatch checks installed versions again. Check services and restart/reboot requirements afterward. [Update commands and recovery](docs/USAGE.md#updates).

### Query from an agent or script

```bash
netwatch --json status
netwatch --json history --since 0
```

Pass the returned `next_cursor` as `--since` to read later events. Give agents read-only access; run `apply` yourself with an account that can update the target.

## Reference

- [Usage guide](docs/USAGE.md): supported environments, caching, update commands and recovery.
- `netwatch --help` or `netwatch COMMAND --help`: command arguments.

Data lives in `~/.local/state/netwatch/state.db`. To use another database, put `--db /path/to/state.db` before the command.

## Development

```bash
python3 -B -m unittest discover -s tests -v
python3 -B scripts/check_package.py
```

For development, install the pinned dependencies with `python3 -m pip install --require-hashes -r requirements.lock`. The packaging check downloads those wheels, then installs and tests from the local copies.

Add package-manager support in [`netwatch/adapters.py`](netwatch/adapters.py) and advisory matching in [`netwatch/sources.py`](netwatch/sources.py). See the [design contract](docs/DESIGN.md).

## License

[Apache License 2.0](LICENSE).
