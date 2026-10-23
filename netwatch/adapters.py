"""Environment adapters: ordinary functions and fixed package-manager commands."""
import json
import os
import shlex
import signal
import subprocess
from pathlib import PurePosixPath

from .core import Error, name, text


KINDS = ("ubuntu", "arch", "cachyos", "conda", "mamba", "uv", "npm")


def target(name_, kind, host="local", path=None):
    name(name_)
    if kind not in KINDS:
        raise Error("Unsupported environment kind")
    text(host, "SSH alias")
    if host.startswith("-") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@" for c in host):
        raise Error("Host must be local or an explicit SSH alias/user@host")
    if kind in ("conda", "mamba", "uv", "npm"):
        text(path, "absolute environment/project path")
        if not PurePosixPath(path).is_absolute():
            raise Error("Environment/project path must be absolute")
    elif path is not None:
        raise Error("OS environments do not take a project path")
    return {"name": name_, "kind": kind, "host": host, "path": path}


def run(t, argv, *, ok=(0,), timeout=120):
    """SSH needs one quoted remote command; no advisory text enters it."""
    cwd = t.get("path") if t["kind"] in ("uv", "npm") else None
    if t["host"] != "local":
        command = shlex.join(argv)
        if cwd:
            command = "cd -- " + shlex.quote(cwd) + " && " + command
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", t["host"], command]
        cwd = None
    env = {**os.environ, "LC_ALL": "C", "LANG": "C", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = process.communicate(timeout=timeout)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f"Command unavailable or timed out: {argv[0]}") from exc
    if len(out) + len(err) > 20 * 1024 * 1024:
        raise Error("Command output exceeds 20 MiB")
    if process.returncode not in ok:
        # Avoid storing tool output that can include credentials or private URLs.
        raise Error(f"Command failed: {argv[0]} (exit {process.returncode})")
    return out.decode("utf-8")


def package(n, v, ecosystem, **extra):
    return {"name": text(n, "package name"), "version": text(v, "version"), "ecosystem": ecosystem, **extra}


def os_info(t, runner):
    data = {}
    for line in runner(t, ["cat", "/etc/os-release"]).splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            data[key] = value.strip('"\'')
    if t["kind"] == "ubuntu" and (data.get("ID"), data.get("VERSION_CODENAME")) != ("ubuntu", "noble"):
        raise Error("Ubuntu adapter currently matches only Ubuntu 24.04 noble")
    if t["kind"] in ("arch", "cachyos") and data.get("ID") != t["kind"]:
        raise Error("Configured OS differs from collected OS")
    return data


def ubuntu_inventory(t, runner):
    os_info(t, runner)
    if runner(t, ["dpkg", "--print-architecture"]).strip() != "amd64":
        raise Error("Ubuntu advisory support currently requires amd64")
    fmt = "${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\t${db:Status-Status}\\n"
    result = []
    for line in runner(t, ["dpkg-query", "-W", "-f=" + fmt]).splitlines():
        n, v, source, sv, arch, status = line.split("\t")
        if status == "installed":
            result.append(package(n.split(":")[0], v, "Ubuntu", source=source, source_version=sv, architecture=arch))
        elif status not in ("not-installed", "config-files"):
            raise Error("Package database has unfinished operations; repair it before checking")
    return result


def arch_inventory(t, runner):
    os_info(t, runner)
    foreign = {line.split()[0] for line in runner(t, ["pacman", "-Qm"], ok=(0, 1)).splitlines()}
    return [package(*line.split(), "Arch", foreign=line.split()[0] in foreign)
            for line in runner(t, ["pacman", "-Q"]).splitlines()]


def conda_inventory(t, runner):
    rows = json.loads(runner(t, [t["kind"], "list", "--json", "--prefix", t["path"]]))
    return [package(r["name"], r["version"], "PyPI" if r.get("channel") == "pypi" else "Conda",
                    build=r.get("build_string", r.get("build", ""))) for r in rows]


def uv_inventory(t, runner):
    python = t["path"].rstrip("/") + "/.venv/bin/python"
    rows = json.loads(runner(t, ["uv", "pip", "list", "--format", "json", "--python", python]))
    return [package(r["name"], r["version"], "PyPI") for r in rows]


def npm_inventory(t, runner):
    # Fail incomplete/broken dependency trees, rather than resolving old findings.
    tree = json.loads(runner(t, ["npm", "ls", "--all", "--json"]))
    result = {}
    def visit(node):
        for n, row in node.get("dependencies", {}).items():
            if row.get("missing") or row.get("invalid") or not row.get("version"):
                raise Error("npm dependency tree is incomplete")
            p = package(n, row["version"], "npm")
            result[(n, row["version"])] = p
            visit(row)
    visit(tree)
    return list(result.values())


INVENTORIES = {"ubuntu": ubuntu_inventory, "arch": arch_inventory, "cachyos": arch_inventory,
               "conda": conda_inventory, "mamba": conda_inventory, "uv": uv_inventory, "npm": npm_inventory}


def inventory(t, runner=run):
    rows = INVENTORIES[t["kind"]](t, runner)
    if len(rows) > 50000:
        raise Error("Inventory exceeds 50,000 packages")
    return sorted(rows, key=lambda p: (p["name"], p["version"], p.get("architecture", "")))


def updates(t, runner=run):
    kind = t["kind"]
    if kind == "ubuntu":
        output = runner(t, ["apt", "list", "--upgradable"])
        return [{"package": line.split("/")[0], "candidate": line.split()[1]}
                for line in output.splitlines() if "/" in line and len(line.split()) >= 2]
    if kind in ("arch", "cachyos"):
        # checkupdates refreshes an isolated sync database, not the live one.
        output = runner(t, ["checkupdates"], ok=(0, 2))
        return [{"package": line.split()[0], "candidate": line.split()[-1]} for line in output.splitlines()]
    if kind in ("conda", "mamba"):
        data = json.loads(runner(t, [kind, "update", "--all", "--dry-run", "--json", "--prefix", t["path"]], timeout=300))
        if data.get("success") is False or data.get("error"):
            raise Error("Environment solver could not determine updates")
        return [{"package": r["name"], "candidate": r["version"]} for r in data.get("actions", {}).get("LINK", [])]
    if kind == "uv":
        data = json.loads(runner(t, ["uv", "pip", "list", "--outdated", "--format", "json", "--python",
                                    t["path"].rstrip("/") + "/.venv/bin/python"]))
        return [{"package": r["name"], "candidate": r["latest_version"]} for r in data]
    data = json.loads(runner(t, ["npm", "outdated", "--json"], ok=(0, 1)) or "{}")
    return [{"package": n, "candidate": r.get("wanted"), "latest": r.get("latest")} for n, r in sorted(data.items())]


def commands(t):
    """Operator-approved environment-wide updates, not arbitrary feed commands."""
    return {
        "ubuntu": [["sudo", "-n", "apt-get", "update"], ["sudo", "-n", "apt-get", "upgrade", "-y"]],
        "arch": [["sudo", "-n", "pacman", "-Syu", "--noconfirm"]],
        "cachyos": [["sudo", "-n", "pacman", "-Syu", "--noconfirm"]],
        "conda": [["conda", "update", "--all", "--yes", "--prefix", t.get("path")]],
        "mamba": [["mamba", "update", "--all", "--yes", "--prefix", t.get("path")]],
        "uv": [["uv", "lock", "--upgrade"], ["uv", "sync", "--locked"]],
        "npm": [["npm", "update", "--ignore-scripts"]],
    }[t["kind"]]
