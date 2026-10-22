#!/usr/bin/env python3
"""Build and check an offline wheel/sdist in disposable state, never the host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv, *, cwd, env, timeout=120):
    result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"Offline packaging check failed at {Path(argv[0]).name} (exit {result.returncode})")
    return result.stdout.decode("utf-8")


def verify_demo(result):
    """Reject empty or misleading summaries even when the child exits zero."""
    def require(condition):
        if not condition:
            raise ValueError()

    try:
        require(result["schema_version"] == 1 and result["kind"] == "disposable-command-demo")
        require(result["synthetic"] is True and result["backend"] == "simulator")
        require(type(result["commands_run"]) is int and 1 <= result["commands_run"] <= 128)
        require(result["cleanup"] == {"temporary_state_removed": True, "caller_state_used": False})
        scenarios = result["scenarios"]
        require(set(scenarios) == {"manual", "automatic", "before_write", "after_write"})
        for mode in ("manual", "automatic"):
            row = scenarios[mode]
            require(row["status"] == "succeeded" and row["verified_package_state"] is True)
            require(row["manual_approval"] is (mode == "manual") and row["repeat_execution"] == "denied")
            require(row["export_trusted"] is False and row["duplicate_imports"] == {"debian": True, "pwn": True})
        before, after = scenarios["before_write"], scenarios["after_write"]
        require(before["status"] == "failed" and before["verified"] is False)
        require(before["package_state_unchanged"] is True and before["gate_retained"] is False)
        require(after["status"] == "needs_attention" and after["verified"] is False)
        require(after["package_state_changed"] is True and after["gate_retained_before_resolution"] is True)
        require(after["gate_blocked_other_plan"] is True)
        require(after["recovery"] == {
            "gate_cleared": True, "verified": False, "generation_changed": True,
            "fresh_collection_required": True, "old_approved_plan": "stale",
            "new_approved_plan": "succeeded", "original_status": "needs_attention",
        })
    except (ValueError, KeyError, TypeError):
        raise RuntimeError("Installed demo did not verify the required scenarios and cleanup") from None


def main():
    if sys.version_info < (3, 12):
        raise RuntimeError("Packaging check requires a supported Python 3.12 or newer runtime")
    with tempfile.TemporaryDirectory(prefix="autoprotect-package-") as directory:
        root = Path(directory)
        snapshot = root / "source"
        snapshot.mkdir()
        shutil.copy2(ROOT / "pyproject.toml", snapshot / "pyproject.toml")
        if (ROOT / "README.md").exists():
            shutil.copy2(ROOT / "README.md", snapshot / "README.md")
        shutil.copytree(ROOT / "autoprotect", snapshot / "autoprotect",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        env = {"PATH": os.defpath, "HOME": directory, "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
               "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONNOUSERSITE": "1"}
        build = "from setuptools.build_meta import build_wheel, build_sdist; build_wheel('dist'); build_sdist('dist')"
        run([sys.executable, "-c", build], cwd=snapshot, env=env)
        wheel, = (snapshot / "dist").glob("*.whl")
        sdist, = (snapshot / "dist").glob("*.tar.gz")
        required = {f"autoprotect/{name}.py" for name in ("__main__", "cli", "demo", "engine", "store", "backends", "_apt_probe")}
        with zipfile.ZipFile(wheel) as archive:
            if not required <= set(archive.namelist()):
                raise RuntimeError("Wheel omits required runtime modules")
        with tarfile.open(sdist, "r:gz") as archive:
            members = archive.getnames()
            prefix = members[0].split("/", 1)[0] + "/"
            if not {prefix + path for path in required} <= set(members):
                raise RuntimeError("Source distribution omits required runtime modules")
        environment = root / "venv"
        run([sys.executable, "-m", "venv", str(environment)], cwd=root, env=env)
        python = environment / "bin" / "python"
        command = environment / "bin" / "autoprotect"
        run([str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)], cwd=root, env=env)
        for invocation in ([str(python), "-I", "-m", "autoprotect"], [str(command)]):
            version = run([*invocation, "--version"], cwd=root, env=env).strip()
            if "0.1.0" not in version:
                raise RuntimeError("Installed version differs from package metadata")
            help_text = run([*invocation, "--help"], cwd=root, env=env)
            if "resolve-recovery" not in help_text or "demo" not in help_text:
                raise RuntimeError("Installed command help is incomplete")
        # Invoke the full command demo once, outside the repository. Its child
        # commands must find only installed package modules, never test fixtures.
        demo = json.loads(run([str(command), "demo"], cwd=root, env=env, timeout=180))
        verify_demo(demo)
        summary = {"wheel": wheel.name, "sdist": sdist.name, "installed_entry_points": 2,
                   "demo": demo, "network_used": False, "state": "temporary; removed on exit"}
    if root.exists():
        raise RuntimeError("Temporary packaging state was not removed")
    print(json.dumps(summary, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Packaging check failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
