#!/usr/bin/env python3
"""Offline build/install/demo check in temporary state; no host package changes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="autoprotect-build-") as tmp:
        tmp = Path(tmp)
        source = tmp / "source"
        source.mkdir()
        for name in ("pyproject.toml", "README.md"):
            shutil.copy2(root / name, source / name)
        shutil.copytree(root / "autoprotect", source / "autoprotect", ignore=shutil.ignore_patterns("__pycache__"))
        env = {**os.environ, "PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        def run(argv, cwd=tmp):
            p = subprocess.run(argv, cwd=cwd, env=env, check=True, capture_output=True, text=True, timeout=90)
            return p.stdout
        run([sys.executable, "-c", "from setuptools.build_meta import build_wheel,build_sdist; build_wheel('dist'); build_sdist('dist')"], source)
        wheel, = (source / "dist").glob("*.whl")
        run([sys.executable, "-m", "venv", str(tmp / "venv")])
        python = str(tmp / "venv/bin/python")
        run([python, "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)])
        command = str(tmp / "venv/bin/autoprotect")
        for entry in ([command], [python, "-I", "-m", "autoprotect"]):
            assert "0.2.0" in run([*entry, "--version"])
            assert "preview" in run([*entry, "--help"])
        result = json.loads(run([command, "--json", "demo"]))
        assert result["synthetic"] and result["result"]["package_state_changed"]
        assert not result["result"]["remaining_findings"]
        print(json.dumps({"wheel": wheel.name, "installed_demo": "passed", "network": False}))


if __name__ == "__main__":
    main()
