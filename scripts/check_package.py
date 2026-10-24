#!/usr/bin/env python3
"""Fetch hash-locked wheels, then build/install/test in temporary state."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import zipfile
from email.parser import Parser


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="netwatch-build-") as tmp:
        tmp = Path(tmp)
        source = tmp / "source"
        source.mkdir()
        for name in ("pyproject.toml", "README.md", "LICENSE", "requirements.lock", "MANIFEST.in"):
            shutil.copy2(root / name, source / name)
        shutil.copytree(root / "netwatch", source / "netwatch", ignore=shutil.ignore_patterns("__pycache__"))
        env = {**os.environ, "PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        def run(argv, cwd=tmp, *, network=False):
            p = subprocess.run(argv, cwd=cwd, env={**env, "PIP_NO_INDEX": "0" if network else "1"}, check=True, capture_output=True, text=True, timeout=90)
            return p.stdout
        run([sys.executable, "-c", "from setuptools.build_meta import build_wheel,build_sdist; build_wheel('dist'); build_sdist('dist')"], source)
        wheel, = (source / "dist").glob("*.whl")
        sdist, = (source / "dist").glob("*.tar.gz")
        license_bytes = (root / "LICENSE").read_bytes()
        with zipfile.ZipFile(wheel) as archive:
            metadata_name, = (n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
            metadata = Parser().parsestr(archive.read(metadata_name).decode())
            assert metadata["Name"] == "netwatch"
            assert metadata["License-Expression"] == "Apache-2.0"
            assert "LICENSE" in metadata.get_all("License-File", [])
            license_name, = (n for n in archive.namelist() if n.endswith(".dist-info/licenses/LICENSE"))
            assert archive.read(license_name) == license_bytes
        with tarfile.open(sdist) as archive:
            license_name, = (n for n in archive.getnames() if n.endswith("/LICENSE"))
            assert archive.extractfile(license_name).read() == license_bytes
            lock_name, = (n for n in archive.getnames() if n.endswith("/requirements.lock"))
            assert archive.extractfile(lock_name).read() == (root / "requirements.lock").read_bytes()
        run([sys.executable, "-m", "venv", str(tmp / "venv")])
        python = str(tmp / "venv/bin/python")
        run([python, "-m", "pip", "download", "--require-hashes", "--only-binary=:all:",
             "--index-url", "https://pypi.org/simple", "-r", str(root / "requirements.lock"), "-d", str(tmp / "wheels")], network=True)
        run([python, "-m", "pip", "install", "--no-index", "--find-links", str(tmp / "wheels"), str(wheel)])
        run([python, "-m", "pip", "check"])
        command = str(tmp / "venv/bin/netwatch")
        for entry in ([command], [python, "-I", "-m", "netwatch"]):
            assert run([*entry, "--version"]).strip() == "netwatch 0.2.0"
            assert "preview" in run([*entry, "--help"])
        result = json.loads(run([command, "--json", "demo"]))
        assert result["synthetic"] and result["result"]["package_state_changed"]
        assert not result["result"]["remaining_findings"]
        print(json.dumps({"wheel": wheel.name, "installed_demo": "passed", "license": "Apache-2.0 (wheel and sdist verified)", "dependency_download": "hash-locked wheels; network/cache", "install": "offline"}))


if __name__ == "__main__":
    main()
