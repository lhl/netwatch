"""Isolated system-python probe for local authenticated APT metadata.

Run only through DebianApt's fixed argument arrays. python3-apt is imported in
main, never at module import. This helper does not refresh indexes or install
packages. It supports HTTP or HTTPS deb sources with explicit Signed-By key
files, fixed Debian codenames and the standard APT/dpkg filesystem locations.
Transport is not the authority: every candidate requires a signed InRelease,
matching Packages hashes and the exact artifact hash.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

MAX_ARTIFACT = 256 * 1024 * 1024
MAX_INDEX = 512 * 1024 * 1024
MAX_CONTROL = 1024 * 1024
MAX_KEYRING = 4 * 1024 * 1024
MAX_RELEASES = 1024
CODENAMES = {"trixie", "trixie-updates", "trixie-security"}
ORIGIN_FIELDS = ("origin", "label", "archive", "codename", "component", "site")
KEYRING_DIRECTORIES = (Path("/usr/share/keyrings"), Path("/etc/apt/keyrings"))
# Required owner of every trusted APT/dpkg input. Tests substitute the invoking
# user to exercise real filesystem checks; the probe itself never changes it.
_OWNER = 0


class ProbeError(Exception):
    """A locally generated, non-secret diagnostic."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _safe_info(path, *, directory=False):
    info = path.lstat()
    if ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid != _OWNER or info.st_mode & 0o022 or (not directory and info.st_nlink != 1)):
        raise ProbeError("APT inputs must be root-owned regular files and directories without writable aliases")
    return info


def _contained(path, roots):
    return any(path == root or root in path.parents for root in roots)


def _safe_link(path, roots):
    """Accept a root-owned symlink only if it resolves inside a checked root.

    Debian ships such links (for example /etc/dpkg/origins/default and the
    debian-archive-keyring *.gpg -> *.pgp aliases). The link text is part of
    the fingerprint; its target is fingerprinted as an ordinary entry of the
    same tree, so a link can never import unchecked bytes.
    """
    info = path.lstat()
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != _OWNER:
        raise ProbeError("APT input links must be root-owned symbolic links")
    target = Path(os.path.realpath(path))
    if not _contained(target, roots) or not target.exists():
        raise ProbeError("APT input links must resolve inside the checked configuration roots")
    _safe_info(target, directory=target.is_dir())
    return os.readlink(path)


def _resolve_key(key):
    """Return the regular key file named by Signed-By, following safe aliases."""
    path = Path(key)
    if stat.S_ISLNK(path.lstat().st_mode):
        _safe_link(path, KEYRING_DIRECTORIES)
        path = Path(os.path.realpath(path))
        if path.parent not in KEYRING_DIRECTORIES or not re.fullmatch(r"[A-Za-z0-9_.+-]+\.(?:gpg|pgp|asc)", path.name):
            raise ProbeError("APT key aliases must resolve to a key file in an approved keyring directory")
    _safe_info(path)
    return str(path)


def _read(path, limit):
    _safe_info(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if os.fstat(stream.fileno()).st_size > limit:
            raise ProbeError("APT input exceeds its size limit")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ProbeError("APT input exceeds its size limit")
    return raw


def _fingerprint_tree(roots, *, limit, skip=()):
    records = []
    total = 0
    for root in roots:
        if not root.exists():
            records.append([str(root), None])
            continue
        _safe_info(root, directory=True)
        for directory, dirs, files in os.walk(root, followlinks=False):
            links = sorted(d for d in dirs if d not in skip and (Path(directory) / d).is_symlink())
            dirs[:] = sorted(d for d in dirs if d not in skip and d not in links)
            for name in dirs:
                _safe_info(Path(directory) / name, directory=True)
            for name in sorted(files + links):
                if name in skip:
                    continue
                path = Path(directory) / name
                if path.is_symlink():
                    if len(records) >= 10000:
                        raise ProbeError("APT configuration or indexes exceed their aggregate limit")
                    records.append([str(path), "link", _safe_link(path, roots)])
                    continue
                info = _safe_info(path)
                total += info.st_size
                if total > limit or len(records) >= 10000:
                    raise ProbeError("APT configuration or indexes exceed their aggregate limit")
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                checksum = hashlib.sha256()
                read = 0
                with os.fdopen(descriptor, "rb") as stream:
                    while chunk := stream.read(65536):
                        read += len(chunk)
                        if read > info.st_size:
                            raise ProbeError("APT input changed while hashing")
                        checksum.update(chunk)
                if read != info.st_size:
                    raise ProbeError("APT input changed while hashing")
                records.append([str(path), info.st_mode & 0o777, checksum.hexdigest()])
    return _digest(records)


def _paragraphs(raw):
    """Strict case-insensitive Debian control parser, preserving continuations."""
    if not isinstance(raw, str) or len(raw) > 4 * 1024 * 1024:
        raise ProbeError("control metadata exceeds its size limit")
    if any((ord(c) < 32 and c not in "\n\t") or ord(c) == 127 for c in raw):
        raise ProbeError("control metadata contains unsupported characters")
    result, current, key = [], {}, None
    for line in raw.split("\n"):
        if not line:
            if current:
                result.append(current)
            current, key = {}, None
        elif line[0] in " \t":
            if key is None:
                raise ProbeError("control continuation has no field")
            current[key] += "\n" + line[1:]
        else:
            field, separator, value = line.partition(":")
            field = field.lower()
            if not separator or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", field) or field in current:
                raise ProbeError("control metadata has malformed or duplicate fields")
            current[field] = value.strip(" \t")
            key = field
    if current:
        result.append(current)
    return result


def _single(raw):
    paragraphs = _paragraphs(raw)
    if len(paragraphs) != 1:
        raise ProbeError("expected one complete control paragraph")
    return paragraphs[0]


def _source_entry(uri, suite, components, key, architectures="amd64"):
    parsed = urlsplit(uri)
    ports = {"https": (None, 443), "http": (None, 80)}
    if (parsed.scheme not in ports or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.port not in ports[parsed.scheme]
            or any(ord(c) <= 32 or ord(c) >= 127 for c in uri) or "%" in uri):
        raise ProbeError("APT sources require plain HTTP(S) archive URLs without credentials or query strings")
    if suite not in CODENAMES or architectures != "amd64":
        raise ProbeError("APT source suite or architecture is unsupported")
    if not components or any(c not in ("main", "contrib", "non-free", "non-free-firmware") for c in components):
        raise ProbeError("APT source component is unsupported")
    keypath = Path(key)
    if (not keypath.is_absolute() or keypath.parent not in KEYRING_DIRECTORIES
            or not re.fullmatch(r"[A-Za-z0-9_.+-]+\.(?:gpg|pgp|asc)", keypath.name)):
        raise ProbeError("APT sources require an explicit key file in an approved keyring directory")
    return {"uri": uri.rstrip("/") + "/", "suite": suite, "components": components, "key": key}


def parse_sources(content, *, deb822):
    """Parse the deliberately narrow reviewed source configuration subset."""
    entries = []
    if deb822:
        content = "\n".join(line for line in content.splitlines() if not line.startswith("#"))
        for record in _paragraphs(content):
            if set(record) - {"types", "uris", "suites", "components", "architectures", "signed-by", "enabled"}:
                raise ProbeError("APT source contains unsupported options or trust overrides")
            enabled = record.get("enabled", "yes").lower()
            types = record.get("types", "").split()
            if enabled not in ("yes", "no") or not types or set(types) - {"deb", "deb-src"} or len(set(types)) != len(types):
                raise ProbeError("APT source types or enabled flag are unsupported")
            # Disabled stanzas and source-code indexes cannot supply binaries.
            if enabled == "no" or "deb" not in types:
                continue
            for uri in record.get("uris", "").split():
                for suite in record.get("suites", "").split():
                    entries.append(_source_entry(uri, suite, record.get("components", "").split(),
                                                 record.get("signed-by", ""), record.get("architectures", "amd64")))
            if not record.get("uris") or not record.get("suites"):
                raise ProbeError("APT source requires URI and suite")
    else:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("deb-src "):
                continue  # Source-code indexes cannot supply binary candidates.
            match = re.fullmatch(r"deb \[([^\]]+)\] (\S+) (\S+) (.+)", line)
            if not match:
                raise ProbeError("APT list sources require explicit Signed-By options")
            options = {}
            for option in match[1].split():
                key, separator, value = option.partition("=")
                if not separator or key in options or key not in ("arch", "signed-by"):
                    raise ProbeError("APT source contains unsupported options or trust overrides")
                options[key] = value
            entries.append(_source_entry(match[2], match[3], match[4].split(), options.get("signed-by", ""),
                                         options.get("arch", "amd64")))
    return entries


def _configuration():
    roots = [Path("/etc/apt"), Path("/etc/dpkg"), Path("/usr/share/keyrings")]
    fingerprint = _fingerprint_tree(roots, limit=32 * 1024 * 1024)
    aptdir = roots[0]
    sources = []
    paths = [aptdir / "sources.list"]
    parts = aptdir / "sources.list.d"
    if parts.exists():
        paths += sorted(p for p in parts.iterdir() if p.suffix in (".list", ".sources"))
    for path in paths:
        if path.exists():
            sources += parse_sources(_read(path, 1024 * 1024).decode("utf-8"), deb822=path.suffix == ".sources")
    if not sources or len(sources) > 64:
        raise ProbeError("between one and 64 explicit APT sources are required")
    for source in sources:
        source["key"] = _resolve_key(source["key"])
        _read(Path(source["key"]), MAX_KEYRING)
    # All include targets must be fingerprinted; reject external include syntax
    # instead of guessing APT's config preprocessor semantics.
    conf = [aptdir / "apt.conf"]
    if (aptdir / "apt.conf.d").exists():
        conf += list((aptdir / "apt.conf.d").iterdir())
    for path in conf:
        if path.exists() and re.search(rb"#\s*include\b", _read(path, 1024 * 1024), re.I):
            raise ProbeError("external APT configuration includes are unsupported")
    # dpkg reads these files itself. Reject force/admindir/root/instdir/hook
    # directives that could defeat the fixed installation argument vector.
    dpkgconf = [Path("/etc/dpkg/dpkg.cfg")]
    if Path("/etc/dpkg/dpkg.cfg.d").exists():
        dpkgconf += list(Path("/etc/dpkg/dpkg.cfg.d").iterdir())
    for path in dpkgconf:
        if path.exists():
            for line in _read(path, 1024 * 1024).decode("utf-8").splitlines():
                line = line.strip()
                # Path filters change which payload files are unpacked, not
                # package selection, authentication or the dpkg database.
                if (line and not line.startswith("#") and line not in ("no-debsig", "log /var/log/dpkg.log")
                        and not re.fullmatch(r"path-(?:exclude|include)[ =]/[^\s]*", line)):
                    raise ProbeError("dpkg configuration has options outside the supported installation contract")
    return fingerprint, sources


def check_effective_config(config):
    """Reject insecure authentication, redirected inputs and executable overrides."""
    for key in config.keys():
        lowered = key.lower()
        value = config.find(key)
        if any(word in lowered for word in ("allowunauthenticated", "allowinsecure", "allowweak", "allowdowngradetoinsecure")):
            if str(value).lower() not in ("", "0", "false", "no"):
                raise ProbeError("APT configuration permits insecure authentication")
        if any(word in lowered for word in ("check-valid-until", "check-date", "verify-peer", "verify-host")):
            if str(value).lower() not in ("1", "true", "yes"):
                raise ProbeError("APT configuration disables date or transport verification")
        if lowered.startswith(("dpkg::options", "dir::bin", "apt::solver", "apt::planner")) and value:
            # Standard executable locations appear in APT defaults.
            defaults = {"dir::bin::methods": "/usr/lib/apt/methods", "dir::bin::dpkg": "/usr/bin/dpkg",
                        "dir::bin::solvers": "/usr/lib/apt/solvers", "dir::bin::planners": "/usr/lib/apt/planners"}
            if defaults.get(lowered.rstrip(":")) != value:
                raise ProbeError("APT configuration changes package execution semantics")
    required_dirs = {"Dir": "/", "Dir::Etc": "/etc/apt/", "Dir::Etc::parts": "/etc/apt/apt.conf.d/",
                     "Dir::Etc::sourceparts": "/etc/apt/sources.list.d/", "Dir::Etc::preferencesparts": "/etc/apt/preferences.d/",
                     "Dir::Etc::trustedparts": "/etc/apt/trusted.gpg.d/", "Dir::State::lists": "/var/lib/apt/lists/"}
    required_files = {"Dir::Etc::main": "/etc/apt/apt.conf", "Dir::Etc::sourcelist": "/etc/apt/sources.list",
                      "Dir::Etc::preferences": "/etc/apt/preferences", "Dir::Etc::trusted": "/etc/apt/trusted.gpg",
                      "Dir::State::status": "/var/lib/dpkg/status"}
    for key, path in required_dirs.items():
        if os.path.normpath(config.find_dir(key)) != os.path.normpath(path):
            raise ProbeError("APT configuration redirects trusted directories")
    for key, path in required_files.items():
        actual = config.find_file(key)
        if key == "Dir::Etc::trusted" and not actual:
            continue  # APT 3 removed this legacy default; every source has Signed-By.
        if actual != path:
            raise ProbeError("APT configuration redirects trusted files")


def _metadata_digest():
    return _fingerprint_tree([Path("/var/lib/apt/lists")], limit=2 * 1024 * 1024 * 1024,
                             skip=("lock", "partial", "auxfiles"))


def _release_fields(raw):
    content = raw.decode("utf-8")
    if not content.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
        raise ProbeError("only clear-signed InRelease metadata is supported")
    _, separator, content = content.partition("\n\n")
    content, ending, _ = content.partition("\n-----BEGIN PGP SIGNATURE-----")
    if not separator or not ending:
        raise ProbeError("InRelease has an invalid signed-message envelope")
    return _single("\n".join(line[2:] if line.startswith("- ") else line for line in content.split("\n")))


def release_freshness(fields):
    def date(key):
        try:
            parsed = parsedate_to_datetime(fields[key])
            if parsed.tzinfo is None:
                raise ValueError
            return int(parsed.timestamp())
        except (KeyError, ValueError, TypeError, OverflowError) as exc:
            raise ProbeError("Release requires a valid timezone-qualified date") from exc
    return {"codename": fields.get("codename"), "date": date("date"),
            "valid_until": date("valid-until") if "valid-until" in fields else None}


def _keyring_output_limit():
    # This probe is a single-threaded isolated process. Apply the file bound in
    # the conversion child only; never change the parent's resource limits.
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = MAX_KEYRING if hard == resource.RLIM_INFINITY else min(MAX_KEYRING, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def _command(argv, *, home, keyring_output=False):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30, check=False, close_fds=True,
                                cwd=str(home), env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                                   "HOME": str(home), "GNUPGHOME": str(home)},
                                preexec_fn=_keyring_output_limit if keyring_output else None)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProbeError("repository key conversion or signature verification failed") from exc
    if result.returncode != 0:
        raise ProbeError("repository key conversion or signature verification failed")


def _verify_release(key, release):
    # gpgv expects binary OpenPGP keyrings, not ASCII armor. Convert only the
    # explicit bounded Signed-By file; never import keys or discover trust.
    with tempfile.TemporaryDirectory(prefix="autoprotect-gpg-", dir="/tmp") as directory:
        home = Path(directory)
        keyring = Path(key)
        if keyring.suffix == ".asc":
            raw = _read(keyring, MAX_KEYRING)
            armored = home / "archive.asc"
            with armored.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw)
            keyring = home / "archive.gpg"
            _command(["/usr/bin/gpg", "--no-options", "--homedir", directory, "--batch", "--no-tty",
                      "--no-autostart", "--no-default-keyring", "--no-auto-key-retrieve", "--no-auto-key-import",
                      "--output", str(keyring), "--dearmor", str(armored)], home=home, keyring_output=True)
            if not 0 < keyring.stat().st_size <= MAX_KEYRING:
                raise ProbeError("converted repository keyring is empty or exceeds its size limit")
        _command(["/usr/bin/gpgv", "--homedir", directory, "--keyring", str(keyring), str(release)], home=home)


def _index_hash(path):
    # apt-helper understands APT's on-disk lz4/gzip/xz representation. Hash the
    # uncompressed Packages bytes, which Release authenticates. No extraction.
    process = subprocess.Popen(["/usr/lib/apt/apt-helper", "cat-file", str(path)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    try:
        checksum, size = hashlib.sha256(), 0
        while chunk := process.stdout.read(65536):
            size += len(chunk)
            if size > MAX_INDEX:
                raise ProbeError("uncompressed package index exceeds its limit")
            checksum.update(chunk)
        if process.wait(timeout=10) != 0:
            raise ProbeError("package index decompression failed")
        return checksum.hexdigest(), size
    finally:
        if process.poll() is None:
            process.kill()
        process.stdout.close()
        process.wait(timeout=10)


def _signed_release(apt_pkg, source):
    """Read and authenticate one source's local InRelease with its own key."""
    prefix = source["uri"] + "dists/" + source["suite"] + "/"
    release = Path("/var/lib/apt/lists") / apt_pkg.uri_to_filename(prefix + "InRelease")
    raw = _read(release, 4 * 1024 * 1024)
    _verify_release(source["key"], release)
    fields = _release_fields(raw)
    if fields.get("codename") != source["suite"]:
        raise ProbeError("signed Release codename differs from the configured codename")
    return fields


def _origin(fields, source, component):
    return {"origin": fields.get("origin"), "label": fields.get("label"), "archive": fields.get("suite"),
            "codename": fields.get("codename"), "component": component, "site": urlsplit(source["uri"]).hostname}


def _verified_index(apt_pkg, package_file, sources):
    filename = Path(package_file.filename)
    _safe_info(filename)
    if filename.parent != Path("/var/lib/apt/lists"):
        raise ProbeError("candidate package index is outside the fixed APT state directory")
    for source in sources:
        for component in source["components"]:
            relative = component + "/binary-amd64/Packages"
            prefix = source["uri"] + "dists/" + source["suite"] + "/"
            expected = apt_pkg.uri_to_filename(prefix + relative)
            if filename.name not in [expected + suffix for suffix in ("", ".lz4", ".gz", ".xz", ".bz2")]:
                continue
            fields = _signed_release(apt_pkg, source)
            sums = {}
            for line in fields.get("sha256", "").splitlines():
                if not line.strip():
                    continue  # The normal multiline field starts after an empty header.
                parts = line.split()
                if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]) or not parts[1].isdigit():
                    raise ProbeError("Release SHA-256 entries are malformed")
                if parts[2] in sums:
                    raise ProbeError("Release contains duplicate SHA-256 paths")
                sums[parts[2]] = (parts[0], int(parts[1]))
            if relative not in sums or _index_hash(filename) != sums[relative]:
                raise ProbeError("local Packages bytes do not match the signed Release")
            origin = _origin(fields, source, component)
            # Check APT's cached origin as well as the signed Release fields.
            for key in ("origin", "label", "archive", "component", "site"):
                if getattr(package_file, key) != origin[key]:
                    raise ProbeError("APT cached origin differs from signed Release identity")
            return origin, release_freshness(fields)
    raise ProbeError("candidate index cannot be mapped to an approved explicit source")


def control_identity(record):
    name, binary, architecture = record.get("package"), record.get("version"), record.get("architecture")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{1,127}", name):
        raise ProbeError("package control name is invalid")
    if not isinstance(binary, str) or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]{0,255}", binary):
        raise ProbeError("package control version is invalid")
    if architecture not in ("amd64", "all"):
        raise ProbeError("package control architecture is unsupported")
    source = record.get("source", name)
    match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]{1,127})(?: \(([0-9][A-Za-z0-9.+:~\-]{0,255})\))?", source)
    if not match:
        raise ProbeError("package source identity is malformed")
    return {"name": name, "version": binary, "architecture": architecture,
            "source_name": match[1], "source_version": match[2] or binary,
            "relationships": {key: record.get(key.lower(), "") for key in ("Conflicts", "Breaks", "Replaces")},
            "essential": record.get("essential", "no") != "no" or record.get("protected", "no") != "no"}


def _checked_config(apt_pkg):
    config_digest, sources = _configuration()
    apt_pkg.init_config()
    # debSystem::Initialize normally fills this default during init_system.
    # Supply only the missing fixed default so all overrides are checked before
    # any native cache/system initialization can consult execution settings.
    if not apt_pkg.config.find("Dir::State::status"):
        apt_pkg.config.set("Dir::State::status", "/var/lib/dpkg/status")
    check_effective_config(apt_pkg.config)
    return config_digest, sources


def _config_report(apt_pkg):
    """Describe the effective reviewed inputs; this observation approves nothing.

    The administrator compares sources, key file digests and signed origins
    with an independent review before copying any value into policy.
    """
    config_digest, sources = _checked_config(apt_pkg)
    report_sources, origins = [], {}
    for source in sources:
        key = _read(Path(source["key"]), MAX_KEYRING)
        entry = {"uri": source["uri"], "suite": source["suite"], "components": source["components"],
                 "key": source["key"], "key_sha256": hashlib.sha256(key).hexdigest(), "release": None}
        try:
            fields = _signed_release(apt_pkg, source)
        except FileNotFoundError:
            entry["release"] = "missing; run the separately authorized index refresh before reviewing origins"
        else:
            freshness = release_freshness(fields)
            entry["release"] = {"date": freshness["date"], "valid_until": freshness["valid_until"]}
            for component in source["components"]:
                origin = _origin(fields, source, component)
                origins[_canonical(origin)] = origin
        report_sources.append(entry)
    return {"config_digest": config_digest, "sources": report_sources,
            "origins": [origins[key] for key in sorted(origins)]}


def _resolve(apt, apt_pkg, name, architecture):
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{1,127}", name) or architecture not in ("amd64", "all"):
        raise ProbeError("package selector is invalid")
    config_digest, sources = _checked_config(apt_pkg)
    # Opening local metadata must not create persistent cache files.
    apt_pkg.config.set("Dir::Cache::pkgcache", "")
    apt_pkg.config.set("Dir::Cache::srcpkgcache", "")
    apt_pkg.init_system()
    metadata_digest = _metadata_digest()
    cache = apt.Cache(progress=None)
    package = cache[name + ":amd64"]
    candidate, installed = package.candidate, package.installed
    if candidate is None or installed is None or candidate.architecture != architecture or installed.architecture != architecture:
        raise ProbeError("APT candidate or installed architecture is missing or changed")
    if package.essential or cache.broken_count or package.is_now_broken or package.is_inst_broken:
        raise ProbeError("APT package state is essential or broken")
    source_list = apt_pkg.SourceList()
    source_list.read_main_list()
    records = apt_pkg.PackageRecords(cache._cache)
    artifacts, identities, origins, releases = [], [], {}, {}
    for same_version in package.versions:
        if same_version.version != candidate.version:
            continue
        for package_file, index in same_version._cand.file_list:
            if package_file.filename == "/var/lib/dpkg/status":
                continue
            source_index = source_list.find_index(package_file)
            if source_index is None or not source_index.is_trusted:
                raise ProbeError("APT candidate is not from an authenticated index")
            if not records.lookup((package_file, index)):
                raise ProbeError("APT candidate record cannot be read")
            record = _single(records.record)
            identity = control_identity(record)
            if identity["name"] != name or identity["architecture"] != architecture or identity["version"] != candidate.version:
                raise ProbeError("APT candidate record identity is inconsistent")
            sha, size = record.get("sha256", ""), record.get("size", "")
            if not re.fullmatch(r"[0-9a-f]{64}", sha) or not size.isdigit() or not 1 <= int(size) <= MAX_ARTIFACT:
                raise ProbeError("APT candidate requires bounded size and SHA-256")
            if not re.fullmatch(r"pool/[A-Za-z0-9_+./%:~\-]+\.deb", record.get("filename", "")) or ".." in record["filename"]:
                raise ProbeError("APT artifact filename is outside the archive pool")
            origin, release = _verified_index(apt_pkg, package_file, sources)
            origins[_canonical(origin)] = origin
            constraint = {"origin": origin, "codename": release["codename"],
                          "date": release["date"], "valid_until": release["valid_until"]}
            releases[_canonical(constraint)] = constraint
            if len(releases) > MAX_RELEASES:
                raise ProbeError("contributing release constraints exceed their limit")
            artifacts.append((sha, int(size)))
            identities.append(identity)
    if not artifacts or len(set(artifacts)) != 1 or any(i != identities[0] for i in identities):
        raise ProbeError("same-version candidate artifacts are absent or ambiguous")
    identity = identities[0]
    if identity["essential"] or any(identity["relationships"].values()):
        raise ProbeError("candidate contains prohibited essential or relationship fields")
    if identity["source_name"] != installed.source_name:
        raise ProbeError("candidate source identity differs from installed lineage")
    if _configuration()[0] != config_digest or _metadata_digest() != metadata_digest:
        raise ProbeError("APT inputs changed during candidate resolution")
    target = {"name": name, "architecture": architecture, "from_version": installed.version,
              "to_version": candidate.version, "source_name": identity["source_name"], "source_version": identity["source_version"],
              "sha256": artifacts[0][0], "size": artifacts[0][1], "origins": [origins[key] for key in sorted(origins)],
              "config_digest": config_digest, "metadata_digest": metadata_digest}
    # Version/Package objects can refer back to the Cache through weak proxies.
    # Keep the cache alive through fetch_binary in the download caller.
    return {"target": target, "authenticated": True, "essential": False,
            "relationships": identity["relationships"], "releases": [releases[key] for key in sorted(releases)]}, candidate, cache


def _download(apt, apt_pkg, args):
    name, architecture, version, sha, size, config, metadata, destination = args
    evidence, candidate, cache = _resolve(apt, apt_pkg, name, architecture)
    target = evidence["target"]
    if (target["to_version"], target["sha256"], str(target["size"]), target["config_digest"], target["metadata_digest"]) != (
            version, sha, size, config, metadata):
        raise ProbeError("download inputs no longer match the approved candidate")
    staging = Path(destination)
    info = _safe_info(staging, directory=True)
    if info.st_mode & 0o077 or not staging.is_absolute() or staging.resolve() != staging or list(staging.iterdir()):
        raise ProbeError("download requires an empty private staging directory")
    resource.setrlimit(resource.RLIMIT_FSIZE, (target["size"], target["size"]))
    from apt.progress.base import AcquireProgress

    class BoundedProgress(AcquireProgress):
        def pulse(self, owner):
            return self.current_bytes <= target["size"]

    fetched = Path(candidate.fetch_binary(str(staging), progress=BoundedProgress(), allow_unauthenticated=False))
    if fetched.parent != staging or not fetched.is_file() or fetched.is_symlink():
        raise ProbeError("APT returned a download outside the private staging directory")
    if set(staging.iterdir()) != {fetched}:
        raise ProbeError("APT downloaded unexpected files")
    os.chmod(fetched, 0o600)
    fetched.rename(staging / "package.deb")
    return {"downloaded": True}


def _artifact(apt_inst, path):
    # Inspect only control metadata; never extract or execute package payloads.
    package = apt_inst.DebFile(path)
    controls = []

    def member(info, data):
        if info.name in ("control", "./control"):
            if not info.isfile() or not 0 < info.size <= MAX_CONTROL:
                raise ProbeError("package control member is not a bounded regular file")
            controls.append(info.name)

    package.control.go(member, extract_data=False)
    if len(controls) != 1:
        raise ProbeError("package archive must have exactly one control member")
    raw = package.control.extractdata(controls[0])
    if len(raw) > MAX_CONTROL:
        raise ProbeError("package control exceeds its byte limit")
    return control_identity(_single(raw.decode("utf-8")))


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        # Isolated system Python loads distribution bindings, not venv packages.
        import apt
        import apt_pkg
        import apt_inst
        if len(args) == 3 and args[0] == "resolve":
            result = _resolve(apt, apt_pkg, args[1], args[2])[0]
        elif len(args) == 9 and args[0] == "download":
            result = _download(apt, apt_pkg, args[1:])
        elif len(args) == 2 and args[0] == "artifact":
            result = _artifact(apt_inst, args[1])
        elif len(args) == 1 and args[0] == "config":
            result = _config_report(apt_pkg)
        else:
            raise ProbeError("unsupported probe action or arguments")
        print(_canonical(result))
        return 0
    except (Exception,):
        # Do not expose repository credentials, raw records or tool diagnostics.
        print('{"error":"APT prerequisite, configuration, signature or artifact check failed"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
