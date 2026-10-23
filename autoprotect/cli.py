"""Command-line boundary over the policy-bound runtime; no trust overrides."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys

from . import __version__, core, local_files
from .backends import DebianApt, Simulator, _NATIVE_STATE
from .engine import Engine, validate_policy
from .store import Store


_POLICY_BYTES = 1024 * 1024
_DATA_BYTES = 64 * 1024 * 1024
_FEED_BYTES = {"pwn": 8 * 1024 * 1024, "debian": 128 * 1024 * 1024}
_LIVE_COMMANDS = {"execute", "recovery-status", "recover", "resolve-recovery"}
_STATE_NAMES = ("state.sqlite3", "state.sqlite3-journal", "state.sqlite3-wal", "state.sqlite3-shm",
                "simulator.json", "simulator.json.lock", "simulator.json.gate", "simulator.json.generation")
# These are the backend's fixed exclusive-publication aliases. They must not
# contain operator inputs: recovery may remove an unpublished gate alias.
_STATE_NAMES += tuple(".publish-" + hashlib.sha256(name.encode("ascii")).hexdigest()
                      for name in ("simulator.json", "simulator.json.gate"))


class _ArgumentError(Exception):
    pass


class _HelpRequested(Exception):
    pass


class _OutputError(Exception):
    pass


def _write_output(stream, value):
    try:
        stream.write(value)
        stream.flush()
    except (OSError, ValueError) as exc:
        # Failed buffered writes can be retried at interpreter shutdown,
        # leaking a raw diagnostic and replacing our exit code with 120.
        # Close only the failing interpreter-owned standard stream. Caller
        # streams (redirected captures, embedded use) remain caller-owned.
        if stream is sys.__stdout__ or stream is sys.__stderr__:
            try:
                stream.close()
            except (OSError, ValueError):
                pass  # TextIOWrapper closes its buffer even if flushing fails.
        raise _OutputError() from exc


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def _print_message(self, message, file=None):
        if message:
            _write_output(file if file is not None else sys.stderr, message)

    def error(self, message):
        # argparse's default usage/error output can contain untrusted argv.
        raise _ArgumentError(message)

    def exit(self, status=0, message=None):
        if status:
            raise _ArgumentError(message or "Invalid command arguments; use --help")
        raise _HelpRequested()


def _parser():
    parser = _Parser(prog="autoprotect", description="Investigate advisories and run policy-authorized remediation.",
                     epilog="Place operational options before the command. Output is JSON except help/version.")
    parser.add_argument("--version", action="version", version=f"autoprotect {__version__}")
    parser.add_argument("--state-dir", metavar="DIR", help="private state directory; required for operational commands")
    parser.add_argument("--policy", metavar="FILE", help="private policy JSON; required for operational commands")
    parser.add_argument("--live", action="store_true", help="opt into native execution/recovery; requires effective root")
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("init-simulator", help="initialize new disposable simulator state, never replace it")
    setup.add_argument("--inventory", required=True, metavar="FILE")
    setup.add_argument("--catalog", required=True, metavar="FILE")
    ingest = commands.add_parser("import-feed", help="import untrusted feed data without HTTPS provenance")
    ingest.add_argument("source", choices=("pwn", "debian"), metavar="SOURCE")
    ingest.add_argument("file", metavar="FILE")
    poll = commands.add_parser("poll", help="fetch one fixed HTTPS source; failure retains last good data")
    poll.add_argument("source", choices=("pwn", "debian"), metavar="SOURCE")
    inventory = commands.add_parser("inventory", help="collect selected-backend inventory or import untrusted data")
    inventory.add_argument("--import", dest="import_file", metavar="FILE")
    for name, help_text in (("triage", "match supported advisories and report unknown coverage"),
                            ("export", "export untrusted advisory data, not instructions")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("asset_id", metavar="ASSET_ID")
    plan = commands.add_parser("plan", help="create an immutable plan from a finding")
    plan.add_argument("finding_id", metavar="FINDING_ID")
    for name, help_text in (("approve", "approve an immutable plan under current policy"),
                            ("execute", "execute with manual approval or automatic policy authorization"),
                            ("recovery-status", "inspect the target gate under recovery locks"),
                            ("recover", "record abandoned execution as needs_attention, not success"),
                            ("resolve-recovery", "attest recovery and clear the gate, never certify success")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("plan_id", metavar="PLAN_ID")
        if name in ("approve", "resolve-recovery"):
            command.add_argument("--actor", required=True, metavar="LABEL",
                                 help="operator audit label, not authenticated identity")
        if name == "resolve-recovery":
            command.add_argument("--reason", required=True, metavar="TEXT", help="explicit recovery attestation")
            command.add_argument("--malformed-digest", metavar="SHA256", help="exact digest from recovery-status")
    commands.add_parser("queue", help="show persisted plans and their status")
    commands.add_parser("audit", help="show persisted audit events")
    commands.add_parser("demo", help="run isolated simulation; accepts no operational global options")
    commands.add_parser("native-config", help="report local APT configuration digest, sources and signed origins "
                                              "for review; approves nothing and accepts no global options")
    return parser


def _policy_provider(path, *, live):
    selected_backend = None

    def load():
        nonlocal selected_backend
        raw = local_files.read_bytes(path, max_bytes=_POLICY_BYTES, private=True, live=live)
        policy = validate_policy(core.load_json(raw, max_bytes=_POLICY_BYTES))
        if selected_backend is not None and policy["backend"] != selected_backend:
            raise core.PolicyError("Policy backend changed during this command; restart with the intended policy")
        selected_backend = policy["backend"]
        return policy

    return load


class _DeferredBackend:
    """Do not even open backend state for imports or persisted investigations."""

    def __init__(self, name, simulator_path, *, live):
        self.name = name
        self._path = simulator_path
        self._live = live
        self._backend = None

    def __getattr__(self, name):
        if self._backend is None:
            self._backend = Simulator(self._path) if self.name == "simulator" else DebianApt(live=self._live)
        return getattr(self._backend, name)


def _json_file(path, *, object_required=False):
    data = core.load_json(local_files.read_bytes(path, max_bytes=_DATA_BYTES),
                          max_bytes=_DATA_BYTES, max_nodes=8_000_000)
    # In Engine.inventory, None means actual collection, not an imported null.
    if object_required and type(data) is not dict:
        raise core.ValidationError("Inventory input must be a JSON object, not a collection request")
    return data


def _comparison_path(path):
    # Linux treats / and // as the same root, unlike abspath's spelling.
    # This key is ONLY for collision checks. Always give original paths to
    # protected traversal, so normalization cannot erase unsafe ancestors.
    return "/" + os.path.abspath(path).lstrip("/")


def _inputs(args):
    paths = [args.policy]
    data = {}
    if args.command == "init-simulator":
        paths += [args.inventory, args.catalog]
        data["inventory"] = _json_file(args.inventory, object_required=True)
        data["catalog"] = _json_file(args.catalog)
    elif args.command == "import-feed":
        paths.append(args.file)
        data["raw"] = local_files.read_bytes(args.file, max_bytes=_FEED_BYTES[args.source])
    elif args.command == "inventory" and args.import_file is not None:
        paths.append(args.import_file)
        data["inventory"] = _json_file(args.import_file, object_required=True)
    # This comparison never opens a normalized path. The helpers separately
    # validate every original component (including those before '..'). Inputs
    # cannot also be database, simulator or coordination files we may write.
    destinations = {_comparison_path(os.path.join(args.state_dir, name)) for name in _STATE_NAMES}
    # Native coordination is shared across databases, not beneath state_dir.
    # Recovery may delete an unpublished gate alias; never let an operator
    # policy/import become that disposable file, even on an investigation call.
    native_names = ("local.lock", "local.gate", "local.generation",
                    ".publish-" + hashlib.sha256(b"local.gate").hexdigest())
    destinations.update(_comparison_path(_NATIVE_STATE / name) for name in native_names)
    if any(_comparison_path(path) in destinations for path in paths):
        raise core.ValidationError("Policy and input files must be separate from fixed writable state paths")
    return data


def _dispatch(engine, args, data):
    command = args.command
    if command == "import-feed":
        return engine.ingest(args.source, data["raw"])
    if command == "poll":
        return engine.poll(args.source)
    if command == "inventory":
        return engine.inventory(data["inventory"]) if "inventory" in data else engine.inventory()
    if command in ("triage", "export"):
        return getattr(engine, command)(args.asset_id)
    if command == "plan":
        return engine.plan(args.finding_id)
    if command == "approve":
        return engine.approve(args.plan_id, args.actor)
    if command in ("execute", "recover", "recovery-status"):
        return getattr(engine, command.replace("-", "_"))(args.plan_id)
    if command == "resolve-recovery":
        return engine.resolve_recovery(args.plan_id, args.actor, args.reason, malformed_digest=args.malformed_digest)
    if command in ("queue", "audit"):
        return getattr(engine, command)()
    raise core.ValidationError("Unsupported command")


def _require_trusted_code():
    # Any root invocation, not only --live, would run this code with root
    # privileges, including native-config's APT helper and inventory queries.
    try:
        local_files.require_trusted_code(os.path.dirname(os.path.abspath(__file__)), sys.path)
    except core.ValidationError as exc:
        raise core.PolicyError("Running as root requires a root-owned installation and module search path; run the "
                               "installed entry point or python3 -I from a root-owned location (" + str(exc) + ")") from exc


def _operate(args):
    if args.live and os.geteuid() != 0:
        raise core.PolicyError("--live requires effective root; use non-live commands for investigation")
    provider = _policy_provider(args.policy, live=args.live)
    policy = provider()
    if policy["backend"] == "simulator" and args.live:
        raise core.PolicyError("--live is not permitted for the simulator")
    if policy["backend"] == "debian-apt" and args.command in _LIVE_COMMANDS and not args.live:
        raise core.PolicyError("Native execution and recovery locks require explicit --live and effective root")
    if args.command == "init-simulator" and policy["backend"] != "simulator":
        raise core.PolicyError("init-simulator requires a simulator policy")
    data = _inputs(args)
    if args.command == "init-simulator" and any(
        os.path.lexists(os.path.join(args.state_dir, name)) for name in _STATE_NAMES
    ):
        raise core.ValidationError("Simulator setup requires new state; use a fresh private directory without existing state files")
    database = local_files.prepare_database(args.state_dir, live=args.live)
    simulator_path = database.parent / "simulator.json"
    with Store(database) as store:
        if args.command == "init-simulator":
            backend = Simulator.initialize(simulator_path, data["inventory"], data["catalog"])
            inventory = Engine(store, provider, backend).inventory()
            return {"status": "initialized", "backend": "simulator", "simulation_only": True,
                    "state_dir": str(database.parent), "simulator_path": str(simulator_path), "inventory": inventory}
        backend = _DeferredBackend(policy["backend"], simulator_path, live=args.live)
        return _dispatch(Engine(store, provider, backend), args, data)


def _native_config():
    """Read-only observation of the local APT inputs a native policy would bind.

    The report is evidence for an administrator's independent review, never an
    approval: nothing here writes policy or state, and copying a digest that
    was not reviewed would defeat the configuration binding.
    """
    report = DebianApt().configuration_report()
    return {"kind": "native-configuration-observation", "approved": False,
            "warning": ("Observation only. Review every source, key file digest and origin independently before "
                        "copying config_digest into approved_config_digest or origins into allowed_origins."),
            **report}


def _error(code, message, status):
    # Exception messages from our runtime are operator-facing. Bound them and
    # escape even lone surrogates in argv; never stringify OS/subprocess errors.
    encoded = json.dumps({"error": {"code": code, "message": message[:2048]}}, ensure_ascii=True, allow_nan=False)
    try:
        _write_output(sys.stderr, encoded + "\n")
    except _OutputError:
        pass  # Keep the original error's exit code if its diagnostic is undeliverable.
    return status


def main(argv=None):
    """Return a process exit code; help/version are the only plain-text output."""
    try:
        args = _parser().parse_args(argv)
        if os.geteuid() == 0:
            _require_trusted_code()
        if args.command in ("demo", "native-config"):
            if args.state_dir is not None or args.policy is not None or args.live:
                raise _ArgumentError(f"{args.command} accepts no --state-dir, --policy or --live options")
            if args.command == "demo":
                from .demo import run_demo
                result = run_demo()
            else:
                result = _native_config()
        else:
            if args.state_dir is None or args.policy is None:
                raise _ArgumentError("Operational commands require --state-dir DIR and --policy FILE before the command")
            result = _operate(args)
        output = core.canonical(result)
        _write_output(sys.stdout, output + "\n")
        if args.command == "poll" and result.get("error"):
            return 1
        if args.command == "execute" and result.get("status") != "succeeded":
            return 1
        return 0
    except _HelpRequested:
        return 0
    except _OutputError:
        return _error("io_error", "Command output could not be written; inspect queue and recovery state before retrying execution", 1)
    except _ArgumentError as exc:
        return _error("argument_error", str(exc), 2)
    except KeyboardInterrupt:
        return _error("interrupted", "Interrupted; inspect queue and recovery-status before retrying execution or resolving recovery", 130)
    except core.AutoprotectError as exc:
        if isinstance(exc, core.IndeterminateError):
            code = "indeterminate_error"
        elif isinstance(exc, core.PolicyError):
            code = "policy_error"
        elif isinstance(exc, core.ValidationError):
            code = "validation_error"
        elif isinstance(exc, core.BackendError):
            code = "backend_error"
        else:
            code = "application_error"
        return _error(code, str(exc), 1)
    except sqlite3.Error:
        return _error("state_error", "State operation failed; check protected state and inspect queue/recovery before retrying execution", 1)
    except OSError:
        return _error("io_error", "Local operation failed; check paths, permissions and storage, then inspect queue/recovery before retrying execution", 1)
    except Exception:
        return _error("internal_error", "Command failed unexpectedly; inspect queue and recovery state before retrying execution", 1)
