"""``x64dbg-vm-gateway`` command line (plan 5.1).

Commands::

    serve [--transport stdio|http]      MCP server (stdio for Claude Code, http for remote clients)
    doctor                              configuration / environment checks
    status                              session status (VM, backends, job)
    init                                write a config file (wizard, or --non-interactive flags)
    jobs [list | show JOB_ID]           read-only view of the job directories
    discard JOB_ID [--yes]              human-only: mark a job DISCARDED so it may be reverted
    provision --x64dbg-root PATH ...    prepare the guest (plugin config, tasks, auto-logon)
    install-plugin [--dist DIR] ...     copy a plugin build (default: the bundled one) into the guest
    setup [--dry-run] ...               init (no config yet), doctor, install-plugin, provision,
                                        doctor, then print the ``claude mcp add`` commands
    mcp-config [--client claude]        the ``claude mcp add`` commands for the gateway and the
                                        configured static tools (placeholders as <...>)
    static-scripts [--dest DIR]         where the packaged static-tool sync scripts are, or a copy
    snapshot refresh --name NEW         human-only: a new clean snapshot of the running guest
             [--set-clean]              (``provision.take_clean_snapshot``), recorded in
                                        ``snapshot_ledger``; --set-clean edits an init-written config
    snapshot prune --keep N [--yes]     human-only: gw-* and recorded old clean snapshots beyond the
                                        newest N (dry run unless --yes; protected / clean never)

Global options (before or after the command): ``--config PATH``, ``--profile NAME``,
``--json`` (machine-readable stdout), ``-v/--verbose``.

Exit codes: 0 success, 1 failure (gateway errors print code, message and hint),
2 usage error. Diagnostics and interactive prompts go to stderr; stdout carries
only results (and, for ``serve --transport stdio``, nothing but the MCP stream).
Output never fails on a stream whose encoding cannot represent it (a
redirected stdout on Windows uses the ANSI code page): JSON falls back to
ASCII escapes, which is the same data, and text to backslash escapes.

The orchestrator (``wiring.build_app``) and the provisioning module are
imported lazily inside the commands, so importing this module stays cheap and
tests can substitute them through ``sys.modules``. ``jobs`` reads the
``state.json`` files directly (read-only, no store lock) so it also works while
a gateway is serving.

A serving gateway holds the jobs root (``JobStore`` process lock). Commands
that need it (``discard``, ``status``, ``doctor``, ``provision``,
``install-plugin``, ``setup``, ``snapshot``) then fail with LOCK_TIMEOUT naming the gateway's
pid and what to do instead (stop it, or use its MCP tools). ``provision`` and
``install-plugin`` claim the jobs root first (so they never run next to a
serving gateway), pause supervision and hold the VM write lock while they
change the guest; after a plugin install (or a provisioning reboot) every
backend starts a new epoch and cached clients/tokens are dropped.

``install-plugin`` without ``--dist`` installs the build bundled in the package
(``plugin_bundle``; a release wheel carries it) and derives ``--x64dbg-root``
from the profile's backend paths. ``setup`` chains the commands with one
gateway instance: everything that can be checked locally (plugin build, guest
user and password, provisioning arguments, x64dbg root) is checked before the
VM is contacted; then the doctor precheck (which, like doctor, creates missing
job folders) stops on a failed check setup cannot fix
(``SETUP_BLOCKING_CHECKS``, plus the clean snapshot without provisioning) and
on an existing target snapshot (provisioning never replaces one). With
provisioning the plugin is installed without relaunch (on a fresh guest the
logon tasks do not exist yet; the provisioning reboot starts the debuggers).

``setup`` on a terminal (stdin a TTY, no ``--non-interactive``) asks for what the
flags, the config and the environment leave open: the VM (from ``vm_inventory``:
``vmrun list`` and the VMware library), the guest user, the guest password
(``getpass``; never echoed, logged or printed) and the x64dbg folder (offering
``provision.discover_x64dbg`` in the running guest), then offers to save the
credentials in a 0600 env file (``--save-password-file [PATH]`` does that without
asking; ``--force`` updates an existing one). The file is written only after the
doctor precheck's guest_credentials check passed (a refused or unchecked password
is not saved), restricted to its owner before the secret goes in. A new config
names the file in gateway.env_file (the profile keeps guest_user); an existing
config is never edited (setup prints the line).
Without a terminal, setup asks nothing and names the missing flags. Typed values
reach this run's gateway through the environment mapping handed to
``wiring.build_app``, never through ``os.environ``.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import getpass
import importlib
import json
import logging
import math
import os
import re
import shlex
import sys
import tempfile
import textwrap
import tomllib
import warnings
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any, TextIO

from .. import config as gw_config
from .. import envfile, plugin_bundle, static_scripts, static_tools
from .. import platform as gw_platform
from .. import policy as gw_policy
from .. import ps as gw_ps
from ..contracts import TERMINAL_JOB_STATES, PowerState, Secret
from ..errors import (
    ConfigError,
    GatewayError,
    GuestAuthFailed,
    JobNotFound,
    LockTimeout,
    StateViolation,
    TransferError,
    VmrunNotFound,
)
from ..jobs import DISCARD_ACTOR, JOB_ID_RE, Job, validate_job_id
from ..proxy import sanitize_untrusted_text
from .tool_defs import InternalError

log = logging.getLogger(__name__)

PROG = "x64dbg-vm-gateway"
EXIT_OK, EXIT_FAILURE, EXIT_USAGE = 0, 1, 2
_PACKAGE = __name__.rsplit(".", 2)[0]  # "x64dbg_vm_gateway"

DEFAULT_PROFILE_NAME = "win10"
DEFAULT_CLEAN_SNAPSHOT = "MCP_CLEAN"
DEFAULT_PASSWORD_ENV = "X64DBG_GW_GUEST_PW"  # noqa: S105 - a variable NAME, not a secret
DEFAULT_WAIT_READY_S = 300.0
DEFAULT_PLUGIN_BIND = "0.0.0.0"  # noqa: S104 - guest-side bind on the isolated host-only network
_BACKEND_LAYOUT = (  # (id, port, subdirectory, executable, scheduled task)
    ("x64", 9094, "x64", "x64dbg.exe", "MCP-x64dbg"),
    ("x32", 9095, "x32", "x32dbg.exe", "MCP-x32dbg"),
)
_MAX_STATE_BYTES = 16 * 1024 * 1024
VM_LOCK_TIMEOUT_S = 120.0  # wait for the VM write lock (in-process VM operations finish first)
_SERVING_ADVICE = {
    "discard": "stop that gateway first (discard is human-only and has no MCP tool), run discard again, "
               "then start the gateway again",
    "status": "use the running gateway's MCP tool session_status instead, or stop the gateway first",
    "doctor": "use the running gateway's MCP tool gateway_doctor instead, or stop the gateway first",
    "provision": "stop that gateway first: provisioning reboots the guest and must not run next to it",
    "install-plugin": "stop that gateway first: installing the plugin kills and relaunches the debuggers",
    "setup": "stop that gateway first: setup installs the plugin and reboots the guest",
    "serve": "a gateway is already serving this jobs root: connect to it, or stop it first",
    "snapshot": "stop that gateway first: snapshot refresh and prune change the VM's snapshots (they have no "
                "MCP tool)",
}
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_WIN_ABS_RE = re.compile(r"^[A-Za-z]:\\")
_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class UsageError(Exception):
    """Bad command line usage (exit code 2)."""


# ── output ──────────────────────────────────────────────────────────
def _safe(text: Any) -> str:
    """Strip terminal control characters from text that may come from the guest."""
    return sanitize_untrusted_text(str(text), max_len=10_000)


def _safe_command(text: Any) -> str:
    """``_safe`` for a line that carries a printed command, which is never cut short. The config
    refuses the characters the sanitiser strips (so the command is printed as configured);
    stripping stays as a last line of defence."""
    text = str(text)
    return sanitize_untrusted_text(text, max_len=max(len(text), 1))


def _dumps(value: Any, *, ascii_only: bool = False) -> str:
    return json.dumps(value, indent=2, ensure_ascii=ascii_only, default=str)


def _encodable(stream: TextIO, text: str) -> bool:
    try:
        text.encode(getattr(stream, "encoding", None) or "utf-8")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _emit(stream: TextIO, text: str, end: str = "\n") -> None:
    """Write ``text``; characters the stream cannot encode become backslash escapes."""
    text += end
    if not _encodable(stream, text):
        encoding = getattr(stream, "encoding", None) or "utf-8"
        try:
            text = text.encode(encoding, errors="backslashreplace").decode(encoding, errors="replace")
        except LookupError:
            text = text.encode("ascii", errors="backslashreplace").decode("ascii")
    stream.write(text)


def _emit_json(stream: TextIO, value: Any) -> None:
    text = _dumps(value)
    if not _encodable(stream, text):
        text = _dumps(value, ascii_only=True)  # \uXXXX escapes: the same JSON data
    _emit(stream, text)


def _prompt(text: str) -> str:
    """Ask on stderr (stdout carries only results) and read one line; EOFError at end of input."""
    _emit(sys.stderr, text, end="")
    sys.stderr.flush()
    return input()


class _Output:
    def __init__(self, json_mode: bool) -> None:
        self.json_mode = json_mode

    def data(self, value: Any, human: Callable[[Any], str] | None = None) -> None:
        if self.json_mode or human is None:
            _emit_json(sys.stdout, value)
        else:
            _emit(sys.stdout, human(value))

    def note(self, text: str) -> None:
        _emit(sys.stderr, text)

    def error(self, err: GatewayError) -> None:
        if self.json_mode:
            _emit_json(sys.stdout, {"ok": False, "error": err.to_dict()})
            return
        lines = [f"error [{err.code}]: {_safe(err.message)}"]
        if err.hint:
            lines.append(f"  hint: {_safe(err.hint)}")
        if err.next_tool:
            lines.append(f"  next: {err.next_tool}")
        _emit(sys.stderr, "\n".join(lines))


# ── shared helpers ──────────────────────────────────────────────────
def _load_config(args: argparse.Namespace) -> gw_config.GatewayConfig:
    return gw_config.load_config(args.config, environ=os.environ)


def _import(module: str) -> Any:
    name = f"{_PACKAGE}.{module}"
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as e:
        if e.name != name:
            raise
        raise InternalError(f"this installation has no {name} module", stage="cli",
                            hint="reinstall x64dbg-vm-gateway") from None


@contextlib.contextmanager
def _app(args: argparse.Namespace, config: gw_config.GatewayConfig,
         environ: Mapping[str, str] | None = None) -> Iterator[Any]:
    """The gateway for ``config``; ``environ`` (default: the process environment) is what its
    ``*_env`` names resolve in, over gateway.env_file."""
    app = _import("wiring").build_app(config, profile=args.profile,
                                      environ=os.environ if environ is None else environ)
    try:
        yield app
    finally:
        try:
            app.close()
        except Exception:
            log.warning("closing the gateway failed", exc_info=True)


def _runtime(app: Any, profile: str | None) -> Any:
    runtime = getattr(app, "runtime", None)
    if runtime is None:
        raise InternalError("this gateway build cannot provision guests (no runtime access)", stage="cli")
    return runtime(profile)


def _claim_jobs_root(app: Any) -> None:
    """Open the gateway's job store now: fails (LOCK_TIMEOUT naming the pid) while another
    gateway process serves the same jobs root, before anything in the guest changes."""
    opener = getattr(app, "open", None)
    if callable(opener):
        opener()


@contextlib.contextmanager
def _holding_vm(runtime: Any) -> Iterator[None]:
    """Supervision paused and the VM write lock held (like the gateway's own VM operations),
    so no relaunch or backend call of this process races with the guest changes."""
    with runtime.supervisor.paused(), runtime.lock.write(timeout_s=VM_LOCK_TIMEOUT_S):
        yield


def _new_epochs(app: Any, runtime: Any, profile: str | None, reason: str) -> list[str]:
    """The debuggers were killed/relaunched: every backend starts a new epoch, cached clients
    and tokens are dropped (the next connect re-reads them). The epochs live in this process
    only, so the job store records it too: the profile's jobs whose debugger held the sample
    get ``flags.debuggee_lost`` (``Gateway.note_debuggers_restarted``); returns their ids."""
    for bid in list(runtime.backends):
        runtime.supervisor.bump_epoch(bid, reason)
    invalidate = getattr(runtime, "invalidate_clients", None)
    if callable(invalidate):
        invalidate(drop_tokens=True, reason=reason)
    note = getattr(app, "note_debuggers_restarted", None)
    return list(note(profile, reason)) if callable(note) else []


def _report_lost(result: Any, lost: list[str], out: _Output) -> Any:
    """Name the jobs whose debuggee is gone (stderr, and in the result as debuggee_lost_jobs)."""
    if not lost:
        return result
    for job_id in lost:
        out.note(f"job {job_id}: the debuggers were restarted, its sample is no longer loaded")
    return {**result, "debuggee_lost_jobs": lost} if isinstance(result, Mapping) else result


def _explain(err: GatewayError, command: str) -> GatewayError:
    """A jobs root held by a serving gateway: say which process and what to do instead."""
    if not isinstance(err, LockTimeout) or "owner_pid" not in err.details:
        return err
    pid, host = err.details.get("owner_pid"), err.details.get("owner_host")
    who = f"pid {pid}" if pid is not None else "pid unknown"
    if host:
        who += f" on {host}"
    advice = _SERVING_ADVICE.get(command, "stop the running gateway first, or use its MCP tools")
    lock = err.details.get("lock")
    if lock:
        advice += f". Lock file: {lock} (delete it by hand only if no gateway runs)"
    return LockTimeout(
        f"another x64dbg-vm-gateway process ({who}) is serving this jobs root; `{command}` "
        "cannot run next to it",
        stage="cli", hint=advice, details=dict(err.details),
    )


def _is_windows_abs(path: str) -> bool:
    return bool(_WIN_ABS_RE.match(path.replace("/", "\\")))


def _require_windows_abs(path: str, flag: str) -> str:
    if not _is_windows_abs(path):
        raise UsageError(f"{flag} must be an absolute guest path such as C:\\x64dbg\\release")
    return str(PureWindowsPath(path.replace("/", "\\")))


def _confirm(prompt: str) -> bool:
    try:
        answer = _prompt(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


# ── serve / doctor / status ─────────────────────────────────────────
def cmd_serve(args: argparse.Namespace, out: _Output) -> int:
    config = _load_config(args)
    if args.transport == "http":
        if not config.http.enabled:
            raise ConfigError(
                "serve --transport http needs http.enabled = true in the config",
                stage="cli",
                hint="add an [http] table with enabled = true, bind, port and token_envs (see the README, "
                     "'Remote access')",
                details={"key": "http.enabled"},
            )
        from . import http_server

        # http.token_envs are *_env names: the real environment over gateway.env_file
        environ = envfile.resolve_environ(config, os.environ)
        http_server.check_http_config(config.http, environ)  # fail before touching the VM
        with _app(args, config) as app:
            http_server.serve_http(app, config.http, environ=environ, jobs_root=config.jobs_root_path)
        return EXIT_OK
    from . import mcp_server

    with _app(args, config) as app:
        mcp_server.run_stdio(app)
    return EXIT_OK


def _format_doctor(result: Any) -> str:
    raw = result.get("checks") if isinstance(result, Mapping) else None
    checks = [c for c in raw if isinstance(c, Mapping)] if isinstance(raw, list) else []
    lines = []
    warnings = 0
    for check in checks:
        ok = bool(check.get("ok"))
        warn = ok and check.get("level") == "warn"  # passes, but needs attention (e.g. static_tools)
        warnings += warn
        detail = check.get("detail")
        tag = "WARN" if warn else (" ok " if ok else "FAIL")
        line = f"[{tag}] {_safe(check.get('name'))}"
        lines.append(f"{line}: {_safe(detail)}" if detail else line)
        if (warn or not ok) and check.get("hint"):
            lines.append(f"       hint: {_safe(check['hint'])}")
    failed = sum(1 for c in checks if not c.get("ok"))
    ok_all = isinstance(result, Mapping) and bool(result.get("ok"))
    note = f" ({warnings} warning{'s' if warnings != 1 else ''})" if warnings else ""
    lines.append(f"doctor: all checks passed{note}" if ok_all else f"doctor: {failed} check(s) failed{note}")
    return "\n".join(lines)


def cmd_doctor(args: argparse.Namespace, out: _Output) -> int:
    config = _load_config(args)
    with _app(args, config) as app:
        result = app.doctor(args.profile)
    out.data(result, _format_doctor)
    return EXIT_OK if isinstance(result, Mapping) and result.get("ok") else EXIT_FAILURE


def cmd_status(args: argparse.Namespace, out: _Output) -> int:
    config = _load_config(args)
    with _app(args, config) as app:
        result = app.session_status(args.profile)
    out.data(result)
    return EXIT_OK


# ── discard ─────────────────────────────────────────────────────────
def cmd_discard(args: argparse.Namespace, out: _Output) -> int:
    job_id = validate_job_id(args.job_id)
    config = _load_config(args)
    if not args.yes and not _confirm(
            f"Discard job {job_id}? Its uncollected results are lost when the VM is reverted. [y/N] "):
        out.note("aborted: the job was not discarded")
        return EXIT_FAILURE
    with _app(args, config) as app:
        result = app.discard_job(job_id, actor=DISCARD_ACTOR)
    out.data(result, lambda r: f"job {job_id} discarded (state: {_safe(r.get('state', '?'))})"
             if isinstance(r, Mapping) else _dumps(r))
    return EXIT_OK


# ── jobs (read-only) ────────────────────────────────────────────────
def _read_job(state_file: Path) -> Job:
    with open(state_file, "rb") as f:
        data = f.read(_MAX_STATE_BYTES + 1)
    if len(data) > _MAX_STATE_BYTES:
        raise ValueError("state.json is too large")
    return Job.from_json(data)


def _job_row(job: Job) -> dict[str, Any]:
    sample = job.sample
    name = None
    if sample is not None:
        name = sample.original_name or PureWindowsPath(sample.host_path.replace("/", "\\")).name
    return {"id": job.id, "profile": job.profile, "state": str(job.state.value), "updated_at": job.updated_at,
            "sample": name, "sha256": sample.sha256 if sample is not None else None}


def _scan_jobs(root: Path, profile: str | None) -> list[dict[str, Any]]:
    if not root.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for job_dir in sorted(root.iterdir()):
        if not JOB_ID_RE.fullmatch(job_dir.name) or not job_dir.is_dir():
            continue
        try:
            row = _job_row(_read_job(job_dir / "state.json"))
        except (OSError, ValueError) as e:
            reason = e.strerror if isinstance(e, OSError) and e.strerror else str(e)
            # Shown under every --profile filter on purpose: its profile is unknown, and the
            # job store likewise lets such a job block every profile until a human resolves it.
            rows.append({"id": job_dir.name, "profile": None, "state": "CORRUPT", "updated_at": None,
                         "sample": None, "sha256": None, "error": reason})
            continue
        if profile is None or row["profile"] == profile:
            rows.append(row)
    return rows


def _format_jobs(rows: Any) -> str:
    if not rows:
        return "no jobs"
    cols = ("id", "profile", "state", "updated_at", "sample")
    table = [[c.upper() for c in cols]] + [[_safe(r.get(c) or "-") for c in cols] for r in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(cols))]
    return "\n".join("  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)).rstrip()
                     for row in table)


def cmd_jobs(args: argparse.Namespace, out: _Output) -> int:
    config = _load_config(args)
    root = config.jobs_root_path
    if args.action == "show":
        if not args.job_id:
            raise UsageError("jobs show needs a JOB_ID")
        job_id = validate_job_id(args.job_id)
        state_file = root / job_id / "state.json"
        if not state_file.is_file():
            raise JobNotFound(f"job {job_id} not found under {root}", details={"job_id": job_id},
                              hint=f"run `{PROG} jobs list`")
        try:
            job = _read_job(state_file)
        except (OSError, ValueError) as e:
            raise StateViolation(f"job {job_id} has an unreadable state.json ({type(e).__name__})",
                                 details={"job_id": job_id}) from None
        out.data(job.to_json())
        return EXIT_OK
    if args.job_id:
        raise UsageError("jobs list takes no JOB_ID (did you mean `jobs show JOB_ID`?)")
    out.data(_scan_jobs(root, args.profile), _format_jobs)
    return EXIT_OK


# ── provision / install-plugin ──────────────────────────────────────
def _result_ok(result: Any) -> bool:
    return not (isinstance(result, Mapping) and result.get("ok") is False)


def _derive_x64dbg_root(prof: gw_config.ProfileConfig) -> str | None:
    """``<root>`` of the backends' ``<root>\\<arch>\\x64dbg.exe`` / ``mcp_config.json`` paths (the
    layout ``init`` writes); None when they name no such path or disagree."""
    roots: dict[str, str] = {}
    for backend in prof.backends:
        for value in (backend.exe, backend.config):
            if not value or not _is_windows_abs(value):
                continue
            path = PureWindowsPath(value.replace("/", "\\"))
            if path.parent.name.casefold() != backend.arch.casefold():
                return None
            root = str(path.parent.parent)
            roots.setdefault(root.casefold(), root)
    return next(iter(roots.values())) if len(roots) == 1 else None


def _x64dbg_root(args: argparse.Namespace, prof: gw_config.ProfileConfig) -> str:
    if args.x64dbg_root:
        return _require_windows_abs(args.x64dbg_root, "--x64dbg-root")
    root = _derive_x64dbg_root(prof)
    if root is None:
        raise UsageError("--x64dbg-root is needed: the profile's backends do not name guest paths of the "
                         "form <root>\\x64\\x64dbg.exe or <root>\\x64\\mcp_config.json")
    return root


@dataclasses.dataclass(frozen=True)
class _PluginSource:
    """The plugin build to install: a ``--dist`` folder or the build bundled in the package."""

    dist: Path | None
    bundle: plugin_bundle.PluginBundle | None

    def describe(self) -> dict[str, Any]:
        if self.bundle is not None:
            return self.bundle.describe()
        return {"source": "dist", "path": str(self.dist)}

    def label(self) -> str:
        if self.bundle is not None:
            return f"bundled build v{self.bundle.version}" if self.bundle.version else "bundled build"
        return f"build from {self.dist}"

    @contextlib.contextmanager
    def directory(self) -> Iterator[Path]:
        """A folder holding ``x64/plugins/...`` and ``x32/plugins/...`` (a temporary copy for the bundle)."""
        if self.bundle is None:
            assert self.dist is not None
            yield self.dist
            return
        with plugin_bundle.materialize(self.bundle) as dist:
            yield dist


def _plugin_source(dist_arg: str | None, *, also: str = "") -> _PluginSource:
    """``--dist`` (must be a folder), else the bundled build; TransferError when there is none."""
    if dist_arg:
        dist = Path(dist_arg).expanduser()
        if not dist.is_dir():
            raise UsageError(f"--dist is not a directory: {dist}")
        missing = [f"{arch}/plugins/{name}" for arch, name in plugin_bundle.PLUGIN_FILES.items()
                   if not (dist / arch / "plugins" / name).is_file()]
        if missing:
            raise TransferError(
                f"--dist {dist} does not hold the plugin build", stage="install_plugin",
                details={"dist_dir": str(dist), "missing": missing},
                hint="pass the folder that holds x64/plugins and x32/plugins (`zig build "
                     "-Doptimize=ReleaseSafe --prefix dist` writes one)" + also)
        return _PluginSource(dist, None)
    bundle = plugin_bundle.find_bundle()
    if bundle is None:
        raise TransferError(
            "this installation has no bundled plugin build",
            stage="install_plugin",
            details={"missing": plugin_bundle.missing_files()},
            hint="install a release wheel (scripts/build-release.sh in the repository builds one into "
                 "release/), or pass --dist DIR, a folder holding x64/plugins and x32/plugins "
                 "(`zig build -Doptimize=ReleaseSafe --prefix dist` writes one)" + also,
        )
    return _PluginSource(None, bundle)


def _install_plugin_step(app: Any, runtime: Any, profile: str | None, source: _PluginSource, *,
                         x64dbg_root: str, relaunch: bool, out: _Output) -> Any:
    provision = _import("provision")
    with source.directory() as dist, _holding_vm(runtime):
        result = provision.install_plugin(runtime, dist_dir=dist, x64dbg_root=x64dbg_root, relaunch=relaunch)
        if _result_ok(result):
            reason = "plugin reinstalled (debuggers killed" + (" and relaunched)" if relaunch else ")")
            lost = _new_epochs(app, runtime, profile, reason)
            result = _report_lost(result, lost, out)
    return {**result, "plugin": source.describe()} if isinstance(result, Mapping) else result


def _check_wait_ready(value: float) -> None:
    if not math.isfinite(value) or value <= 0:
        raise UsageError("--wait-ready must be a number of seconds greater than 0")


@dataclasses.dataclass(frozen=True)
class _ProvisionInputs:
    user: str
    password: Secret | None
    autologon: bool


def _provision_inputs(args: argparse.Namespace, config: gw_config.GatewayConfig,
                      prof: gw_config.ProfileConfig, *, environ: Mapping[str, str] | None = None,
                      also: str = "") -> _ProvisionInputs:
    """The guest user and password (``--user``, the profile, gateway.env_file); fails before any VM
    work. ``environ``: an already resolved environment (setup adds what it asked for); ``also``
    extends the hint of a missing password."""
    _check_wait_ready(args.wait_ready)
    if environ is None:
        # the same resolution as the serving gateway: the real environment over gateway.env_file
        environ = envfile.resolve_environ(config, os.environ)
    user = args.user or prof.guest_user or (environ.get(prof.guest_user_env) if prof.guest_user_env else None)
    if not user:
        raise UsageError(
            "--user is required because the profile has no guest_user"
            + (f" and {prof.guest_user_env} is not set" if prof.guest_user_env else "")
        )
    password = gw_config.resolve_secret(prof.guest_password_env, dict(environ))
    autologon = not args.no_autologon
    if autologon and password is None:
        env_name = prof.guest_password_env
        raise ConfigError(
            "auto-logon needs the guest password, but "
            + (f"environment variable {env_name} is not set (environment or gateway.env_file)" if env_name
               else f"profile {prof.name!r} has no guest_password_env"),
            stage="provision",
            hint="export the guest password in that variable, or pass --no-autologon" + also,
            details={"key": f"profiles.{prof.name}.guest_password_env"},
        )
    return _ProvisionInputs(user, password, autologon)


def _provision_step(app: Any, runtime: Any, profile: str | None, inputs: _ProvisionInputs, *,
                    x64dbg_root: str, bind: str, reboot: bool, wait_ready_s: float, snapshot: str | None,
                    out: _Output) -> Any:
    provision = _import("provision")
    with _holding_vm(runtime):
        result = provision.provision_guest(
            runtime,
            x64dbg_root=x64dbg_root,
            user=inputs.user,
            password=inputs.password,
            autologon=inputs.autologon,
            bind=bind,
            reboot=reboot,
            wait_ready_s=float(wait_ready_s),
            clean_snapshot=snapshot,
        )
        if isinstance(result, Mapping) and result.get("rebooted") is True:
            lost = _new_epochs(app, runtime, profile, "guest rebooted by provision")
            result = _report_lost(result, lost, out)
    return result


def cmd_provision(args: argparse.Namespace, out: _Output) -> int:
    x64dbg_root = _require_windows_abs(args.x64dbg_root, "--x64dbg-root")
    config = _load_config(args)
    inputs = _provision_inputs(args, config, config.profile(args.profile))
    _import("provision")  # an installation without it fails here, before the gateway is built
    with _app(args, config) as app:
        _claim_jobs_root(app)
        runtime = _runtime(app, args.profile)
        result = _provision_step(app, runtime, args.profile, inputs, x64dbg_root=x64dbg_root,
                                 bind=args.bind, reboot=not args.no_reboot, wait_ready_s=args.wait_ready,
                                 snapshot=args.snapshot, out=out)
        if _result_ok(result):
            _record_provisioned_snapshot(config, config.profile(args.profile), result, out)
    out.data(result)
    return EXIT_OK if _result_ok(result) else EXIT_FAILURE


def cmd_install_plugin(args: argparse.Namespace, out: _Output) -> int:
    source = _plugin_source(args.dist)
    config = _load_config(args)
    x64dbg_root = _x64dbg_root(args, config.profile(args.profile))
    _import("provision")  # an installation without it fails here, before the gateway is built
    with _app(args, config) as app:
        _claim_jobs_root(app)
        runtime = _runtime(app, args.profile)
        result = _install_plugin_step(app, runtime, args.profile, source, x64dbg_root=x64dbg_root,
                                      relaunch=not args.no_relaunch, out=out)
    out.data(result)
    return EXIT_OK if _result_ok(result) else EXIT_FAILURE


# ── init ────────────────────────────────────────────────────────────
def _toml_str(value: str) -> str:
    if "'" not in value and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return f"'{value}'"  # literal string: Windows paths stay readable
    out = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return _toml_str(value)
    if isinstance(value, list | tuple):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    raise TypeError(f"cannot write {type(value).__name__} to TOML")


def _toml_key(key: str) -> str:
    return key if _BARE_KEY_RE.match(key) else _toml_str(key)


def to_toml(doc: Mapping[str, Any], header: str = "") -> str:
    """Serialise nested tables of str/int/float/bool/list values (enough for the config)."""
    lines = [f"# {line}" if line else "#" for line in header.splitlines()]
    if lines:
        lines.append("")

    def table(path: list[str], body: Mapping[str, Any]) -> None:
        scalars = [(k, v) for k, v in body.items() if not isinstance(v, Mapping)]
        subtables = [(k, v) for k, v in body.items() if isinstance(v, Mapping)]
        if path and (scalars or not subtables):
            lines.append("[" + ".".join(_toml_key(p) for p in path) + "]")
        for key, value in scalars:
            lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
        if path and (scalars or not subtables):
            lines.append("")
        for key, value in subtables:
            table([*path, key], value)

    table([], doc)
    return "\n".join(lines).rstrip("\n") + "\n"


_HTTP_EXAMPLE = """
# Remote access (optional, see the README): serve --transport http
# [http]
# enabled = true
# bind = "127.0.0.1"            # non-loopback binds also need tls_cert/tls_key
# port = 9100
# allow_clients = []            # CIDRs; empty = loopback only
# token_envs = { read = "GW_TOKEN_READ", analyze = "GW_TOKEN_ANALYZE", admin = "GW_TOKEN_ADMIN" }
"""


def _check_env_name(value: str) -> str | None:
    if _ENV_NAME_RE.match(value):
        return None
    return "must be an environment variable NAME ([A-Za-z_][A-Za-z0-9_]*)"


def _check_windows_abs(value: str) -> str | None:
    return None if _is_windows_abs(value) else "must be an absolute guest path such as C:\\x64dbg\\release"


def _check_url(value: str) -> str | None:
    return None if value.startswith(("http://", "https://")) else "must start with http:// or https://"


def _check_mode(value: str) -> str | None:
    return None if value in gw_config.MODES else f"must be one of {', '.join(gw_config.MODES)}"


def _ask(prompt: str, default: str | None = None, *, required: bool = True,
         check: Callable[[str], str | None] | None = None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        try:
            raw = _prompt(f"{prompt}{suffix}: ")
        except EOFError:
            raise UsageError("cancelled (end of input)") from None
        value = raw.strip() or (default or "")
        if not value:
            if not required:
                return ""
            _emit(sys.stderr, "  a value is required")
            continue
        problem = check(value) if check else None
        if problem:
            _emit(sys.stderr, f"  {problem}")
            continue
        return value


def _init_answers(args: argparse.Namespace) -> dict[str, Any]:
    a: dict[str, Any] = {
        "mode": args.mode or "vmware",
        "profile_name": args.profile_name or DEFAULT_PROFILE_NAME,
        "vmx": args.vmx,
        "clean_snapshot": args.clean_snapshot or DEFAULT_CLEAN_SNAPSHOT,
        "guest_user": args.guest_user,
        "guest_password_env": args.guest_password_env or DEFAULT_PASSWORD_ENV,
        "x64dbg_root": args.x64dbg_root,
        "jobs_root": args.jobs_root or gw_config.GatewayConfig.jobs_root,
        "vmrun": args.vmrun,
        "x64_url": args.x64_url, "x64_token_env": args.x64_token_env,
        "x32_url": args.x32_url, "x32_token_env": args.x32_token_env,
        "upload_roots": _upload_roots(getattr(args, "upload_roots", None)),
        "env_file": getattr(args, "env_file", None),
    }
    if args.non_interactive:
        if a["mode"] == "vmware":
            missing = [flag for flag, key in (("--vmx", "vmx"), ("--guest-user", "guest_user"),
                                              ("--x64dbg-root", "x64dbg_root")) if not a[key]]
        else:
            missing = [] if (a["x64_url"] or a["x32_url"]) else ["--x64-url (or --x32-url)"]
            for arch in ("x64", "x32"):
                if a[f"{arch}_url"] and not a[f"{arch}_token_env"]:
                    missing.append(f"--{arch}-token-env")
        if missing:
            raise UsageError(f"init --non-interactive needs {', '.join(missing)}")
    else:
        a["mode"] = _ask("Mode (vmware = a local VMware VM, endpoint = plugin URLs only)", a["mode"],
                         check=_check_mode)
        a["profile_name"] = _ask("Profile name", a["profile_name"])
        if a["mode"] == "vmware":
            a["vmx"] = _ask("Path of the VM's .vmx file", a["vmx"])
            a["clean_snapshot"] = _ask("Clean snapshot name", a["clean_snapshot"])
            a["guest_user"] = _ask("Guest user (runs the debuggers)", a["guest_user"])
            a["guest_password_env"] = _ask("Environment variable holding the guest password",
                                           a["guest_password_env"], check=_check_env_name)
            a["x64dbg_root"] = _ask("x64dbg release directory in the guest (contains x64\\ and x32\\)",
                                    a["x64dbg_root"], check=_check_windows_abs)
        else:
            a["x64_url"] = _ask("x64dbg plugin URL (empty to skip)", a["x64_url"], required=False,
                                check=_check_url)
            if a["x64_url"]:
                a["x64_token_env"] = _ask("Environment variable holding the x64 token", a["x64_token_env"],
                                          check=_check_env_name)
            a["x32_url"] = _ask("x32dbg plugin URL (empty to skip)", a["x32_url"], required=not a["x64_url"],
                                check=_check_url)
            if a["x32_url"]:
                a["x32_token_env"] = _ask("Environment variable holding the x32 token", a["x32_token_env"],
                                          check=_check_env_name)
        a["jobs_root"] = _ask("Host directory for job artifacts (outside any repository)", a["jobs_root"])
    if a["mode"] == "vmware" and not _is_windows_abs(a["x64dbg_root"]):
        raise UsageError("--x64dbg-root must be an absolute guest path such as C:\\x64dbg\\release")
    if a["mode"] not in gw_config.MODES:
        raise UsageError(f"--mode must be one of {', '.join(gw_config.MODES)}")
    return a


def _upload_roots(values: Sequence[str] | None) -> list[str]:
    """``--upload-root`` values for gateway.upload_roots: ``~`` paths stay as given (the gateway
    expands them), a relative path becomes absolute (relative to the current directory)."""
    if any(not v.strip() for v in values or ()):
        raise UsageError("--upload-root must name a folder (an empty value would allow the current folder)")
    return [v if v.startswith("~") else str(Path(v).absolute()) for v in values or ()]


def _init_document(a: Mapping[str, Any], vmrun_value: str) -> dict[str, Any]:
    name = a["profile_name"]
    if a["mode"] == "vmware":
        root = PureWindowsPath(a["x64dbg_root"].replace("/", "\\"))
        backends = {
            bid: {"port": port, "exe": str(root / sub / exe), "config": str(root / sub / "mcp_config.json"),
                  "launch_task": task}
            for bid, port, sub, exe, task in _BACKEND_LAYOUT
        }
        profile: dict[str, Any] = {
            "mode": "vmware",
            "vmx": a["vmx"],
            "vmrun": vmrun_value,
            "clean_snapshot": a["clean_snapshot"],
            "protected_snapshots": [a["clean_snapshot"]],
            "guest_user": a["guest_user"],
            "guest_password_env": a["guest_password_env"],
            "require_isolation": True,
            "token_source": "guest-config",
            "backends": backends,
        }
    else:
        profile = {"mode": "endpoint", "token_source": "env", "backends": {
            arch: {"url": a[f"{arch}_url"], "token_env": a[f"{arch}_token_env"]}
            for arch in ("x64", "x32") if a[f"{arch}_url"]
        }}
    gateway: dict[str, Any] = {"jobs_root": a["jobs_root"], "default_profile": name}
    if a.get("upload_roots"):
        gateway["upload_roots"] = list(a["upload_roots"])
    if a.get("env_file"):
        gateway["env_file"] = a["env_file"]
    return {"gateway": gateway, "profiles": {name: profile}}


def _discover_vmrun(a: Mapping[str, Any], out: _Output) -> tuple[str, str | None]:
    """(value for the config, path found or None). An explicit --vmrun must exist."""
    if a["mode"] != "vmware":
        return "auto", None
    if a["vmrun"]:
        return a["vmrun"], gw_platform.find_vmrun(a["vmrun"])
    try:
        return "auto", gw_platform.find_vmrun("auto")
    except VmrunNotFound as e:
        out.note(f"warning: vmrun was not found ({_safe(e.message)}); the config uses vmrun = \"auto\""
                 + (f"\n  hint: {e.hint}" if e.hint else ""))
        return "auto", None


def _config_target(args: argparse.Namespace) -> Path:
    if args.config:
        return Path(args.config).expanduser()
    env_path = os.environ.get(gw_config.ENV_CONFIG_PATH)
    if env_path:
        return Path(env_path).expanduser()
    return gw_config.default_config_path()


def _write_private(path: Path, text: str, *, replace: bool) -> None:
    """Create ``path`` (0600). ``replace``: write a fresh temp file and rename it over ``path``."""
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
        gw_platform.secure_dir(parent)
    data = text.encode("utf-8")
    if replace:
        # A unique name (0600, O_EXCL): a leftover of a crashed run cannot block this one.
        fd, temp_name = tempfile.mkstemp(dir=parent, prefix=f".{path.name}.", suffix=".tmp")
        target = Path(temp_name)
    else:
        target = path
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise ConfigError(f"{path} already exists; refusing to overwrite it", stage="init",
                              hint="pass --force to replace it", details={"path": str(path)}) from None
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        if replace:
            os.replace(target, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(target)
        raise
    gw_platform.secure_file(path)


def _format_init(result: Mapping[str, Any]) -> str:
    lines = [f"wrote {result['path']} (profile {result['profile']!r})"]
    if result.get("vmrun"):
        lines.append(f"vmrun: {result['vmrun']}")
    lines.append("next steps:")
    lines.extend(f"  {i}. {step}" for i, step in enumerate(result["next_steps"], 1))
    return "\n".join(lines)


@dataclasses.dataclass(frozen=True)
class _InitPlan:
    answers: dict[str, Any]
    document: dict[str, Any]
    config: gw_config.GatewayConfig
    text: str
    vmrun_path: str | None


def _plan_init(args: argparse.Namespace, out: _Output, path: Path) -> _InitPlan:
    """Ask (or take from the flags) the init answers and build the validated config text."""
    answers = _init_answers(args)
    vmrun_value, vmrun_path = _discover_vmrun(answers, out)
    doc = _init_document(answers, vmrun_value)
    config = gw_config.config_from_dict(doc, source=str(path))  # same validation as load_config
    text = to_toml(doc, header=f"x64dbg-vm-gateway configuration (written by `{PROG} init`).\n"
                               "Secrets are never stored here: *_env keys name environment variables.")
    if tomllib.loads(text) != json.loads(json.dumps(doc)):  # belt and braces for the TOML writer
        raise InternalError("generated TOML does not round-trip", stage="init")
    return _InitPlan(answers, doc, config, text + _HTTP_EXAMPLE, vmrun_path)


def cmd_init(args: argparse.Namespace, out: _Output) -> int:
    path = _config_target(args)
    if path.exists() and not args.force:
        raise ConfigError(f"{path} already exists; refusing to overwrite it", stage="init",
                          hint="pass --force to replace it", details={"path": str(path)})
    plan = _plan_init(args, out, path)
    answers, vmrun_path = plan.answers, plan.vmrun_path
    _write_private(path, plan.text, replace=args.force)
    name = answers["profile_name"]
    steps = []
    if answers["mode"] == "vmware":
        steps += [
            f"put the guest password in environment variable {answers['guest_password_env']} "
            "(never in the file)",
            f"{PROG} provision --x64dbg-root '{answers['x64dbg_root']}' "
            f"--snapshot {answers['clean_snapshot']}",
        ]
    else:
        steps += [f"export {answers[f'{arch}_token_env']} with the plugin token"
                  for arch in ("x64", "x32") if answers[f"{arch}_url"]]
    steps += [f"{PROG} doctor", f"claude mcp add x64dbg-vm -- {PROG} serve"]
    out.data({"ok": True, "path": str(path), "profile": name, "vmrun": vmrun_path, "next_steps": steps},
             _format_init)
    return EXIT_OK


# ── setup ───────────────────────────────────────────────────────────
MCP_SERVER_NAME = gw_config.GATEWAY_MCP_NAME  # "x64dbg-vm"
SETUP_STEPS = ("init", "precheck", "install-plugin", "provision", "doctor")
#: doctor checks about what setup never changes (VM, vmrun, guest credentials, isolation, job
#: roots): one of them failing stops setup before the plugin install or provisioning changes the
#: guest (the precheck doctor itself may create missing job folders, like doctor does)
SETUP_BLOCKING_CHECKS = frozenset({
    "vmrun", "runtime", "vmx", "single_vm_instance", "vm_power", "tools", "guest_credentials", "guest_ip",
    "isolation", "guest_job_root", "host_jobs_root",
})
#: doctor checks that only inform (they never fail): setup reports them and goes on
SETUP_ADVISORY_CHECKS = frozenset({"static_tools"})
#: init options that only matter while setup creates the config (--x64dbg-root also feeds the guest steps)
_SETUP_INIT_ONLY = ("profile_name", "vmx", "clean_snapshot", "guest_user", "guest_password_env", "jobs_root",
                    "vmrun", "upload_roots")
_INIT_FLAG_NAMES = {"upload_roots": "--upload-root"}
_ENDPOINT_INIT_DEFAULTS = {"mode": None, "force": False, "x64_url": None, "x64_token_env": None,
                           "x32_url": None, "x32_token_env": None}


#: printed above the commands on a Windows host (``shell`` "powershell" in the JSON)
POWERSHELL_NOTE = "The commands are for PowerShell (in cmd.exe the quoting differs)."
# A PowerShell word that needs no quotes: a path or plain word that does not start with a digit
# (1kb, 0x10 would be numbers), or a plain option name (-e, --project-path; "--" itself is the
# end-of-parameters token, and an option with "." or ":" is split by Windows PowerShell).
_PS_BAREWORD_RE = re.compile(r"[A-Za-z/\\][A-Za-z0-9_\-./:=+~\\]*|--?[A-Za-z][A-Za-z0-9-]*")


def _windows_host() -> bool:
    return os.name == "nt"


def command_shell() -> str:
    """The shell the printed commands are for: "powershell" on a Windows host, else "posix"."""
    return "powershell" if _windows_host() else "posix"


def powershell_quote(arg: str) -> str:
    """``arg`` as one PowerShell argument: plain words stay, anything else becomes a verbatim
    single-quoted literal (``ps.ps_quote``: nothing inside is expanded, quote characters are doubled)."""
    return arg if _PS_BAREWORD_RE.fullmatch(arg) else gw_ps.ps_quote(arg)


def shell_join(argv: Sequence[str], *, windows: bool | None = None) -> str:
    """A command line to paste into a shell: POSIX quoting (``shlex``), or on Windows PowerShell
    quoting (``powershell_quote``; a quoted program is run with the call operator ``&``)."""
    if not (windows if windows is not None else _windows_host()):
        return shlex.join(argv)
    words = [powershell_quote(arg) for arg in argv]
    if words and words[0] != argv[0]:
        words.insert(0, "&")
    return " ".join(words)


def _is_default_config(path: Path) -> bool:
    def norm(p: Path) -> str:
        return os.path.normcase(os.path.abspath(p.expanduser()))

    return norm(path) == norm(gw_config.default_config_path())


def _register_argv(args: argparse.Namespace, path: Path) -> list[str]:
    """``claude mcp add`` for this gateway; ``-e`` names the config only when it is not the default one."""
    argv = ["claude", "mcp", "add", MCP_SERVER_NAME]
    if not _is_default_config(path):
        argv += ["-e", f"{gw_config.ENV_CONFIG_PATH}={path.expanduser().absolute()}"]
    argv += ["--", PROG, "serve"]
    if args.profile:
        argv += ["--profile", args.profile]
    return argv


def _global_argv(args: argparse.Namespace) -> list[str]:
    """The global options a step's equivalent command needs to reach the same config and profile."""
    argv = ["--config", args.config] if args.config else []
    return argv + (["--profile", args.profile] if args.profile else [])


class _SetupReport:
    def __init__(self, args: argparse.Namespace, path: Path) -> None:
        self.data: dict[str, Any] = {
            "ok": False, "dry_run": bool(args.dry_run), "shell": command_shell(),
            "config": {"path": str(path), "created": False, "profile": None},
            "steps": [{"step": name, "status": "not_run", "detail": ""} for name in SETUP_STEPS],
            "notes": [],
        }
        if args.dry_run:
            self.data["problems"] = []

    def step(self, name: str) -> dict[str, Any]:
        return next(s for s in self.data["steps"] if s["step"] == name)

    def set(self, name: str, status: str, detail: str = "", **extra: Any) -> None:
        self.step(name).update(status=status, detail=detail, **extra)

    def note(self, text: str) -> None:
        self.data["notes"].append(text)


def _setup_init_args(args: argparse.Namespace, session: _SetupSession) -> argparse.Namespace:
    """The init options of ``setup`` as ``init`` sees them (vmware mode, never --force, never the
    init wizard: setup asked its own questions already); the global --profile and --snapshot name
    the new profile and its clean snapshot unless given explicitly. With a password file the new
    config names it in gateway.env_file (the profile keeps guest_user: the file may never be written,
    when the guest refuses the password)."""
    ns = argparse.Namespace(**{**_ENDPOINT_INIT_DEFAULTS, **vars(args)})
    ns.force = False
    ns.non_interactive = True
    ns.profile_name = args.profile_name or args.profile
    ns.clean_snapshot = args.clean_snapshot or args.snapshot
    pf = session.password_file
    ns.env_file = str(pf.path) if pf is not None else None
    return ns


def _check_profile_names(args: argparse.Namespace) -> None:
    if args.profile and args.profile_name and args.profile != args.profile_name:
        raise UsageError(f"--profile {args.profile} and --profile-name {args.profile_name} name different "
                         "profiles for the new config")


def _setup_config(args: argparse.Namespace, out: _Output, path: Path, report: _SetupReport,
                  session: _SetupSession) -> tuple[gw_config.GatewayConfig, _InitPlan | None]:
    """(a) The existing config, or the one the init logic would write (with its plan; nothing is
    written here)."""
    if path.exists():
        config = gw_config.load_config(path, environ=os.environ)
        report.set("init", "skipped", f"using the existing config {path}")
        given = [_INIT_FLAG_NAMES.get(k, f"--{k.replace('_', '-')}") for k in _SETUP_INIT_ONLY
                 if getattr(args, k, None)]
        if given:
            report.note(f"the config exists, so {', '.join(given)} were not used (edit {path}, or run "
                        f"`{PROG} init --force`)")
        return config, None
    _check_profile_names(args)
    plan = _plan_init(_setup_init_args(args, session), out, path)
    report.set("init", "planned", f"write {path} (profile {plan.answers['profile_name']!r})",
               document=plan.document)
    return plan.config, plan


def _write_setup_config(path: Path, init: _InitPlan, report: _SetupReport,
                        out: _Output) -> gw_config.GatewayConfig:
    _write_private(path, init.text, replace=False)
    report.data["config"]["created"] = True
    out.note(f"setup: wrote {path}")
    step = report.step("init")
    step.pop("document", None)
    report.set("init", "done", f"wrote {path} (profile {init.answers['profile_name']!r})",
               vmrun=init.vmrun_path)
    return gw_config.load_config(path, environ=os.environ)


@dataclasses.dataclass(frozen=True)
class _SetupPlan:
    x64dbg_root: str | None
    install: bool
    source: _PluginSource | None  # None with install: a dry-run problem
    relaunch: bool
    provision: bool
    inputs: _ProvisionInputs | None  # None with provision: a dry-run problem
    snapshot: str


def _plan_setup(args: argparse.Namespace, config: gw_config.GatewayConfig, prof: gw_config.ProfileConfig,
                report: _SetupReport, session: _SetupSession) -> _SetupPlan:
    """Everything that can be checked without the VM (usage errors always raise; other problems are
    listed for --dry-run and raised otherwise), and the planned steps in the report."""
    vmware = prof.mode == "vmware"
    install = vmware and not args.skip_plugin
    provision = vmware and not args.skip_provision
    problems: list[GatewayError] = []

    def attempt(fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except GatewayError as e:
            if not args.dry_run:
                raise
            problems.append(e)
            return None

    root = _x64dbg_root(args, prof) if install or provision else None
    _check_wait_ready(args.wait_ready)
    skip_hint = ", or run setup with --skip-plugin"
    source = attempt(lambda: _plugin_source(args.dist, also=skip_hint)) if install else None
    ask_hint = "" if session.interactive else "; on a terminal (without --non-interactive) setup asks for it"
    inputs = attempt(lambda: _provision_inputs(args, config, prof, environ=session.environ(config),
                                               also=ask_hint)) if provision else None
    if inputs is not None:  # what provision_guest checks first, but only after the plugin install
        backends = {b.id: b for b in prof.backends}
        attempt(lambda: _import("provision").check_provision_arguments(user=inputs.user, bind=args.bind,
                                                                       backends=backends))
    derived = _derive_x64dbg_root(prof)
    if root is not None and derived is not None and root.casefold() != derived.casefold():
        report.note(f"--x64dbg-root {root} is not the folder the profile's backends use ({derived}); the "
                    "gateway keeps using the backend paths of the config")
    snapshot = args.snapshot or prof.clean_snapshot or DEFAULT_CLEAN_SNAPSHOT
    plan = _SetupPlan(root, install, source, relaunch=not provision, provision=provision, inputs=inputs,
                      snapshot=snapshot)

    pending = "planned" if args.dry_run else "not_run"
    global_argv = _global_argv(args)
    blocking = ", ".join(sorted(SETUP_BLOCKING_CHECKS))
    report.set("precheck", pending, f"doctor; setup stops if a check it cannot fix fails ({blocking})"
               + (f", or if snapshot {snapshot!r} exists already" if provision else ""))
    skip_why = "endpoint profile: there is no guest to prepare" if not vmware else None
    if install:
        assert root is not None
        what = source.label() if source is not None else "no plugin build (see problems)"
        after = ("the debuggers are relaunched through the logon tasks that provisioning registered"
                 if plan.relaunch else "the debuggers are stopped and come back with the provisioning reboot")
        command = [PROG, "install-plugin", "--x64dbg-root", root]
        if source is not None and source.dist is not None:
            command += ["--dist", str(source.dist)]
        command += [] if plan.relaunch else ["--no-relaunch"]
        report.set("install-plugin", pending, f"{what} into {root}; {after}",
                   command=shell_join(command + global_argv))
    else:
        report.set("install-plugin", "skipped", skip_why or "--skip-plugin")
    if provision:
        who = (f"user {inputs.user}, auto-logon {'on' if inputs.autologon else 'off'}, " if inputs is not None
               else "")
        assert root is not None
        command = [PROG, "provision", "--x64dbg-root", root, "--snapshot", snapshot]
        command += ["--user", args.user] if args.user else []
        command += ["--no-autologon"] if args.no_autologon else []
        command += ["--bind", args.bind] if args.bind != DEFAULT_PLUGIN_BIND else []
        command += ["--wait-ready", f"{args.wait_ready:g}"] if args.wait_ready != DEFAULT_WAIT_READY_S else []
        report.set("provision", pending,
                   f"{who}bind {args.bind}, reboot, wait up to {args.wait_ready:g} s for the plugins, "
                   f"take snapshot {snapshot!r}", command=shell_join(command + global_argv))
        if args.no_autologon:
            who_logs_on = inputs.user if inputs is not None else "the guest user"
            report.note(f"without auto-logon nobody logs on after the reboot: log on as {who_logs_on} in the "
                        f"VM within {args.wait_ready:g} s (the debuggers start at logon), or the wait for "
                        "the plugins times out before the snapshot")
        if snapshot != prof.clean_snapshot:
            report.note(f"the profile's clean_snapshot is {prof.clean_snapshot!r}: set "
                        f"profiles.{prof.name}.clean_snapshot (and protected_snapshots) to {snapshot!r} so "
                        "analyses revert to the new snapshot")
    else:
        report.set("provision", "skipped", skip_why or "--skip-provision")
    report.set("doctor", pending, "doctor again, after the changes")
    if provision and not args.no_autologon:
        report.data["autologon_warning"] = AUTOLOGON_WARNING
    if args.dry_run:
        report.data["problems"] = [p.to_dict() for p in problems]
    return plan


def _failed(result: Any) -> list[Mapping[str, Any]]:
    raw = result.get("checks") if isinstance(result, Mapping) else None
    checks = [c for c in raw if isinstance(c, Mapping)] if isinstance(raw, list) else []
    return [c for c in checks if not c.get("ok")]


def _failed_checks(result: Any) -> list[str]:
    return [str(c.get("name")) for c in _failed(result)]


def setup_check_kind(name: str) -> str:
    """What setup makes of a failed doctor check: "blocking" (it cannot fix it), "snapshot"
    (provisioning takes it), "token" (provisioning rewrites the token configs), "backend"
    (installing or provisioning brings the plugin up), "advisory" (only informs, never fails:
    static_tools) or "unknown"."""
    if name in SETUP_BLOCKING_CHECKS:
        return "blocking"
    if name in SETUP_ADVISORY_CHECKS:
        return "advisory"
    if name == "clean_snapshot":
        return "snapshot"
    if name.startswith("backend:") and name.endswith(":token"):
        return "token"
    if name.startswith(("backend:", "catalog:")):
        return "backend"
    return "unknown"


def _classify_precheck(result: Any, plan: _SetupPlan) -> tuple[list[str], list[str], list[str]]:
    """(blockers, fixable, unknown) among the failed doctor checks. Plugin answers and tokens are
    fixed by installing and provisioning, the clean snapshot by provisioning; checks this
    version does not know never stop setup (the final doctor still reports them)."""
    blockers: list[str] = []
    fixable: list[str] = []
    unknown: list[str] = []
    for check in _failed(result):
        name = str(check.get("name"))
        kind = setup_check_kind(name)
        if kind == "token" and str(check.get("detail") or "").startswith("skipped:"):
            kind = "backend"  # not checked because the backend is down: it stands or falls with that
        if kind == "blocking":
            blockers.append(name)
        elif kind in ("snapshot", "token"):
            (fixable if plan.provision else blockers).append(name)
        elif kind == "backend":
            (fixable if plan.install or plan.provision else blockers).append(name)
        else:
            unknown.append(name)
    return blockers, fixable, unknown


def _snapshot_exists(app: Any, profile: str | None, name: str) -> bool:
    listing = app.vm_snapshots_list(profile)
    snaps = listing.get("snapshots") if isinstance(listing, Mapping) else None
    names = [s.get("name") for s in snaps if isinstance(s, Mapping)] if isinstance(snaps, list) else []
    return any(isinstance(n, str) and n.casefold() == name.casefold() for n in names)


def _doctor_ok(result: Any) -> bool:
    return isinstance(result, Mapping) and bool(result.get("ok"))


def _run_setup(args: argparse.Namespace, config: gw_config.GatewayConfig, prof: gw_config.ProfileConfig,
               plan: _SetupPlan, report: _SetupReport, out: _Output, current: list[str],
               session: _SetupSession) -> bool:
    """(b)-(e) against the VM; ``current[0]`` names the running step (for error reports)."""
    with _app(args, session.run_config(config), {**os.environ, **session.env}) as app:
        current[0] = "precheck"
        _claim_jobs_root(app)
        out.note("setup: checking the configuration, the VM and the guest (doctor) ...")
        before = app.doctor(args.profile)
        _save_password_file_after_precheck(session.password_file, before, args, prof, report, out)
        _refused_password_note(before, session, config, prof, report)
        blockers, fixable, unknown = _classify_precheck(before, plan)
        found = {"result": before, "blockers": blockers, "fixable": fixable, "unknown": unknown}
        if blockers:
            report.set("precheck", "blocked", f"setup cannot fix: {', '.join(blockers)} (hints below)",
                       **found)
            return False
        if plan.provision and _snapshot_exists(app, args.profile, plan.snapshot):
            report.set("precheck", "blocked", f"snapshot {plan.snapshot!r} exists already", **found)
            raise StateViolation(
                f"snapshot {plan.snapshot!r} already exists, and provisioning never replaces it",
                stage="setup", details={"snapshot": plan.snapshot},
                hint=f"if `{PROG} doctor` passes, the guest is set up already. To install a new plugin build "
                     "and take a new clean snapshot, run setup --snapshot NEW_NAME and then point "
                     f"profiles.{prof.name}.clean_snapshot at it; setup --skip-provision only reinstalls the "
                     "plugin (the clean snapshot keeps the old one); setup --skip-plugin --skip-provision "
                     "only checks and prints the registration command")
        detail = (f"{len(fixable)} failed check(s) that setup addresses: {', '.join(fixable)}" if fixable
                  else "all checks passed" if not unknown else "")
        if unknown:
            detail += ("; " if detail else "") + f"not judged by setup: {', '.join(unknown)}"
        report.set("precheck", "done", detail, **found)
        runtime = _runtime(app, args.profile) if plan.install or plan.provision else None
        if plan.install:
            assert plan.source is not None and plan.x64dbg_root is not None
            current[0] = "install-plugin"
            out.note(f"setup: installing the {plan.source.label()} into {plan.x64dbg_root} "
                     "(the debuggers are stopped) ...")
            result = _install_plugin_step(app, runtime, args.profile, plan.source,
                                          x64dbg_root=plan.x64dbg_root, relaunch=plan.relaunch, out=out)
            installed = result.get("installed") if isinstance(result, Mapping) else None
            archs = f" ({', '.join(installed)})" if isinstance(installed, Mapping) and installed else ""
            if not _result_ok(result):
                report.set("install-plugin", "failed", "install-plugin reported a failure", result=result)
                return False
            report.set("install-plugin", "done", f"{plan.source.label()} -> {plan.x64dbg_root}{archs}",
                       result=result)
        if plan.provision:
            assert plan.inputs is not None and plan.x64dbg_root is not None
            current[0] = "provision"
            out.note(f"setup: provisioning the guest: reboot, wait for the plugins, take snapshot "
                     f"{plan.snapshot!r} (this takes a few minutes) ...")
            result = _provision_step(app, runtime, args.profile, plan.inputs, x64dbg_root=plan.x64dbg_root,
                                     bind=args.bind, reboot=True, wait_ready_s=args.wait_ready,
                                     snapshot=plan.snapshot, out=out)
            if not _result_ok(result):
                report.set("provision", "failed", "provision reported a failure", result=result)
                return False
            snap = result.get("snapshot") if isinstance(result, Mapping) else None
            taken = snap.get("name") if isinstance(snap, Mapping) else None
            parts = (["rebooted"] if isinstance(result, Mapping) and result.get("rebooted") else []) + (
                [f"snapshot {taken!r} taken"] if taken else [])
            report.set("provision", "done", ", ".join(parts) or "done", result=result)
            _record_provisioned_snapshot(config, prof, result, out)
        current[0] = "doctor"
        out.note("setup: checking again (doctor) ...")
        after = app.doctor(args.profile)
        failed = _failed_checks(after)
        ok = _doctor_ok(after)
        report.set("doctor", "done" if ok else "failed",
                   "all checks passed" if ok else f"{len(failed)} check(s) failed: {', '.join(failed)}",
                   result=after)
        return ok


def _password_note(config: gw_config.GatewayConfig, prof: gw_config.ProfileConfig) -> str | None:
    var = prof.guest_password_env if prof.mode == "vmware" else None
    if not var:
        return None
    where = (f"gateway.env_file ({config.env_file}) or the environment" if config.env_file
             else "the environment: start Claude Code where it is exported, or name a 0600 file in "
                  "gateway.env_file")
    return (f"serve reads the guest password from {var} in {where}; do not pass it with "
            "claude mcp add -e (that stores it in Claude's config)")


_STATUS_WORDS = {"not_run": "not run"}


def _format_setup(report: Mapping[str, Any]) -> str:
    shows_commands = report["dry_run"] or bool(report.get("mcp_config"))
    lines = [POWERSHELL_NOTE, ""] if shows_commands and report.get("shell") == "powershell" else []
    for step in report["steps"]:
        status = _STATUS_WORDS.get(step["status"], step["status"])
        detail = _safe(step.get("detail") or "")
        lines.append(f"[{status}] {step['step']}" + (f": {detail}" if detail else ""))
        final_failed = step["step"] == "doctor" and step["status"] == "failed"
        if (step.get("blockers") or final_failed) and isinstance(step.get("result"), Mapping):
            lines.extend("    " + line for line in _format_doctor(step["result"]).splitlines())
        if report["dry_run"] and step.get("command"):
            lines.append(f"    = {_safe_command(step['command'])}")
    pf = report.get("password_file")
    if isinstance(pf, Mapping):
        if pf["status"] == "not_written":
            why = _safe(pf.get("reason") or "")
            lines.append(f"password file: not written to {_safe(pf['path'])} ({why})")
        else:
            verb = {"written": "wrote", "planned": "would write"}.get(pf["status"], pf["status"])
            when = "; once the guest accepts the password" if pf["status"] == "planned" else ""
            lines.append(f"password file: {verb} {_safe(pf['path'])} ({', '.join(pf['variables'])}; only you "
                         f"can read it{when})")
    lines.extend(f"note: {_safe(n)}" for n in report.get("notes", ()))
    for problem in report.get("problems", ()):
        lines.append(f"problem [{problem['code']}]: {_safe(problem['message'])}")
        if problem.get("hint"):
            lines.append(f"  hint: {_safe(problem['hint'])}")
    if report.get("mcp_config"):  # the same block as `mcp-config`
        lines += ["", "register the MCP servers with Claude Code:", "",
                  format_mcp_config(report["mcp_config"]), ""]
    lines.extend(f"warning: {_safe(w)}" for w in report.get("warnings", ()))
    provision = next((st for st in report["steps"] if st["step"] == "provision"), None)
    if report.get("autologon_warning") and provision is not None and provision["status"] != "not_run":
        lines.append(f"warning: {report['autologon_warning']}")
    if report["dry_run"]:
        lines.append("dry run: nothing was changed")
    elif report["ok"]:
        lines.append("setup complete")
    else:
        lines.append("setup stopped: fix what is shown above and run setup again")
    return "\n".join(lines)


# ── setup: questions on a terminal, the password file ───────────────
DEFAULT_USER_ENV = "X64DBG_GW_GUEST_USER"
#: the one-line warning at the end of a setup run that configures auto-logon
AUTOLOGON_WARNING = ("Windows auto-logon stores the guest password in the guest registry (Winlogon "
                     "DefaultPassword), so the clean snapshot and every later one contain it: use a "
                     "lab-only password")
#: what a first setup needs to create the config, and a placeholder for each in the hint
_SETUP_REQUIRED = (("--vmx", "vmx", "--vmx PATH/TO/VM.vmx"),
                   ("--guest-user", "guest_user", "--guest-user USER"),
                   ("--x64dbg-root", "x64dbg_root", "--x64dbg-root 'C:\\x64dbg\\release'"))
_PASSWORD_TRIES = 3
_USER_FORBIDDEN = frozenset('"/[]:;|=,+*?<>')  # provision.check_provision_arguments refuses these too
_LINE_ENDS = "\r\n\x0b\x0c\x1c\x1d\x1e\x85  "  # where str.splitlines (the env file reader) splits
_NUMBER_RE = re.compile(r"[0-9]+")


def _unstorable(value: str) -> bool:
    """True for a value an env file cannot hold: NUL, or a character envfile.read_env_file
    (``str.splitlines``) ends a line at."""
    return "\x00" in value or any(c in _LINE_ENDS for c in value)


def _unquote(value: str) -> str:
    """A pasted path without one pair of surrounding quotes."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1].strip()
    return value


class _EchoRefused(Exception):
    """getpass could not turn echo off (it would show the password)."""


def _stdin_is_tty() -> bool:
    stream = sys.stdin
    try:
        return bool(stream is not None and stream.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def _ask_secret(prompt: str) -> str:
    """Read a secret on the terminal; nothing is echoed (EOFError at end of input). getpass falls
    back to an echoing read when it cannot control the terminal: that is refused (_EchoRefused)."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt, stream=sys.stderr)
        except getpass.GetPassWarning:
            raise _EchoRefused from None


def _yes(prompt: str) -> bool:
    """A yes/no question whose default (an empty answer) is yes."""
    while True:
        try:
            answer = _prompt(prompt).strip().lower()
        except EOFError:
            raise UsageError("cancelled (end of input)") from None
        if answer in ("", "y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        _emit(sys.stderr, "  answer y or n")


@dataclasses.dataclass
class _PasswordFile:
    """The 0600 env file setup writes the guest credentials to (``--save-password-file``)."""

    path: Path
    user_var: str | None  # None: the profile names the user itself (guest_user)
    values: list[tuple[str, str]] = dataclasses.field(repr=False)  # (variable, value); never printed
    config_line: str | None = None  # the gateway.env_file line the user puts into an existing config
    status: str = "planned"  # -> "written" | "not_written" (with reason)
    reason: str | None = None
    comments: tuple[str, ...] = ()  # extra comment lines of a new file

    def public(self) -> dict[str, Any]:
        data: dict[str, Any] = {"path": str(self.path), "status": self.status,
                                "variables": [k for k, _ in self.values], "config_line": self.config_line}
        if self.reason:
            data["reason"] = self.reason
        return data


@dataclasses.dataclass
class _SetupSession:
    """What setup learned in this run besides the flags and the config: values typed on the
    terminal (by variable name; they reach this run's gateway, never os.environ or the output)
    and the password file to write."""

    interactive: bool
    env: dict[str, str] = dataclasses.field(default_factory=dict, repr=False)
    typed_password: bool = False
    asked_user: str | None = None  # the guest user typed for an existing config
    save: bool = False  # the user said yes to saving the credentials
    password_file: _PasswordFile | None = None

    def pending(self, config: gw_config.GatewayConfig) -> bool:
        """gateway.env_file is the password file this run has not written (yet, or at all)."""
        pf = self.password_file
        return (pf is not None and pf.status != "written" and not pf.path.exists()
                and _env_file_path(config) == pf.path)

    def run_config(self, config: gw_config.GatewayConfig) -> gw_config.GatewayConfig:
        """The config this run's gateway is built from: without gateway.env_file while that file is
        still pending (the session's values stand in for it)."""
        return dataclasses.replace(config, env_file=None) if self.pending(config) else config

    def environ(self, config: gw_config.GatewayConfig) -> dict[str, str]:
        """The environment ``*_env`` names resolve in for this run: the real environment over
        gateway.env_file (unless that is the password file setup has not written yet), then the
        values of this session."""
        if self.pending(config) or not config.env_file:
            base = dict(os.environ)
        else:
            base = envfile.resolve_environ(config, os.environ)
        return {**base, **self.env}

    def environ_before_saving(self, config: gw_config.GatewayConfig) -> dict[str, str]:
        """:meth:`environ` while the password file is still being decided: a gateway.env_file
        that does not exist yet counts as empty (setup may be about to write it)."""
        try:
            return self.environ(config)
        except ConfigError:
            path = _env_file_path(config)
            if path is None or path.exists():
                raise
            return {**os.environ, **self.env}


def _env_file_path(config: gw_config.GatewayConfig) -> Path | None:
    """gateway.env_file as a path (a relative one is relative to the config's folder)."""
    if not config.env_file:
        return None
    path = Path(config.env_file).expanduser()
    if not path.is_absolute() and config.config_path:
        path = Path(config.config_path).expanduser().parent / path
    return path.absolute()


def _default_password_file(profile: str) -> Path:
    return gw_config.default_config_path().parent / f"{profile}.env"


def _check_guest_user(value: str) -> str | None:
    if value != value.strip() or any(c in _USER_FORBIDDEN for c in value):
        return 'a Windows user name: no spaces at the ends and none of " / [ ] : ; | = , + * ? < >'
    return None


def _ask_guest_user(default: str | None) -> str:
    return _ask("Guest user: the Windows account in the VM that logs on and runs the debuggers", default,
                check=_check_guest_user)


def _ask_password(user: str, password_var: str) -> str:
    while True:
        try:
            value = _ask_secret(f"Password of guest user {user} (not shown; lab-only: auto-logon stores it "
                                "in the guest): ")
        except EOFError:
            raise UsageError("cancelled (end of input)") from None
        except _EchoRefused:
            raise UsageError(f"this terminal cannot turn echo off, so setup does not ask for the password: "
                             f"export it in {password_var} and run setup again") from None
        if value and not _unstorable(value):
            return value
        _emit(sys.stderr, "  a password is required (one line): guest operations and auto-logon log on "
                          "with it")


def _vm_candidates(vmrun: str | None, vmrun_type: str) -> list[Any]:
    """The VMs ``vm_inventory`` finds (``vmrun list`` when vmrun is installed, the VM library)."""
    from .. import vm_inventory
    from ..vmrun import VmrunCli

    try:
        path = gw_platform.find_vmrun(vmrun or "auto")
    except VmrunNotFound:
        runner = None
    else:
        runner = VmrunCli(path, None, gw_platform.vmrun_type(vmrun_type), None)
    return vm_inventory.find_vms(runner)


def _ask_vm(vmrun: str | None, out: _Output) -> str:
    found = _vm_candidates(vmrun, "auto")
    if found:
        out.note("VMs on this host:")
        for i, vm in enumerate(found, 1):
            tags = ", ".join(t for t in (vm.name, "running" if vm.running else None) if t)
            out.note(f"  {i}) {_safe(vm.vmx)}" + (f"  ({_safe(tags)})" if tags else ""))
    else:
        out.note("setup: no VM found (vmrun list, the VMware library); type the path of the VM's .vmx file")

    def check(value: str) -> str | None:
        if _NUMBER_RE.fullmatch(value):
            if found and 1 <= int(value) <= len(found):
                return None
            if found:
                return f"choose 1 to {len(found)}, or type a path"
            return "type the path of the VM's .vmx file"
        p = Path(_unquote(value)).expanduser()
        if p.suffix.lower() != ".vmx":
            return "the path of the VM's .vmx file"
        return None if p.is_file() else f"no such file: {p}"

    answer = _ask("VM: a number from the list, or the path of its .vmx file" if found
                  else "VM: the path of its .vmx file", "1" if found else None, check=check)
    if _NUMBER_RE.fullmatch(answer):
        return found[int(answer) - 1].vmx
    return str(Path(_unquote(answer)).expanduser().absolute())


def _open_guest(vmx: str, *, vmrun: str, vmrun_type: str, user: str, password: Secret) -> tuple[Any, Any]:
    """A VM provider and a guest channel for ``vmx`` with these credentials, without a config:
    what the x64dbg search of a first setup uses (tests replace it)."""
    from ..contracts import GuestCredentials
    from ..guest import VixChannel
    from ..vmrun import VmrunCli, VmrunProvider

    runner = VmrunCli(gw_platform.find_vmrun(vmrun), vmx, gw_platform.vmrun_type(vmrun_type),
                      GuestCredentials(user=user, password=password))
    return VmrunProvider(runner, vmx), VixChannel(runner)


def _search_x64dbg(out: _Output, session: _SetupSession, *, vmx: str, vmrun: str, vmrun_type: str, user: str,
                   password_var: str, environ: Mapping[str, str]) -> list[Mapping[str, Any]]:
    """``provision.discover_x64dbg`` in the guest; [] (with a note) when the VM does not run or the
    search fails. The password is the typed one, else the one ``environ`` resolves (environment,
    gateway.env_file); a typed password the guest refuses is asked again."""
    for attempt in range(1, _PASSWORD_TRIES + 1):
        password = session.env.get(password_var) or environ.get(password_var) or ""
        out.note("setup: searching the guest for x64dbg (the user profiles and C:\\, 4 folders deep; this "
                 "can take a minute) ...")
        try:
            vm, channel = _open_guest(vmx, vmrun=vmrun, vmrun_type=vmrun_type, user=user,
                                      password=Secret(password))
            power = vm.power_state()
            if power != PowerState.RUNNING:
                out.note(f"  the VM is not running ({power.value}), so its guest cannot be searched: type "
                         "the folder (setup needs the VM running, start it before the next step)")
                return []
            found = [e for e in _import("provision").discover_x64dbg(channel) if isinstance(e, Mapping)]
        except GuestAuthFailed:
            if not session.typed_password or attempt == _PASSWORD_TRIES:
                out.note(f"  the guest refused the user name or password of {user}: type the folder (the "
                         "doctor check guest_credentials stops setup before anything changes, and the "
                         "password is not saved)")
                return []
            out.note(f"  the guest refused the user name or password of {user}; type the password again")
            session.env[password_var] = _ask_password(user, password_var)
            continue
        except GatewayError as e:
            out.note(f"  the search failed ({e.code}: {_safe(e.message)}): type the folder")
            return []
        if not found:
            out.note("  no x64dbg found (a folder holding x64\\x64dbg.exe or x32\\x32dbg.exe)")
        return found
    return []


def _debuggers(entry: Mapping[str, Any]) -> str:
    names = [exe for arch, exe in (("x64", "x64dbg.exe"), ("x32", "x32dbg.exe"))
             if isinstance(entry.get(arch), Mapping) and entry[arch].get("exe")]
    return ", ".join(names) or "no debugger"


def _ask_x64dbg_root(args: argparse.Namespace, out: _Output, session: _SetupSession, *, vmx: str, vmrun: str,
                     vmrun_type: str, user: str, password_var: str, environ: Mapping[str, str]) -> str:
    found: list[Mapping[str, Any]] = []
    if args.dry_run:
        out.note("setup: --dry-run contacts nothing, so the guest is not searched for x64dbg")
    elif _yes("Search the guest for x64dbg now (the VM must be running)? [Y/n] "):
        found = _search_x64dbg(out, session, vmx=vmx, vmrun=vmrun, vmrun_type=vmrun_type, user=user,
                               password_var=password_var, environ=environ)
    if found:
        out.note("x64dbg in the guest:")
        for i, entry in enumerate(found, 1):
            out.note(f"  {i}) {_safe(entry.get('root'))}  ({_debuggers(entry)})")

    def check(value: str) -> str | None:
        if found and _NUMBER_RE.fullmatch(value):
            return None if 1 <= int(value) <= len(found) else f"choose 1 to {len(found)}, or type a path"
        return _check_windows_abs(_unquote(value))

    answer = _ask("x64dbg release folder in the guest (it holds x64\\ and x32\\)"
                  + (": a number from the list, or a path" if found else ", e.g. C:\\x64dbg\\release"),
                  "1" if found else None, check=check)
    if found and _NUMBER_RE.fullmatch(answer):
        return str(found[int(answer) - 1]["root"])
    return str(PureWindowsPath(_unquote(answer).replace("/", "\\")))


def _password_file_target(args: argparse.Namespace, config_env_file: Path | None, profile: str) -> Path:
    """``--save-password-file PATH``, else the file gateway.env_file names, else
    ``<profile>.env`` in the per-user config folder."""
    if args.save_password_file:
        return Path(args.save_password_file).expanduser().absolute()
    return config_env_file or _default_password_file(profile)


def _offer_save(target: Path, args: argparse.Namespace, out: _Output) -> bool:
    if target.exists() and not args.force:
        out.note(f"setup: {target} exists already, so the password is not saved there (setup "
                 "--save-password-file --force updates it)")
        return False
    return _yes(f"Save the guest user and password in {target} (only you can read it) so the MCP server can "
                "log on to the guest later? It is written once the guest has accepted it. [Y/n] ")


def _missing_flags(missing: Sequence[tuple[str, str, str]], path: Path, non_interactive: bool) -> str:
    flags = [flag for flag, _key, _example in missing]
    named = flags[0] if len(flags) == 1 else ", ".join(flags[:-1]) + " and " + flags[-1]
    why = ("--non-interactive asks nothing" if non_interactive
           else "stdin is not a terminal, so setup cannot ask for them")
    return (f"setup needs {named} to create the config {path} ({why})\n"
            f"  add: {' '.join(example for _flag, _key, example in missing)}")


def _new_config_questions(args: argparse.Namespace, out: _Output, session: _SetupSession, path: Path) -> None:
    """No config yet: the VM, the guest user, the guest password and the x64dbg folder (each only
    when its flag is missing; the password when its variable is not set), then whether to save the
    credentials. Without a terminal or with --non-interactive: a usage error naming the missing flags."""
    _check_profile_names(args)
    missing = [entry for entry in _SETUP_REQUIRED if not getattr(args, entry[1])]
    password_var = args.guest_password_env or DEFAULT_PASSWORD_ENV
    if not session.interactive:
        if missing:
            raise UsageError(_missing_flags(missing, path, args.non_interactive))
        return
    if _check_env_name(password_var):
        raise UsageError(f"--guest-password-env {_check_env_name(password_var)}")
    if missing or not os.environ.get(password_var):
        out.note(f"setup: there is no config at {path} yet; setup asks for what it needs to create it "
                 "(Ctrl-C stops; nothing is written before the questions are done)")
    if not args.vmx:
        args.vmx = _ask_vm(args.vmrun, out)
    if not args.guest_user:
        args.guest_user = _ask_guest_user(args.user)
    if not os.environ.get(password_var):
        session.env[password_var] = _ask_password(args.guest_user, password_var)
        session.typed_password = True
    if not args.x64dbg_root:
        args.x64dbg_root = _ask_x64dbg_root(args, out, session, vmx=args.vmx, vmrun=args.vmrun or "auto",
                                            vmrun_type="auto", user=args.guest_user,
                                            password_var=password_var, environ=os.environ)
    if session.typed_password and args.save_password_file is None:
        profile = args.profile_name or args.profile or DEFAULT_PROFILE_NAME
        session.save = _offer_save(_password_file_target(args, None, profile), args, out)


def _existing_config_questions(args: argparse.Namespace, out: _Output, session: _SetupSession,
                               config: gw_config.GatewayConfig, prof: gw_config.ProfileConfig) -> None:
    """A config exists: on a terminal, the guest user, the guest password and the x64dbg folder
    when the config, the flags and the environment do not give them (the password also with
    --save-password-file when it is not exported: that is the one to save), then whether to save
    the credentials."""
    if not session.interactive or prof.mode != "vmware":
        return
    env_file = _env_file_path(config)
    environ = session.environ_before_saving(config)
    user = args.user or prof.guest_user or (environ.get(prof.guest_user_env) if prof.guest_user_env else None)
    if not user:
        user = args.user = session.asked_user = _ask_guest_user(None)
        if prof.guest_user_env:
            session.env[prof.guest_user_env] = user
    password_var = prof.guest_password_env
    target = _password_file_target(args, env_file, prof.name)
    wants_file = args.save_password_file is not None and (args.force or not target.exists())
    if password_var and (not environ.get(password_var) or (wants_file and not os.environ.get(password_var))):
        session.env[password_var] = _ask_password(prof.guest_user or user, password_var)
        session.typed_password = True
    guest_steps = not (args.skip_plugin and args.skip_provision)
    root_needed = guest_steps and not args.x64dbg_root and _derive_x64dbg_root(prof) is None
    if root_needed and password_var and prof.vmx:
        args.x64dbg_root = _ask_x64dbg_root(args, out, session, vmx=prof.vmx, vmrun=prof.vmrun,
                                            vmrun_type=prof.vmrun_type, user=prof.guest_user or user,
                                            password_var=password_var, environ=environ)
    if session.typed_password and args.save_password_file is None:
        session.save = _offer_save(target, args, out)


def _plan_password_file(args: argparse.Namespace, session: _SetupSession, *, profile: str, user: str | None,
                        user_var: str | None, password_var: str | None, config_env_file: Path | None,
                        new_config: bool, environ: Mapping[str, str]) -> _PasswordFile | None:
    """The password file to write (``--save-password-file [PATH]``, or yes to the question), see
    :func:`_password_file_target`. The password is the typed one, else the one ``environ`` resolves.
    Refused before anything is written when the path exists (without --force) or is no file, or
    when there is no password or a value an env file cannot hold."""
    if not (session.save or args.save_password_file is not None):
        return None
    if not password_var:
        raise UsageError("--save-password-file needs a vmware profile with guest_password_env")
    target = _password_file_target(args, config_env_file, profile)
    password = session.env.get(password_var) or environ.get(password_var)
    if not password:
        raise ConfigError(f"--save-password-file: there is no guest password to save ({password_var} is not "
                          "set)", stage="setup", hint="export it, or run setup on a terminal to type it",
                          details={"variable": password_var})
    keys = ", ".join(k for k in (user_var, password_var) if k)
    if target.exists() and not target.is_file():
        raise ConfigError(f"{target} is not a file; setup writes the password file there",
                          stage="setup", details={"path": str(target)},
                          hint="name a file with --save-password-file PATH")
    if target.exists() and not args.force:
        raise ConfigError(f"{target} exists already; setup does not overwrite it", stage="setup",
                          details={"path": str(target)},
                          hint=f"pass --force to update its {keys} lines (other lines are kept), or name "
                               "another file with --save-password-file PATH")
    values = ([(user_var, user)] if user_var and user else []) + [(password_var, password)]
    for key, value in values:
        _env_line(key, value)  # refuses what an env file cannot hold, before anything is written
    line = None if new_config or config_env_file == target else f"env_file = {_toml_str(str(target))}"
    comments = ((f"{user_var} is for reference: the config's guest_user names the account the gateway uses.",)
                if new_config and user_var and user else ())
    return _PasswordFile(target, user_var if user_var and user else None, values, line, comments=comments)


def _env_line(key: str, value: str, *, export: bool = False) -> str:
    """``KEY='value'``: envfile.read_env_file strips one pair of surrounding quotes and nothing
    else, so any value without a line separator or NUL reads back unchanged."""
    if _unstorable(value):
        raise UsageError(f"{key}: a value with a line separator or NUL cannot be stored in an env file")
    return f"{'export ' if export else ''}{key}='{value}'"


def _updated_env_text(old: str, values: Sequence[tuple[str, str]]) -> str:
    """``old`` with the lines of these variables replaced (every other line kept as it is) and the
    missing ones appended."""
    wanted = dict(values)
    out: list[str] = []
    done: set[str] = set()
    for raw in old.splitlines(keepends=True):
        body = raw.rstrip(_LINE_ENDS)
        stripped = body.strip()
        export = stripped.startswith("export ")
        key = (stripped[len("export "):] if export else stripped).partition("=")[0].strip()
        if key in wanted and not stripped.startswith("#"):
            if key not in done:
                out.append(_env_line(key, wanted[key], export=export) + (raw[len(body):] or "\n"))
                done.add(key)
            continue
        out.append(raw)
    if out and not out[-1].endswith(tuple(_LINE_ENDS)):
        out[-1] += "\n"
    out += [_env_line(k, v) + "\n" for k, v in values if k not in done]
    return "".join(out)


def _write_in_place(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0))
    try:
        view = memoryview(text.encode("utf-8"))
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def write_password_file(path: Path, values: Sequence[tuple[str, str]], *, profile: str, force: bool,
                        comments: Sequence[str] = ()) -> None:
    """Write ``values`` to the env file ``path``, readable by its owner only. The file is created
    empty (0600, parent 0700), restricted (``platform.restrict_to_owner``: chmod 0600, on Windows
    icacls) and only then filled, so the secret never sits in a file others may read; when the
    restriction fails nothing is written (a new file is removed) and ConfigError is raised. An
    existing file is only changed with ``force``: the lines of these variables are replaced, every
    other line is kept (it must be UTF-8)."""
    lines = [_env_line(k, v) for k, v in values]  # refuses unstorable values before anything is written
    created = False
    if path.exists():
        if not path.is_file():
            raise ConfigError(f"{path} is not a file", stage="setup", details={"path": str(path)})
        if not force:
            raise ConfigError(f"{path} exists already; setup does not overwrite it", stage="setup",
                              hint="pass --force to update it", details={"path": str(path)})
        try:
            text = _updated_env_text(path.read_bytes().decode("utf-8"), values)
        except UnicodeDecodeError:
            raise ConfigError(f"{path} is not valid UTF-8, so setup does not change it", stage="setup",
                              details={"path": str(path)}) from None
    else:
        header = [f"# x64dbg-vm-gateway: guest credentials of profile {profile!r} (written by "
                  f"`{PROG} setup`).",
                  "# The config's gateway.env_file names this file; keep it readable only by you.",
                  "# Lab-only password: Windows auto-logon stores it in the guest registry and in every "
                  "snapshot.", *(f"# {c}" for c in comments)]
        text = "\n".join(header + lines) + "\n"
        _write_private(path, "", replace=False)
        created = True
    if not gw_platform.restrict_to_owner(path):
        if created:
            with contextlib.suppress(OSError):
                path.unlink()
        raise ConfigError(f"{path} could not be restricted to your account, so the password was not written "
                          "to it", stage="setup", details={"path": str(path)},
                          hint="on Windows icacls must be able to change the file's permissions; or export "
                               "the password where the MCP client starts serve instead")
    _write_in_place(path, text)


def _record_not_saved(pf: _PasswordFile, why: str, report: _SetupReport) -> None:
    pf.status, pf.reason = "not_written", why
    report.data["password_file"] = pf.public()
    report.note(f"the password was not saved in {pf.path}: {why}; run setup again (on a terminal it asks for "
                "the password and offers to save it)")


def _save_password_file_after_precheck(pf: _PasswordFile | None, precheck: Any, args: argparse.Namespace,
                                       prof: gw_config.ProfileConfig, report: _SetupReport,
                                       out: _Output) -> None:
    """Write the planned password file once the precheck's guest_credentials check passed: a
    password the guest refused, or could not check (VM not running), is not saved."""
    if pf is None or pf.status != "planned":
        return
    raw = precheck.get("checks") if isinstance(precheck, Mapping) else None
    cred = next((c for c in raw or () if isinstance(c, Mapping) and c.get("name") == "guest_credentials"),
                None)
    if cred is None or not cred.get("ok"):
        detail = str(cred.get("detail") or "") if cred is not None else ""
        if cred is None:
            why = "doctor did not check the guest credentials"
        elif detail.startswith("skipped:"):
            why = f"the guest could not check it ({detail[len('skipped:'):].strip()})"
        else:
            why = "the guest refused the user name or password"
        _record_not_saved(pf, why, report)
        return
    try:
        write_password_file(pf.path, pf.values, profile=prof.name, force=bool(args.force),
                            comments=pf.comments)
    except ConfigError as e:
        pf.status, pf.reason = "not_written", e.message
        report.data["password_file"] = pf.public()
        report.data.setdefault("warnings", []).append(
            f"{e.message} (not saved): export {pf.values[-1][0]} where the MCP client starts serve instead")
        return
    pf.status = "written"
    report.data["password_file"] = pf.public()
    out.note(f"setup: wrote {pf.path}")


def _refused_password_note(precheck: Any, session: _SetupSession, config: gw_config.GatewayConfig,
                           prof: gw_config.ProfileConfig, report: _SetupReport) -> None:
    """The guest refused a password that came from gateway.env_file: say where it is."""
    env_file = _env_file_path(config)
    var = prof.guest_password_env
    if env_file is None or not var or session.env.get(var) or os.environ.get(var):
        return
    if "guest_credentials" in _failed_checks(precheck) and env_file.exists():
        report.note(f"the guest refused the password from {env_file} ({var}): fix it there, or run setup "
                    "--save-password-file --force on a terminal to type it again")


def _password_file_notes(session: _SetupSession, report: _SetupReport, config_path: Path,
                         config: gw_config.GatewayConfig, prof: gw_config.ProfileConfig) -> None:
    pf = session.password_file
    config_env_file = _env_file_path(config)
    if pf is not None:
        report.data["password_file"] = pf.public()
        if pf.config_line:
            what = ("change gateway.env_file in the [gateway] table of" if config_env_file is not None
                    else "add this line to the [gateway] table of")
            report.note(f"setup does not edit an existing config: {what} {config_path} so serve finds the "
                        f"password file: {pf.config_line}")
    elif session.typed_password and prof.guest_password_env:
        report.note("the guest password typed for this run was not saved: before the MCP client starts "
                    f"serve, export {prof.guest_password_env} where it runs, or run setup "
                    "--save-password-file to keep it in a file only you can read")


def _check_env_file_exists(config: gw_config.GatewayConfig, session: _SetupSession, path: Path,
                           prof: gw_config.ProfileConfig) -> None:
    """gateway.env_file names a file that is not there and this run does not write it: stop with
    what to do, before the VM is contacted."""
    env_file = _env_file_path(config)
    if env_file is None or env_file.exists() or session.pending(config):
        return
    var = prof.guest_password_env or "the password variable"
    raise ConfigError(f"gateway.env_file names {env_file}, which does not exist", stage="setup",
                      details={"path": str(env_file)},
                      hint=f"run setup --save-password-file with the guest password exported in {var} to "
                           "create it, or run setup on a terminal to type the password; or fix "
                           f"gateway.env_file in {path}")


def cmd_setup(args: argparse.Namespace, out: _Output) -> int:
    path = _config_target(args)
    report = _SetupReport(args, path)
    session = _SetupSession(interactive=not args.non_interactive and _stdin_is_tty())
    new_config = not path.exists()
    deferred: list[GatewayError] = []  # --dry-run lists these with the other problems

    def plan_file(**kw: Any) -> _PasswordFile | None:
        try:
            return _plan_password_file(args, session, **kw)
        except GatewayError as e:
            if not args.dry_run:
                raise
            deferred.append(e)
            return None

    if new_config:
        _new_config_questions(args, out, session, path)
        password_var = args.guest_password_env or DEFAULT_PASSWORD_ENV
        profile = args.profile_name or args.profile or DEFAULT_PROFILE_NAME
        session.password_file = plan_file(profile=profile, user=args.guest_user, user_var=DEFAULT_USER_ENV,
                                          password_var=password_var, config_env_file=None, new_config=True,
                                          environ=os.environ)
    config, init = _setup_config(args, out, path, report, session)
    prof = config.profile(args.profile)
    report.data["config"]["profile"] = prof.name
    if not new_config:
        _existing_config_questions(args, out, session, config, prof)
        if prof.mode == "vmware":
            environ = session.environ_before_saving(config)
            # the profile's own user (a run-only --user is not saved)
            user = session.asked_user or prof.guest_user or (
                environ.get(prof.guest_user_env) if prof.guest_user_env else None)
            session.password_file = plan_file(profile=prof.name, user=user, user_var=prof.guest_user_env,
                                              password_var=prof.guest_password_env,
                                              config_env_file=_env_file_path(config), new_config=False,
                                              environ=environ)
        elif args.save_password_file is not None:
            raise UsageError("--save-password-file only applies to a vmware profile")
        _check_env_file_exists(config, session, path, prof)
    _password_file_notes(session, report, path, config, prof)
    # raises (outside --dry-run) before anything is written
    plan = _plan_setup(args, config, prof, report, session)
    if args.dry_run:
        report.data["problems"] += [p.to_dict() for p in deferred]
    elif init is not None:  # the config first: the password file is written once the guest accepted it
        config = _write_setup_config(path, init, report, out)
        prof = config.profile(args.profile)
    error: GatewayError | None = None
    if args.dry_run:
        ok = not report.data["problems"]
    else:
        current = ["precheck"]
        try:
            ok = _run_setup(args, config, prof, plan, report, out, current, session)
        except GatewayError as e:
            error = _explain(e, "setup")
            step = report.step(current[0])
            if step["status"] != "blocked":
                report.set(current[0], "failed", f"{error.code}: {error.message}")
            report.data["error"] = error.to_dict()
            ok = False
        pf = session.password_file
        if pf is not None and pf.status == "planned":
            _record_not_saved(pf, "setup stopped before the guest checked the password", report)
    report.data["ok"] = ok
    if ok or args.dry_run:
        argv = _register_argv(args, path)
        report.data["register"] = {"command": shell_join(argv), "argv": argv}
        note = _password_note(config, prof)
        if note:
            report.data["register"]["note"] = note
        report.data["mcp_config"] = mcp_config_entries(args, config, path)
    out.data(report.data, _format_setup)
    if error is not None and not out.json_mode:
        sys.stdout.flush()  # the summary first, then the error with its hint
        out.error(error)
    return EXIT_OK if ok else EXIT_FAILURE



# ── snapshot refresh / prune (human-only: no MCP tool) ──────────────
SNAPSHOT_REFRESH_WAIT_S = 60.0
_SNAPSHOT_NAME_MAX = 100  # app.SNAPSHOT_NAME_MAX
_NO_AGE_LIMIT_DAYS = 36500  # prune keeps by count only
#: failed doctor checks that do not stop a refresh: the current clean snapshot may well be missing
_REFRESH_IGNORED_CHECKS = frozenset({"clean_snapshot"})
_INIT_HEADER = f"# x64dbg-vm-gateway configuration (written by `{PROG} init`)."


def _fold(name: str) -> str:
    return name.strip().casefold()


def _require_vmware(prof: gw_config.ProfileConfig, what: str) -> None:
    if prof.mode != "vmware":
        raise UsageError(f"{what} needs a vmware profile (profile {prof.name!r} is {prof.mode})")


def _same_vm_profiles(config: gw_config.GatewayConfig,
                      prof: gw_config.ProfileConfig) -> list[gw_config.ProfileConfig]:
    """``prof`` first, then every other vmware profile of the config on the same .vmx: snapshots
    and the guest belong to the VM, not to one profile."""
    def norm(path: str) -> str:
        return os.path.normcase(os.path.abspath(os.path.expanduser(path)))

    if not prof.vmx:
        return [prof]
    return [prof, *(p for p in config.profiles.values() if p.name != prof.name and p.mode == "vmware"
                    and p.vmx and norm(p.vmx) == norm(prof.vmx))]


def _protection(profiles: Sequence[gw_config.ProfileConfig]) -> dict[str, str]:
    """Folded snapshot name -> why it is never deleted: the clean snapshot and the protected
    snapshots of every profile on the VM (the first profile's reasons win)."""
    reasons: dict[str, str] = {}
    for i, p in enumerate(profiles):
        whose = "" if i == 0 else f" of profile {p.name!r} (same VM)"
        if p.clean_snapshot:
            reasons.setdefault(_fold(p.clean_snapshot), f"the current clean snapshot{whose} (never deleted)")
        for name in p.protected_snapshots:
            reasons.setdefault(_fold(name), f"protected{whose} (never deleted)")
    return reasons


def _check_clean_name(name: str, prof: gw_config.ProfileConfig,
                      profiles: Sequence[gw_config.ProfileConfig]) -> str:
    if not name or name != name.strip():
        raise UsageError("--name must be a snapshot name without spaces at the ends")
    if any(c in "/\\" or ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise UsageError("--name must not contain '/', '\\' or control characters")
    if len(name) > _SNAPSHOT_NAME_MAX:
        raise UsageError(f"--name is longer than {_SNAPSHOT_NAME_MAX} characters")
    if prof.snapshot_prefix and name.startswith(prof.snapshot_prefix):
        prefix = prof.snapshot_prefix
        raise UsageError(f"--name must not start with {prefix!r}: that prefix marks the gateway's own "
                         "snapshots, which the gateway may delete")
    if _fold(name) in _protection(profiles):
        raise UsageError(f"{name!r} is a clean snapshot or a protected one already: choose a new name")
    return name


def _unfinished_jobs(app: Any, profiles: Sequence[gw_config.ProfileConfig]) -> list[dict[str, Any]]:
    """The jobs of these profiles (every profile on the VM) that are not DONE / FAILED, and the
    unreadable job folders that may belong to them."""
    listing = app.list_jobs(None)
    listing = listing if isinstance(listing, Mapping) else {}
    names = {p.name for p in profiles}
    terminal = {s.value for s in TERMINAL_JOB_STATES}
    jobs = [{"job_id": j.get("job_id"), "profile": j.get("profile"), "state": j.get("state")}
            for j in listing.get("jobs") or ()
            if isinstance(j, Mapping) and j.get("state") not in terminal
            and (j.get("profile") is None or j.get("profile") in names)]
    jobs += [{"job_id": c.get("job_id"), "profile": c.get("profile"), "state": "unreadable"}
             for c in listing.get("corrupt") or ()
             if isinstance(c, Mapping) and (c.get("profile") is None or c.get("profile") in names)]
    return jobs


def _snapshot_listing(app: Any, profile: str | None) -> list[str]:
    listing = app.vm_snapshots_list(profile)
    snaps = listing.get("snapshots") if isinstance(listing, Mapping) else None
    return [s["name"] for s in snaps or () if isinstance(s, Mapping) and isinstance(s.get("name"), str)]


def _ledger_write(config: gw_config.GatewayConfig, name: str, out: _Output,
                  write: Callable[[Path], Any]) -> None:
    """Update the ledger ``snapshot prune`` reads (best effort: a failure is a warning)."""
    from .. import snapshot_ledger

    try:
        write(config.jobs_root_path)
    except OSError as e:
        where = snapshot_ledger.path_for(config.jobs_root)
        why = e.strerror or type(e).__name__
        out.note(f"warning: could not record snapshot {name!r} in {where} ({why}); snapshot prune will not "
                 "list it")


def _record_taken(config: gw_config.GatewayConfig, prof: gw_config.ProfileConfig, name: str, source: str, *,
                  clean: bool, out: _Output) -> None:
    from .. import snapshot_ledger

    vmx = prof.vmx
    if vmx:
        _ledger_write(config, name, out, lambda root: snapshot_ledger.record_taken(
            root, profile=prof.name, vmx=vmx, name=name, source=source, clean=clean))


def _record_was_clean(config: gw_config.GatewayConfig, prof: gw_config.ProfileConfig, name: str,
                      out: _Output) -> None:
    from .. import snapshot_ledger

    vmx = prof.vmx
    if vmx:
        _ledger_write(config, name, out, lambda root: snapshot_ledger.mark_clean(
            root, profile=prof.name, vmx=vmx, name=name))


def _record_provisioned_snapshot(config: gw_config.GatewayConfig, prof: gw_config.ProfileConfig, result: Any,
                                 out: _Output) -> None:
    snap = result.get("snapshot") if isinstance(result, Mapping) else None
    name = snap.get("name") if isinstance(snap, Mapping) else None
    if isinstance(name, str) and name:
        clean = bool(prof.clean_snapshot) and _fold(name) == _fold(prof.clean_snapshot or "")
        _record_taken(config, prof, name, "provision", clean=clean, out=out)



def _clean_snapshot_change(prof: gw_config.ProfileConfig, new: str) -> tuple[list[str], str | None]:
    """The new protected_snapshots (the replaced clean snapshot drops out, the new one is added)
    and the snapshot that loses its protection."""
    old = prof.clean_snapshot
    protected = [p for p in prof.protected_snapshots if not (old and _fold(p) == _fold(old))]
    if _fold(new) not in {_fold(p) for p in protected}:
        protected.append(new)
    return protected, (old if old and _fold(old) != _fold(new) else None)


def _edit_clean_snapshot(path: Path, profile: str, new: str, protected: list[str]) -> str | None:
    """Rewrite ``clean_snapshot`` and ``protected_snapshots`` of ``[profiles.<profile>]`` in a
    config that init or setup wrote. Returns why it was not done, or None. Nothing is written
    unless the result parses to exactly the old document with those two values changed."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return f"cannot read {path} ({e.strerror or type(e).__name__})"
    if not text.startswith(_INIT_HEADER):
        return "the config was not written by init or setup, so setup does not edit it"
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return "the config is not valid TOML"
    table = doc.get("profiles", {}).get(profile) if isinstance(doc.get("profiles"), dict) else None
    if not isinstance(table, dict) or not {"clean_snapshot", "protected_snapshots"} <= set(table):
        return f"[profiles.{profile}] has no clean_snapshot and protected_snapshots lines to change"
    expected = json.loads(json.dumps(doc))
    expected["profiles"][profile].update(clean_snapshot=new, protected_snapshots=list(protected))
    header = "[" + ".".join(_toml_key(p) for p in ("profiles", profile)) + "]"
    values = {"clean_snapshot": _toml_str(new), "protected_snapshots": _toml_value(list(protected))}
    lines: list[str] = []
    inside = False
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("["):
            inside = stripped == header
        elif inside and stripped.partition("=")[0].strip() in values:
            key = stripped.partition("=")[0].strip()
            line = f"{key} = {values.pop(key)}{line[len(line.rstrip(chr(13) + chr(10))):]}"
        lines.append(line)
    new_text = "".join(lines)
    try:
        same = not values and tomllib.loads(new_text) == expected
        gw_config.config_from_dict(expected, source=str(path))
    except (tomllib.TOMLDecodeError, ConfigError):
        same = False
    if not same:
        return "its clean_snapshot / protected_snapshots lines are not in the shape init writes"
    _write_private(path, new_text, replace=True)
    return None


def _format_refresh(result: Mapping[str, Any]) -> str:
    res = result.get("result") if isinstance(result.get("result"), Mapping) else {}
    conf = result["config"]
    lines = [f"snapshot {result['snapshot']!r} taken (the guest was ready after {res.get('ready_s', '?')} s; "
             f"{res.get('cleaned_guest_tmp', 0)} stale helper file(s) removed from the guest temp folder)"]
    if conf["updated"]:
        lines.append(f"{conf['path']} now makes it the clean snapshot:")
    else:
        why = (f"--set-clean: {conf['reason']}; " if conf.get("set_clean") else
               "--set-clean writes this into a config written by init or setup; ")
        lines.append(f"to make it the clean snapshot, {why}set in [profiles.{result['profile']}] of "
                     f"{conf['path']}:")
    lines.extend(f"  {line}" for line in conf["lines"])
    if conf.get("unprotected"):
        then = "is no longer" if conf["updated"] else "is then no longer"
        lines.append(f"{conf['unprotected']!r} {then} protected: `{PROG} snapshot prune` lists it, and "
                     "deletes it only with --yes")
    return "\n".join(lines)


def cmd_snapshot_refresh(args: argparse.Namespace, out: _Output) -> int:
    config = _load_config(args)
    prof = config.profile(args.profile)
    _require_vmware(prof, "snapshot refresh")
    profiles = _same_vm_profiles(config, prof)
    name = _check_clean_name(args.name, prof, profiles)
    _check_wait_ready(args.wait_ready)
    provision = _import("provision")
    with _app(args, config) as app:
        _claim_jobs_root(app)
        unfinished = _unfinished_jobs(app, profiles)
        if unfinished:
            def label(job: Mapping[str, Any]) -> str:
                whose = f", profile {job['profile']}" if job.get("profile") not in (None, prof.name) else ""
                return f"{job['job_id']} ({job['state']}{whose})"

            listed = ", ".join(label(j) for j in unfinished)
            raise StateViolation(
                f"snapshot refresh: job(s) {listed} on this VM are not finished, and a clean snapshot must "
                "not contain a sample", stage="snapshot", details={"jobs": unfinished},
                hint="collect and finish them from the MCP client (analysis_collect, analysis_finish), or "
                     f"`{PROG} discard JOB_ID` one you give up, then run snapshot refresh again")
        existing = _snapshot_listing(app, args.profile)
        if any(_fold(n) == _fold(name) for n in existing):
            raise StateViolation(f"snapshot {name!r} exists already; a refresh never replaces a snapshot",
                                 stage="snapshot", details={"snapshot": name}, hint="choose another --name")
        out.note("snapshot refresh: checking the VM, the guest and the plugins (doctor) ...")
        checked = app.doctor(args.profile)
        blockers = [c for c in _failed(checked) if str(c.get("name")) not in _REFRESH_IGNORED_CHECKS
                    and setup_check_kind(str(c.get("name"))) != "advisory"]
        if blockers:
            if not out.json_mode:
                out.note(_format_doctor(checked))
            raise StateViolation(
                "snapshot refresh: the guest is not ready for a clean snapshot: "
                + ", ".join(str(c.get("name")) for c in blockers) + " failed", stage="snapshot",
                details={"failed": [str(c.get("name")) for c in blockers], "doctor": checked},
                hint=f"fix what doctor reports (`{PROG} doctor` shows the hints), then run snapshot refresh "
                     "again")
        runtime = _runtime(app, args.profile)
        out.note(f"snapshot refresh: waiting for the plugins, then taking snapshot {name!r} (a memory "
                 "snapshot takes a few minutes) ...")
        with _holding_vm(runtime):
            result = provision.take_clean_snapshot(runtime, name, wait_ready_s=float(args.wait_ready))
    protected, unprotected = _clean_snapshot_change(prof, name)
    path = _config_target(args)
    lines = [f"clean_snapshot = {_toml_str(name)}", f"protected_snapshots = {_toml_value(protected)}"]
    reason = (_edit_clean_snapshot(path, prof.name, name, protected) if args.set_clean
              else "--set-clean not given")
    # the ledger prune reads: the replaced clean snapshot has been the clean one; the new one is
    # the clean one only once the config says so
    if prof.clean_snapshot and any(_fold(n) == _fold(prof.clean_snapshot) for n in existing):
        _record_was_clean(config, prof, prof.clean_snapshot, out)
    _record_taken(config, prof, name, "refresh", clean=reason is None, out=out)
    conf: dict[str, Any] = {"path": str(path), "updated": reason is None, "set_clean": bool(args.set_clean),
                            "lines": lines, "unprotected": unprotected}
    if reason is not None:
        conf["reason"] = reason
    out.data({"ok": True, "profile": prof.name, "snapshot": name, "result": result, "config": conf},
             _format_refresh)
    return EXIT_OK


@dataclasses.dataclass
class _PruneRow:
    name: str
    action: str  # "delete" | "keep"
    reason: str


def _prune_plan(names: Sequence[str], profiles: Sequence[gw_config.ProfileConfig],
                recorded: Sequence[tuple[str, bool]], keep: int,
                unfinished_ids: Sequence[str]) -> tuple[list[_PruneRow], int]:
    """(rows, untouched) for ``profiles[0]``: the gateway's ``gw-*`` snapshots
    (``policy.retention_plan``: the newest ``keep`` job snapshots stay, so do those of unfinished
    jobs and gw-* names that are not job snapshots); the recorded ``(name, was_clean)`` snapshots
    of its ledger that were the clean snapshot once (the newest ``keep`` stay) and the ones that
    never were (kept); the clean and protected snapshots of every profile on the VM (always kept).
    ``untouched`` counts every other snapshot."""
    prof = profiles[0]
    protection = _protection(profiles)
    rows: dict[str, _PruneRow] = {}

    def owned(name: str) -> bool:
        try:
            gw_policy.check_snapshot_delete(name, prof)
        except GatewayError:
            return False
        return _fold(name) not in protection

    gateway = [n for n in names if owned(n)]
    excluded = [j for j in unfinished_ids if isinstance(j, str) and JOB_ID_RE.fullmatch(j)]
    retention = gw_config.RetentionConfig(max_gateway_snapshots=keep, max_age_days=_NO_AGE_LIMIT_DAYS)
    doomed = set(gw_policy.retention_plan(gateway, prof.snapshot_prefix, retention, datetime.now(UTC),
                                          sorted(protection), exclude_job_ids=excluded))
    job_name = re.compile(re.escape(prof.snapshot_prefix) + r"(?:job|pre-revert)-(.+)")
    for name in gateway:
        m = job_name.fullmatch(name)
        if name in doomed:
            rows[name] = _PruneRow(name, "delete", f"gateway snapshot, older than the newest {keep}")
        elif m is None or not JOB_ID_RE.fullmatch(m.group(1)):
            rows[name] = _PruneRow(name, "keep", f"not a job snapshot ({prof.snapshot_prefix}job-<job id>), "
                                                 "delete it in VMware if you do not need it")
        elif m.group(1) in excluded:
            rows[name] = _PruneRow(name, "keep", f"snapshot of the unfinished job {m.group(1)}")
        else:
            rows[name] = _PruneRow(name, "keep", f"gateway snapshot, among the newest {keep}")
    present = {_fold(n): n for n in names}
    candidates = [(present[_fold(n)], was_clean) for n, was_clean in recorded
                  if _fold(n) in present and _fold(n) not in protection and present[_fold(n)] not in rows]
    old = [n for n, was_clean in candidates if was_clean]
    kept_old = set(old[len(old) - keep:]) if keep else set()
    for name in old:
        if name in kept_old:
            rows[name] = _PruneRow(name, "keep", f"old clean snapshot, among the newest {keep}")
        else:
            rows[name] = _PruneRow(name, "delete", f"old clean snapshot, older than the newest {keep}")
    for name, was_clean in candidates:
        if not was_clean:
            rows[name] = _PruneRow(name, "keep", "taken by the gateway but never the clean snapshot (make it "
                                                 "clean_snapshot, or delete it in VMware)")
    for name in names:
        if _fold(name) in protection:
            rows[name] = _PruneRow(name, "keep", protection[_fold(name)])
    ordered = [rows[n] for n in names if n in rows]
    return ordered, len(names) - len(ordered)


def _format_prune(result: Mapping[str, Any]) -> str:
    rows = result["snapshots"]
    keep = result["keep"]
    lines = [f"snapshot prune, profile {result['profile']!r}: keep the newest {keep} gateway snapshots and "
             f"the newest {keep} old clean snapshots"]
    width = max([len(r["name"]) for r in rows] or [0])
    lines.extend(f"  {r['action']:<6}  {_safe(r['name']):<{width}}  {r['reason']}" for r in rows)
    if not rows:
        lines.append("  (no gateway or clean snapshot)")
    if result["untouched"]:
        lines.append(f"{result['untouched']} other snapshot(s) are not the gateway's and are not touched")
    for failure in result["failed"]:
        lines.append(f"failed: {_safe(failure['name'])} ({failure['error']['code']}: "
                     f"{_safe(failure['error']['message'])})")
    n = len(result["delete"])
    if result["dry_run"]:
        lines.append(f"dry run: nothing was deleted; run again with --yes to delete {n} snapshot(s)" if n
                     else "nothing to delete")
    else:
        lines.append(f"deleted {len(result['deleted'])} snapshot(s)")
    return "\n".join(lines)


def cmd_snapshot_prune(args: argparse.Namespace, out: _Output) -> int:
    from .. import snapshot_ledger

    if args.keep < 0:
        raise UsageError("--keep must be 0 or more")
    config = _load_config(args)
    prof = config.profile(args.profile)
    _require_vmware(prof, "snapshot prune")
    vmx = prof.vmx
    assert vmx is not None
    profiles = _same_vm_profiles(config, prof)
    protection = _protection(profiles)
    recorded = [(e.name, e.was_clean)
                for e in snapshot_ledger.entries(config.jobs_root_path, profile=prof.name, vmx=vmx)]
    deleted: list[str] = []
    failed: list[dict[str, Any]] = []
    with _app(args, config) as app:
        _claim_jobs_root(app)
        unfinished = [str(j["job_id"]) for j in _unfinished_jobs(app, profiles) if j.get("job_id")]
        names = _snapshot_listing(app, args.profile)
        rows, untouched = _prune_plan(names, profiles, recorded, args.keep, unfinished)
        doomed = [r.name for r in rows if r.action == "delete"]
        if args.yes and doomed:
            runtime = _runtime(app, args.profile)
            with _holding_vm(runtime):
                for name in doomed:
                    if _fold(name) in protection:  # never, whatever the plan says
                        continue
                    try:
                        runtime.vm.delete_snapshot(name)
                    except GatewayError as e:
                        failed.append({"name": name, "error": e.to_dict()})
                    else:
                        deleted.append(name)
    if deleted:
        _ledger_write(config, ", ".join(deleted), out, lambda root: snapshot_ledger.forget(
            root, profile=prof.name, vmx=vmx, names=deleted))
    result = {"ok": not failed, "profile": prof.name, "dry_run": not args.yes, "keep": args.keep,
              "snapshots": [dataclasses.asdict(r) for r in rows], "untouched": untouched, "delete": doomed,
              "deleted": deleted, "failed": failed}
    out.data(result, _format_prune)
    return EXIT_OK if not failed else EXIT_FAILURE



def cmd_snapshot(args: argparse.Namespace, out: _Output) -> int:
    handler = {"refresh": cmd_snapshot_refresh, "prune": cmd_snapshot_prune}[args.snapshot_action]
    return handler(args, out)


# ── mcp-config ──────────────────────────────────────────────────────
MCP_CLIENTS = ("claude",)


def _sync_script_path(tool_id: str) -> str | None:
    """The tool's sync script inside this installation (None for a zipped one)."""
    root = static_scripts.installed_root()
    if root is None:
        return None
    rel = static_scripts.relative_path(static_tools.get_tool(tool_id).sync_script)
    return str(root.joinpath(*rel.split("/")))


def _gateway_entry(args: argparse.Namespace, config: gw_config.GatewayConfig, path: Path) -> dict[str, Any]:
    argv = _register_argv(args, path)
    notes: list[str] = []
    try:
        note = _password_note(config, config.profile(args.profile))
    except ConfigError:  # no profile to name (several and no default): nothing to say about it
        note = None
    if note:
        notes.append(note)
    return {"id": "gateway", "display": PROG, "name": MCP_SERVER_NAME, "transport": "stdio", "verified": True,
            "argv": argv, "command": shell_join(argv), "fill_in": [], "notes": notes}


def _static_entry(tool_id: str, static: gw_config.StaticConfig) -> dict[str, Any]:
    """One static tool's registration (``claude mcp add``) from its effective recipe; placeholders
    stay visible as ``<...>`` and are listed under ``fill_in``."""
    tool = static_tools.get_tool(tool_id)
    entry: dict[str, Any] = {"id": tool_id, "display": tool.display,
                             "name": static_tools.server_name(tool_id, static)}
    try:
        recipe = static_tools.effective_recipe(tool_id, static)
    except ConfigError as e:
        recipe, argv = tool.mcp, None
        entry["error"] = {"message": e.message, "hint": e.hint}
    else:
        if recipe.command:
            argv = ["claude", "mcp", "add", recipe.name]
            for name, value in recipe.env:
                argv += ["-e", f"{name}={value}"]
            argv += ["--", *recipe.command]
        else:
            argv = ["claude", "mcp", "add", "--transport", recipe.transport, recipe.name, recipe.url or ""]
    entry.update(
        project=recipe.project, homepage=recipe.homepage or None, transport=recipe.transport,
        verified=recipe.verified, argv=argv, command=shell_join(argv) if argv else None,
        fill_in=list(static_tools.placeholders(recipe)) if argv else [], install=recipe.install or None,
        sync_script=_sync_script_path(tool_id), notes=list(recipe.notes), warning=recipe.warning or None)
    return entry


def mcp_config_entries(args: argparse.Namespace, config: gw_config.GatewayConfig, path: Path
                       ) -> list[dict[str, Any]]:
    """The MCP client registrations: the gateway first, then every configured static tool in
    ``[static] tools`` order (``mcp-config`` and ``setup`` print them)."""
    return [_gateway_entry(args, config, path),
            *(_static_entry(tid, config.static) for tid in config.static.tools)]


def format_mcp_config(entries: Sequence[Mapping[str, Any]], *, shell: str | None = None) -> str:
    """The registrations as text; ``shell`` "powershell" puts ``POWERSHELL_NOTE`` first."""
    blocks: list[str] = [POWERSHELL_NOTE] if shell == "powershell" else []
    for e in entries:
        if e["id"] == "gateway":
            lines = [f"{e['name']}: the gateway ({e['display']})"]
        elif e["argv"]:
            verified = "verified" if e["verified"] else "recipe not verified"
            lines = [f"{e['id']}: {e['display']} via {e['project']} (MCP server '{e['name']}', {verified})"]
        else:
            lines = [f"{e['id']}: {e['display']}: no MCP server is registered by default"]
        if e.get("warning"):
            lines.append(f"  WARNING: {e['warning']}")
        if e["command"]:
            lines.append(f"  {e['command']}")
        elif e.get("error") and not e.get("warning"):
            hint = e["error"]["hint"]
            lines.append(f"  {e['error']['message']}" + (f" ({hint})" if hint else ""))
        if e["fill_in"]:
            lines.append(f"  fill in: {', '.join(e['fill_in'])}")
        if e.get("install"):
            lines.append(f"  install: {e['install']}")
        if "sync_script" in e:
            lines.append(f"  sync script: {e['sync_script']}" if e["sync_script"] else
                         f"  sync script: inside the zipped package (`{PROG} static-scripts --dest DIR` "
                         "copies it)")
        lines.extend(f"  note: {note}" for note in e["notes"])
        blocks.append("\n".join(_safe_command(line) for line in lines))  # each line whole
    return "\n\n".join(blocks)


def _format_mcp_config_result(result: Mapping[str, Any]) -> str:
    return format_mcp_config(result["servers"], shell=result.get("shell"))


def cmd_mcp_config(args: argparse.Namespace, out: _Output) -> int:
    """Print the registration commands for the gateway and the configured static tools (MCP client
    ``--client``, only Claude Code so far); nothing is run or written."""
    path = _config_target(args)
    config = gw_config.load_config(path, environ=os.environ)
    out.data({"ok": True, "client": args.client, "config": str(path), "shell": command_shell(),
              "servers": mcp_config_entries(args, config, path)}, _format_mcp_config_result)
    return EXIT_OK


# ── static-scripts ──────────────────────────────────────────────────
def _format_static_scripts(result: Mapping[str, Any]) -> str:
    if "dest" in result:
        return "\n".join([f"copied {len(result['copied'])} files to {result['dest']}",
                          *(f"  {rel}" for rel in result["copied"])])
    root = result["root"]
    lines = [f"static sync scripts in this installation: {root}" if root else
             "static sync scripts: inside a zipped installation (copy them out with --dest DIR)"]
    tools = result["tools"]
    width = max(len(t) for t in [*tools, "common"])
    lines.extend(f"  {tool_id:<{width}}  {rel}" for tool_id, rel in tools.items())
    lines.append(f"  {'common':<{width}}  common/x64dbg_sync_core.py (the ghidra and radare2 scripts load it "
                 "from ../common/)")
    lines.append(f"copy them elsewhere: {PROG} static-scripts --dest DIR")
    return "\n".join(lines)


def cmd_static_scripts(args: argparse.Namespace, out: _Output) -> int:
    """Where the packaged sync scripts are, or (``--dest``) a copy of them; needs no config."""
    if args.force and not args.dest:
        raise UsageError("--force only applies together with --dest")
    if args.dest:
        dest = Path(args.dest).expanduser()
        copied = static_scripts.copy_to(dest, force=args.force)
        out.data({"ok": True, "dest": str(dest), "copied": copied}, _format_static_scripts)
        return EXIT_OK
    root = static_scripts.installed_root()
    tools = {tid: static_scripts.relative_path(static_tools.get_tool(tid).sync_script)
             for tid in static_tools.TOOL_IDS}
    out.data({"ok": True, "root": str(root) if root is not None else None,
              "files": list(static_scripts.SCRIPT_FILES), "tools": tools}, _format_static_scripts)
    return EXIT_OK


# ── parser ──────────────────────────────────────────────────────────
_PROFILE_HELP = "profile to use (default: gateway.default_profile)"


def _add_global_options(parser: argparse.ArgumentParser, *, suppress: bool,
                        profile_help: str = _PROFILE_HELP) -> None:
    def default(value: Any) -> Any:
        return argparse.SUPPRESS if suppress else value

    group = parser.add_argument_group("global options")
    group.add_argument("--config", metavar="PATH", default=default(None),
                       help=f"config file (default: ${gw_config.ENV_CONFIG_PATH} or the per-user location)")
    group.add_argument("--profile", metavar="NAME", default=default(None), help=profile_help)
    group.add_argument("--json", action="store_true", default=default(False), help="machine-readable output")
    group.add_argument("-v", "--verbose", action="store_true", default=default(False),
                       help="debug logging on stderr")


def _add_init_options(p: Any, *, setup: bool = False) -> None:
    """The config values ``init`` asks for (``setup`` uses them when it creates the config)."""
    if setup:
        helps = {
            "--non-interactive": "never ask: take every value from the flags and the environment (also what "
                                 "happens when stdin is not a terminal)",
            "--profile-name": "name of the profile in a new config (default: the global --profile, else "
                              f"{DEFAULT_PROFILE_NAME})",
            "--vmx": "host path of the VM's .vmx file, written to a new config",
            "--clean-snapshot": "clean_snapshot written to a new config: the snapshot analyses revert to "
                                f"(default: --snapshot, else {DEFAULT_CLEAN_SNAPSHOT})",
            "--guest-user": "guest account written to a new config as guest_user; provisioning also uses it "
                            "unless --user names another one",
            "--x64dbg-root": "x64dbg release folder in the guest, holding x64\\ and x32\\ (default: derived "
                             "from the profile's backends); a new config takes the backend paths from it",
        }
    else:
        helps = {
            "--non-interactive": "take every value from flags",
            "--profile-name": f"name of the new profile (default: {DEFAULT_PROFILE_NAME})",
            "--vmx": "host path of the VM's .vmx file",
            "--clean-snapshot": f"the snapshot analyses revert to (default: {DEFAULT_CLEAN_SNAPSHOT})",
            "--guest-user": "guest account that logs on and runs the debuggers",
            "--x64dbg-root": "guest directory containing x64\\ and x32\\",
        }
    p.add_argument("--non-interactive", action="store_true", help=helps["--non-interactive"])
    p.add_argument("--profile-name", metavar="NAME", help=helps["--profile-name"])
    p.add_argument("--vmx", metavar="PATH", help=helps["--vmx"])
    p.add_argument("--clean-snapshot", metavar="NAME", help=helps["--clean-snapshot"])
    p.add_argument("--guest-user", metavar="USER", help=helps["--guest-user"])
    p.add_argument("--guest-password-env", metavar="VAR",
                   help=f"environment variable holding the guest password (default: {DEFAULT_PASSWORD_ENV})")
    p.add_argument("--x64dbg-root", metavar="GUEST_PATH", help=helps["--x64dbg-root"])
    p.add_argument("--jobs-root", metavar="DIR", help="host directory for job artifacts")
    p.add_argument("--vmrun", metavar="PATH", help="vmrun executable (default: auto-detect)")
    p.add_argument("--upload-root", metavar="DIR", action="append", dest="upload_roots",
                   help="host folder samples and uploads may be read from, written to gateway.upload_roots "
                        "(repeatable; default: ~, the home folder)")


_TOP_EPILOG = f"""\
Getting started:
  1) {PROG} setup
       create the config, install the plugin, prepare the guest and take the
       clean snapshot (on a terminal it asks for what it needs; try --dry-run)
  2) {PROG} mcp-config
       print the MCP client registration commands
  3) claude mcp add {MCP_SERVER_NAME} -- {PROG} serve
       register the gateway with Claude Code (setup and mcp-config print the
       exact command for your config)
serve is started by the MCP client, not by hand.
"""

_DOCTOR_DESCRIPTION = """\
Check the configuration and the environment, one line per check, with a hint
for each failure: vmrun, the .vmx file, the VM (power, a single running
instance, VMware Tools, guest IP, isolation), the guest credentials, the guest
and host job folders, the clean snapshot, every backend (reachable, token, tool
catalog) and the static tools. For a vmware profile the VM must be running:
most checks look inside the guest.
"""

_DOCTOR_EPILOG = """\
Exit codes: 0 every check passed (warnings included), 1 a check failed,
2 usage error.

While an MCP client runs the gateway (serve), that process holds the jobs
folder: the CLI commands doctor, status and provision then stop with
LOCK_TIMEOUT. Use the gateway_doctor and session_status tools from the MCP
client instead, or close the client first.
"""

_SETUP_EPILOG = f"""\
Example, first run (no config yet, the VM is running):
  {PROG} setup --vmx ~/vmware/win10/win10.vmx --guest-user analyst \\
      --x64dbg-root 'C:\\x64dbg\\release'

These are the three values a first run needs: the VM's .vmx file, the Windows
account in the guest that logs on and runs the debuggers, and the x64dbg
release folder in the guest (it holds x64\\ and x32\\). On a terminal setup asks
for whichever is missing, and for the guest password unless the variable
{DEFAULT_PASSWORD_ENV} (--guest-password-env) holds it; --non-interactive
asks nothing. Try --dry-run first: it prints the plan and changes nothing.
"""


def _wrap(text: str, width: int = 78) -> str:
    """Pre-wrapped text for a raw help section (a raw formatter keeps descriptions as given)."""
    return "\n".join(textwrap.wrap(text, width))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG, description="Host-side MCP gateway for x64dbg-MCP inside VMware guests.",
        epilog=_TOP_EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_global_options(parser, suppress=False)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def command(name: str, handler: Callable[[argparse.Namespace, _Output], int], help_text: str, *,
                description: str | None = None, epilog: str | None = None,
                profile_help: str = _PROFILE_HELP) -> argparse.ArgumentParser:
        raw = description is not None or epilog is not None
        p = sub.add_parser(name, help=help_text, description=description or help_text, epilog=epilog,
                           formatter_class=argparse.RawDescriptionHelpFormatter if raw
                           else argparse.HelpFormatter)
        _add_global_options(p, suppress=True, profile_help=profile_help)
        p.set_defaults(handler=handler)
        return p

    p = command("serve", cmd_serve, "run the MCP server (stdio for Claude Code, http for remote clients)")
    p.add_argument("--transport", choices=("stdio", "http"), default="stdio")

    command("doctor", cmd_doctor, "check configuration, VM, guest and backends",
            description=_DOCTOR_DESCRIPTION, epilog=_DOCTOR_EPILOG)
    command("status", cmd_status, "show VM, backend and job status")

    p = command("init", cmd_init, "create a config file (interactive unless --non-interactive)")
    p.add_argument("--force", action="store_true", help="overwrite an existing config file")
    p.add_argument("--mode", choices=gw_config.MODES)
    _add_init_options(p)
    for arch in ("x64", "x32"):
        p.add_argument(f"--{arch}-url", metavar="URL", help=f"endpoint mode: {arch} plugin URL")
        p.add_argument(f"--{arch}-token-env", metavar="VAR",
                       help=f"endpoint mode: env var with the {arch} token")

    p = command("jobs", cmd_jobs, "list jobs or show one job (read-only)")
    p.add_argument("action", nargs="?", choices=("list", "show"), default="list")
    p.add_argument("job_id", nargs="?", metavar="JOB_ID")

    p = command("discard", cmd_discard, "mark a job DISCARDED (human-only) so the VM may be reverted")
    p.add_argument("job_id", metavar="JOB_ID")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    p = command("provision", cmd_provision, "prepare the guest: plugin config, tokens, tasks, auto-logon")
    p.add_argument("--x64dbg-root", required=True, metavar="GUEST_PATH",
                   help="guest directory containing x64\\ and x32\\ (e.g. C:\\x64dbg\\release)")
    p.add_argument("--user", metavar="USER",
                   help="interactive guest user (default: the profile's guest_user)")
    p.add_argument("--no-autologon", action="store_true", help="do not configure Windows auto-logon")
    p.add_argument("--bind", metavar="ADDR", default=DEFAULT_PLUGIN_BIND,
                   help=f"plugin bind address in the guest (default: {DEFAULT_PLUGIN_BIND})")
    p.add_argument("--snapshot", metavar="NAME", help="take this clean snapshot when the guest is ready")
    p.add_argument("--no-reboot", action="store_true", help="do not reboot the guest afterwards")
    p.add_argument("--wait-ready", type=float, default=DEFAULT_WAIT_READY_S, metavar="SECONDS",
                   help="how long to wait for the plugins after the reboot "
                        f"(default: {DEFAULT_WAIT_READY_S:g})")

    p = command("install-plugin", cmd_install_plugin, "copy a plugin build into the guest and relaunch")
    p.add_argument("--dist", metavar="DIR",
                   help="host folder holding x64/plugins/*.dp64 and x32/plugins/*.dp32 "
                        "(default: the build bundled with this installation)")
    p.add_argument("--x64dbg-root", metavar="GUEST_PATH", help="default: derived from the profile's backends")
    p.add_argument("--no-relaunch", action="store_true", help="do not restart the debuggers")

    setup_help = ("one-shot setup: init (if there is no config), doctor, install-plugin, provision, doctor, "
                  "and the MCP client registration command")
    p = command("setup", cmd_setup, setup_help, description=_wrap(setup_help + "."), epilog=_SETUP_EPILOG,
                profile_help="profile to use (default: gateway.default_profile); a new config also takes it "
                             "as its profile name, like --profile-name")
    p.add_argument("--dry-run", action="store_true", help="print the plan; change and contact nothing")
    p.add_argument("--skip-plugin", action="store_true", help="do not install the plugin")
    p.add_argument("--skip-provision", action="store_true",
                   help="do not provision (the debuggers are then relaunched after the plugin install)")
    group = p.add_argument_group(
        "config creation", _wrap("Used only when there is no config file yet (see init); --x64dbg-root also "
                                 "feeds install-plugin and provision.", 76))
    _add_init_options(group, setup=True)
    group = p.add_argument_group(
        "password file", _wrap(
            "The guest password comes from the variable --guest-password-env names (default "
            f"{DEFAULT_PASSWORD_ENV}), from gateway.env_file, or, on a terminal, from a question. Auto-logon "
            "stores it in the guest registry: use a lab-only password.", 76))
    group.add_argument("--save-password-file", metavar="PATH", nargs="?", const="",
                       help="write the guest user and password to a new env file only you can read, once "
                            "the doctor precheck shows that the guest accepts them (default PATH: the file "
                            "gateway.env_file names, else <profile>.env in the per-user config folder, e.g. "
                            "~/.config/x64dbg-vm-gateway/win10.env); a new config gets gateway.env_file, an "
                            "existing one is not edited (setup prints the line to add). On a terminal setup "
                            "offers this after asking for the password")
    group.add_argument("--force", action="store_true",
                       help="with --save-password-file: update an existing env file (only the user and "
                            "password lines change; the config file itself is never overwritten)")
    group = p.add_argument_group("plugin")
    group.add_argument("--dist", metavar="DIR",
                       help="host folder holding x64/plugins and x32/plugins (default: the bundled build)")
    group = p.add_argument_group("provisioning", "See provision. These apply to this run only.")
    group.add_argument("--snapshot", metavar="NAME",
                       help="snapshot provisioning takes now (default: the profile's clean_snapshot, else "
                            f"{DEFAULT_CLEAN_SNAPSHOT}); a new config also makes it its clean_snapshot "
                            "unless --clean-snapshot names another one")
    group.add_argument("--user", metavar="USER",
                       help="guest account provisioning sets up for auto-logon and the debuggers' logon "
                            "tasks, for this run (default: the profile's guest_user); --guest-user instead "
                            "writes the account into a new config")
    group.add_argument("--no-autologon", action="store_true", help="do not configure Windows auto-logon")
    group.add_argument("--bind", metavar="ADDR", default=DEFAULT_PLUGIN_BIND,
                       help=f"plugin bind address in the guest (default: {DEFAULT_PLUGIN_BIND})")
    group.add_argument("--wait-ready", type=float, default=DEFAULT_WAIT_READY_S, metavar="SECONDS",
                       help="how long to wait for the plugins after the reboot "
                            f"(default: {DEFAULT_WAIT_READY_S:g})")

    p = command("mcp-config", cmd_mcp_config,
                "print the MCP client registration commands for the gateway and the configured static "
                "tools (IDA, Ghidra, radare2, Cutter)")
    p.add_argument("--client", choices=MCP_CLIENTS, default="claude", help="MCP client (default: claude)")

    snapshot_help = "human-only clean-snapshot maintenance: take a new clean snapshot, prune old snapshots"
    p = command("snapshot", cmd_snapshot, snapshot_help, description=_wrap(
        snapshot_help + ". There is no MCP tool for either: a client cannot replace or delete the clean "
        "snapshot. Both stop with LOCK_TIMEOUT while an MCP client runs the gateway (serve)."))
    actions = p.add_subparsers(dest="snapshot_action", metavar="ACTION", required=True)
    refresh_help = ("take a new clean snapshot of the guest as it is now, after the readiness checks "
                    "provision uses (no unfinished job, a single VM instance, the plugins answer)")
    sp = actions.add_parser("refresh", help=refresh_help, description=_wrap(
        refresh_help + ". It never replaces a snapshot. Without --set-clean it prints the clean_snapshot and "
        "protected_snapshots lines to put into the config; the old clean snapshot then leaves "
        "protected_snapshots, so snapshot prune may delete it later (only with --yes)."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_global_options(sp, suppress=True)
    sp.add_argument("--name", required=True, metavar="NEW", help="name of the new clean snapshot")
    sp.add_argument("--set-clean", action="store_true",
                    help="also make it the profile's clean_snapshot (and protect it) in the config: only in "
                         "a config written by init or setup; any other config is not edited, the lines are "
                         "printed")
    sp.add_argument("--wait-ready", type=float, default=SNAPSHOT_REFRESH_WAIT_S, metavar="SECONDS",
                    help="how long to wait for the plugins to answer before the snapshot "
                         f"(default: {SNAPSHOT_REFRESH_WAIT_S:g})")
    prune_help = ("list the gateway's gw-* snapshots and the old clean snapshots it recorded, and delete "
                  "them with --yes (dry run by default)")
    sp = actions.add_parser("prune", help=prune_help, description=_wrap(
        prune_help + ". The newest --keep N of each kind stay, and so do the snapshots of unfinished jobs, "
        "the profile's clean snapshot and its protected snapshots (always). Snapshots the gateway did not "
        "make or record are never touched."), formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_global_options(sp, suppress=True)
    sp.add_argument("--keep", type=int, required=True, metavar="N",
                    help="how many of the newest gateway snapshots and of the newest old clean snapshots "
                         "stay")
    sp.add_argument("--yes", action="store_true", help="delete them (without it, only the list is printed)")

    p = command("static-scripts", cmd_static_scripts,
                "show where the static-tool sync scripts (IDA, Ghidra, radare2/rizin/Cutter) are installed, "
                "or copy them")
    p.add_argument("--dest", metavar="DIR", help="copy the scripts into DIR (keeps their layout)")
    p.add_argument("--force", action="store_true", help="with --dest: replace files that already exist")
    return parser


def _setup_logging(verbose: bool, command: str) -> None:
    root = logging.getLogger()
    if root.handlers:  # embedded (tests, another host program): leave logging alone
        return
    level = logging.DEBUG if verbose else (logging.INFO if command == "serve" else logging.WARNING)
    logging.basicConfig(level=level, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as e:  # argparse: --help (0) or a usage error (2)
        return e.code if isinstance(e.code, int) else EXIT_USAGE
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    _setup_logging(args.verbose, args.command)
    out = _Output(args.json)
    try:
        return int(args.handler(args, out))
    except UsageError as e:
        _emit(sys.stderr, f"{PROG} {args.command}: error: {e}")
        return EXIT_USAGE
    except GatewayError as e:
        out.error(_explain(e, args.command))
        return EXIT_FAILURE
    except KeyboardInterrupt:
        out.note("interrupted")
        return 130
    except Exception as e:
        log.debug("unexpected error in %s", args.command, exc_info=True)
        out.error(InternalError(f"unexpected {type(e).__name__}", stage="cli",
                                hint="run again with --verbose to see the traceback"))
        return EXIT_FAILURE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
