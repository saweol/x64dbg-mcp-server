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
``install-plugin``, ``setup``) then fail with LOCK_TIMEOUT naming the gateway's
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
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import importlib
import json
import logging
import math
import os
import re
import shlex
import subprocess  # noqa: S404 - only list2cmdline (quoting), nothing is run
import sys
import tempfile
import tomllib
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, Any, TextIO

from .. import config as gw_config
from .. import envfile, plugin_bundle, static_scripts, static_tools
from .. import platform as gw_platform
from ..errors import (
    ConfigError,
    GatewayError,
    JobNotFound,
    LockTimeout,
    StateViolation,
    TransferError,
    VmrunNotFound,
)
from ..jobs import DISCARD_ACTOR, JOB_ID_RE, Job, validate_job_id
from ..proxy import sanitize_untrusted_text
from .tool_defs import InternalError

if TYPE_CHECKING:
    from ..contracts import Secret

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
def _app(args: argparse.Namespace, config: gw_config.GatewayConfig) -> Iterator[Any]:
    app = _import("wiring").build_app(config, profile=args.profile, environ=os.environ)
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
                      prof: gw_config.ProfileConfig) -> _ProvisionInputs:
    """The guest user and password (``--user``, the profile, gateway.env_file); fails before any VM work."""
    _check_wait_ready(args.wait_ready)
    # the same resolution as the serving gateway: the real environment over gateway.env_file
    environ = envfile.resolve_environ(config, os.environ)
    user = args.user or prof.guest_user or (environ.get(prof.guest_user_env) if prof.guest_user_env else None)
    if not user:
        raise UsageError(
            "--user is required because the profile has no guest_user"
            + (f" and {prof.guest_user_env} is not set" if prof.guest_user_env else "")
        )
    password = gw_config.resolve_secret(prof.guest_password_env, environ)
    autologon = not args.no_autologon
    if autologon and password is None:
        env_name = prof.guest_password_env
        raise ConfigError(
            "auto-logon needs the guest password, but "
            + (f"environment variable {env_name} is not set (environment or gateway.env_file)" if env_name
               else f"profile {prof.name!r} has no guest_password_env"),
            stage="provision",
            hint="export the guest password in that variable, or pass --no-autologon",
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
            raise UsageError("init cancelled (end of input)") from None
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
    return {"gateway": {"jobs_root": a["jobs_root"], "default_profile": name}, "profiles": {name: profile}}


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
                    "vmrun", "non_interactive")
_ENDPOINT_INIT_DEFAULTS = {"mode": None, "force": False, "x64_url": None, "x64_token_env": None,
                           "x32_url": None, "x32_token_env": None}


def _windows_host() -> bool:
    return os.name == "nt"


def shell_join(argv: Sequence[str], *, windows: bool | None = None) -> str:
    """A command line to paste into a shell: POSIX quoting, or cmd/PowerShell quoting on Windows."""
    if windows if windows is not None else _windows_host():
        return subprocess.list2cmdline(list(argv))
    return shlex.join(argv)


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
            "ok": False, "dry_run": bool(args.dry_run),
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


def _setup_init_args(args: argparse.Namespace) -> argparse.Namespace:
    """The init options of ``setup`` as ``init`` sees them (vmware mode, never --force); the global
    --profile and --snapshot name the new profile and its clean snapshot unless given explicitly."""
    ns = argparse.Namespace(**{**_ENDPOINT_INIT_DEFAULTS, **vars(args)})
    ns.profile_name = args.profile_name or args.profile
    ns.clean_snapshot = args.clean_snapshot or args.snapshot
    return ns


def _setup_config(args: argparse.Namespace, out: _Output, path: Path,
                  report: _SetupReport) -> tuple[gw_config.GatewayConfig, _InitPlan | None]:
    """(a) The existing config, or the one the init logic would write (with its plan; nothing is
    written here)."""
    if path.exists():
        config = gw_config.load_config(path, environ=os.environ)
        report.set("init", "skipped", f"using the existing config {path}")
        given = [f"--{k.replace('_', '-')}" for k in _SETUP_INIT_ONLY if getattr(args, k, None)]
        if given:
            report.note(f"the config exists, so {', '.join(given)} were not used (edit {path}, or run "
                        f"`{PROG} init --force`)")
        return config, None
    if args.profile and args.profile_name and args.profile != args.profile_name:
        raise UsageError(f"--profile {args.profile} and --profile-name {args.profile_name} name different "
                         "profiles for the new config")
    plan = _plan_init(_setup_init_args(args), out, path)
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
                report: _SetupReport) -> _SetupPlan:
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
    inputs = attempt(lambda: _provision_inputs(args, config, prof)) if provision else None
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
               plan: _SetupPlan, report: _SetupReport, out: _Output, current: list[str]) -> bool:
    """(b)-(e) against the VM; ``current[0]`` names the running step (for error reports)."""
    with _app(args, config) as app:
        current[0] = "precheck"
        _claim_jobs_root(app)
        out.note("setup: checking the configuration, the VM and the guest (doctor) ...")
        before = app.doctor(args.profile)
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
    lines: list[str] = []
    for step in report["steps"]:
        status = _STATUS_WORDS.get(step["status"], step["status"])
        detail = _safe(step.get("detail") or "")
        lines.append(f"[{status}] {step['step']}" + (f": {detail}" if detail else ""))
        final_failed = step["step"] == "doctor" and step["status"] == "failed"
        if (step.get("blockers") or final_failed) and isinstance(step.get("result"), Mapping):
            lines.extend("    " + line for line in _format_doctor(step["result"]).splitlines())
        if report["dry_run"] and step.get("command"):
            lines.append(f"    = {_safe(step['command'])}")
    lines.extend(f"note: {_safe(n)}" for n in report.get("notes", ()))
    for problem in report.get("problems", ()):
        lines.append(f"problem [{problem['code']}]: {_safe(problem['message'])}")
        if problem.get("hint"):
            lines.append(f"  hint: {_safe(problem['hint'])}")
    if report.get("mcp_config"):  # the same block as `mcp-config`
        lines += ["", "register the MCP servers with Claude Code:", "",
                  format_mcp_config(report["mcp_config"]), ""]
    if report["dry_run"]:
        lines.append("dry run: nothing was changed")
    elif report["ok"]:
        lines.append("setup complete")
    else:
        lines.append("setup stopped: fix what is shown above and run setup again")
    return "\n".join(lines)


def cmd_setup(args: argparse.Namespace, out: _Output) -> int:
    path = _config_target(args)
    report = _SetupReport(args, path)
    config, init = _setup_config(args, out, path, report)
    prof = config.profile(args.profile)
    report.data["config"]["profile"] = prof.name
    plan = _plan_setup(args, config, prof, report)  # raises (outside --dry-run) before anything is written
    if init is not None and not args.dry_run:
        config = _write_setup_config(path, init, report, out)
        prof = config.profile(args.profile)
    error: GatewayError | None = None
    if args.dry_run:
        ok = not report.data["problems"]
    else:
        current = ["precheck"]
        try:
            ok = _run_setup(args, config, prof, plan, report, out, current)
        except GatewayError as e:
            error = _explain(e, "setup")
            step = report.step(current[0])
            if step["status"] != "blocked":
                report.set(current[0], "failed", f"{error.code}: {error.message}")
            report.data["error"] = error.to_dict()
            ok = False
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


def format_mcp_config(entries: Sequence[Mapping[str, Any]]) -> str:
    blocks: list[str] = []
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
        blocks.append("\n".join(_safe(line) for line in lines))
    return "\n\n".join(blocks)


def _format_mcp_config_result(result: Mapping[str, Any]) -> str:
    return format_mcp_config(result["servers"])


def cmd_mcp_config(args: argparse.Namespace, out: _Output) -> int:
    """Print the registration commands for the gateway and the configured static tools (MCP client
    ``--client``, only Claude Code so far); nothing is run or written."""
    path = _config_target(args)
    config = gw_config.load_config(path, environ=os.environ)
    out.data({"ok": True, "client": args.client, "config": str(path),
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
def _add_global_options(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    def default(value: Any) -> Any:
        return argparse.SUPPRESS if suppress else value

    group = parser.add_argument_group("global options")
    group.add_argument("--config", metavar="PATH", default=default(None),
                       help=f"config file (default: ${gw_config.ENV_CONFIG_PATH} or the per-user location)")
    group.add_argument("--profile", metavar="NAME", default=default(None),
                       help="profile to use (default: gateway.default_profile)")
    group.add_argument("--json", action="store_true", default=default(False), help="machine-readable output")
    group.add_argument("-v", "--verbose", action="store_true", default=default(False),
                       help="debug logging on stderr")


def _add_init_options(p: Any, *,
                      x64dbg_root_help: str = "guest directory containing x64\\ and x32\\") -> None:
    """The config values ``init`` asks for (``setup`` passes them through to it)."""
    p.add_argument("--non-interactive", action="store_true", help="take every value from flags")
    p.add_argument("--profile-name", metavar="NAME")
    p.add_argument("--vmx", metavar="PATH", help="host path of the VM's .vmx file")
    p.add_argument("--clean-snapshot", metavar="NAME", help=f"default: {DEFAULT_CLEAN_SNAPSHOT}")
    p.add_argument("--guest-user", metavar="USER")
    p.add_argument("--guest-password-env", metavar="VAR", help=f"default: {DEFAULT_PASSWORD_ENV}")
    p.add_argument("--x64dbg-root", metavar="GUEST_PATH", help=x64dbg_root_help)
    p.add_argument("--jobs-root", metavar="DIR", help="host directory for job artifacts")
    p.add_argument("--vmrun", metavar="PATH", help="vmrun executable (default: auto-detect)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG, description="Host-side MCP gateway for x64dbg-MCP inside VMware guests.")
    _add_global_options(parser, suppress=False)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def command(name: str, handler: Callable[[argparse.Namespace, _Output], int], help_text: str
                ) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        _add_global_options(p, suppress=True)
        p.set_defaults(handler=handler)
        return p

    p = command("serve", cmd_serve, "run the MCP server (stdio for Claude Code, http for remote clients)")
    p.add_argument("--transport", choices=("stdio", "http"), default="stdio")

    command("doctor", cmd_doctor, "check configuration, VM, guest and backends")
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

    p = command("setup", cmd_setup,
                "one-shot setup: init (if there is no config), doctor, install-plugin, provision, doctor, "
                "and the MCP client registration command")
    p.add_argument("--dry-run", action="store_true", help="print the plan; change and contact nothing")
    p.add_argument("--skip-plugin", action="store_true", help="do not install the plugin")
    p.add_argument("--skip-provision", action="store_true",
                   help="do not provision (the debuggers are then relaunched after the plugin install)")
    group = p.add_argument_group("config creation (used only when there is no config file, see init; "
                                 "--x64dbg-root also feeds install-plugin and provision)")
    _add_init_options(group, x64dbg_root_help="guest directory containing x64\\ and x32\\ "
                                              "(default: derived from the profile's backends)")
    group = p.add_argument_group("plugin")
    group.add_argument("--dist", metavar="DIR",
                       help="host folder holding x64/plugins and x32/plugins (default: the bundled build)")
    group = p.add_argument_group("provisioning (see provision)")
    group.add_argument("--snapshot", metavar="NAME",
                       help="clean snapshot to take (default: the profile's clean_snapshot, "
                            f"{DEFAULT_CLEAN_SNAPSHOT})")
    group.add_argument("--user", metavar="USER",
                       help="interactive guest user (default: the profile's guest_user)")
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
