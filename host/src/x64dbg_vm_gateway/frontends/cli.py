"""``x64dbg-vm-gateway`` command line (plan 5.1).

Commands::

    serve [--transport stdio|http]      MCP server (stdio for Claude Code, http for remote clients)
    doctor                              configuration / environment checks
    status                              session status (VM, backends, job)
    init                                write a config file (wizard, or --non-interactive flags)
    jobs [list | show JOB_ID]           read-only view of the job directories
    discard JOB_ID [--yes]              human-only: mark a job DISCARDED so it may be reverted
    provision --x64dbg-root PATH ...    prepare the guest (plugin config, tasks, auto-logon)
    install-plugin --dist DIR ...       copy a plugin build into the guest

Global options (before or after the command): ``--config PATH``, ``--profile NAME``,
``--json`` (machine-readable stdout), ``-v/--verbose``.

Exit codes: 0 success, 1 failure (gateway errors print code, message and hint),
2 usage error. Diagnostics go to stderr; stdout carries only results (and,
for ``serve --transport stdio``, nothing but the MCP stream).

The orchestrator (``wiring.build_app``) and the provisioning module are
imported lazily inside the commands, so importing this module stays cheap and
tests can substitute them through ``sys.modules``. ``jobs`` reads the
``state.json`` files directly (read-only, no store lock) so it also works while
a gateway is serving.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import logging
import os
import re
import sys
import tomllib
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path, PureWindowsPath
from typing import Any

from .. import config as gw_config
from .. import platform as gw_platform
from ..errors import ConfigError, GatewayError, JobNotFound, StateViolation, VmrunNotFound
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
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_WIN_ABS_RE = re.compile(r"^[A-Za-z]:\\")
_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class UsageError(Exception):
    """Bad command line usage (exit code 2)."""


# ── output ──────────────────────────────────────────────────────────
def _safe(text: Any) -> str:
    """Strip terminal control characters from text that may come from the guest."""
    return sanitize_untrusted_text(str(text), max_len=10_000)


def _dumps(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


class _Output:
    def __init__(self, json_mode: bool) -> None:
        self.json_mode = json_mode

    def data(self, value: Any, human: Callable[[Any], str] | None = None) -> None:
        if self.json_mode or human is None:
            print(_dumps(value))
        else:
            print(human(value))

    def note(self, text: str) -> None:
        print(text, file=sys.stderr)

    def error(self, err: GatewayError) -> None:
        if self.json_mode:
            print(_dumps({"ok": False, "error": err.to_dict()}))
            return
        lines = [f"error [{err.code}]: {_safe(err.message)}"]
        if err.hint:
            lines.append(f"  hint: {_safe(err.hint)}")
        if err.next_tool:
            lines.append(f"  next: {err.next_tool}")
        print("\n".join(lines), file=sys.stderr)


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


def _is_windows_abs(path: str) -> bool:
    return bool(_WIN_ABS_RE.match(path.replace("/", "\\")))


def _require_windows_abs(path: str, flag: str) -> str:
    if not _is_windows_abs(path):
        raise UsageError(f"{flag} must be an absolute guest path such as C:\\x64dbg\\release")
    return str(PureWindowsPath(path.replace("/", "\\")))


def _confirm(prompt: str) -> bool:
    try:
        answer = input(prompt)
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

        http_server.check_http_config(config.http, os.environ)  # fail before touching the VM
        with _app(args, config) as app:
            http_server.serve_http(app, config.http, environ=os.environ, jobs_root=config.jobs_root_path)
        return EXIT_OK
    from . import mcp_server

    with _app(args, config) as app:
        mcp_server.run_stdio(app)
    return EXIT_OK


def _format_doctor(result: Any) -> str:
    raw = result.get("checks") if isinstance(result, Mapping) else None
    checks = [c for c in raw if isinstance(c, Mapping)] if isinstance(raw, list) else []
    lines = []
    for check in checks:
        ok = bool(check.get("ok"))
        detail = check.get("detail")
        line = f"[{' ok ' if ok else 'FAIL'}] {_safe(check.get('name'))}"
        lines.append(f"{line}: {_safe(detail)}" if detail else line)
        if not ok and check.get("hint"):
            lines.append(f"       hint: {_safe(check['hint'])}")
    failed = sum(1 for c in checks if not c.get("ok"))
    ok_all = isinstance(result, Mapping) and bool(result.get("ok"))
    lines.append("doctor: all checks passed" if ok_all else f"doctor: {failed} check(s) failed")
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


def cmd_provision(args: argparse.Namespace, out: _Output) -> int:
    x64dbg_root = _require_windows_abs(args.x64dbg_root, "--x64dbg-root")
    if args.wait_ready <= 0:
        raise UsageError("--wait-ready must be greater than 0")
    config = _load_config(args)
    prof = config.profile(args.profile)
    user = args.user or prof.guest_user
    if not user:
        raise UsageError("--user is required because the profile has no guest_user")
    password = gw_config.resolve_secret(prof.guest_password_env, os.environ)
    autologon = not args.no_autologon
    if autologon and password is None:
        env_name = prof.guest_password_env
        raise ConfigError(
            "auto-logon needs the guest password, but "
            + (f"environment variable {env_name} is not set" if env_name
               else f"profile {prof.name!r} has no guest_password_env"),
            stage="provision",
            hint="export the guest password in that variable, or pass --no-autologon",
            details={"key": f"profiles.{prof.name}.guest_password_env"},
        )
    provision = _import("provision")
    with _app(args, config) as app:
        result = provision.provision_guest(
            _runtime(app, args.profile),
            x64dbg_root=x64dbg_root,
            user=user,
            password=password,
            autologon=autologon,
            bind=args.bind,
            reboot=not args.no_reboot,
            wait_ready_s=float(args.wait_ready),
            clean_snapshot=args.snapshot,
        )
    out.data(result)
    return EXIT_OK if _result_ok(result) else EXIT_FAILURE


def cmd_install_plugin(args: argparse.Namespace, out: _Output) -> int:
    dist = Path(args.dist).expanduser()
    if not dist.is_dir():
        raise UsageError(f"--dist is not a directory: {dist}")
    x64dbg_root = _require_windows_abs(args.x64dbg_root, "--x64dbg-root") if args.x64dbg_root else None
    config = _load_config(args)
    provision = _import("provision")
    with _app(args, config) as app:
        result = provision.install_plugin(_runtime(app, args.profile), dist_dir=dist, x64dbg_root=x64dbg_root,
                                          relaunch=not args.no_relaunch)
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
            raw = input(f"{prompt}{suffix}: ")
        except EOFError:
            raise UsageError("init cancelled (end of input)") from None
        value = raw.strip() or (default or "")
        if not value:
            if not required:
                return ""
            print("  a value is required", file=sys.stderr)
            continue
        problem = check(value) if check else None
        if problem:
            print(f"  {problem}", file=sys.stderr)
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
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
        gw_platform.secure_dir(parent)
    data = text.encode("utf-8")
    target = parent / f".{path.name}.{os.getpid()}.tmp" if replace else path
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


def cmd_init(args: argparse.Namespace, out: _Output) -> int:
    path = _config_target(args)
    if path.exists() and not args.force:
        raise ConfigError(f"{path} already exists; refusing to overwrite it", stage="init",
                          hint="pass --force to replace it", details={"path": str(path)})
    answers = _init_answers(args)
    vmrun_value, vmrun_path = _discover_vmrun(answers, out)
    doc = _init_document(answers, vmrun_value)
    gw_config.config_from_dict(doc, source=str(path))  # same validation as load_config
    text = to_toml(doc, header=f"x64dbg-vm-gateway configuration (written by `{PROG} init`).\n"
                               "Secrets are never stored here: *_env keys name environment variables.")
    if tomllib.loads(text) != json.loads(json.dumps(doc)):  # belt and braces for the TOML writer
        raise InternalError("generated TOML does not round-trip", stage="init")
    _write_private(path, text + _HTTP_EXAMPLE, replace=args.force)
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
    p.add_argument("--non-interactive", action="store_true", help="take every value from flags")
    p.add_argument("--force", action="store_true", help="overwrite an existing config file")
    p.add_argument("--mode", choices=gw_config.MODES)
    p.add_argument("--profile-name", metavar="NAME")
    p.add_argument("--vmx", metavar="PATH", help="host path of the VM's .vmx file")
    p.add_argument("--clean-snapshot", metavar="NAME", help=f"default: {DEFAULT_CLEAN_SNAPSHOT}")
    p.add_argument("--guest-user", metavar="USER")
    p.add_argument("--guest-password-env", metavar="VAR", help=f"default: {DEFAULT_PASSWORD_ENV}")
    p.add_argument("--x64dbg-root", metavar="GUEST_PATH", help="guest directory containing x64\\ and x32\\")
    p.add_argument("--jobs-root", metavar="DIR", help="host directory for job artifacts")
    p.add_argument("--vmrun", metavar="PATH", help="vmrun executable (default: auto-detect)")
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
    p.add_argument("--dist", required=True, metavar="DIR", help="host directory with the built .dp64/.dp32")
    p.add_argument("--x64dbg-root", metavar="GUEST_PATH", help="default: derived from the profile's backends")
    p.add_argument("--no-relaunch", action="store_true", help="do not restart the debuggers")
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
        print(f"{PROG} {args.command}: error: {e}", file=sys.stderr)
        return EXIT_USAGE
    except GatewayError as e:
        out.error(e)
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
