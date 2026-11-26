"""Application facade contract between the orchestrator (app.py) and front-ends.

Front-ends (MCP server, CLI, a future static-tool client) talk ONLY to ``GatewayApp``.
Every method is synchronous and thread-safe, returns JSON-serialisable data
(dicts/lists/str/int/float/bool/None) and raises ``errors.GatewayError``
subclasses on failure; front-ends turn those into the error schema
``GatewayError.to_dict()``.

Long-running operations (``analysis_start``, ``vm_snapshot_revert``,
``vm_power``) accept ``wait_s``. If the work is not finished within ``wait_s``
seconds the call returns ``{"state": "in_progress", "op_id": ..., "stage": ...,
"job_id": ...}`` while the work continues on a background thread; progress and
the final outcome are reported by ``session_status()["operation"]``. Calling the
same operation again with identical arguments while it runs returns the same
in-progress record (idempotent) instead of starting a second one.

Several VMs: one app serves every configured profile. Calls that name no profile
(the mirrored tools, ``debugger_*`` without ``profile``, tools without ``job_id``) go to
the *current target* of the client session they come from. A front-end that serves
several clients says which session a call belongs to by running the app call inside
``client_session(key)`` (``CLIENT_SESSION``); calls outside one share the session
``None`` (stdio, the CLI: one client per process). ``analysis_start`` and
``debugger_select(profile=...)`` set the target of their session.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator, Mapping, Sequence
from contextvars import ContextVar
from typing import Any, Protocol, runtime_checkable

from .contracts import ToolInfo

JSON = dict[str, Any]

CLIENT_SESSION: ContextVar[str | None] = ContextVar("x64dbg_vm_gateway_client_session", default=None)
"""Key of the client session the current app call comes from (see the module docstring).
Never part of a tool's arguments: a client cannot name another client's session."""

STATELESS_SESSION = "<stateless>"
"""``CLIENT_SESSION`` of a call from a client without a session the front-end can vouch for
(e.g. a stateless HTTP request): it never keeps a target, so each such call is routed on its
own (explicit profile, the only live job, the default profile, or TARGET_AMBIGUOUS)."""


@contextlib.contextmanager
def client_session(key: str | None) -> Iterator[None]:
    """Run the app calls inside the ``with`` block on behalf of client session ``key``.
    Context variables follow ``anyio.to_thread.run_sync`` into its worker thread."""
    token = CLIENT_SESSION.set(key)
    try:
        yield
    finally:
        CLIENT_SESSION.reset(token)


@runtime_checkable
class GatewayApp(Protocol):
    # ── observation ───────────────────────────────────────────────────
    def session_status(self, profile: str | None = None) -> JSON:
        """VM power/tools/ip, per-backend health + epoch, active job, running
        operation, recovery warnings, isolation warnings. Also ACKs the current
        backend epochs (after this call mutating mirrored tools are accepted again)."""
        ...

    def doctor(self, profile: str | None = None) -> JSON:
        """{"ok": bool, "checks": [{"name", "ok", "detail", "hint"}]} — never raises for
        a failing check; raises only for unusable configuration. A check may add "level"
        ("ok" | "warn") and data: ``static_tools`` (always ok) adds "tools", one entry per
        configured static tool {"id", "display", "executable", "mcp", "warnings"}."""
        ...

    def instructions(self) -> str:
        """Server instructions: gateway loop rules + cached backend instructions."""
        ...

    def list_mirrored_tools(self) -> list[ToolInfo]:
        """Backend tools to expose under their original names (never empty: falls
        back to the builtin catalog)."""
        ...

    # ── VM ────────────────────────────────────────────────────────────
    def vm_snapshots_list(self, profile: str | None = None) -> JSON: ...
    def vm_snapshot_take(self, name: str, profile: str | None = None) -> JSON: ...
    def vm_snapshot_revert(self, name: str | None = None, profile: str | None = None,
                           wait_s: float | None = None) -> JSON: ...
    def vm_snapshot_delete(self, name: str, profile: str | None = None) -> JSON: ...
    def vm_power(self, action: str, profile: str | None = None,
                 wait_s: float | None = None) -> JSON:
        """action in {"start", "stop", "suspend", "reset"}."""
        ...

    def vm_screenshot(self, profile: str | None = None) -> JSON:
        """{"host_path": str}; saved under the active job (or jobs_root/_screens)."""
        ...

    # ── files ─────────────────────────────────────────────────────────
    def file_upload(self, host_path: str, guest_dir: str | None = None,
                    job_id: str | None = None) -> JSON: ...
    def file_download(self, guest_path: str, job_id: str | None = None) -> JSON: ...

    # ── debugger ──────────────────────────────────────────────────────
    def debugger_select(self, backend_id: str | None = None, profile: str | None = None) -> JSON:
        """Make ``profile`` (and/or ``backend_id`` within it) the current target of the
        calling client session; at least one of them is required."""
        ...

    def debugger_restart(self, backend_id: str | None = None, reason: str = "requested",
                         profile: str | None = None) -> JSON: ...
    def debugger_call(self, tool: str, arguments: Mapping[str, Any] | None = None,
                      backend_id: str | None = None, profile: str | None = None) -> JSON:
        """Generic escape hatch: call any backend tool by name (also ones the client
        never saw in tools/list). Result: {"texts": [...], "is_error": bool, "epoch",
        "backend_id", "profile"}. ``profile`` overrides the session target for this call."""
        ...

    def call_mirrored(self, tool: str, arguments: Mapping[str, Any] | None = None) -> JSON:
        """Route a mirrored backend tool to the session's current target (see the module
        docstring). Same result shape as debugger_call. Texts are already sanitised/wrapped
        as untrusted output."""
        ...

    # ── analysis loop ────────────────────────────────────────────────
    def analysis_start(self, sample_path: str, *, profile: str | None = None,
                       snapshot: str | None = None, arch: str = "auto",
                       args: str | None = None, cwd: str | None = None, load: bool = True,
                       revert: bool = True, reload_on_restart: bool = False,
                       wait_s: float | None = None) -> JSON: ...

    def analysis_collect(self, job_id: str | None = None,
                         extra_guest_paths: Sequence[str] = (),
                         extract: bool | None = None) -> JSON: ...

    def analysis_finish(self, job_id: str | None = None, *, revert: bool = True,
                        keep_snapshot: bool = False, wait_s: float | None = None) -> JSON: ...

    # ── static analysis: IDA, Ghidra, radare2/rizin, Cutter (interpretation D) ──
    # Tool-neutral: static address = image base of the static tool's database + RVA. The
    # static tools' own MCP servers are registered next to the gateway, not proxied.
    def static_rebase(self, address: str | int, *, direction: str, module: str | None = None,
                      imagebase: str | int | None = None, job_id: str | None = None,
                      ida_imagebase: str | int | None = None) -> JSON:
        """direction in {"runtime_to_static", "static_to_runtime", "runtime_to_rva",
        "rva_to_runtime"} (older names "runtime_to_ida" / "ida_to_runtime" are accepted).
        ``ida_imagebase`` is a deprecated alias of ``imagebase`` (InvalidArgument when both
        are given and differ).

        ``ida_sync.rebase`` result plus ``static`` / ``imagebase`` (the same values as
        ``ida`` / ``ida_imagebase``), ``job_id`` and ``module_map_source`` ("live":
        ListModules of the job's debugger; "manifest": the collected map). ``warnings``
        also says when the collected map stood in for an unavailable live one while the
        debugger should still hold the sample. Raises InvalidArgument for a bad
        address/module/direction/image base, StateViolation without a map."""
        ...

    def static_export_annotations(self, job_id: str | None = None) -> JSON:
        """SaveDatabase, copy it to the host (``<job>/artifacts/static_sync.dd64|dd32``), write
        ``<job>/artifacts/static_sync.json`` (x64dbg-ida-sync/1, tool-neutral: module + RVA).
        {"host_path", "modules", "items", "counts", "database",
        "module_map_source", "skipped", "warnings", "steps"}. ``database.source`` is "saved",
        "collected" or "not_written" (x64dbg wrote no file; ``host_path`` is None and the
        document is empty; ``warnings`` says whether the plugin reported an empty session or,
        for older plugin builds, that it cannot be told from a failed save). DatabaseFormatError
        for an unreadable (e.g. LZ4-compressed) database; BackendError when SaveDatabase reports
        a failure. Long operation (may answer in_progress)."""
        ...

    def static_import_annotations(self, items: Sequence[Mapping[str, Any]], *, module: str,
                                  imagebase: str | int | None = None,
                                  job_id: str | None = None,
                                  ida_imagebase: str | int | None = None) -> JSON:
        """Items ``{rva | ida_address, name?, comment?}`` (ida_sync.plan_import_report;
        ``ida_address`` is an address in the static tool's database and needs ``imagebase``,
        whose deprecated alias is ``ida_imagebase``) are
        set in the live debugger with CommentOrLabelAtAddress. {"applied", "failed",
        "not_attempted", "operations", "items", "failures", "skipped", "warnings", "stopped",
        ...}. ``stopped`` (else None) is the error that ended the run after something was
        applied, plus the 1-based ``operation`` it hit, its ``runtime_address`` and ``mode``;
        that operation and the later ones count as ``not_attempted``. Long operation (may
        answer in_progress)."""
        ...

    # ── jobs (read-only views of the serving gateway's job store) ───
    def list_jobs(self, profile: str | None = None) -> JSON:
        """{"profile": str | None, "jobs": [job view, oldest first], "corrupt": [...]}.

        Every job the store knows (terminal ones included), optionally of one profile;
        ``corrupt`` lists job directories without a usable state. Changes nothing."""
        ...

    def get_job(self, job_id: str) -> JSON:
        """One job view plus ``history``, ``needs_recovery``, ``recovery_hint`` and
        ``next_tool``. Raises InvalidJobId / JobNotFound. Changes nothing."""
        ...

    # ── human-only (CLI) operations — never exposed as MCP tools ────
    def discard_job(self, job_id: str, actor: str) -> JSON: ...
    def close(self) -> None: ...
