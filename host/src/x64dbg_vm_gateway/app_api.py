"""Application facade contract between the orchestrator (app.py) and front-ends.

Front-ends (MCP server, CLI, a future IDA client) talk ONLY to ``GatewayApp``.
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
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from .contracts import ToolInfo

JSON = dict[str, Any]


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
        a failing check; raises only for unusable configuration."""
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
    def debugger_select(self, backend_id: str) -> JSON: ...
    def debugger_restart(self, backend_id: str | None = None, reason: str = "requested") -> JSON: ...
    def debugger_call(self, tool: str, arguments: Mapping[str, Any] | None = None,
                      backend_id: str | None = None) -> JSON:
        """Generic escape hatch: call any backend tool by name (also ones the client
        never saw in tools/list). Result: {"texts": [...], "is_error": bool}."""
        ...

    def call_mirrored(self, tool: str, arguments: Mapping[str, Any] | None = None) -> JSON:
        """Route a mirrored backend tool to the active backend. Same result shape as
        debugger_call. Texts are already sanitised/wrapped as untrusted output."""
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

    # ── IDA integration (interpretation D) ──────────────────────────
    def ida_rebase(self, address: str | int, *, direction: str, module: str | None = None,
                   ida_imagebase: str | int | None = None, job_id: str | None = None) -> JSON:
        """direction in {"runtime_to_ida", "ida_to_runtime", "runtime_to_rva", "rva_to_runtime"}.

        ``ida_sync.rebase`` result plus ``job_id`` and ``module_map_source`` ("live":
        ListModules of the job's debugger; "manifest": the collected map). ``warnings``
        also says when the collected map stood in for an unavailable live one while the
        debugger should still hold the sample. Raises InvalidArgument for a bad
        address/module/direction, StateViolation without a map."""
        ...

    def ida_export_annotations(self, job_id: str | None = None) -> JSON:
        """SaveDatabase, copy it to the host, write ``<job>/artifacts/ida_sync.json``
        (x64dbg-ida-sync/1). {"host_path", "modules", "items", "counts", "database",
        "module_map_source", "skipped", "warnings", "steps"}. ``database.source`` is "saved",
        "collected" or "not_written" (x64dbg wrote no file; ``host_path`` is None and the
        document is empty; ``warnings`` says whether the plugin reported an empty session or,
        for older plugin builds, that it cannot be told from a failed save). DatabaseFormatError
        for an unreadable (e.g. LZ4-compressed) database; BackendError when SaveDatabase reports
        a failure. Long operation (may answer in_progress)."""
        ...

    def ida_import_annotations(self, items: Sequence[Mapping[str, Any]], *, module: str,
                               ida_imagebase: str | int | None = None,
                               job_id: str | None = None) -> JSON:
        """Items ``{rva | ida_address, name?, comment?}`` (ida_sync.plan_import_report) are
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
