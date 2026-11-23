"""In-memory ``GatewayApp`` used by the front-end tests (MCP server, HTTP server, CLI).

Every facade method records ``(method, kwargs)`` in ``calls`` (with the thread
it ran on in ``threads``) and then, in this order:

1. waits on ``gates[method]`` (a ``threading.Event``) if one is set, so tests can
   hold a call open and prove that other calls still run concurrently;
2. raises ``fail[method]`` if set;
3. returns ``results[method]`` (called with the kwargs if it is callable, deep
   copied otherwise) or a default JSON-serialisable answer.

``runtime(profile)`` and ``open()`` are not part of the Protocol; they mirror
``app.Gateway.runtime`` (which the CLI hands to the provisioning module) and
``app.Gateway.open`` (which claims the jobs root). A ``FakeRuntime`` records, in
``log``, what the CLI does to it around provisioning: ``supervisor.pause`` /
``supervisor.resume``, ``lock.write`` / ``lock.release``, ``bump:<backend>`` and
``invalidate_clients``.
"""

from __future__ import annotations

import contextlib
import copy
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any

from x64dbg_vm_gateway.contracts import ToolInfo

JSON = dict[str, Any]

DEFAULT_INSTRUCTIONS = "Gateway loop: start with analysis_start, collect before finish."


def default_mirrored_tools() -> list[ToolInfo]:
    """A small mirrored catalog: two read-only and two mutating plugin tools."""
    return [
        ToolInfo("GetDebugState", "Returns the debugger state.", {"type": "object", "properties": {}}, True),
        ToolInfo("ReadMemory", "Reads memory.",
                 {"type": "object",
                  "properties": {"address": {"type": "string"}, "size": {"type": "integer"}},
                  "required": ["address", "size"]}, True),
        ToolInfo("SetBreakpoint", "Sets a breakpoint.",
                 {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]},
                 False),
        ToolInfo("run", "Resumes the debuggee.",
                 {"type": "object", "properties": {"timeoutMs": {"type": "integer"}}}, False),
    ]


def _texts_result(tool: str) -> JSON:
    return {"texts": [f"<untrusted_guest_output>{tool}</untrusted_guest_output>",
                      "[gateway] epoch=1 backend=x64 retried=false"],
            "is_error": False}


class _FakeVmOpLock:
    def __init__(self, log: list[str]) -> None:
        self._log = log
        self.write_timeouts: list[float | None] = []

    @contextlib.contextmanager
    def write(self, timeout_s: float | None = None) -> Iterator[None]:
        self.write_timeouts.append(timeout_s)
        self._log.append("lock.write")
        try:
            yield
        finally:
            self._log.append("lock.release")


class _FakeSupervisor:
    def __init__(self, log: list[str]) -> None:
        self._log = log
        self.epochs: dict[str, int] = {}

    @contextlib.contextmanager
    def paused(self) -> Iterator[None]:
        self._log.append("supervisor.pause")
        try:
            yield
        finally:
            self._log.append("supervisor.resume")

    def bump_epoch(self, backend_id: str, reason: str) -> int:
        self._log.append(f"bump:{backend_id}")
        self.epochs[backend_id] = self.epochs.get(backend_id, 0) + 1
        return self.epochs[backend_id]


class FakeRuntime:
    def __init__(self, profile: str | None, backends: Sequence[str] = ("x64", "x32")) -> None:
        self.profile = profile
        self.log: list[str] = []
        self.backends = {b: None for b in backends}
        self.lock = _FakeVmOpLock(self.log)
        self.supervisor = _FakeSupervisor(self.log)

    def invalidate_clients(self, *, drop_tokens: bool = False, reason: str = "") -> None:
        self.log.append("invalidate_clients")


class FakeApp:
    def __init__(self, *, mirrored: Sequence[ToolInfo] | None = None,
                 instructions: str = DEFAULT_INSTRUCTIONS) -> None:
        self.mirrored: list[ToolInfo] = list(mirrored) if mirrored is not None else default_mirrored_tools()
        self.instructions_text = instructions
        self.calls: list[tuple[str, JSON]] = []
        self.threads: list[tuple[str, int]] = []
        self.fail: dict[str, BaseException] = {}
        self.results: dict[str, Any] = {}
        self.gates: dict[str, threading.Event] = {}
        self.closed = False
        self.runtimes: list[FakeRuntime] = []
        self._lock = threading.Lock()

    # ── helpers ─────────────────────────────────────────────────────
    def called(self, method: str) -> list[JSON]:
        """kwargs of every recorded call of ``method`` (in order)."""
        with self._lock:
            return [kw for m, kw in self.calls if m == method]

    def _record(self, method: str, default: Any, **kwargs: Any) -> Any:
        with self._lock:
            self.calls.append((method, dict(kwargs)))
            self.threads.append((method, threading.get_ident()))
        gate = self.gates.get(method)
        if gate is not None:
            gate.wait(timeout=10)
        exc = self.fail.get(method)
        if exc is not None:
            raise exc
        if method in self.results:
            res = self.results[method]
            if callable(res):
                return res(**kwargs)
            return copy.deepcopy(res)
        return default() if callable(default) else copy.deepcopy(default)

    # ── observation ─────────────────────────────────────────────────
    def session_status(self, profile: str | None = None) -> JSON:
        return self._record("session_status", {"vm": {"power": "running"}, "backends": {}, "job": None},
                            profile=profile)

    def doctor(self, profile: str | None = None) -> JSON:
        return self._record("doctor", {"ok": True, "checks": [
            {"name": "vmrun", "ok": True, "detail": "/usr/bin/vmrun", "hint": None}]}, profile=profile)

    def instructions(self) -> str:
        return self.instructions_text

    def list_mirrored_tools(self) -> list[ToolInfo]:
        with self._lock:
            self.calls.append(("list_mirrored_tools", {}))
        exc = self.fail.get("list_mirrored_tools")
        if exc is not None:
            raise exc
        return list(self.mirrored)

    # ── VM ──────────────────────────────────────────────────────────
    def vm_snapshots_list(self, profile: str | None = None) -> JSON:
        return self._record("vm_snapshots_list", {"snapshots": [{"name": "MCP_CLEAN", "protected": True}]},
                            profile=profile)

    def vm_snapshot_take(self, name: str, profile: str | None = None) -> JSON:
        return self._record("vm_snapshot_take", {"taken": name}, name=name, profile=profile)

    def vm_snapshot_revert(self, name: str | None = None, profile: str | None = None,
                           wait_s: float | None = None) -> JSON:
        return self._record("vm_snapshot_revert", {"state": "done"}, name=name, profile=profile,
                            wait_s=wait_s)

    def vm_snapshot_delete(self, name: str, profile: str | None = None) -> JSON:
        return self._record("vm_snapshot_delete", {"deleted": name}, name=name, profile=profile)

    def vm_power(self, action: str, profile: str | None = None, wait_s: float | None = None) -> JSON:
        return self._record("vm_power", {"power": "running"}, action=action, profile=profile, wait_s=wait_s)

    def vm_screenshot(self, profile: str | None = None) -> JSON:
        return self._record("vm_screenshot", {"host_path": "/tmp/screen.png"}, profile=profile)

    # ── files ───────────────────────────────────────────────────────
    def file_upload(self, host_path: str, guest_dir: str | None = None, job_id: str | None = None) -> JSON:
        return self._record("file_upload", {"guest_path": "C:\\mcp\\jobs\\x\\in\\a.bin"},
                            host_path=host_path, guest_dir=guest_dir, job_id=job_id)

    def file_download(self, guest_path: str, job_id: str | None = None) -> JSON:
        return self._record("file_download", {"host_path": "/tmp/out.bin"}, guest_path=guest_path,
                            job_id=job_id)

    # ── debugger ────────────────────────────────────────────────────
    def debugger_select(self, backend_id: str) -> JSON:
        return self._record("debugger_select", {"active": backend_id}, backend_id=backend_id)

    def debugger_restart(self, backend_id: str | None = None, reason: str = "requested") -> JSON:
        return self._record("debugger_restart", {"epoch": 2}, backend_id=backend_id, reason=reason)

    def debugger_call(self, tool: str, arguments: Mapping[str, Any] | None = None,
                      backend_id: str | None = None) -> JSON:
        return self._record("debugger_call", _texts_result(tool),
                            tool=tool, arguments=arguments, backend_id=backend_id)

    def call_mirrored(self, tool: str, arguments: Mapping[str, Any] | None = None) -> JSON:
        return self._record("call_mirrored", _texts_result(tool),
                            tool=tool, arguments=arguments)

    # ── analysis loop ───────────────────────────────────────────────
    def analysis_start(self, sample_path: str, *, profile: str | None = None,
                       snapshot: str | None = None, arch: str = "auto",
                       args: str | None = None, cwd: str | None = None, load: bool = True,
                       revert: bool = True, reload_on_restart: bool = False,
                       wait_s: float | None = None) -> JSON:
        return self._record("analysis_start", {"job_id": "20261123-000000-abcdef", "arch": "x64"},
                            sample_path=sample_path, profile=profile, snapshot=snapshot, arch=arch, args=args,
                            cwd=cwd, load=load, revert=revert, reload_on_restart=reload_on_restart,
                            wait_s=wait_s)

    def analysis_collect(self, job_id: str | None = None, extra_guest_paths: Sequence[str] = (),
                         extract: bool | None = None) -> JSON:
        return self._record("analysis_collect", {"state": "COLLECTED", "manifest": {"files": []}},
                            job_id=job_id, extra_guest_paths=extra_guest_paths, extract=extract)

    def analysis_finish(self, job_id: str | None = None, *, revert: bool = True,
                        keep_snapshot: bool = False, wait_s: float | None = None) -> JSON:
        return self._record("analysis_finish", {"state": "DONE"}, job_id=job_id, revert=revert,
                            keep_snapshot=keep_snapshot, wait_s=wait_s)

    # ── IDA ─────────────────────────────────────────────────────────
    def ida_rebase(self, address: str | int, *, direction: str, module: str | None = None,
                   ida_imagebase: str | int | None = None, job_id: str | None = None) -> JSON:
        return self._record("ida_rebase", {"address": "0x140001000"}, address=address, direction=direction,
                            module=module, ida_imagebase=ida_imagebase, job_id=job_id)

    def ida_export_annotations(self, job_id: str | None = None) -> JSON:
        return self._record("ida_export_annotations", {"host_path": "/tmp/annotations.json"}, job_id=job_id)

    def ida_import_annotations(self, items: Sequence[Mapping[str, Any]], *, module: str,
                               ida_imagebase: str | int | None = None, job_id: str | None = None) -> JSON:
        return self._record("ida_import_annotations", {"applied": len(items)}, items=items, module=module,
                            ida_imagebase=ida_imagebase, job_id=job_id)

    # ── jobs (read-only) ────────────────────────────────────────────
    def list_jobs(self, profile: str | None = None) -> JSON:
        return self._record("list_jobs", {"profile": profile, "jobs": [], "corrupt": []}, profile=profile)

    def get_job(self, job_id: str) -> JSON:
        return self._record("get_job", {"job_id": job_id, "state": "ANALYZING", "history": []},
                            job_id=job_id)

    # ── human-only ──────────────────────────────────────────────────
    def discard_job(self, job_id: str, actor: str) -> JSON:
        return self._record("discard_job", {"job_id": job_id, "state": "DISCARDED"}, job_id=job_id,
                            actor=actor)

    def warm_up(self, timeout_s: float | None = None) -> JSON:
        """No-op (not recorded): nothing to learn in memory (``mcp_server.WarmUpApp``)."""
        return {"profile": None, "backends": {}}

    def close(self) -> None:
        with self._lock:
            self.calls.append(("close", {}))
        self.closed = True

    # ── orchestrator extras (not in the Protocol) ───────────────────
    def open(self) -> None:
        self._record("open", None)

    def note_debuggers_restarted(self, profile: str | None, reason: str) -> list[str]:
        return self._record("note_debuggers_restarted", [], profile=profile, reason=reason)

    def runtime(self, profile: str | None = None) -> FakeRuntime:
        rt = FakeRuntime(profile)
        with self._lock:
            self.calls.append(("runtime", {"profile": profile}))
            self.runtimes.append(rt)
        return rt


def blocking_result(event: threading.Event, value: Any) -> Callable[..., Any]:
    """A ``results`` entry that sets ``event`` (unblocking a gated call) and returns ``value``."""

    def _res(**_kwargs: Any) -> Any:
        event.set()
        return copy.deepcopy(value)

    return _res
