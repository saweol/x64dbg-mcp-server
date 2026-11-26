"""Proxy for mirrored x64dbg-MCP tool calls (plan 4.2, 4.3, 5.5).

Rules applied to every ``Proxy.call``:

(a) Serialisation: mutating tools run one at a time per backend (the plugin runs
    handlers concurrently without locking). Read-only tools, ``PauseDebug`` and
    ``GetDebugState`` bypass the lock so a long ``run`` can be observed/interrupted.
(b) Per-tool HTTP timeout: ``run`` / ``WaitForEvent`` / ``WaitForPause`` /
    ``RunToAddress`` = effective ``timeoutMs`` + 30 s, ``ExecuteDebuggerCommand`` =
    330 s, everything else ``default_timeout_s``. ``RunToAddress`` is not named in
    plan 5.5 but blocks the same way (tools.zig ``runToAddress``: default 30000,
    clamped to 100..120000 ms), so it is planned like the ``WaitFor*`` tools.
(c) Call budget ``max_call_s`` (measured from entry, lock wait included): the
    ``timeoutMs`` of the waiting tools is clamped so the HTTP timeout stays within
    ``max_call_s - 10`` s; the plugin then returns "still running" by itself and
    the client continues with ``WaitForPause``. The effective ``timeoutMs`` is
    always sent as a JSON integer (the plugin ignores floats). Tools whose
    server-side wait cannot be shortened (``ExecuteDebuggerCommand``) get
    ``min(330, max_call_s)`` minus the time spent waiting for the lock, and a
    timeout becomes RESULT_UNKNOWN.
(d) Retries: only catalog-retryable tools (read-only, not ``WaitForEvent``) are
    retried, once, on BackendUnavailable. Any other transport failure asks the
    supervisor for a health check (and a relaunch when DEAD/HUNG) and raises
    BACKEND_RESTARTED if the epoch moved, RESULT_UNKNOWN for every non-retryable
    tool (mutating tools and ``WaitForEvent``, which may have drained events), or
    the original error for retryable read-only tools. Nothing is ever re-executed
    implicitly. Recovery runs after the serialisation lock is released and its
    waits are bounded by what remains of ``max_call_s``: a relaunch is issued but
    not waited for beyond the budget (the supervisor bumps the epoch when it
    issues the launch, so the client gets BACKEND_RESTARTED and the next mutating
    call is gated). The health check and the kill/launch guest commands are
    bounded by their own timeouts, so a failing call may overrun ``max_call_s``
    by those (seconds, not the boot wait). BACKEND_THROTTLED (HTTP 429, the
    plugin's auth-failure lockout) is surfaced as it is: never retried, no health
    check, no relaunch; a health check that finds the backend THROTTLED after
    another failure does not relaunch it either. Nor does one that finds it
    UNRESOLVED (the supervisor could not obtain a client, e.g. a VM revert dropped
    the token while the call was in flight and VMware Tools are not back yet): the
    supervisor never judges a backend it cannot reach.
(e) Epoch gating: after a relaunch / VM revert, the first mutating call fails with
    BACKEND_RESTARTED without reaching the backend until ``ack()`` is called. The
    epoch read by the gate is the reference for the failure path, so a relaunch
    between the gate and the send is reported as BACKEND_RESTARTED.
(f) Every guest-provided text item is sanitised and wrapped in
    ``<untrusted_guest_output>`` and a final ``[gateway] epoch=N backend=ID
    [profile=NAME] retried=true|false`` line is appended (``profile`` when the proxy
    was built for a profile, as ``wiring.build_runtime`` does: one gateway may serve
    several VMs). ``ToolCallResult.raw`` of the returned result holds gateway metadata
    only (``{"gateway": {backend, epoch, retried[, profile]}}``), never the
    unsanitised backend payload.

Supervisor surface used (``SupervisorLike``): ``check`` and ``ensure_alive`` (both
with the ``max_wait_s`` extension: recovery gives them what is left of the call
budget), ``epoch``, ``is_paused`` (calls are refused while
a VM operation holds supervision) and ``note_up`` (a successful call proves the
backend was up in that epoch; used for external-restart detection).

Thread-safety: ``Proxy`` is safe to share between threads; per-backend locks
serialise mutating calls and a small lock guards the acknowledged epochs.
"""

from __future__ import annotations

import logging
import math
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from .contracts import BackendClient, Clock, SystemClock, ToolCallResult
from .errors import (
    BackendError,
    BackendRestarted,
    BackendTimeout,
    BackendUnavailable,
    CancelledByVmOp,
    ConfigError,
    CrashLoop,
    GatewayError,
    LockTimeout,
    ResultUnknown,
)
from .supervisor import HealthReport, HealthState

if TYPE_CHECKING:  # catalog and backend import the sanitiser from here; avoid an import cycle
    from .catalog import ToolCatalog

log = logging.getLogger(__name__)


def _not_sent(exc: GatewayError) -> bool:
    """A connect() that never completed (backend.ConnectTimeout): the request was not sent."""
    return isinstance(exc, BackendUnavailable) and exc.details.get("error") == "ConnectTimeout"

# ── untrusted text ──────────────────────────────────────────────────
UNTRUSTED_OPEN = "<untrusted_guest_output>"
UNTRUSTED_CLOSE = "</untrusted_guest_output>"
DEFAULT_MAX_TEXT = 200_000


def _build_strip_table() -> dict[int, int | None]:
    table: dict[int, int | None] = {}
    for cp in range(0x00, 0x20):  # C0 controls except \t and \n
        if cp not in (0x09, 0x0A):
            table[cp] = None
    table[0x7F] = None  # DEL
    for cp in range(0x80, 0xA0):  # C1 controls
        table[cp] = None
    # bidi / invisible direction controls (Trojan Source set)
    for cp in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)):
        table[cp] = None
    for cp in range(0xD800, 0xE000):  # lone surrogates cannot be encoded as UTF-8
        table[cp] = 0xFFFD
    return table


_STRIP = _build_strip_table()
_TAG_RE = re.compile(r"<(\s*/?\s*)(untrusted_guest_output)", re.IGNORECASE)


def sanitize_untrusted_text(s: str, max_len: int = DEFAULT_MAX_TEXT) -> str:
    """Remove control/bidi characters (keeping ``\\n`` and ``\\t``) and truncate.

    Removed: C0 except TAB/LF (CR included), DEL, C1 (U+0080-U+009F), U+061C,
    U+200E, U+200F, U+202A-U+202E, U+2066-U+2069. Lone surrogates become U+FFFD.
    Text longer than ``max_len`` is cut and ``[truncated N chars]`` is appended.
    """
    out = str(s).translate(_STRIP)
    if len(out) > max_len:
        out = f"{out[:max_len]}\n[truncated {len(out) - max_len} chars]"
    return out


def wrap_untrusted(s: str, max_len: int = DEFAULT_MAX_TEXT) -> str:
    """Sanitise ``s`` and wrap it in ``<untrusted_guest_output>`` tags.

    Any ``<untrusted_guest_output`` / ``</untrusted_guest_output`` inside the text
    (any case/spacing) is neutralised to ``&lt;...`` so the guest cannot close the
    wrapper early. This is a mitigation, not a defence (plan 9).
    """
    body = _TAG_RE.sub(r"&lt;\1\2", sanitize_untrusted_text(s, max_len))
    return f"{UNTRUSTED_OPEN}\n{body}\n{UNTRUSTED_CLOSE}"


# ── timeout planning ────────────────────────────────────────────────
HTTP_GRACE_S = 30.0  # added to the server-side wait of blocking tools
BUDGET_MARGIN_S = 10.0  # kept free inside max_call_s
EXECUTE_COMMAND_TIMEOUT_S = 330.0  # ExecuteDebuggerCommand blocks up to 300 s server-side
LOCK_BYPASS_TOOLS = frozenset({"PauseDebug", "GetDebugState"})
LOST_ON_RESTART = ("debuggee state", "breakpoints (unless restored)", "memory patches")


@dataclass(frozen=True)
class _WaitTool:
    default_ms: int
    min_ms: int
    max_ms: int


# Server-side limits from src/mcp/tools.zig (getParamInt clamps).
WAIT_TOOLS: dict[str, _WaitTool] = {
    "run": _WaitTool(300_000, 1_000, 600_000),
    "WaitForEvent": _WaitTool(30_000, 100, 120_000),
    "WaitForPause": _WaitTool(30_000, 100, 120_000),
    "RunToAddress": _WaitTool(30_000, 100, 120_000),
}


@dataclass(frozen=True)
class CallPlan:
    timeout_s: float
    arguments: dict[str, Any]
    requested_ms: int | None = None  # set when timeoutMs was clamped to the budget
    effective_ms: int | None = None


def _as_ms(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def plan_call(tool: str, arguments: Mapping[str, Any] | None, *, max_call_s: float,
              default_timeout_s: float, schema_default_ms: int | None = None) -> CallPlan:
    """Compute the HTTP timeout and (possibly clamped) arguments for one call."""
    args = dict(arguments or {})
    spec = WAIT_TOOLS.get(tool)
    if spec is not None:
        default_ms = schema_default_ms if schema_default_ms is not None else spec.default_ms
        given = _as_ms(args.get("timeoutMs"))
        invalid = "timeoutMs" in args and given is None
        requested = given if given is not None else default_ms
        server_ms = min(max(requested, spec.min_ms), spec.max_ms)  # what the plugin will actually wait
        budget_ms = int((max_call_s - BUDGET_MARGIN_S - HTTP_GRACE_S) * 1000)
        effective = max(min(server_ms, budget_ms), spec.min_ms)
        timeout_s = effective / 1000 + HTTP_GRACE_S
        if timeout_s > max_call_s - BUDGET_MARGIN_S:  # only for tiny budgets (< ~41 s)
            timeout_s = max(max_call_s - BUDGET_MARGIN_S, effective / 1000 + 1.0)
        budget_clamped = effective < server_ms
        if budget_clamped or invalid or given is not None:
            # always a JSON integer: the plugin's getIntField ignores 5000.0 and waits its default
            args["timeoutMs"] = int(effective)
        return CallPlan(timeout_s, args, requested if budget_clamped else None,
                        effective if budget_clamped else None)
    if tool == "ExecuteDebuggerCommand":
        return CallPlan(min(EXECUTE_COMMAND_TIMEOUT_S, max_call_s), args)
    return CallPlan(min(default_timeout_s, max_call_s), args)


# ── proxy ───────────────────────────────────────────────────────────
class SupervisorLike(Protocol):
    def check(self, backend_id: str, *, max_wait_s: float | None = None) -> HealthReport: ...
    def ensure_alive(self, backend_id: str, *, job_id: str | None = None, reason: str,
                     max_wait_s: float | None = None) -> int: ...
    def epoch(self, backend_id: str) -> int: ...
    def is_paused(self) -> bool: ...
    def note_up(self, backend_id: str, epoch: int) -> None: ...


_RECOVERABLE = (BackendUnavailable, BackendTimeout, CancelledByVmOp)


class Proxy:
    def __init__(self, catalog: ToolCatalog, clients: Mapping[str, BackendClient], supervisor: SupervisorLike,
                 *, max_call_s: float, default_timeout_s: float = 30.0, clock: Clock | None = None,
                 lock_timeout_s: float | None = None, max_text_len: int = DEFAULT_MAX_TEXT,
                 profile: str | None = None) -> None:
        """``clients`` is read on every call (not copied) so it may be shared with the
        supervisor's token refresher. ``lock_timeout_s`` overrides how long a mutating
        call waits for the per-backend lock (default: what remains of the budget).
        ``profile`` names the gateway profile (VM) in every result trailer."""
        if max_call_s <= 0 or default_timeout_s <= 0:
            raise ConfigError("max_call_s and default_timeout_s must be positive")
        self._catalog = catalog
        self._clients = clients
        self._sup = supervisor
        self._max_call_s = float(max_call_s)
        self._default_timeout_s = float(default_timeout_s)
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._lock_timeout_s = lock_timeout_s
        self._max_text = max_text_len
        self._profile = profile
        self._lock = threading.Lock()
        self._backend_locks: dict[str, threading.Lock] = {}
        self._acked: dict[str, int] = {b: supervisor.epoch(b) for b in clients}

    # ── epochs ──────────────────────────────────────────────────────
    def ack(self, backend_id: str) -> int:
        """Acknowledge the current epoch (session_status does this); return it."""
        self._client(backend_id)
        epoch = self._sup.epoch(backend_id)
        with self._lock:
            self._acked[backend_id] = max(epoch, self._acked.get(backend_id, 0))
            return self._acked[backend_id]

    def acked_epoch(self, backend_id: str) -> int:
        self._client(backend_id)
        with self._lock:
            return self._acked.setdefault(backend_id, self._sup.epoch(backend_id))

    def _gate(self, backend_id: str, tool: str) -> int:
        """Refuse a mutating call after an unacknowledged restart; return the epoch checked."""
        epoch = self._sup.epoch(backend_id)
        acked = self.acked_epoch(backend_id)
        if epoch > acked:
            raise BackendRestarted(
                f"backend {backend_id} was restarted (epoch {acked} -> {epoch}); {tool} was not executed",
                stage="call", next_tool="session_status",
                hint="call session_status to acknowledge, then re-check addresses and breakpoints",
                details={"backend": backend_id, "tool": tool, "epoch": epoch, "acked_epoch": acked,
                         "lost": list(LOST_ON_RESTART)},
            )
        return epoch

    # ── helpers ─────────────────────────────────────────────────────
    def _client(self, backend_id: str) -> BackendClient:
        try:
            return self._clients[backend_id]
        except KeyError:
            raise ConfigError(f"unknown backend: {backend_id!r}") from None

    def _backend_lock(self, backend_id: str) -> threading.Lock:
        with self._lock:
            return self._backend_locks.setdefault(backend_id, threading.Lock())

    def _schema_default_ms(self, backend_id: str, tool: str) -> int | None:
        info = self._catalog.tool(tool, backend_id)
        if info is None:
            return None
        prop = (info.input_schema.get("properties") or {}).get("timeoutMs")
        return _as_ms(prop.get("default")) if isinstance(prop, dict) else None

    def plan(self, backend_id: str, tool: str, arguments: Mapping[str, Any] | None) -> CallPlan:
        return plan_call(tool, arguments, max_call_s=self._max_call_s,
                         default_timeout_s=self._default_timeout_s,
                         schema_default_ms=self._schema_default_ms(backend_id, tool))

    # ── main entry ──────────────────────────────────────────────────
    def call(self, backend_id: str, tool: str, arguments: Mapping[str, Any] | None = None, *,
             job_id: str | None = None) -> ToolCallResult:
        client = self._client(backend_id)
        t_entry = self._clock.monotonic()
        deadline = t_entry + self._max_call_s
        if self._sup.is_paused():
            raise CancelledByVmOp(f"a VM operation is in progress; {tool} was not sent",
                                  stage="call", hint="retry after the VM operation completes",
                                  next_tool="session_status", details={"backend": backend_id, "tool": tool})
        mutating = not self._catalog.is_read_only(tool, backend_id)
        retryable = self._catalog.is_retryable(tool, backend_id)
        plan = self.plan(backend_id, tool, arguments)

        lock: threading.Lock | None = None
        if mutating and tool not in LOCK_BYPASS_TOOLS:
            lock = self._backend_lock(backend_id)
            wait_s = self._lock_timeout_s
            if wait_s is None:
                wait_s = max(1.0, self._max_call_s - BUDGET_MARGIN_S - plan.timeout_s)
            if not lock.acquire(timeout=wait_s):
                raise LockTimeout(
                    f"another mutating call is still running on backend {backend_id}; {tool} was not sent",
                    stage="call", retryable=True, next_tool="PauseDebug",
                    hint="wait for the running call (WaitForPause) or interrupt it with PauseDebug",
                    details={"backend": backend_id, "tool": tool, "waited_s": wait_s},
                )
        failure: GatewayError | None = None
        retried = False
        try:
            # One epoch read is the reference for both the gate and the failure path.
            epoch_before = self._gate(backend_id, tool) if mutating else self._sup.epoch(backend_id)
            timeout_s = plan.timeout_s
            if tool not in WAIT_TOOLS:
                # Not shortenable server-side: whatever the lock wait used comes off the budget
                # (counted in whole tenths of a second so uncontended calls keep the plan value).
                spent = math.floor((self._clock.monotonic() - t_entry) * 10) / 10
                timeout_s = max(1.0, min(timeout_s, self._max_call_s - spent))
            t0 = self._clock.monotonic()
            while True:
                try:
                    result = client.call_tool(tool, plan.arguments, timeout_s)
                    log.debug("backend %s: %s done in %.0f ms (timeout %.0f s, retried=%s)", backend_id, tool,
                              (self._clock.monotonic() - t0) * 1000, timeout_s, retried)
                    break
                except BackendUnavailable as e:
                    # A connect that never completed would only take its whole budget again.
                    if retryable and not retried and not _not_sent(e):
                        retried = True
                        log.info("backend %s: retrying read-only %s once after %s", backend_id, tool, e.code)
                        # the retry gets what is left of the client's call budget
                        spent = self._clock.monotonic() - t_entry
                        timeout_s = max(1.0, min(timeout_s, self._max_call_s - BUDGET_MARGIN_S - spent))
                        continue
                    failure = e
                    break
                except (BackendTimeout, CancelledByVmOp) as e:
                    failure = e
                    break
                except GatewayError as e:
                    e.details.setdefault("tool", tool)
                    e.details.setdefault("backend", backend_id)
                    raise
        finally:
            if lock is not None:
                lock.release()
        if failure is not None:
            # Outside the lock: recovery may relaunch the debugger and must not block other callers.
            raise self._recover(backend_id, tool, retryable, failure, epoch_before, job_id, deadline)
        self._sup.note_up(backend_id, epoch_before)
        return self._decorate(backend_id, result, plan, retried)

    def _decorate(self, backend_id: str, result: ToolCallResult, plan: CallPlan,
                  retried: bool) -> ToolCallResult:
        # The backend's raw payload is guest-controlled and unsanitised: it never leaves the proxy.
        texts = [wrap_untrusted(t, self._max_text) for t in result.texts]
        if plan.requested_ms is not None:
            texts.append(
                f"[gateway] timeoutMs clamped to {plan.effective_ms} ms (requested {plan.requested_ms} ms) "
                f"to fit the client call budget (max_call_s={self._max_call_s:g}); if the target is still "
                "running, call WaitForPause to keep waiting."
            )
        epoch = self._sup.epoch(backend_id)
        where = f" profile={self._profile}" if self._profile else ""
        texts.append(f"[gateway] epoch={epoch} backend={backend_id}{where} "
                     f"retried={'true' if retried else 'false'}")
        gateway: dict[str, Any] = {"backend": backend_id, "epoch": epoch, "retried": retried}
        if self._profile:
            gateway["profile"] = self._profile
        return ToolCallResult(texts=texts, is_error=result.is_error, raw={"gateway": gateway})

    def _recover(self, backend_id: str, tool: str, retryable: bool, exc: GatewayError, epoch_before: int,
                 job_id: str | None, deadline: float) -> GatewayError:
        """Health-check (and relaunch if DEAD/HUNG) after a failed call; return the error to raise."""
        state: HealthState = HealthState.UNKNOWN
        recovery_error: GatewayError | None = None
        try:
            # the health check may resolve the client (token re-read): within the call budget
            report = self._sup.check(backend_id, max_wait_s=max(0.0, deadline - self._clock.monotonic()))
            state = report.state
            if state in (HealthState.DEAD, HealthState.HUNG):
                remaining = max(0.0, deadline - self._clock.monotonic())
                self._sup.ensure_alive(backend_id, job_id=job_id, reason=f"{tool} failed with {exc.code}",
                                       max_wait_s=remaining)
                state = HealthState.HEALTHY
        except CrashLoop as e:
            e.details.update({"tool": tool, "cause": exc.code, "result_unknown": not retryable})
            return e
        except GatewayError as e:
            recovery_error = e
        epoch_now = self._sup.epoch(backend_id)
        details: dict[str, Any] = {"backend": backend_id, "tool": tool, "epoch": epoch_now,
                                   "state": str(state), "cause": exc.code}
        not_sent = _not_sent(exc)
        if not_sent:
            details["not_sent"] = True
        pending = False
        if recovery_error is not None:
            details["recovery_error"] = recovery_error.code
            details["recovery_message"] = recovery_error.message
            pending = bool(recovery_error.details.get("relaunch_pending"))
            if pending:
                details["relaunch_pending"] = True
        if epoch_now != epoch_before:
            details.update(previous_epoch=epoch_before, lost=list(LOST_ON_RESTART))
            outcome = ("it was not sent (the connection never completed)" if not_sent
                       else "its result is unknown")
            message = (f"backend {backend_id} was restarted while {tool} was in flight "
                       f"(epoch {epoch_before} -> {epoch_now}); {outcome} and debuggee state is gone")
            hint = "call session_status to acknowledge, then reload the sample if needed"
            if pending:
                message += " (the new debugger is not ready yet)"
                hint += "; the debugger is still starting, so retry session_status in a few seconds"
            elif recovery_error is not None:
                message += f" (relaunch failed: {recovery_error.code})"
                hint += "; the relaunch failed (see recovery_message), so check the guest before retrying"
            return BackendRestarted(message, stage="call", next_tool="session_status", details=details,
                                    hint=hint)
        if not_sent:
            exc.details.update(details)
            exc.hint = (f"{tool} was not sent: the connection to backend {backend_id} never completed "
                        f"(state {state}); check session_status, then repeat it if still wanted")
            exc.next_tool = "session_status"
            return exc
        if not retryable:
            mutating = not self._catalog.is_read_only(tool, backend_id)
            return ResultUnknown(
                f"{tool} on backend {backend_id} did not complete ({exc.code}); it was NOT retried and "
                "its effect is unknown",
                stage="call", next_tool="GetDebugState", details=details,
                hint="call GetDebugState to inspect the debugger before deciding whether to repeat it"
                if mutating else
                f"{tool} may already have consumed queued debug events; call GetDebugState before "
                "waiting again",
            )
        if isinstance(exc, BackendError | CancelledByVmOp):
            exc.details.update(details)
        return exc
