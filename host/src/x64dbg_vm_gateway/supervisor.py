"""Backend supervision: health classification, relaunch and epochs (plan 4.2, 5.4).

Health levels:

- L1: ``GET /`` + bearer (2 s) - the plugin's HTTP thread is alive.
- L2: ``tools/call GetDebugState`` (5 s) - the x64dbg bridge makes progress.
  It is safe to run in parallel with a long ``run`` call.

Classification (``check``), first match wins:

=========================================================  ===========
observation                                                state
=========================================================  ===========
supervisor paused (a VM operation holds the write lock)    PAUSED
VM power state is not RUNNING                              VM_DOWN
VMware Tools not RUNNING                                   TOOLS_DOWN
HTTP 401 (after one token refresh per epoch)               AUTH
L1 refused, no guest process named basename(exe)           DEAD
L1 refused, process present, < boot_grace_s since first    LOADING
L1 refused, process present, >= boot_grace_s               HUNG
L1 ok, L2 failed >= l2_fail_threshold times in a row
spanning >= l2_min_window_s                                HUNG
VM / guest query failed                                    UNKNOWN
otherwise                                                  HEALTHY
=========================================================  ===========

Without a VM provider / guest channel (endpoint mode) only the HTTP rows apply
and relaunching is impossible.

Epochs: an integer per backend, incremented whenever the debugger is relaunched
(``ensure_alive``) or the VM is reverted (``bump_epoch``). The proxy uses it to
refuse mutating calls after state loss until the client acknowledges.

Thread-safety: all public methods may be called from any thread. Bookkeeping is
guarded by one re-entrant lock that is never held across guest/HTTP I/O; a
per-backend relaunch lock guarantees one relaunch at a time per backend
(concurrent ``ensure_alive`` callers wait and then observe the new epoch).
"""

from __future__ import annotations

import enum
import logging
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from typing import Any

from .config import BackendConfig
from .contracts import BackendClient, Clock, GuestChannel, PowerState, SystemClock, ToolsState, VmProvider
from .errors import (
    BackendAuthError,
    BackendError,
    BackendUnavailable,
    CancelledByVmOp,
    ConfigError,
    CrashLoop,
    GatewayError,
    LockTimeout,
    VmNotReady,
)

log = logging.getLogger(__name__)

SCHTASKS_EXE = "C:\\Windows\\System32\\schtasks.exe"
RELAUNCH_MODES = ("task", "direct")


class HealthState(enum.StrEnum):
    HEALTHY = "HEALTHY"
    LOADING = "LOADING"
    DEAD = "DEAD"
    HUNG = "HUNG"
    AUTH = "AUTH"
    VM_DOWN = "VM_DOWN"
    TOOLS_DOWN = "TOOLS_DOWN"
    PAUSED = "PAUSED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class HealthReport:
    state: HealthState
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Track:
    """Per-backend transient observations (reset on epoch change and on resume)."""

    loading_since: float | None = None
    l2_failures: int = 0
    l2_first_failure: float | None = None


class Supervisor:
    def __init__(
        self,
        *,
        vm: VmProvider | None,
        guest: GuestChannel | None,
        clients: Mapping[str, BackendClient],
        backends: Mapping[str, BackendConfig],
        relaunch_mode: str,
        token_refresher: Callable[[str], None] | None = None,
        clock: Clock | None = None,
        boot_grace_s: float = 90.0,
        l2_fail_threshold: int = 3,
        l2_min_window_s: float = 30.0,
        max_restarts_per_job: int = 3,
        relaunch_ready_timeout_s: float = 120.0,
        poll_interval_s: float = 2.0,
        l1_timeout_s: float = 2.0,
        l2_timeout_s: float = 5.0,
    ) -> None:
        """``clients`` is read on every use (not copied), so a token refresher may
        replace an entry; ``backends`` supplies exe/launch_task (falling back to the
        client's endpoint fields)."""
        if relaunch_mode not in RELAUNCH_MODES:
            raise ConfigError(f"relaunch_mode must be one of {RELAUNCH_MODES}, got {relaunch_mode!r}")
        self._vm = vm
        self._guest = guest
        self._clients = clients
        self._backends = dict(backends)
        self._mode = relaunch_mode
        self._token_refresher = token_refresher
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._boot_grace_s = boot_grace_s
        self._l2_threshold = max(1, l2_fail_threshold)
        self._l2_window_s = l2_min_window_s
        self._max_restarts = max_restarts_per_job
        self._ready_timeout_s = relaunch_ready_timeout_s
        self._poll_s = poll_interval_s
        self._l1_timeout_s = l1_timeout_s
        self._l2_timeout_s = l2_timeout_s
        # real-time bound for waiting on another caller's relaunch
        self._relaunch_lock_timeout_s = boot_grace_s + relaunch_ready_timeout_s + 120.0

        self._lock = threading.RLock()
        self._pause_depth = 0
        self._epochs: dict[str, int] = {}
        self._history: dict[str, list[dict[str, Any]]] = {}
        self._track: dict[str, _Track] = {}
        self._seen_up_epoch: dict[str, int] = {}  # backend -> last epoch in which L1 answered
        self._auth_refreshed_epoch: dict[str, int] = {}
        self._restarts: dict[str, int] = {}  # job_id -> relaunch attempts
        self._relaunch_locks: dict[str, threading.Lock] = {}

    # ── helpers ─────────────────────────────────────────────────────
    def _client(self, backend_id: str) -> BackendClient:
        try:
            return self._clients[backend_id]
        except KeyError:
            raise ConfigError(f"unknown backend: {backend_id!r}") from None

    def _cfg(self, backend_id: str, attr: str) -> str | None:
        cfg = self._backends.get(backend_id)
        value = getattr(cfg, attr, None) if cfg is not None else None
        if value is None:
            value = getattr(self._client(backend_id).endpoint, attr, None)
        return value

    def _exe(self, backend_id: str) -> str | None:
        return self._cfg(backend_id, "exe")

    def _image_name(self, backend_id: str) -> str | None:
        exe = self._exe(backend_id)
        return PureWindowsPath(exe).name.lower() if exe else None

    def _tr(self, backend_id: str) -> _Track:
        with self._lock:
            return self._track.setdefault(backend_id, _Track())

    def _reset_track(self, backend_id: str | None = None) -> None:
        with self._lock:
            if backend_id is None:
                self._track.clear()
            else:
                self._track.pop(backend_id, None)

    def _relaunch_lock(self, backend_id: str) -> threading.Lock:
        with self._lock:
            return self._relaunch_locks.setdefault(backend_id, threading.Lock())

    @staticmethod
    def _report(state: HealthState, backend_id: str, **details: Any) -> HealthReport:
        details["backend"] = backend_id
        return HealthReport(state, details)

    # ── pause / resume ──────────────────────────────────────────────
    def pause(self) -> None:
        """Suspend supervision (nestable). While paused, check() reports PAUSED and
        ensure_alive() raises CancelledByVmOp instead of relaunching."""
        with self._lock:
            self._pause_depth += 1

    def resume(self) -> None:
        with self._lock:
            if self._pause_depth > 0:
                self._pause_depth -= 1
            if self._pause_depth == 0:
                # observations made before the VM operation are stale now
                self._track.clear()

    def is_paused(self) -> bool:
        with self._lock:
            return self._pause_depth > 0

    @contextmanager
    def paused(self) -> Iterator[None]:
        self.pause()
        try:
            yield
        finally:
            self.resume()

    def _raise_if_paused(self, backend_id: str) -> None:
        if self.is_paused():
            raise CancelledByVmOp(
                f"supervision of backend {backend_id} is paused by a VM operation",
                stage="supervisor", hint="retry after the VM operation completes",
                next_tool="session_status", details={"backend": backend_id},
            )

    # ── epochs ──────────────────────────────────────────────────────
    def epoch(self, backend_id: str) -> int:
        self._client(backend_id)
        with self._lock:
            return self._epochs.get(backend_id, 0)

    def epoch_history(self, backend_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(h) for h in self._history.get(backend_id, [])]

    def _bump(self, backend_id: str, reason: str, *, seen_up: bool) -> int:
        with self._lock:
            new = self._epochs.get(backend_id, 0) + 1
            self._epochs[backend_id] = new
            self._history.setdefault(backend_id, []).append(
                {"epoch": new, "reason": reason, "at": self._clock.now_iso()})
            self._track.pop(backend_id, None)
            if seen_up:
                self._seen_up_epoch[backend_id] = new
        log.info("backend %s: epoch -> %d (%s)", backend_id, new, reason)
        return new

    def bump_epoch(self, backend_id: str, reason: str) -> int:
        """Increment the epoch after state loss caused elsewhere (e.g. VM revert)."""
        self._client(backend_id)
        return self._bump(backend_id, reason, seen_up=False)

    # ── restart accounting ──────────────────────────────────────────
    def restarts(self, job_id: str) -> int:
        with self._lock:
            return self._restarts.get(job_id, 0)

    def forget_job(self, job_id: str) -> None:
        with self._lock:
            self._restarts.pop(job_id, None)

    def _count_restart(self, backend_id: str, job_id: str | None) -> None:
        if job_id is None:
            return
        with self._lock:
            done = self._restarts.get(job_id, 0)
            if done >= self._max_restarts:
                raise CrashLoop(
                    f"debugger for job {job_id} was relaunched {done} time(s); giving up "
                    "(crash loop or debugger-detecting sample)",
                    stage="supervisor", next_tool="analysis_collect",
                    hint="collect what is available; the sample may be terminating the debugger",
                    details={"job_id": job_id, "backend": backend_id, "debugger_killed_by_target": done,
                             "max_restarts_per_job": self._max_restarts},
                )
            self._restarts[job_id] = done + 1

    # ── classification ──────────────────────────────────────────────
    def check(self, backend_id: str) -> HealthReport:
        """Classify the backend's health (see module docstring). Never relaunches."""
        self._client(backend_id)
        if self.is_paused():
            return self._report(HealthState.PAUSED, backend_id)
        if self._vm is not None:
            try:
                power = self._vm.power_state()
                if power != PowerState.RUNNING:
                    return self._report(HealthState.VM_DOWN, backend_id, power=str(power.value))
                tools = self._vm.tools_state()
            except GatewayError as e:
                return self._report(HealthState.UNKNOWN, backend_id, error=e.code, message=e.message)
            if tools != ToolsState.RUNNING:
                return self._report(HealthState.TOOLS_DOWN, backend_id, tools=str(tools.value))
        return self._check_http(backend_id, allow_refresh=True)

    def _check_http(self, backend_id: str, *, allow_refresh: bool) -> HealthReport:
        client = self._client(backend_id)
        try:
            l1 = client.health_l1(timeout_s=self._l1_timeout_s)
        except BackendAuthError:
            return self._on_auth(backend_id, allow_refresh)
        except (BackendError, CancelledByVmOp, OSError):
            l1 = False
        if not l1:
            with self._lock:
                tr = self._tr(backend_id)
                tr.l2_failures, tr.l2_first_failure = 0, None
            return self._classify_refused(backend_id)

        epoch = self.epoch(backend_id)
        with self._lock:
            self._tr(backend_id).loading_since = None
            self._seen_up_epoch[backend_id] = epoch
        try:
            l2 = client.health_l2(timeout_s=self._l2_timeout_s)
        except BackendAuthError:
            return self._on_auth(backend_id, allow_refresh)
        except (BackendError, CancelledByVmOp, OSError):
            l2 = False
        now = self._clock.monotonic()
        with self._lock:
            tr = self._tr(backend_id)
            if l2:
                tr.l2_failures, tr.l2_first_failure = 0, None
                return self._report(HealthState.HEALTHY, backend_id, epoch=epoch)
            tr.l2_failures += 1
            if tr.l2_first_failure is None:
                tr.l2_first_failure = now
            failures, span = tr.l2_failures, now - tr.l2_first_failure
        if failures >= self._l2_threshold and span >= self._l2_window_s:
            return self._report(HealthState.HUNG, backend_id, epoch=epoch, l2_failures=failures,
                                l2_failing_for_s=span, reason="L1 answers but GetDebugState keeps failing")
        return self._report(HealthState.HEALTHY, backend_id, epoch=epoch, l2_ok=False, l2_failures=failures,
                            l2_failing_for_s=span)

    def _on_auth(self, backend_id: str, allow_refresh: bool) -> HealthReport:
        epoch = self.epoch(backend_id)
        refresh = False
        if allow_refresh and self._token_refresher is not None:
            with self._lock:
                if self._auth_refreshed_epoch.get(backend_id) != epoch:
                    self._auth_refreshed_epoch[backend_id] = epoch
                    refresh = True
        if refresh:
            assert self._token_refresher is not None
            try:
                self._token_refresher(backend_id)
            except Exception as e:  # noqa: BLE001 - user callback; reported, never fatal
                code = e.code if isinstance(e, GatewayError) else type(e).__name__
                log.warning("backend %s: token refresh failed (%s)", backend_id, code)
                return self._report(HealthState.AUTH, backend_id, token_refreshed=False, refresh_error=code)
            log.info("backend %s: token refreshed after HTTP 401; re-checking", backend_id)
            return self._check_http(backend_id, allow_refresh=False)
        with self._lock:
            refreshed = self._auth_refreshed_epoch.get(backend_id) == epoch
        return self._report(HealthState.AUTH, backend_id, token_refreshed=refreshed)

    def _classify_refused(self, backend_id: str) -> HealthReport:
        if self._guest is None:
            return self._report(HealthState.DEAD, backend_id, l1="refused", mode="endpoint")
        image = self._image_name(backend_id)
        if image is None:
            return self._report(HealthState.DEAD, backend_id, l1="refused",
                                reason="exe not configured; cannot look for the debugger process")
        try:
            procs = self._guest.list_processes()
        except GatewayError as e:
            return self._report(HealthState.UNKNOWN, backend_id, l1="refused", error=e.code,
                                message=e.message)
        pids = [p.pid for p in procs if p.image_name == image]
        if not pids:
            with self._lock:
                self._tr(backend_id).loading_since = None
            return self._report(HealthState.DEAD, backend_id, l1="refused", process=None, image=image)
        now = self._clock.monotonic()
        with self._lock:
            tr = self._tr(backend_id)
            if tr.loading_since is None:
                tr.loading_since = now
            elapsed = now - tr.loading_since
        if elapsed < self._boot_grace_s:
            return self._report(HealthState.LOADING, backend_id, l1="refused", pids=pids, image=image,
                                loading_for_s=elapsed, boot_grace_s=self._boot_grace_s)
        return self._report(HealthState.HUNG, backend_id, l1="refused", pids=pids, image=image,
                            loading_for_s=elapsed,
                            reason=f"process present but HTTP refused for {elapsed:.0f}s")

    # ── recovery ────────────────────────────────────────────────────
    def ensure_alive(self, backend_id: str, *, job_id: str | None = None, reason: str) -> int:
        """Make sure the backend is HEALTHY, relaunching it if needed; return the epoch.

        Raises CancelledByVmOp (paused), VmNotReady (VM/Tools down), BackendAuthError,
        BackendUnavailable (endpoint mode, relaunch failed or not ready in time),
        CrashLoop (too many relaunches for ``job_id``), ConfigError, LockTimeout, and
        guest-channel errors from kill/run.
        """
        self._client(backend_id)
        self._raise_if_paused(backend_id)
        entry_epoch = self.epoch(backend_id)
        lock = self._relaunch_lock(backend_id)
        if not lock.acquire(timeout=self._relaunch_lock_timeout_s):
            raise LockTimeout(f"timed out waiting for another relaunch of backend {backend_id}",
                              stage="supervisor", details={"backend": backend_id})
        try:
            current = self.epoch(backend_id)
            if current != entry_epoch:
                return current  # another caller relaunched while we waited
            self._raise_if_paused(backend_id)
            with self._lock:
                was_up = self._seen_up_epoch.get(backend_id) == current
            report = self.check(backend_id)
            waited_for_boot = False
            while report.state is HealthState.LOADING:  # bounded: turns HUNG after boot_grace_s
                waited_for_boot = True
                self._clock.sleep(self._poll_s)
                self._raise_if_paused(backend_id)
                report = self.check(backend_id)
            state = report.state
            if state is HealthState.HEALTHY:
                if waited_for_boot and was_up:
                    # The debugger answered earlier in this epoch, then went away and came back
                    # by itself (external restart): its debuggee state is gone.
                    return self._bump(backend_id, f"debugger restarted outside the gateway: {reason}",
                                      seen_up=True)
                return self.epoch(backend_id)
            self._raise_for_state(backend_id, report)
            # DEAD or HUNG from here on
            if self._guest is None:
                raise BackendUnavailable(
                    f"backend {backend_id} is {state.value} and cannot be relaunched",
                    stage="supervisor", details=dict(report.details),
                    hint="endpoint mode cannot relaunch the debugger; restart x64dbg on the remote "
                         "machine manually, then call session_status",
                )
            self._count_restart(backend_id, job_id)
            if state is HealthState.HUNG:
                self._kill(backend_id)
            log.warning("backend %s: relaunching debugger (%s; reason: %s)", backend_id, state.value, reason)
            self._launch(backend_id)
            self._wait_ready(backend_id)
            return self._bump(backend_id, f"relaunch after {state.value}: {reason}", seen_up=True)
        finally:
            lock.release()

    def _raise_for_state(self, backend_id: str, report: HealthReport) -> None:
        state = report.state
        details = dict(report.details)
        if state is HealthState.PAUSED:
            self._raise_if_paused(backend_id)
            raise CancelledByVmOp(f"supervision of backend {backend_id} is paused", stage="supervisor",
                                  details=details)
        if state in (HealthState.VM_DOWN, HealthState.TOOLS_DOWN):
            raise VmNotReady(f"cannot recover backend {backend_id}: {state.value}", stage="supervisor",
                             details=details, next_tool="session_status")
        if state is HealthState.AUTH:
            raise BackendAuthError(f"backend {backend_id} rejects the bearer token", stage="supervisor",
                                   details=details, hint="check token_source / the token env var")
        if state is HealthState.UNKNOWN:
            raise BackendUnavailable(f"cannot determine the health of backend {backend_id}",
                                     stage="supervisor", details=details)

    def _kill(self, backend_id: str) -> None:
        assert self._guest is not None
        image = self._image_name(backend_id)
        if image is None:
            return
        for p in self._guest.list_processes():
            if p.image_name == image:
                log.warning("backend %s: killing hung debugger pid %d", backend_id, p.pid)
                self._guest.kill_process(p.pid)

    def _launch(self, backend_id: str) -> None:
        assert self._guest is not None
        if self._mode == "task":
            task = self._cfg(backend_id, "launch_task")
            if not task:
                raise ConfigError(f"backend {backend_id}: relaunch_mode 'task' needs launch_task")
            rc = self._guest.run_program(SCHTASKS_EXE, ["/run", "/tn", task], wait=True, timeout_s=60.0)
            if rc not in (0, None):
                raise BackendUnavailable(
                    f"relaunching backend {backend_id}: schtasks /run failed",
                    stage="relaunch", details={"backend": backend_id, "exit_code": rc, "task": task},
                    hint="check that the scheduled task exists in the guest (guest/provision.ps1)",
                )
        else:
            exe = self._exe(backend_id)
            if not exe:
                raise ConfigError(f"backend {backend_id}: relaunch needs the guest path of the debugger exe")
            self._guest.run_program(exe, (), wait=False, interactive=True, active_window=True)

    def _wait_ready(self, backend_id: str) -> None:
        deadline = self._clock.monotonic() + self._ready_timeout_s
        while True:
            self._raise_if_paused(backend_id)
            client = self._client(backend_id)
            try:
                if client.health_l1(timeout_s=self._l1_timeout_s) and \
                        client.health_l2(timeout_s=self._l2_timeout_s):
                    return
            except BackendAuthError:
                report = self._on_auth(backend_id, allow_refresh=True)
                if report.state is HealthState.HEALTHY:
                    return
                if report.state is HealthState.AUTH:
                    raise BackendAuthError(f"relaunched backend {backend_id} rejects the bearer token",
                                           stage="relaunch", details=dict(report.details)) from None
            except (BackendError, CancelledByVmOp, OSError):
                pass
            if self._clock.monotonic() >= deadline:
                raise BackendUnavailable(
                    f"backend {backend_id} did not become ready within {self._ready_timeout_s:g}s "
                    "after relaunch",
                    stage="relaunch", details={"backend": backend_id, "timeout_s": self._ready_timeout_s},
                    hint="take a screenshot (vm_screenshot) to look for a modal dialog in the guest",
                )
            self._clock.sleep(self._poll_s)
