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
no resolved client (VM not ready, Tools starting, guest    UNRESOLVED
channel error while reading the token, placeholder)
token unusable while resolving, or HTTP 401 (after one     AUTH
token refresh per epoch)
HTTP 429 on L1 or L2 (plugin v1.10 auth-failure lockout)   THROTTLED
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

Resolved clients only (E4 on the spike VM): ``check`` and ``ensure_alive`` first
obtain the client through ``resolve(backend_id)`` (the runtime passes
``Runtime.connect``, which reads the guest token if needed); without a resolver
the ``clients`` entry is used. A client that cannot be resolved, or a placeholder
(``is_unresolved_client``: ``wiring.UnresolvedClient`` until the URL and token are
known), is UNRESOLVED: nothing is probed, nothing is classified from guest
processes, no L2 failure is counted, nothing is killed or relaunched, and
``ensure_alive`` raises VmNotReady (retryable). Health probes refuse a placeholder
outright (AssertionError), so a stand-in can never look like a refused plugin.
After a revert the placeholder answered ``health_l1() == False`` while x64dbg ran:
the old classification turned that into LOADING, then HUNG, and killed a healthy
debugger.

THROTTLED means the plugin is alive but has locked this host out after repeated
authentication failures (``details["retry_after_s"]``). It is never a reason to
kill or relaunch the debugger (a new instance would only hide the token problem):
``ensure_alive`` raises BackendThrottled for it, also while waiting for a
relaunched debugger to become ready.

Epochs: an integer per backend, incremented whenever debuggee state is lost:
``ensure_alive`` bumps it as soon as a relaunch has been issued (after a HUNG
debugger was killed, or for a DEAD one right before the launch), *before*
waiting for readiness, so a relaunch that later fails, times out or is
interrupted by a VM operation can never leave a fresh debugger behind the old
epoch. ``bump_epoch`` covers losses caused elsewhere (VM revert). The proxy uses
the epoch to refuse mutating calls after state loss until the client acknowledges.

External restarts: when ``ensure_alive`` waits through LOADING and the backend
comes back HEALTHY although it had been up in the current epoch (seen by
``check()`` or reported by ``note_up``), the debugger restarted outside the
gateway and the epoch is bumped - unless the LOADING process ids are the ones
recorded while this epoch's instance was healthy (a transient L1 failure of the
same process). Without recorded ids the bump is conservative.

Crash loops: relaunches are counted per job (``max_restarts_per_job``); calls
without a job id are counted per backend within ``crash_loop_window_s`` and the
count is reset by ``bump_epoch`` (VM revert).

Bounded waits: ``ensure_alive(max_wait_s=...)`` bounds the wait for another
relaunch, the LOADING wait and the readiness wait (the launch itself is always
issued); the guest commands (list/kill/run) are bounded by their own timeouts.

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
    BackendThrottled,
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
    THROTTLED = "THROTTLED"
    VM_DOWN = "VM_DOWN"
    TOOLS_DOWN = "TOOLS_DOWN"
    PAUSED = "PAUSED"
    UNRESOLVED = "UNRESOLVED"
    UNKNOWN = "UNKNOWN"


def is_unresolved_client(client: object) -> bool:
    """True for a stand-in client whose backend URL/token are not known yet
    (``wiring.UnresolvedClient`` sets ``unresolved = True``): never probe it."""
    return getattr(client, "unresolved", False) is True


class _Unresolved(Exception):
    """No usable client for a backend (reported as HealthState.UNRESOLVED)."""

    def __init__(self, reason: str, code: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


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
        hang_hook: Callable[[str, HealthReport], None] | None = None,
        crash_loop_window_s: float = 600.0,
        kill_exit_timeout_s: float = 10.0,
        resolve: Callable[[str], BackendClient] | None = None,
    ) -> None:
        """``clients`` is read on every use (not copied), so a token refresher may
        replace an entry; ``backends`` supplies exe/launch_task (falling back to the
        client's endpoint fields). ``hang_hook(backend_id, report)`` runs before a
        HUNG debugger is killed (e.g. to save a screenshot into the job directory);
        its exceptions are logged and ignored. ``resolve(backend_id)`` returns a
        usable client (resolving URL and token when needed, bounded by its own
        timeout); without it the ``clients`` entry is used (see "Resolved clients
        only" in the module docstring)."""
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
        self._hang_hook = hang_hook
        self._crash_window_s = crash_loop_window_s
        self._kill_exit_timeout_s = kill_exit_timeout_s
        self._resolve = resolve
        # LOADING turns HUNG after boot_grace_s; this caps the polls in case the clock stalls
        self._max_loading_polls = int(boot_grace_s / max(poll_interval_s, 0.01)) + 2
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
        self._jobless_restarts: dict[str, list[float]] = {}  # backend -> monotonic times of relaunches
        self._ready_epoch: dict[str, int] = {}  # backend -> epoch whose relaunch reached readiness
        self._known_pids: dict[str, tuple[int, frozenset[int]]] = {}  # backend -> (epoch, pids while up)
        self._relaunch_locks: dict[str, threading.Lock] = {}

    # ── helpers ─────────────────────────────────────────────────────
    def _client(self, backend_id: str) -> BackendClient:
        try:
            return self._clients[backend_id]
        except KeyError:
            raise ConfigError(f"unknown backend: {backend_id!r}") from None

    def _resolved_client(self, backend_id: str, client: BackendClient | None = None) -> BackendClient:
        """A client that may be probed: ``client`` if given, else the resolver's, else the
        ``clients`` entry. Raises _Unresolved (no usable client: VM not ready, Tools
        starting, guest-channel error, placeholder), BackendAuthError (the token cannot
        be used), BackendThrottled and ConfigError."""
        if client is None:
            if self._resolve is None:
                client = self._client(backend_id)
            else:
                try:
                    client = self._resolve(backend_id)
                except (BackendAuthError, BackendThrottled, ConfigError):
                    raise
                except GatewayError as e:
                    raise _Unresolved(f"{e.code}: {e.message}", e.code) from e
        if is_unresolved_client(client):
            reason = getattr(client, "reason", None) or "endpoint not resolved"
            raise _Unresolved(f"backend {backend_id} is not resolved yet ({reason})")
        return client

    @staticmethod
    def _probe_l1(client: BackendClient, timeout_s: float) -> bool:
        if is_unresolved_client(client):  # never a silent False: that reads as "refused"
            raise AssertionError("health_l1 must never run against an unresolved placeholder")
        return client.health_l1(timeout_s=timeout_s)

    @staticmethod
    def _probe_l2(client: BackendClient, timeout_s: float) -> bool:
        if is_unresolved_client(client):
            raise AssertionError("health_l2 must never run against an unresolved placeholder")
        return client.health_l2(timeout_s=timeout_s)

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
        """Increment the epoch after state loss caused elsewhere (e.g. VM revert).

        Also resets the job-less crash-loop count: the guest starts from a clean state.
        """
        self._client(backend_id)
        with self._lock:
            self._jobless_restarts.pop(backend_id, None)
        return self._bump(backend_id, reason, seen_up=False)

    def note_up(self, backend_id: str, epoch: int) -> None:
        """Record that the backend answered a call in ``epoch`` (the proxy calls this on success).

        Ignored when ``epoch`` is no longer current. Used by the external-restart
        detection in ``ensure_alive``.
        """
        self._client(backend_id)
        with self._lock:
            if self._epochs.get(backend_id, 0) == epoch:
                self._seen_up_epoch[backend_id] = epoch

    def _record_pids(self, backend_id: str, epoch: int) -> None:
        """Remember which debugger process ids serve ``epoch`` (best effort, no raise)."""
        guest, image = self._guest, self._image_name(backend_id)
        if guest is None or image is None:
            return
        try:
            pids = frozenset(p.pid for p in guest.list_processes() if p.image_name == image)
        except GatewayError as e:
            log.debug("backend %s: could not list guest processes (%s)", backend_id, e.code)
            return
        with self._lock:
            if self._epochs.get(backend_id, 0) == epoch:
                self._known_pids[backend_id] = (epoch, pids)

    # ── restart accounting ──────────────────────────────────────────
    def restarts(self, job_id: str) -> int:
        with self._lock:
            return self._restarts.get(job_id, 0)

    def forget_job(self, job_id: str) -> None:
        with self._lock:
            self._restarts.pop(job_id, None)

    def _recent_jobless(self, backend_id: str, now: float) -> list[float]:
        """Job-less relaunch times still inside the crash-loop window (lock held by caller)."""
        return [t for t in self._jobless_restarts.get(backend_id, []) if now - t < self._crash_window_s]

    def jobless_restarts(self, backend_id: str) -> int:
        """Relaunches without a job id inside the current crash-loop window."""
        now = self._clock.monotonic()
        with self._lock:
            return len(self._recent_jobless(backend_id, now))

    def _count_restart(self, backend_id: str, job_id: str | None) -> None:
        with self._lock:
            now = self._clock.monotonic()
            recent = self._recent_jobless(backend_id, now)
            done = len(recent) if job_id is None else self._restarts.get(job_id, 0)
            if done >= self._max_restarts:
                details: dict[str, Any] = {"job_id": job_id, "backend": backend_id,
                                           "debugger_killed_by_target": done,
                                           "max_restarts_per_job": self._max_restarts}
                if job_id is None:
                    details["window_s"] = self._crash_window_s
                    who = f"backend {backend_id} (no job, last {self._crash_window_s:g}s)"
                    next_tool = "session_status"
                    hint = "the debugger keeps dying; revert the VM (resets the count) or wait for the window"
                else:
                    who, next_tool = f"job {job_id}", "analysis_collect"
                    hint = "collect what is available; the sample may be terminating the debugger"
                raise CrashLoop(
                    f"debugger for {who} was relaunched {done} time(s); giving up "
                    "(crash loop or debugger-detecting sample)",
                    stage="supervisor", next_tool=next_tool, hint=hint, details=details,
                )
            if job_id is None:
                recent.append(now)
                self._jobless_restarts[backend_id] = recent
            else:
                self._restarts[job_id] = done + 1

    # ── classification ──────────────────────────────────────────────
    def check(self, backend_id: str, *, client: BackendClient | None = None,
              vm_state: tuple[PowerState, ToolsState] | None = None,
              record_pids: bool = True) -> HealthReport:
        """Classify the backend's health (see module docstring). Never relaunches.

        ``client``: probe this client instead of resolving one (a placeholder is
        UNRESOLVED). ``vm_state``: the (power, Tools) states the caller just observed,
        so the VM is not asked again. ``record_pids=False`` (status polling) lists guest
        processes only when L1 fails; the default also records the debugger's process
        ids once per epoch, the evidence of the external-restart detection.
        """
        self._client(backend_id)
        if self.is_paused():
            return self._report(HealthState.PAUSED, backend_id)
        if self._vm is not None:
            if vm_state is not None:
                power, tools = vm_state
            else:
                try:
                    power = self._vm.power_state()
                    tools = self._vm.tools_state() if power == PowerState.RUNNING else ToolsState.UNKNOWN
                except GatewayError as e:
                    return self._report(HealthState.UNKNOWN, backend_id, error=e.code, message=e.message)
            if power != PowerState.RUNNING:
                return self._report(HealthState.VM_DOWN, backend_id, power=str(power.value))
            if tools != ToolsState.RUNNING:
                return self._report(HealthState.TOOLS_DOWN, backend_id, tools=str(tools.value))
        return self._probe(backend_id, client, refreshed=False, record_pids=record_pids)

    def _probe(self, backend_id: str, client: BackendClient | None, *, refreshed: bool,
               record_pids: bool = True) -> HealthReport:
        """Resolve a client (unless given) and classify it over HTTP. ``refreshed``: the
        token was re-read already, so a 401 is not answered with another refresh."""
        try:
            target = self._resolved_client(backend_id, client)
        except _Unresolved as u:
            return self._report(HealthState.UNRESOLVED, backend_id, reason=u.reason, error=u.code)
        except BackendAuthError as e:
            return self._report(HealthState.AUTH, backend_id, token_refreshed=refreshed,
                                resolve_error=e.code, message=e.message)
        except BackendThrottled as e:
            return self._throttled_report(backend_id, e, "connect")
        again = None if refreshed else self._recheck(backend_id, client, record_pids)
        return self._check_http(backend_id, target, again=again, record_pids=record_pids)

    def _recheck(self, backend_id: str, client: BackendClient | None,
                 record_pids: bool = True) -> Callable[[], HealthReport]:
        return lambda: self._probe(backend_id, client, refreshed=True, record_pids=record_pids)

    def _check_http(self, backend_id: str, client: BackendClient, *,
                    again: Callable[[], HealthReport] | None, record_pids: bool = True) -> HealthReport:
        """L1 + L2 of a resolved ``client``. ``again`` re-checks after a token refresh
        (None: a refresh happened already or is not allowed)."""
        try:
            l1 = self._probe_l1(client, self._l1_timeout_s)
        except BackendAuthError:
            return self._on_auth(backend_id, again)
        except BackendThrottled as e:
            return self._throttled_report(backend_id, e, "L1")
        except (BackendError, CancelledByVmOp, OSError):
            l1 = False
        if not l1:
            with self._lock:
                tr = self._tr(backend_id)
                tr.l2_failures, tr.l2_first_failure = 0, None
            return self._classify_refused(backend_id)

        epoch = self.epoch(backend_id)
        with self._lock:
            tr = self._tr(backend_id)
            was_loading = tr.loading_since is not None
            tr.loading_since = None
            self._seen_up_epoch[backend_id] = epoch
            known = self._known_pids.get(backend_id)
        if record_pids and not was_loading and (known is None or known[0] != epoch):
            # Once per epoch: evidence for restart detection. Not right after LOADING, where
            # the process that answers may already be a restarted instance.
            self._record_pids(backend_id, epoch)
        try:
            l2 = self._probe_l2(client, self._l2_timeout_s)
        except BackendAuthError:
            return self._on_auth(backend_id, again)
        except BackendThrottled as e:
            return self._throttled_report(backend_id, e, "L2")
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

    def _throttled_report(self, backend_id: str, exc: BackendThrottled, level: str) -> HealthReport:
        """The plugin is up but locked this host out: not dead, not hung (no L2 failure counted)."""
        with self._lock:
            self._tr(backend_id).loading_since = None
        return self._report(HealthState.THROTTLED, backend_id, level=level,
                            retry_after_s=exc.details.get("retry_after_s"))

    def _on_auth(self, backend_id: str, again: Callable[[], HealthReport] | None) -> HealthReport:
        """HTTP 401: re-read the token once per epoch, then ``again()`` checks once more."""
        epoch = self.epoch(backend_id)
        refresher = self._token_refresher if again is not None else None
        if refresher is not None:
            with self._lock:
                if self._auth_refreshed_epoch.get(backend_id) == epoch:
                    refresher = None  # already refreshed once in this epoch
                else:
                    self._auth_refreshed_epoch[backend_id] = epoch
        if refresher is not None and again is not None:
            try:
                refresher(backend_id)
            except Exception as e:  # noqa: BLE001 - user callback; reported, never fatal
                code = e.code if isinstance(e, GatewayError) else type(e).__name__
                log.warning("backend %s: token refresh failed (%s)", backend_id, code)
                return self._report(HealthState.AUTH, backend_id, token_refreshed=False, refresh_error=code)
            log.info("backend %s: token refreshed after HTTP 401; re-checking", backend_id)
            return again()
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
    def ensure_alive(self, backend_id: str, *, job_id: str | None = None, reason: str,
                     max_wait_s: float | None = None) -> int:
        """Make sure the backend is HEALTHY, relaunching it if needed; return the epoch.

        ``max_wait_s`` (default: unbounded apart from the configured timeouts) bounds
        the waits: for another caller's relaunch, for a LOADING debugger, and for
        readiness after a launch. A launch is always issued once decided; when the
        budget runs out before the new debugger is ready, BackendUnavailable is
        raised with ``details['relaunch_pending'] = True`` and the epoch has
        already been bumped.

        Raises CancelledByVmOp (paused), VmNotReady (VM/Tools down, or UNRESOLVED: no
        client could be resolved, nothing was probed or restarted), BackendAuthError,
        BackendUnavailable (endpoint mode, relaunch failed or not ready in time),
        CrashLoop (too many relaunches for ``job_id`` / for the backend without a job),
        ConfigError, LockTimeout, and guest-channel errors from kill/run.
        """
        self._client(backend_id)
        self._raise_if_paused(backend_id)
        budget_end = None if max_wait_s is None else self._clock.monotonic() + max(0.0, max_wait_s)
        entry_epoch = self.epoch(backend_id)
        lock = self._relaunch_lock(backend_id)
        lock_wait = self._relaunch_lock_timeout_s
        if max_wait_s is not None:
            lock_wait = max(0.01, min(lock_wait, max_wait_s))
        if not lock.acquire(timeout=lock_wait):
            # another caller holds the relaunch lock: a relaunch is in progress, not failed
            raise LockTimeout(f"timed out waiting for another relaunch of backend {backend_id}",
                              stage="supervisor", hint="call session_status in a few seconds",
                              details={"backend": backend_id, "waited_s": lock_wait,
                                       "relaunch_pending": True})
        try:
            current = self.epoch(backend_id)
            with self._lock:
                relaunched_ok = self._ready_epoch.get(backend_id) == current
            if current != entry_epoch and relaunched_ok:
                return current  # another caller relaunched successfully while we waited
            self._raise_if_paused(backend_id)
            with self._lock:
                was_up = self._seen_up_epoch.get(backend_id) == current
            report = self.check(backend_id)
            waited_for_boot = False
            loading_pids: set[int] = set()
            polls = 0
            while report.state is HealthState.LOADING:  # turns HUNG after boot_grace_s
                waited_for_boot = True
                loading_pids.update(report.details.get("pids") or ())
                if polls >= self._max_loading_polls:
                    report = HealthReport(HealthState.HUNG, {
                        **report.details, "reason": "still loading after the maximum number of polls"})
                    break
                if budget_end is not None and self._clock.monotonic() >= budget_end:
                    raise BackendUnavailable(
                        f"backend {backend_id} is still loading", stage="supervisor",
                        details={**report.details, "state": HealthState.LOADING.value,
                                 "max_wait_s": max_wait_s},
                        hint="the debugger is starting; call session_status in a few seconds",
                    )
                polls += 1
                self._clock.sleep(self._poll_s)
                self._raise_if_paused(backend_id)
                report = self.check(backend_id)
            state = report.state
            if state is HealthState.HEALTHY:
                if waited_for_boot and was_up and not self._same_instance(backend_id, current, loading_pids):
                    # The debugger answered earlier in this epoch, then went away and came back
                    # by itself (external restart): its debuggee state is gone.
                    new = self._bump(backend_id, f"debugger restarted outside the gateway: {reason}",
                                     seen_up=True)
                    self._record_pids(backend_id, new)
                    return new
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
            launch = self._launch_spec(backend_id)  # validate config before any side effect
            self._count_restart(backend_id, job_id)
            killed: frozenset[int] = frozenset()
            if state is HealthState.HUNG:
                self._run_hang_hook(backend_id, report)
                killed = self._kill(backend_id)
            # From here the old debuggee state is gone (killed, or the debugger was dead).
            new = self._bump(backend_id, f"relaunch after {state.value}: {reason}", seen_up=False)
            if killed:
                self._wait_exit(backend_id, killed)
            log.warning("backend %s: relaunching debugger (%s; reason: %s)", backend_id, state.value, reason)
            self._launch(backend_id, launch)
            self._wait_ready(backend_id, budget_end)
            with self._lock:
                self._ready_epoch[backend_id] = new
                if self._epochs.get(backend_id, 0) == new:
                    self._seen_up_epoch[backend_id] = new
            self._record_pids(backend_id, new)
            return self.epoch(backend_id)
        finally:
            lock.release()

    def _same_instance(self, backend_id: str, epoch: int, loading_pids: set[int]) -> bool:
        """True if the LOADING process ids are the ones recorded while ``epoch`` was healthy."""
        with self._lock:
            known = self._known_pids.get(backend_id)
        return known is not None and known[0] == epoch and bool(loading_pids) and loading_pids <= known[1]

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
        if state is HealthState.UNRESOLVED:
            raise VmNotReady(
                f"backend {backend_id} cannot be reached yet ({details.get('reason')}); it was neither "
                "probed nor restarted",
                stage="supervisor", next_tool="session_status", retryable=True,
                details={**details, "state": state.value},
                hint="the guest may still be starting (VMware Tools); call session_status and retry",
            )
        if state is HealthState.AUTH:
            raise BackendAuthError(f"backend {backend_id} rejects the bearer token", stage="supervisor",
                                   details=details, hint="check token_source / the token env var")
        if state is HealthState.THROTTLED:
            raise self._throttled_error(backend_id, details)
        if state is HealthState.UNKNOWN:
            raise BackendUnavailable(f"cannot determine the health of backend {backend_id}",
                                     stage="supervisor", details=details)

    @staticmethod
    def _throttled_error(backend_id: str, details: dict[str, Any]) -> BackendThrottled:
        retry = details.get("retry_after_s")
        wait = f"retry after {retry} s" if retry is not None else "retry later"
        return BackendThrottled(
            f"backend {backend_id} has locked this host out after repeated authentication failures; "
            "it is running and was not restarted",
            stage="supervisor", retry_after_s=retry, next_tool="session_status",
            details={**details, "backend": backend_id},
            hint=f"wait ({wait}); if the lockout comes back the gateway's token is wrong "
                 "(x64dbg-vm-gateway doctor)",
        )

    def _run_hang_hook(self, backend_id: str, report: HealthReport) -> None:
        if self._hang_hook is None:
            return
        try:
            self._hang_hook(backend_id, report)
        except Exception as e:  # noqa: BLE001 - diagnostics only; never blocks recovery
            log.warning("backend %s: hang hook failed (%s)", backend_id, type(e).__name__)

    def _kill(self, backend_id: str) -> frozenset[int]:
        """Kill every guest process running the backend's debugger image; return the pids killed.

        A kill that fails because the process already exited is ignored; if the
        process is still there the error propagates (relaunching next to a hung
        instance would only collide on the port).
        """
        guest = self._guest
        image = self._image_name(backend_id)
        if guest is None or image is None:
            return frozenset()
        killed: set[int] = set()
        for p in guest.list_processes():
            if p.image_name != image:
                continue
            log.warning("backend %s: killing hung debugger pid %d", backend_id, p.pid)
            try:
                guest.kill_process(p.pid)
                killed.add(p.pid)
            except GatewayError:
                if any(q.pid == p.pid for q in guest.list_processes()):
                    raise
                log.info("backend %s: pid %d had already exited", backend_id, p.pid)
        return frozenset(killed)

    def _wait_exit(self, backend_id: str, pids: frozenset[int]) -> None:
        """Wait (bounded) until the killed processes are gone from the guest.

        TerminateProcess is asynchronous and the plugin binds with SO_REUSEADDR, so
        a new instance started too early could share the port with the dying one.
        """
        guest = self._guest
        if guest is None:
            return
        interval = min(self._poll_s, 0.5)
        deadline = self._clock.monotonic() + self._kill_exit_timeout_s
        max_polls = int(self._kill_exit_timeout_s / max(interval, 0.01)) + 2  # in case the clock stalls
        polls = 0
        alive = set(pids)
        while True:
            try:
                alive = {p.pid for p in guest.list_processes()} & set(pids)
            except GatewayError as e:
                log.debug("backend %s: process listing failed while waiting for exit (%s)",
                          backend_id, e.code)
            if not alive:
                return
            polls += 1
            if self._clock.monotonic() >= deadline or polls >= max_polls:
                raise BackendUnavailable(
                    f"killed debugger of backend {backend_id} did not exit within "
                    f"{self._kill_exit_timeout_s:g}s; not relaunching next to it",
                    stage="relaunch", details={"backend": backend_id, "pids": sorted(alive),
                                               "timeout_s": self._kill_exit_timeout_s},
                    hint="take a screenshot (vm_screenshot); the process may be stuck in the kernel",
                )
            self._clock.sleep(interval)

    def _launch_spec(self, backend_id: str) -> tuple[str, list[str], dict[str, Any]]:
        """Validate the relaunch configuration; return (exe, args, run_program kwargs)."""
        if self._mode == "task":
            task = self._cfg(backend_id, "launch_task")
            if not task:
                raise ConfigError(f"backend {backend_id}: relaunch_mode 'task' needs launch_task")
            return SCHTASKS_EXE, ["/run", "/tn", task], {"wait": True, "timeout_s": 60.0}
        exe = self._exe(backend_id)
        if not exe:
            raise ConfigError(f"backend {backend_id}: relaunch needs the guest path of the debugger exe")
        return exe, [], {"wait": False, "interactive": True, "active_window": True}

    def _launch(self, backend_id: str, spec: tuple[str, list[str], dict[str, Any]]) -> None:
        guest = self._guest
        if guest is None:
            raise BackendUnavailable(f"backend {backend_id}: no guest channel to relaunch with",
                                     stage="relaunch", details={"backend": backend_id})
        exe, args, kwargs = spec
        if self._mode == "task":
            rc = guest.run_program(exe, args, **kwargs)
            if rc not in (0, None):
                raise BackendUnavailable(
                    f"relaunching backend {backend_id}: schtasks /run failed",
                    stage="relaunch", details={"backend": backend_id, "exit_code": rc, "task": args[-1]},
                    hint="check that the scheduled task exists in the guest (guest/provision.ps1)",
                )
        else:
            guest.run_program(exe, tuple(args), **kwargs)

    def _wait_ready(self, backend_id: str, budget_end: float | None = None) -> None:
        """Poll L1+L2 until ready, bounded by relaunch_ready_timeout_s and ``budget_end``."""
        now = self._clock.monotonic()
        deadline = now + self._ready_timeout_s
        by_budget = budget_end is not None and budget_end < deadline
        if by_budget:
            deadline = budget_end  # type: ignore[assignment]
        max_polls = int(max(0.0, deadline - now) / max(self._poll_s, 0.01)) + 2  # in case the clock stalls
        polls = 0
        while True:
            polls += 1
            self._raise_if_paused(backend_id)
            try:
                client: BackendClient | None = self._resolved_client(backend_id)
            except _Unresolved:
                client = None  # e.g. the token cannot be read yet: not ready, keep polling
            except BackendAuthError as e:
                raise BackendAuthError(
                    f"relaunched backend {backend_id}: its token cannot be used ({e.message})",
                    stage="relaunch", hint=e.hint, details={"backend": backend_id, "cause": e.code},
                ) from None
            except BackendThrottled as e:
                raise self._throttled_error(backend_id, {"retry_after_s": e.details.get("retry_after_s"),
                                                         "stage": "relaunch"}) from None
            try:
                if client is not None and self._probe_l1(client, self._l1_timeout_s) and \
                        self._probe_l2(client, self._l2_timeout_s):
                    return
            except BackendAuthError:
                report = self._on_auth(backend_id, self._recheck(backend_id, None))
                if report.state is HealthState.HEALTHY:
                    return
                if report.state is HealthState.AUTH:
                    raise BackendAuthError(f"relaunched backend {backend_id} rejects the bearer token",
                                           stage="relaunch", details=dict(report.details)) from None
                if report.state is HealthState.THROTTLED:
                    raise self._throttled_error(backend_id, dict(report.details)) from None
            except BackendThrottled as e:
                # alive but locked out: polling on would only prolong the lockout
                raise self._throttled_error(backend_id, {"retry_after_s": e.details.get("retry_after_s"),
                                                         "stage": "relaunch"}) from None
            except (BackendError, CancelledByVmOp, OSError):
                pass
            if self._clock.monotonic() >= deadline or polls >= max_polls:
                if by_budget:
                    raise BackendUnavailable(
                        f"backend {backend_id} was relaunched but is not ready yet",
                        stage="relaunch", details={"backend": backend_id, "relaunch_pending": True,
                                                   "timeout_s": self._ready_timeout_s},
                        hint="the debugger is starting; call session_status in a few seconds",
                    )
                raise BackendUnavailable(
                    f"backend {backend_id} did not become ready within {self._ready_timeout_s:g}s "
                    "after relaunch",
                    stage="relaunch", details={"backend": backend_id, "timeout_s": self._ready_timeout_s},
                    hint="take a screenshot (vm_screenshot) to look for a modal dialog in the guest",
                )
            self._clock.sleep(self._poll_s)
