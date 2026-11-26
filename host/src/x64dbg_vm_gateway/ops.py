"""Background runner for long gateway operations (app_api module docstring, plan 5.6).

``OperationRunner.run(op_name, key, fn, wait_s=...)`` executes ``fn(progress)`` on a
daemon thread and waits up to ``wait_s`` seconds for it:

- finished in time: its result is returned (its exception is re-raised);
- still running: ``{"state": "in_progress", "op_id", "op", "stage", "job_id",
  "started_at"}`` is returned and the work continues in the background.

One operation runs at a time per runner (the gateway keeps one runner per VM
profile). While it runs, ``run()`` with the same ``(op_name, key)`` returns the
same in-progress record (idempotent retry), and any other operation is refused
with ``StateViolation``. ``current()`` reports the running or last operation for
``session_status``.

Undelivered outcomes: when an operation finishes after its caller already got
an in-progress record, its outcome is kept *undelivered*, so a client that
repeats the call to poll gets that result (or error) instead of starting the
work a second time. The replay is bounded, because a stale "done" must never
stand in for new work (a later deliberate revert would otherwise do nothing):

- it happens at most once, and only within ``replay_ttl_s`` of the finish;
- ``current(deliver=True)`` (what ``session_status`` reports to the client)
  counts as delivery;
- ``settle()`` drops it; the gateway calls it when other activity (a debugger
  call, an upload, a restart) changed the state the old outcome described.

``progress(stage, *, job_id=None)`` records the current stage (and the job id
once the operation knows it).

Owners: ``run(..., profile=...)`` records which gateway profile an operation belongs to
(profiles of one VM share a runner). An identical ``(op_name, key)`` of another profile is
refused like any other operation (never joined or replayed), and ``current(profile=...)``
of another profile shows the operation without its outcome and never marks it delivered.

Thread-safety: all public methods may be called from any thread; state is
guarded by one lock that is never held while ``fn`` runs or while waiting.
"""

from __future__ import annotations

import itertools
import secrets
import threading
from collections.abc import Callable, Hashable
from dataclasses import dataclass, field
from typing import Any

from .contracts import Clock, SystemClock
from .errors import GatewayError, StateViolation

__all__ = ["DEFAULT_REPLAY_TTL_S", "OperationRunner", "Progress"]

DEFAULT_REPLAY_TTL_S = 120.0
"""How long an undelivered outcome answers a repeated identical call (seconds)."""


class Progress:
    """Callable handed to an operation: ``progress(stage, job_id=None)``."""

    def __init__(self, runner: OperationRunner, op: _Op) -> None:
        self._runner = runner
        self._op = op

    def __call__(self, stage: str, *, job_id: str | None = None) -> None:
        with self._runner._lock:
            self._op.stage = str(stage)
            if job_id is not None:
                self._op.job_id = job_id


@dataclass(eq=False)
class _Op:
    op_id: str
    op: str
    key: Hashable
    started_at: str
    job_id: str | None = None
    profile: str | None = None  # the gateway profile it belongs to (None: not recorded)
    stage: str = "starting"
    state: str = "running"  # running | done | failed
    finished_at: str | None = None
    finished_mono: float | None = None
    result: Any = None
    error: BaseException | None = None
    delivered: bool = False
    done: threading.Event = field(default_factory=threading.Event)


def _error_dict(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, GatewayError):
        return exc.to_dict()
    # Unexpected exceptions may carry arbitrary text; only the type is reported.
    return {
        "code": "INTERNAL_ERROR",
        "message": f"unexpected {type(exc).__name__}",
        "stage": None,
        "retryable": False,
        "hint": "see the gateway log",
        "next_tool": None,
        "details": {},
    }


class OperationRunner:
    def __init__(
        self, clock: Clock | None = None, *, name: str = "ops", replay_ttl_s: float = DEFAULT_REPLAY_TTL_S
    ) -> None:
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._name = name
        self._replay_ttl_s = max(0.0, float(replay_ttl_s))
        self._lock = threading.Lock()
        self._op: _Op | None = None
        self._ids = itertools.count(1)

    # ── public ──────────────────────────────────────────────────────
    def run(
        self,
        op_name: str,
        key: Hashable,
        fn: Callable[[Progress], Any],
        *,
        wait_s: float | None,
        job_id: str | None = None,
        profile: str | None = None,
    ) -> Any:
        """Run ``fn(progress)`` in the background; see the module docstring.

        ``wait_s=None`` waits until the operation finishes; ``wait_s <= 0`` never waits.
        ``profile``: the owner (see "Owners" in the module docstring).
        """
        with self._lock:
            cur = self._op
            if cur is not None and cur.state == "running":
                if (cur.op, cur.key, cur.profile) == (op_name, key, profile):
                    return self._in_progress(cur)
                raise StateViolation(
                    f"operation {cur.op} is still running (stage {cur.stage}); {op_name} was not started",
                    stage="operation",
                    hint=f"wait for {cur.op}; poll session_status",
                    next_tool="session_status",
                    details={
                        "op_id": cur.op_id,
                        "op": cur.op,
                        "stage": cur.stage,
                        "job_id": cur.job_id,
                        "requested": op_name,
                        **({"profile": cur.profile} if cur.profile is not None else {}),
                    },
                )
            if cur is not None and cur.profile == profile and self._replayable(cur, op_name, key):
                cur.delivered = True
                return self._outcome(cur)
            op = _Op(
                op_id=f"op-{next(self._ids)}-{secrets.token_hex(3)}",
                op=op_name,
                key=key,
                started_at=self._clock.now_iso(),
                job_id=job_id,
                profile=profile,
            )
            self._op = op
        worker = threading.Thread(
            target=self._work, args=(op, fn), name=f"gw-{self._name}-{op_name}", daemon=True
        )
        worker.start()
        if wait_s is None or wait_s > 0:
            op.done.wait(wait_s)
        with self._lock:
            if op.state == "running":
                return self._in_progress(op)
            op.delivered = True
        return self._outcome(op)

    def current(self, *, deliver: bool = False, profile: str | None = None) -> dict[str, Any] | None:
        """The running or last operation, or None before the first one.

        ``deliver=True`` marks a finished outcome as delivered (the caller shows it
        to the client), so a later identical ``run()`` starts the work again.
        ``profile``: the asking profile. An operation recorded for another profile is
        reported without its result or error (``note`` names its profile) and is never
        marked delivered by this call.
        """
        with self._lock:
            op = self._op
            if op is None:
                return None
            other = profile is not None and op.profile is not None and op.profile != profile
            if deliver and op.state != "running" and not other:
                op.delivered = True
            out: dict[str, Any] = {
                "op_id": op.op_id,
                "op": op.op,
                "state": op.state,
                "stage": op.stage,
                "job_id": op.job_id,
                "started_at": op.started_at,
                "finished_at": op.finished_at,
            }
            if op.profile is not None:
                out["profile"] = op.profile
            if other:
                out["note"] = (f"operation of profile {op.profile} (the same VM); its outcome is reported to "
                               f"session_status(profile='{op.profile}')")
                return out
            if op.state == "done":
                out["result"] = op.result
            elif op.state == "failed" and op.error is not None:
                out["error"] = _error_dict(op.error)
            return out

    def busy(self) -> bool:
        with self._lock:
            return self._op is not None and self._op.state == "running"

    def running(self, op_name: str, key: Hashable) -> bool:
        """True while the operation ``(op_name, key)`` runs."""
        with self._lock:
            op = self._op
            return op is not None and op.state == "running" and (op.op, op.key) == (op_name, key)

    def pending_key(self, op_name: str) -> Hashable | None:
        """Key of the last operation if it is ``op_name`` and still running or replayable."""
        with self._lock:
            op = self._op
            if op is None or op.op != op_name:
                return None
            if op.state == "running" or self._replayable(op, op.op, op.key):
                return op.key
            return None

    def settle(self) -> None:
        """Drop an undelivered outcome of the last (finished) operation; see the module docstring."""
        with self._lock:
            if self._op is not None and self._op.state != "running":
                self._op.delivered = True

    def wait_idle(self, timeout_s: float | None = None) -> bool:
        """Wait until no operation runs; True if idle (used by close() and tests)."""
        with self._lock:
            op = self._op
        return op is None or op.done.wait(timeout_s)

    # ── internals ───────────────────────────────────────────────────
    def _work(self, op: _Op, fn: Callable[[Progress], Any]) -> None:
        try:
            result = fn(Progress(self, op))
        except BaseException as exc:  # noqa: BLE001 - handed to the caller, never swallowed
            with self._lock:
                op.error, op.state = exc, "failed"
                op.finished_at = self._clock.now_iso()
                op.finished_mono = self._clock.monotonic()
        else:
            with self._lock:
                op.result, op.state = result, "done"
                op.finished_at = self._clock.now_iso()
                op.finished_mono = self._clock.monotonic()
        finally:
            op.done.set()

    def _replayable(self, op: _Op, op_name: str, key: Hashable) -> bool:
        """Caller holds the lock. See "Undelivered outcomes" in the module docstring."""
        if op.delivered or (op.op, op.key) != (op_name, key) or op.finished_mono is None:
            return False
        return self._clock.monotonic() - op.finished_mono <= self._replay_ttl_s

    @staticmethod
    def _in_progress(op: _Op) -> dict[str, Any]:
        return {
            "state": "in_progress",
            "op_id": op.op_id,
            "op": op.op,
            "stage": op.stage,
            "job_id": op.job_id,
            "started_at": op.started_at,
        }

    @staticmethod
    def _outcome(op: _Op) -> Any:
        if op.state == "failed" and op.error is not None:
            raise op.error
        return op.result
