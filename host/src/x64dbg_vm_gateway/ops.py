"""Background runner for long gateway operations (app_api module docstring, plan 5.6).

``OperationRunner.run(op_name, key, fn, wait_s=...)`` executes ``fn(progress)`` on a
daemon thread and waits up to ``wait_s`` seconds for it:

- finished in time: its result is returned (its exception is re-raised);
- still running: ``{"state": "in_progress", "op_id", "op", "stage", "job_id",
  "started_at"}`` is returned and the work continues in the background.

One operation runs at a time per runner (the gateway keeps one runner per VM
profile). While it runs, ``run()`` with the same ``(op_name, key)`` returns the
same in-progress record (idempotent retry), and any other operation is refused
with ``StateViolation``. When an operation finishes after its caller already got
an in-progress record, its outcome is kept *undelivered*: the next ``run()``
with the same ``(op_name, key)`` returns that result (or raises that error)
instead of starting the work again. ``current()`` reports the running or last
operation for ``session_status``.

``progress(stage, *, job_id=None)`` records the current stage (and the job id
once the operation knows it).

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

__all__ = ["OperationRunner", "Progress"]


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
    stage: str = "starting"
    state: str = "running"  # running | done | failed
    finished_at: str | None = None
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
    def __init__(self, clock: Clock | None = None, *, name: str = "ops") -> None:
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._name = name
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
    ) -> Any:
        """Run ``fn(progress)`` in the background; see the module docstring.

        ``wait_s=None`` waits until the operation finishes; ``wait_s <= 0`` never waits.
        """
        with self._lock:
            cur = self._op
            if cur is not None and cur.state == "running":
                if (cur.op, cur.key) == (op_name, key):
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
                    },
                )
            if cur is not None and not cur.delivered and (cur.op, cur.key) == (op_name, key):
                cur.delivered = True
                return self._outcome(cur)
            op = _Op(
                op_id=f"op-{next(self._ids)}-{secrets.token_hex(3)}",
                op=op_name,
                key=key,
                started_at=self._clock.now_iso(),
                job_id=job_id,
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

    def current(self) -> dict[str, Any] | None:
        """The running or last operation, or None before the first one."""
        with self._lock:
            op = self._op
            if op is None:
                return None
            out: dict[str, Any] = {
                "op_id": op.op_id,
                "op": op.op,
                "state": op.state,
                "stage": op.stage,
                "job_id": op.job_id,
                "started_at": op.started_at,
                "finished_at": op.finished_at,
            }
            if op.state == "done":
                out["result"] = op.result
            elif op.state == "failed" and op.error is not None:
                out["error"] = _error_dict(op.error)
            return out

    def busy(self) -> bool:
        with self._lock:
            return self._op is not None and self._op.state == "running"

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
        else:
            with self._lock:
                op.result, op.state = result, "done"
                op.finished_at = self._clock.now_iso()
        finally:
            op.done.set()

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
