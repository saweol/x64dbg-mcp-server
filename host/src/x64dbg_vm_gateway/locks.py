"""VM operation lock (plan 4.3).

``VmOpLock`` is a writer-preferring readers-writer lock:

- write lock: revert, power, snapshot take/delete (anything that changes VM state)
- read lock: backend tool calls and guest file operations

When a writer starts waiting while readers are active, the registered preempt
hooks run once (in the writer's thread, outside the internal mutex) so readers
can abort in-flight work, e.g. ``BackendClient.cancel_all()`` which turns the
pending calls into ``CANCELLED_BY_VM_OP``.

Thread-safety: every public method is thread-safe. Locks are reentrant per
thread (a read inside a read, a read or write inside a write). Upgrading a held
read lock to a write lock is refused with RuntimeError because two upgrading
readers would deadlock each other.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from .errors import LockTimeout

log = logging.getLogger(__name__)

PreemptHook = Callable[[], None]


class VmOpLock:
    DEFAULT_READ_TIMEOUT_S = 60.0
    DEFAULT_WRITE_TIMEOUT_S = 120.0

    def __init__(self) -> None:
        self._cond = threading.Condition(threading.Lock())
        self._readers: dict[int, int] = {}  # thread id -> nested read holds
        self._writer: int | None = None  # thread id holding the write lock
        self._writer_depth = 0
        self._waiting_writers = 0
        self._waiting_readers = 0  # diagnostics/tests only; not part of state()
        self._hooks: list[PreemptHook] = []

    # ── public API ──────────────────────────────────────────────────
    @contextmanager
    def read(self, timeout_s: float | None = DEFAULT_READ_TIMEOUT_S) -> Iterator[None]:
        """Hold the lock shared. ``timeout_s=None`` waits forever. Raises LockTimeout."""
        self._acquire_read(timeout_s)
        try:
            yield
        finally:
            self._release_read()

    @contextmanager
    def write(self, timeout_s: float | None = DEFAULT_WRITE_TIMEOUT_S) -> Iterator[None]:
        """Hold the lock exclusively. ``timeout_s=None`` waits forever. Raises LockTimeout."""
        self._acquire_write(timeout_s)
        try:
            yield
        finally:
            self._release_write()

    def add_preempt_hook(self, fn: PreemptHook) -> Callable[[], None]:
        """Register ``fn``; returns a callable that unregisters it."""
        with self._cond:
            self._hooks.append(fn)

        def remove() -> None:
            with self._cond:
                if fn in self._hooks:
                    self._hooks.remove(fn)

        return remove

    def state(self) -> dict[str, int | bool]:
        """Snapshot: number of reader threads, writer held, writers waiting."""
        with self._cond:
            return self._state_locked()

    # ── internals ───────────────────────────────────────────────────
    @staticmethod
    def _deadline(timeout_s: float | None) -> float | None:
        return None if timeout_s is None else time.monotonic() + max(0.0, timeout_s)

    @staticmethod
    def _remaining(deadline: float | None) -> float | None:
        return None if deadline is None else deadline - time.monotonic()

    def _state_locked(self) -> dict[str, int | bool]:
        return {
            "readers": len(self._readers),
            "writer": self._writer is not None,
            "waiting_writers": self._waiting_writers,
        }

    def _timeout(self, mode: str, timeout_s: float | None) -> LockTimeout:
        return LockTimeout(
            f"timed out after {timeout_s}s waiting for the VM {mode} lock",
            stage="vm_lock",
            hint="another VM operation is in progress; retry later or check session_status",
            next_tool="session_status",
            details={"mode": mode, "timeout_s": timeout_s, "state": self._state_locked()},
        )

    def _acquire_read(self, timeout_s: float | None) -> None:
        me = threading.get_ident()
        deadline = self._deadline(timeout_s)
        with self._cond:
            if self._writer == me or me in self._readers:
                # Reentrant: never queue behind a waiting writer while we already
                # hold the lock, or the writer and this thread deadlock.
                self._readers[me] = self._readers.get(me, 0) + 1
                return
            self._waiting_readers += 1
            try:
                while self._writer is not None or self._waiting_writers > 0:
                    remaining = self._remaining(deadline)
                    if remaining is not None and remaining <= 0:
                        raise self._timeout("read", timeout_s)
                    self._cond.wait(remaining)
            finally:
                self._waiting_readers -= 1
            self._readers[me] = 1

    def _release_read(self) -> None:
        me = threading.get_ident()
        with self._cond:
            count = self._readers.get(me, 0)
            if count <= 0:
                raise RuntimeError("release of a VmOpLock read lock that is not held")
            if count == 1:
                del self._readers[me]
                if not self._readers:
                    self._cond.notify_all()
            else:
                self._readers[me] = count - 1

    def _acquire_write(self, timeout_s: float | None) -> None:
        me = threading.get_ident()
        deadline = self._deadline(timeout_s)
        with self._cond:
            if self._writer == me:
                self._writer_depth += 1
                return
            if me in self._readers:
                raise RuntimeError("cannot upgrade a held VmOpLock read lock to a write lock")
            if self._writer is None and not self._readers:
                self._writer, self._writer_depth = me, 1
                return
            self._waiting_writers += 1
            hooks = list(self._hooks) if self._readers else []
        try:
            # Outside the mutex: hooks may call back into this lock or block briefly.
            self._run_hooks(hooks)
            with self._cond:
                while self._writer is not None or self._readers:
                    remaining = self._remaining(deadline)
                    if remaining is not None and remaining <= 0:
                        raise self._timeout("write", timeout_s)
                    self._cond.wait(remaining)
                self._writer, self._writer_depth = me, 1
        finally:
            with self._cond:
                self._waiting_writers -= 1
                if self._writer != me:
                    # Gave up (timeout or error): readers queued behind us may proceed.
                    self._cond.notify_all()

    def _release_write(self) -> None:
        me = threading.get_ident()
        with self._cond:
            if self._writer != me:
                raise RuntimeError("release of a VmOpLock write lock that is not held by this thread")
            self._writer_depth -= 1
            if self._writer_depth == 0:
                self._writer = None
                self._cond.notify_all()

    @staticmethod
    def _run_hooks(hooks: list[PreemptHook]) -> None:
        for hook in hooks:
            try:
                hook()
            except Exception:  # a broken hook must not block the VM operation
                log.exception("VmOpLock preempt hook failed")
