"""Tests for locks.VmOpLock (plan 4.3): writer-preferring RW lock with preempt hooks.

Synchronisation uses threading.Event plus bounded polling of lock.state(); no
test sleeps longer than a few milliseconds at a time.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

import pytest

from x64dbg_vm_gateway.errors import LockTimeout
from x64dbg_vm_gateway.locks import VmOpLock

WAIT = 5.0  # generous upper bound for cross-thread handshakes; normally instant


def until(pred: Callable[[], bool], timeout: float = WAIT) -> None:
    deadline = time.monotonic() + timeout
    while not pred():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        time.sleep(0.001)


class Worker(threading.Thread):
    """Runs ``body`` in a daemon thread and records any exception."""

    def __init__(self, body: Callable[[], None]) -> None:
        super().__init__(daemon=True)
        self.body = body
        self.exc: BaseException | None = None

    def run(self) -> None:
        try:
            self.body()
        except BaseException as e:  # re-raised in the test thread by finish()
            self.exc = e

    def finish(self) -> None:
        self.join(WAIT)
        assert not self.is_alive(), "worker did not finish"
        if self.exc is not None:
            raise self.exc


def hold_read(lock: VmOpLock, acquired: threading.Event, release: threading.Event,
              log: list[str] | None = None, tag: str = "r", lock_timeout: float = WAIT) -> Worker:
    def body() -> None:
        with lock.read(lock_timeout):
            if log is not None:
                log.append(f"{tag}+")
            acquired.set()
            release.wait(WAIT)
            if log is not None:
                log.append(f"{tag}-")

    w = Worker(body)
    w.start()
    return w


def test_initial_state():
    assert VmOpLock().state() == {"readers": 0, "writer": False, "waiting_writers": 0}


def test_readers_share_the_lock():
    lock = VmOpLock()
    a1, a2, rel = threading.Event(), threading.Event(), threading.Event()
    w1 = hold_read(lock, a1, rel)
    w2 = hold_read(lock, a2, rel)
    assert a1.wait(WAIT) and a2.wait(WAIT)
    assert lock.state()["readers"] == 2
    rel.set()
    w1.finish()
    w2.finish()
    assert lock.state() == {"readers": 0, "writer": False, "waiting_writers": 0}


def test_writer_excludes_readers_and_reports_state():
    lock = VmOpLock()
    with lock.write(1.0):
        assert lock.state() == {"readers": 0, "writer": True, "waiting_writers": 0}
        got = threading.Event()

        def reader() -> None:
            with lock.read(WAIT):
                got.set()

        w = Worker(reader)
        w.start()
        assert not got.wait(0.05)
    w.finish()
    assert got.is_set()


def test_writer_waits_for_active_reader():
    lock = VmOpLock()
    acquired, release = threading.Event(), threading.Event()
    log: list[str] = []
    r = hold_read(lock, acquired, release, log)
    assert acquired.wait(WAIT)

    def writer() -> None:
        with lock.write(WAIT):
            log.append("w+")

    w = Worker(writer)
    w.start()
    until(lambda: lock.state()["waiting_writers"] == 1)
    assert "w+" not in log
    release.set()
    r.finish()
    w.finish()
    assert log == ["r+", "r-", "w+"]


def test_writer_preference_blocks_new_readers():
    lock = VmOpLock()
    acquired, release = threading.Event(), threading.Event()
    log: list[str] = []
    r1 = hold_read(lock, acquired, release, log, "r1")
    assert acquired.wait(WAIT)

    w_release = threading.Event()

    def writer() -> None:
        with lock.write(WAIT):
            log.append("w+")
            w_release.wait(WAIT)
            log.append("w-")

    w = Worker(writer)
    w.start()
    until(lambda: lock.state()["waiting_writers"] == 1)

    r2_acquired, r2_release = threading.Event(), threading.Event()
    r2 = hold_read(lock, r2_acquired, r2_release, log, "r2")
    # a writer is waiting: the new reader must queue behind it
    assert not r2_acquired.wait(0.05)
    release.set()  # r1 leaves -> writer goes first
    until(lambda: "w+" in log)
    assert not r2_acquired.is_set()
    w_release.set()
    assert r2_acquired.wait(WAIT)
    r2_release.set()
    r1.finish()
    w.finish()
    r2.finish()
    assert log == ["r1+", "r1-", "w+", "w-", "r2+", "r2-"]


def test_read_timeout_raises_lock_timeout():
    lock = VmOpLock()
    with lock.write(1.0):
        result: list[BaseException] = []

        def reader() -> None:
            try:
                with lock.read(0.05):
                    pass
            except LockTimeout as e:
                result.append(e)

        w = Worker(reader)
        w.start()
        w.finish()
    assert len(result) == 1
    assert result[0].code == "LOCK_TIMEOUT" and result[0].retryable is True
    assert result[0].details["mode"] == "read"


def test_write_timeout_cleans_up_and_unblocks_queued_readers():
    lock = VmOpLock()
    acquired, release = threading.Event(), threading.Event()
    r1 = hold_read(lock, acquired, release)
    assert acquired.wait(WAIT)

    outcome: list[BaseException] = []
    # The writer waits for its preempt hooks (bounded by its own timeout) before it blocks:
    # holding the hook until the second reader is provably queued makes the ordering
    # deterministic, and the writer's timeout must outlast that handshake.
    lock.add_preempt_hook(lambda: until(lambda: lock._waiting_readers == 1))

    def writer() -> None:
        try:
            with lock.write(0.3):
                pass
        except LockTimeout as e:
            outcome.append(e)

    w = Worker(writer)
    w.start()
    until(lambda: lock.state()["waiting_writers"] == 1)

    r2_acquired = threading.Event()
    r2_release = threading.Event()
    # r2's own lock timeout is long: only a prompt wake-up from the writer giving up admits it
    r2 = hold_read(lock, r2_acquired, r2_release, lock_timeout=30.0)
    w.finish()
    assert len(outcome) == 1 and outcome[0].details["mode"] == "write"
    # once the writer gave up, the queued reader must be admitted (no lost wake-up)
    assert r2_acquired.wait(2.0)
    assert lock.state()["waiting_writers"] == 0
    release.set()
    r2_release.set()
    r1.finish()
    r2.finish()
    assert lock.state() == {"readers": 0, "writer": False, "waiting_writers": 0}


def test_preempt_hook_called_once_when_writer_waits_on_readers():
    lock = VmOpLock()
    acquired, release = threading.Event(), threading.Event()
    calls: list[dict] = []

    def hook() -> None:
        # runs outside the internal mutex: calling back into the lock must not deadlock
        calls.append(lock.state())
        release.set()  # e.g. BackendClient.cancel_all() makes in-flight readers finish

    lock.add_preempt_hook(hook)
    r = hold_read(lock, acquired, release)
    assert acquired.wait(WAIT)
    with lock.write(WAIT):
        assert lock.state()["writer"] is True
    r.finish()
    assert len(calls) == 1
    assert calls[0]["readers"] == 1 and calls[0]["waiting_writers"] == 1


def test_preempt_hook_not_called_without_readers():
    lock = VmOpLock()
    calls: list[int] = []
    lock.add_preempt_hook(lambda: calls.append(1))
    with lock.write(1.0):
        pass
    assert calls == []


def test_preempt_hook_not_called_when_only_a_writer_blocks():
    lock = VmOpLock()
    calls: list[int] = []
    lock.add_preempt_hook(lambda: calls.append(1))
    held, release = threading.Event(), threading.Event()

    def first_writer() -> None:
        with lock.write(WAIT):
            held.set()
            release.wait(WAIT)

    w1 = Worker(first_writer)
    w1.start()
    assert held.wait(WAIT)
    done = threading.Event()

    def second_writer() -> None:
        with lock.write(WAIT):
            done.set()

    w2 = Worker(second_writer)
    w2.start()
    until(lambda: lock.state()["waiting_writers"] == 1)
    release.set()
    w1.finish()
    w2.finish()
    assert done.is_set()
    assert calls == []


def test_each_waiting_writer_triggers_hooks():
    lock = VmOpLock()
    acquired, release = threading.Event(), threading.Event()
    calls: list[int] = []
    lock.add_preempt_hook(lambda: calls.append(1))
    r = hold_read(lock, acquired, release)
    assert acquired.wait(WAIT)

    def writer() -> None:
        with lock.write(WAIT):
            pass

    w1, w2 = Worker(writer), Worker(writer)
    w1.start()
    until(lambda: lock.state()["waiting_writers"] == 1)
    w2.start()
    until(lambda: lock.state()["waiting_writers"] == 2)
    until(lambda: len(calls) == 2)
    release.set()
    r.finish()
    w1.finish()
    w2.finish()
    assert len(calls) == 2


def test_failing_hook_does_not_break_the_writer():
    lock = VmOpLock()
    acquired, release = threading.Event(), threading.Event()
    good: list[int] = []

    def bad() -> None:
        raise RuntimeError("hook exploded")

    lock.add_preempt_hook(bad)
    lock.add_preempt_hook(lambda: (good.append(1), release.set()))
    r = hold_read(lock, acquired, release)
    assert acquired.wait(WAIT)
    with lock.write(WAIT):
        pass
    r.finish()
    assert good == [1]


def test_remove_preempt_hook():
    lock = VmOpLock()
    calls: list[int] = []
    remove = lock.add_preempt_hook(lambda: calls.append(1))
    remove()
    acquired, release = threading.Event(), threading.Event()
    r = hold_read(lock, acquired, release)
    assert acquired.wait(WAIT)

    def writer() -> None:
        with lock.write(WAIT):
            pass

    w2 = Worker(writer)
    w2.start()
    until(lambda: lock.state()["waiting_writers"] == 1)
    release.set()
    r.finish()
    w2.finish()
    assert calls == []


def test_reentrant_read_does_not_deadlock_behind_waiting_writer():
    lock = VmOpLock()
    outer, go_inner, inner_done = threading.Event(), threading.Event(), threading.Event()

    def reader() -> None:
        with lock.read(WAIT):
            outer.set()
            go_inner.wait(WAIT)
            with lock.read(0.5):  # same thread re-enters while a writer waits
                inner_done.set()

    r = Worker(reader)
    r.start()
    assert outer.wait(WAIT)
    w = Worker(lambda: _write_once(lock))
    w.start()
    until(lambda: lock.state()["waiting_writers"] == 1)
    go_inner.set()
    assert inner_done.wait(WAIT)
    r.finish()
    w.finish()


def _write_once(lock: VmOpLock) -> None:
    with lock.write(WAIT):
        pass


def test_reentrant_write_and_read_inside_write():
    lock = VmOpLock()
    with lock.write(1.0):
        with lock.write(1.0):
            with lock.read(1.0):
                # a read nested in the caller's own write lock is not a separate reader
                assert lock.state() == {"readers": 0, "writer": True, "waiting_writers": 0}
        assert lock.state()["writer"] is True
    assert lock.state() == {"readers": 0, "writer": False, "waiting_writers": 0}


def test_read_nested_in_write_does_not_trigger_preempt_hooks():
    # e.g. a revert holding the write lock runs its post-revert health check under a nested
    # read: a second VM op queueing up must not cancel that check through the hooks.
    lock = VmOpLock()
    calls: list[dict] = []
    lock.add_preempt_hook(lambda: calls.append(lock.state()))
    in_read, release = threading.Event(), threading.Event()

    def first_writer() -> None:
        with lock.write(WAIT):
            with lock.read(WAIT):
                in_read.set()
                release.wait(WAIT)

    w1 = Worker(first_writer)
    w1.start()
    assert in_read.wait(WAIT)
    w2 = Worker(lambda: _write_once(lock))
    w2.start()
    until(lambda: lock.state()["waiting_writers"] == 1)
    assert lock.state() == {"readers": 0, "writer": True, "waiting_writers": 1}
    release.set()
    w1.finish()
    w2.finish()
    assert calls == []
    assert lock.state() == {"readers": 0, "writer": False, "waiting_writers": 0}


def test_write_downgrades_to_read_when_released_first():
    lock = VmOpLock()
    write_cm, read_cm = lock.write(1.0), lock.read(1.0)
    write_cm.__enter__()
    read_cm.__enter__()
    write_cm.__exit__(None, None, None)  # still holding the nested read
    assert lock.state() == {"readers": 1, "writer": False, "waiting_writers": 0}
    got = threading.Event()

    def other_reader() -> None:
        with lock.read(WAIT):
            got.set()

    r = Worker(other_reader)
    r.start()
    assert got.wait(WAIT)  # shared with other readers now
    r.finish()
    with pytest.raises(RuntimeError):  # and, like any read hold, cannot be upgraded
        with lock.write(0.05):
            pass
    read_cm.__exit__(None, None, None)
    assert lock.state() == {"readers": 0, "writer": False, "waiting_writers": 0}


def test_slow_preempt_hook_does_not_stretch_the_write_timeout():
    lock = VmOpLock()
    acquired, release = threading.Event(), threading.Event()
    hook_release, hook_started = threading.Event(), threading.Event()

    def stuck_hook() -> None:  # e.g. a cancel_all() that hangs
        hook_started.set()
        hook_release.wait(WAIT)

    lock.add_preempt_hook(stuck_hook)
    r = hold_read(lock, acquired, release)
    assert acquired.wait(WAIT)
    started = time.monotonic()
    try:
        with pytest.raises(LockTimeout):
            with lock.write(0.1):
                pass
        elapsed = time.monotonic() - started
        assert hook_started.is_set()
        assert elapsed < 1.0, elapsed  # bounded by the 0.1s timeout, not by the stuck hook
        assert lock.state() == {"readers": 1, "writer": False, "waiting_writers": 0}
    finally:
        hook_release.set()
        release.set()
    r.finish()


def test_read_to_write_upgrade_is_refused():
    lock = VmOpLock()
    with lock.read(1.0):
        with pytest.raises(RuntimeError):
            with lock.write(0.05):
                pass
    assert lock.state() == {"readers": 0, "writer": False, "waiting_writers": 0}


def test_lock_released_when_body_raises():
    lock = VmOpLock()
    with pytest.raises(ValueError):
        with lock.read(1.0):
            raise ValueError("x")
    with pytest.raises(ValueError):
        with lock.write(1.0):
            raise ValueError("y")
    assert lock.state() == {"readers": 0, "writer": False, "waiting_writers": 0}


def test_many_threads_mutual_exclusion_invariant():
    """Stress: no reader ever observes an active writer and vice versa."""
    lock = VmOpLock()
    violations: list[str] = []
    active = {"r": 0, "w": 0}
    guard = threading.Lock()

    def reader() -> None:
        for _ in range(50):
            with lock.read(WAIT):
                with guard:
                    active["r"] += 1
                    if active["w"]:
                        violations.append("reader saw writer")
                with guard:
                    active["r"] -= 1

    def writer() -> None:
        for _ in range(20):
            with lock.write(WAIT):
                with guard:
                    active["w"] += 1
                    if active["w"] > 1 or active["r"]:
                        violations.append("writer not exclusive")
                with guard:
                    active["w"] -= 1

    workers = [Worker(reader) for _ in range(4)] + [Worker(writer) for _ in range(2)]
    for w in workers:
        w.start()
    for w in workers:
        w.finish()
    assert violations == []
    assert lock.state() == {"readers": 0, "writer": False, "waiting_writers": 0}
