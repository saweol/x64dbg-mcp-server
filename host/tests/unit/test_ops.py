"""Tests for ops.OperationRunner (background operations with in-progress records)."""

from __future__ import annotations

import threading

import pytest
from x64dbg_vm_gateway.ops import OperationRunner

from tests.fakes.fake_vm import FakeClock
from x64dbg_vm_gateway.errors import GatewayError, StateViolation, VmNotReady

SHORT = 0.05  # real seconds a caller waits when the test wants an in-progress answer
LONG = 5.0  # real seconds a caller waits when the test expects the work to finish


@pytest.fixture
def runner() -> OperationRunner:
    return OperationRunner(FakeClock())


def blocking(gate: threading.Event, started: threading.Event | None = None, result=None, stages=()):
    def fn(progress):
        for s in stages:
            progress(s)
        if started is not None:
            started.set()
        assert gate.wait(LONG), "test gate never opened"
        return result

    return fn


def test_fast_operation_returns_its_result(runner):
    out = runner.run("vm_power", "start", lambda progress: {"ok": True}, wait_s=LONG)
    assert out == {"ok": True}
    cur = runner.current()
    assert cur["op"] == "vm_power" and cur["state"] == "done" and cur["result"] == {"ok": True}
    assert cur["finished_at"] is not None and cur["started_at"] is not None
    assert cur["op_id"]


def test_no_operation_yet(runner):
    assert runner.current() is None
    assert runner.busy() is False


def test_gateway_error_is_reraised_and_recorded(runner):
    def fn(progress):
        progress("tools")
        raise VmNotReady("tools did not start", hint="h")

    with pytest.raises(VmNotReady) as ei:
        runner.run("vm_snapshot_revert", "MCP_CLEAN", fn, wait_s=LONG)
    assert ei.value.hint == "h"
    cur = runner.current()
    assert cur["state"] == "failed" and cur["stage"] == "tools"
    assert cur["error"]["code"] == "VM_NOT_READY"
    assert "result" not in cur


def test_unexpected_exception_is_reraised_and_recorded_without_its_text(runner):
    def fn(progress):
        raise RuntimeError("secret-ish internal detail")

    with pytest.raises(RuntimeError):
        runner.run("op", 1, fn, wait_s=LONG)
    err = runner.current()["error"]
    assert err["code"] == "INTERNAL_ERROR" and "secret-ish" not in str(err)


def test_slow_operation_returns_in_progress_record(runner):
    gate, started = threading.Event(), threading.Event()
    rec = runner.run("analysis_start", "abc", blocking(gate, started, stages=("upload",)), wait_s=SHORT,
                     job_id="j-1")
    assert started.wait(LONG)
    assert rec["state"] == "in_progress" and rec["op"] == "analysis_start"
    assert rec["job_id"] == "j-1" and rec["op_id"] and rec["started_at"]
    assert runner.busy() is True
    cur = runner.current()
    assert cur["state"] == "running" and cur["stage"] == "upload"
    gate.set()
    assert runner.wait_idle(LONG)
    assert runner.current()["state"] == "done"


def test_progress_can_set_the_job_id(runner):
    gate = threading.Event()

    def fn(progress):
        progress("job_create", job_id="20261123-000000-abcdef")
        gate.wait(LONG)
        return 1

    rec = runner.run("analysis_start", "k", fn, wait_s=SHORT)
    # the job id may arrive after the first answer; current() always has the latest
    deadline = threading.Event()
    for _ in range(100):
        if runner.current()["job_id"]:
            break
        deadline.wait(0.01)
    assert runner.current()["job_id"] == "20261123-000000-abcdef"
    assert rec["state"] == "in_progress"
    gate.set()
    runner.wait_idle(LONG)


def test_same_operation_and_key_is_idempotent_while_running(runner):
    gate, started = threading.Event(), threading.Event()
    calls = []

    def fn(progress):
        calls.append(1)
        started.set()
        gate.wait(LONG)
        return "r"

    first = runner.run("analysis_start", "sha", fn, wait_s=SHORT)
    assert started.wait(LONG)
    second = runner.run("analysis_start", "sha", fn, wait_s=SHORT)
    assert second["op_id"] == first["op_id"] and second["state"] == "in_progress"
    assert len(calls) == 1
    gate.set()
    runner.wait_idle(LONG)


def test_different_operation_while_running_is_refused(runner):
    gate, started = threading.Event(), threading.Event()
    runner.run("analysis_start", "sha", blocking(gate, started), wait_s=SHORT)
    assert started.wait(LONG)
    with pytest.raises(StateViolation) as ei:
        runner.run("vm_snapshot_revert", "MCP_CLEAN", lambda p: None, wait_s=SHORT)
    assert ei.value.hint == "wait for analysis_start; poll session_status"
    assert ei.value.details["op"] == "analysis_start"
    # same op name with another key is a different operation too
    with pytest.raises(StateViolation):
        runner.run("analysis_start", "other-sha", lambda p: None, wait_s=SHORT)
    gate.set()
    runner.wait_idle(LONG)


def test_finished_result_is_delivered_once_to_a_caller_that_got_in_progress(runner):
    gate, started = threading.Event(), threading.Event()
    calls = []

    def fn(progress):
        calls.append(1)
        started.set()
        gate.wait(LONG)
        return {"job_id": "j"}

    rec = runner.run("analysis_start", "sha", fn, wait_s=SHORT)
    assert rec["state"] == "in_progress"
    gate.set()
    runner.wait_idle(LONG)
    # the repeated call picks up the outcome instead of starting again
    assert runner.run("analysis_start", "sha", fn, wait_s=LONG) == {"job_id": "j"}
    assert len(calls) == 1
    # once delivered, the next identical call is a new operation
    gate.set()
    runner.run("analysis_start", "sha", fn, wait_s=LONG)
    assert len(calls) == 2


def test_undelivered_failure_is_reraised_to_the_repeat_caller(runner):
    gate, started = threading.Event(), threading.Event()

    def fn(progress):
        started.set()
        gate.wait(LONG)
        raise StateViolation("nope")

    assert runner.run("vm_power", "start", fn, wait_s=SHORT)["state"] == "in_progress"
    gate.set()
    runner.wait_idle(LONG)
    with pytest.raises(StateViolation):
        runner.run("vm_power", "start", fn, wait_s=LONG)


def test_new_operation_after_completion_is_allowed(runner):
    assert runner.run("a", 1, lambda p: 1, wait_s=LONG) == 1
    assert runner.run("b", 2, lambda p: 2, wait_s=LONG) == 2
    assert runner.current()["op"] == "b"


def test_wait_zero_never_blocks(runner):
    gate = threading.Event()
    rec = runner.run("op", 1, blocking(gate), wait_s=0)
    assert rec["state"] == "in_progress"
    gate.set()
    runner.wait_idle(LONG)


def test_operation_runs_on_a_daemon_thread(runner):
    seen = {}

    def fn(progress):
        t = threading.current_thread()
        seen["daemon"] = t.daemon
        seen["main"] = t is threading.main_thread()
        return None

    runner.run("op", 1, fn, wait_s=LONG)
    assert seen == {"daemon": True, "main": False}


def test_error_details_are_json_ready(runner):
    def fn(progress):
        raise GatewayError("x", details={"a": 1})

    with pytest.raises(GatewayError):
        runner.run("op", 1, fn, wait_s=LONG)
    assert runner.current()["error"]["details"] == {"a": 1}
