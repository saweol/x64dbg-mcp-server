"""Tests for jobs.py: Job model, transition table and the persistent JobStore.

Plan refs: docs/VM_ORCHESTRATION_PLAN.md sections 4.1 (state machine and
invariants), 4.2 (epoch fields) and 4.3 (single controller).
"""

from __future__ import annotations

import itertools
import json
import os
import stat
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.fakes.fake_vm import FakeClock
from x64dbg_vm_gateway.contracts import TERMINAL_JOB_STATES, JobState, SampleInfo
from x64dbg_vm_gateway.errors import LockTimeout, PathNotAllowed, StateViolation
from x64dbg_vm_gateway.jobs import (
    DISCARD_ACTOR,
    DISCARDABLE_STATES,
    JOB_ID_RE,
    TRANSITIONS,
    CorruptJob,
    Job,
    JobNotFound,
    JobStore,
    pid_alive,
    validate_job_id,
)

S = JobState
POSIX = os.name == "posix"
OWN_PID = 4242
GUEST_ROOT = "C:\\mcp\\jobs"

# Shortest legal path from CREATED to every state reachable through transition().
PATH: dict[JobState, list[JobState]] = {
    S.CREATED: [],
    S.PREPARING_VM: [S.PREPARING_VM],
    S.VM_READY: [S.PREPARING_VM, S.VM_READY],
    S.UPLOADING: [S.PREPARING_VM, S.VM_READY, S.UPLOADING],
    S.UPLOADED: [S.PREPARING_VM, S.VM_READY, S.UPLOADING, S.UPLOADED],
    S.LOADING: [S.PREPARING_VM, S.VM_READY, S.UPLOADING, S.UPLOADED, S.LOADING],
    S.ANALYZING: [S.PREPARING_VM, S.VM_READY, S.UPLOADING, S.UPLOADED, S.LOADING, S.ANALYZING],
}
PATH[S.COLLECTING] = [*PATH[S.ANALYZING], S.COLLECTING]
PATH[S.COLLECTED] = [*PATH[S.COLLECTING], S.COLLECTED]
PATH[S.COLLECTED_PARTIAL] = [*PATH[S.COLLECTING], S.COLLECTED_PARTIAL]
PATH[S.REVERTING] = [*PATH[S.COLLECTED], S.REVERTING]
PATH[S.DONE] = [*PATH[S.REVERTING], S.DONE]
PATH[S.FAILED] = [S.FAILED]


def _ids() -> Callable[[], str]:
    n = itertools.count(1)
    return lambda: f"20261123-000000-{next(n):06x}"


def make_store(root: Path, *, pid: int = OWN_PID, alive: Callable[[int], bool] | None = None,
               clock: FakeClock | None = None, id_factory: Callable[[], str] | None = None) -> JobStore:
    return JobStore(
        root,
        clock=clock or FakeClock(),
        id_factory=id_factory or _ids(),
        pid=pid,
        pid_alive=alive or (lambda p: p == pid),
    )


def drive(store: JobStore, job_id: str, target: JobState) -> Job:
    """Move ``job_id`` from CREATED to ``target`` along a legal path."""
    if target == S.DISCARDED:
        drive(store, job_id, S.ANALYZING)
        return store.discard(job_id, DISCARD_ACTOR)
    job = store.get(job_id)
    for st in PATH[target]:
        job = store.transition(job_id, st, reason=f"to {st.value}")
    return job


def mode(p: Path) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def intent_lines(job: Job) -> list[dict]:
    return [json.loads(x) for x in (Path(job.host_root) / "intent.log").read_text().splitlines()]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "jobs"


@pytest.fixture
def store(root: Path):
    s = make_store(root).open()
    yield s
    s.close()


# ── job id ──────────────────────────────────────────────────────────
def test_job_id_regex_accepts_canonical_ids():
    assert JOB_ID_RE.fullmatch("20261123-153012-0a9fbc")
    assert validate_job_id("20261123-153012-0a9fbc") == "20261123-153012-0a9fbc"


BAD_IDS = [
    "../x",
    "..\\x",
    "20261123-000000-abcde",
    "20261123-000000-ABCDEF",
    "20261123-000000-abcdef\n",
    "20261123-000000-abcdef/..",
    "/20261123-000000-abcdef",
    "",
    "x" * 22,
    None,
    123,
]


@pytest.mark.parametrize("bad", BAD_IDS)
def test_validate_job_id_rejects_malformed_ids(bad):
    with pytest.raises(PathNotAllowed):
        validate_job_id(bad)


@pytest.mark.parametrize("bad", BAD_IDS)
def test_invalid_job_ids_are_rejected_by_every_store_entry_point(store, bad):
    calls = [
        lambda: store.get(bad),
        lambda: store.transition(bad, S.FAILED, reason="x"),
        lambda: store.update(bad, epoch=1),
        lambda: store.discard(bad, DISCARD_ACTOR),
        lambda: store.job_dir(bad),
    ]
    for call in calls:
        with pytest.raises(PathNotAllowed):
            call()


# ── Job model ───────────────────────────────────────────────────────
def _sample_job() -> Job:
    return Job(
        id="20261123-153012-0a9fbc",
        profile="win10",
        state=S.ANALYZING,
        created_at="2026-11-23T15:30:12+00:00",
        updated_at="2026-11-23T15:31:00+00:00",
        guest_root="C:\\mcp\\jobs\\20261123-153012-0a9fbc",
        host_root="/tmp/jobs/20261123-153012-0a9fbc",
        sample=SampleInfo(host_path="/s/a.exe", sha256="ab" * 32, size=10, kind="exe", arch="x64",
                          guest_path="C:\\mcp\\jobs\\x\\in\\abababababab.exe", original_name="a.exe"),
        backend_id="x64",
        epoch=2,
        restarts=1,
        history=[{"from": "LOADING", "to": "ANALYZING", "at": "2026-11-23T15:31:00+00:00", "reason": "r"}],
        manifest_path="/tmp/jobs/x/manifest.json",
        flags={"k": [1, 2]},
        error=None,
    )


def test_job_json_roundtrip_dict_and_text():
    job = _sample_job()
    data = job.to_json()
    json.dumps(data, allow_nan=False)  # must be plain JSON
    assert data["state"] == "ANALYZING"
    assert data["sample"]["sha256"] == "ab" * 32
    assert Job.from_json(data) == job
    assert Job.from_json(json.dumps(data)) == job


def test_job_to_json_is_a_deep_copy():
    job = _sample_job()
    data = job.to_json()
    data["flags"]["k"].append(3)
    data["history"][0]["reason"] = "changed"
    assert job.flags == {"k": [1, 2]} and job.history[0]["reason"] == "r"


def test_job_defaults_and_terminal_property():
    job = Job(id="20261123-153012-0a9fbc", profile="p", state=S.DONE, created_at="t", updated_at="t",
              guest_root="g", host_root="h")
    assert job.sample is None and job.backend_id is None and job.epoch == 0 and job.restarts == 0
    assert job.history == [] and job.flags == {} and job.error is None and job.manifest_path is None
    assert job.terminal
    assert not Job.from_json({**job.to_json(), "state": "ANALYZING"}).terminal


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("id"),
        lambda d: d.pop("state"),
        lambda d: d.update(state="BOGUS"),
        lambda d: d.update(id="../../etc"),
        lambda d: d.update(epoch="1"),
        lambda d: d.update(epoch=True),
        lambda d: d.update(restarts=-1),
        lambda d: d.update(history={}),
        lambda d: d.update(flags=[]),
        lambda d: d.update(error="boom"),
        lambda d: d.update(sample={"host_path": "x"}),
        lambda d: d.update(profile=7),
    ],
)
def test_job_from_json_rejects_malformed_documents(mutate):
    data = _sample_job().to_json()
    mutate(data)
    with pytest.raises(ValueError):
        Job.from_json(data)


def test_job_from_json_rejects_non_object():
    with pytest.raises(ValueError):
        Job.from_json("[1, 2]")
    with pytest.raises(ValueError):
        Job.from_json("{not json")


# ── transition table (plan 4.1) ─────────────────────────────────────
EXPECTED_TRANSITIONS = {
    S.CREATED: {S.PREPARING_VM, S.FAILED},
    S.PREPARING_VM: {S.VM_READY, S.FAILED},
    S.VM_READY: {S.UPLOADING, S.FAILED},
    S.UPLOADING: {S.UPLOADED, S.UPLOADING, S.FAILED},
    S.UPLOADED: {S.LOADING, S.FAILED},
    S.LOADING: {S.ANALYZING, S.FAILED},
    S.ANALYZING: {S.ANALYZING, S.COLLECTING, S.FAILED},
    S.COLLECTING: {S.COLLECTED, S.COLLECTED_PARTIAL, S.FAILED},
    S.COLLECTED: {S.REVERTING, S.ANALYZING, S.FAILED},
    S.COLLECTED_PARTIAL: {S.COLLECTING, S.FAILED},
    S.DISCARDED: {S.REVERTING, S.FAILED},
    S.REVERTING: {S.DONE, S.FAILED},
    S.DONE: set(),
    S.FAILED: set(),
}


def test_transition_table_matches_plan_exactly():
    assert {k: set(v) for k, v in TRANSITIONS.items()} == EXPECTED_TRANSITIONS


def test_every_nonterminal_state_can_fail_and_terminal_states_are_final():
    for st in S:
        if st in TERMINAL_JOB_STATES:
            assert not TRANSITIONS[st]
        else:
            assert S.FAILED in TRANSITIONS[st]


def test_invariant_reverting_only_from_collected_or_discarded():
    sources = {st for st, targets in TRANSITIONS.items() if S.REVERTING in targets}
    assert sources == {S.COLLECTED, S.DISCARDED}


def test_invariant_discarded_is_never_a_transition_target():
    assert all(S.DISCARDED not in targets for targets in TRANSITIONS.values())


def test_transition_table_is_immutable():
    with pytest.raises(TypeError):
        TRANSITIONS[S.CREATED] = frozenset({S.DONE})  # type: ignore[index]


# ── create / get / list / active ────────────────────────────────────
def test_create_builds_job_and_private_host_dirs(store, root):
    job = store.create("win10", GUEST_ROOT)
    assert JOB_ID_RE.fullmatch(job.id)
    assert job.state == S.CREATED and job.profile == "win10" and job.history == []
    assert job.guest_root == f"{GUEST_ROOT}\\{job.id}"
    jd = root.resolve() / job.id
    assert job.host_root == str(jd) and store.job_dir(job.id) == jd
    for sub in ("input", "artifacts", "logs"):
        assert (jd / sub).is_dir()
    on_disk = json.loads((jd / "state.json").read_text())
    assert on_disk["id"] == job.id and on_disk["state"] == "CREATED"
    assert intent_lines(job)[-1]["op"] == "create"
    assert job.created_at == job.updated_at == FakeClock().now_iso()


@pytest.mark.skipif(not POSIX or os.geteuid() == 0, reason="POSIX permission bits (root ignores them)")
def test_create_uses_owner_only_permissions_even_with_odd_umask(root):
    old = os.umask(0o277)  # strips owner write: mkdir/open modes alone would be too narrow
    try:
        s = make_store(root).open()
        job = s.create("win10", GUEST_ROOT)
        s.transition(job.id, S.PREPARING_VM, reason="r")
        s.close()
        s.open()  # reopen: lock/guard files must still be usable
        s.close()
    finally:
        os.umask(old)
    jd = Path(job.host_root)
    for d in (root, jd, jd / "input", jd / "artifacts", jd / "logs"):
        assert mode(d) == 0o700, d
    assert mode(jd / "state.json") == 0o600
    assert mode(jd / "intent.log") == 0o600
    assert mode(root / ".lock.guard") == 0o600


def test_create_strips_trailing_backslash_from_guest_root(store):
    job = store.create("win10", "C:\\mcp\\jobs\\")
    assert job.guest_root == f"C:\\mcp\\jobs\\{job.id}"


def test_create_default_ids_come_from_clock_plus_random_hex(root):
    s = JobStore(root, clock=FakeClock(), pid=OWN_PID, pid_alive=lambda p: p == OWN_PID).open()
    a = s.create("a", GUEST_ROOT)
    b = s.create("b", GUEST_ROOT)
    for j in (a, b):
        assert JOB_ID_RE.fullmatch(j.id)
        assert j.id.startswith("20261123-000040-")  # FakeClock(1000) -> second 40
    assert a.id != b.id
    s.close()


def test_create_refuses_second_active_job_for_same_profile(store):
    first = store.create("win10", GUEST_ROOT)
    with pytest.raises(StateViolation) as ei:
        store.create("win10", GUEST_ROOT)
    assert ei.value.details["job_id"] == first.id
    assert ei.value.details["state"] == "CREATED"
    # other profiles are independent
    store.create("other", GUEST_ROOT)


@pytest.mark.parametrize("final", [S.DONE, S.FAILED])
def test_create_allowed_again_after_previous_job_is_terminal(store, final):
    first = store.create("win10", GUEST_ROOT)
    drive(store, first.id, final)
    second = store.create("win10", GUEST_ROOT)
    assert second.id != first.id


def test_discarded_job_still_blocks_its_profile(store):
    first = store.create("win10", GUEST_ROOT)
    drive(store, first.id, S.DISCARDED)
    with pytest.raises(StateViolation):
        store.create("win10", GUEST_ROOT)


def test_create_rejects_invalid_id_from_factory(root):
    s = make_store(root, id_factory=lambda: "../../evil").open()
    with pytest.raises(PathNotAllowed):
        s.create("win10", GUEST_ROOT)
    assert [p.name for p in root.iterdir() if not p.name.startswith(".")] == []
    s.close()


def test_create_refuses_when_id_cannot_be_made_unique(root):
    s = make_store(root, id_factory=lambda: "20261123-000000-aaaaaa").open()
    s.create("a", GUEST_ROOT)
    with pytest.raises(StateViolation):
        s.create("b", GUEST_ROOT)
    s.close()


@pytest.mark.parametrize("profile", ["", None, 5])
def test_create_rejects_bad_profile_name(store, profile):
    with pytest.raises(ValueError):
        store.create(profile, GUEST_ROOT)


def test_get_unknown_job_raises_job_not_found(store):
    with pytest.raises(JobNotFound) as ei:
        store.get("20261123-000000-ffffff")
    assert isinstance(ei.value, StateViolation)
    assert ei.value.details["job_id"] == "20261123-000000-ffffff"


def test_get_returns_independent_copies(store):
    job = store.create("win10", GUEST_ROOT)
    copy = store.get(job.id)
    copy.flags["x"] = 1
    copy.history.append({"bogus": True})
    copy.state = S.DONE
    fresh = store.get(job.id)
    assert fresh.flags == {} and fresh.history == [] and fresh.state == S.CREATED


def test_list_filters_by_profile_and_orders_by_id(store):
    a = store.create("p1", GUEST_ROOT)
    b = store.create("p2", GUEST_ROOT)
    drive(store, a.id, S.DONE)
    c = store.create("p1", GUEST_ROOT)
    assert [j.id for j in store.list()] == [a.id, b.id, c.id]
    assert [j.id for j in store.list("p1")] == [a.id, c.id]
    assert store.list("nobody") == []


def test_active_returns_nonterminal_job_for_profile(store):
    assert store.active("win10") is None
    a = store.create("win10", GUEST_ROOT)
    assert store.active("win10").id == a.id
    assert store.active("other") is None
    drive(store, a.id, S.FAILED)
    assert store.active("win10") is None


# ── transition ──────────────────────────────────────────────────────
def test_full_happy_path_records_history(store):
    job = store.create("win10", GUEST_ROOT)
    job = drive(store, job.id, S.DONE)
    assert job.state == S.DONE and job.terminal
    assert [h["to"] for h in job.history] == [s.value for s in PATH[S.DONE]]
    assert job.history[0] == {"from": "CREATED", "to": "PREPARING_VM",
                              "at": FakeClock().now_iso(), "reason": "to PREPARING_VM"}


@pytest.mark.parametrize(
    ("start", "to"),
    [
        (S.ANALYZING, S.ANALYZING),
        (S.UPLOADING, S.UPLOADING),
        (S.COLLECTED, S.ANALYZING),
        (S.COLLECTED_PARTIAL, S.COLLECTING),
        (S.COLLECTING, S.COLLECTED_PARTIAL),
        (S.DISCARDED, S.REVERTING),
    ],
)
def test_special_edges_are_allowed(store, start, to):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, start)
    assert store.transition(job.id, to, reason="edge").state == to


@pytest.mark.parametrize("start", [s for s in S if s not in TERMINAL_JOB_STATES])
def test_any_nonterminal_state_can_fail(store, start):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, start)
    failed = store.transition(job.id, S.FAILED, reason="boom", error={"code": "X"})
    assert failed.state == S.FAILED and failed.error == {"code": "X"}


def _illegal_pairs() -> list[tuple[JobState, JobState]]:
    pairs = []
    for src in S:
        for dst in S:
            if dst not in TRANSITIONS[src] and dst != S.DISCARDED:
                pairs.append((src, dst))
    return pairs


@pytest.mark.parametrize(("src", "dst"), _illegal_pairs())
def test_illegal_transitions_are_refused_and_nothing_is_written(store, src, dst):
    job = store.create("win10", GUEST_ROOT)
    before = drive(store, job.id, src)
    state_file = Path(job.host_root) / "state.json"
    disk_before = state_file.read_bytes()
    n_intents = len(intent_lines(job))
    with pytest.raises(StateViolation) as ei:
        store.transition(job.id, dst, reason="nope")
    assert ei.value.details["job_id"] == job.id
    assert ei.value.details["state"] == src.value
    assert ei.value.details["to"] == dst.value
    assert store.get(job.id) == before
    assert state_file.read_bytes() == disk_before
    assert len(intent_lines(job)) == n_intents


@pytest.mark.parametrize("start", [S.ANALYZING, S.CREATED, S.COLLECTED_PARTIAL])
def test_transition_to_discarded_is_refused(store, start):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, start)
    with pytest.raises(StateViolation) as ei:
        store.transition(job.id, S.DISCARDED, reason="ai wants to skip collect")
    assert "discard" in ei.value.message  # points the AI at the human-only CLI path
    assert store.get(job.id).state == start


def test_transition_accepts_state_value_strings(store):
    job = store.create("win10", GUEST_ROOT)
    assert store.transition(job.id, "PREPARING_VM", reason="r", expect_from="CREATED").state == S.PREPARING_VM
    with pytest.raises(ValueError):
        store.transition(job.id, "NOT_A_STATE", reason="r")


def test_expect_from_single_state(store):
    job = store.create("win10", GUEST_ROOT)
    with pytest.raises(StateViolation) as ei:
        store.transition(job.id, S.FAILED, reason="r", expect_from=S.ANALYZING)
    assert ei.value.details["state"] == "CREATED"
    assert ei.value.details["expected"] == ["ANALYZING"]
    assert store.get(job.id).state == S.CREATED
    assert store.transition(job.id, S.FAILED, reason="r", expect_from=S.CREATED).state == S.FAILED


def test_expect_from_iterable(store):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, S.COLLECTED)
    got = store.transition(job.id, S.REVERTING, reason="finish",
                           expect_from=[S.COLLECTED, S.DISCARDED])
    assert got.state == S.REVERTING
    with pytest.raises(StateViolation):
        store.transition(job.id, S.DONE, reason="r", expect_from={S.COLLECTED})


def test_transition_applies_field_updates(store):
    job = store.create("win10", GUEST_ROOT)
    sample = SampleInfo(host_path="/s/a.exe", sha256="cd" * 32, size=3, kind="exe", arch="x32")
    got = store.transition(job.id, S.PREPARING_VM, reason="r", sample=sample, backend_id="x32",
                           epoch=1, restarts=0, flags={"a": 1}, manifest_path="/m.json")
    assert got.sample == sample and got.backend_id == "x32" and got.epoch == 1
    assert got.flags == {"a": 1} and got.manifest_path == "/m.json"
    assert store.get(job.id) == got


def test_transition_accepts_sample_as_mapping(store):
    job = store.create("win10", GUEST_ROOT)
    got = store.transition(job.id, S.PREPARING_VM, reason="r",
                           sample={"host_path": "/a", "sha256": "e" * 64, "size": 1, "kind": "dll",
                                   "arch": "x64"})
    assert isinstance(got.sample, SampleInfo) and got.sample.kind == "dll"


@pytest.mark.parametrize("field_name",
                         ["state", "history", "id", "created_at", "updated_at", "profile",
                          "host_root", "guest_root", "bogus"])
def test_transition_rejects_protected_or_unknown_fields(store, field_name):
    job = store.create("win10", GUEST_ROOT)
    with pytest.raises(TypeError):
        store.transition(job.id, S.PREPARING_VM, reason="r", **{field_name: "x"})
    assert store.get(job.id).state == S.CREATED


def test_transition_on_terminal_job_is_refused(store):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, S.DONE)
    with pytest.raises(StateViolation):
        store.transition(job.id, S.FAILED, reason="late")


def test_transition_requires_reason(store):
    job = store.create("win10", GUEST_ROOT)
    with pytest.raises(TypeError):
        store.transition(job.id, S.PREPARING_VM)  # type: ignore[call-arg]


def test_returned_job_is_a_copy(store):
    job = store.create("win10", GUEST_ROOT)
    got = store.transition(job.id, S.PREPARING_VM, reason="r")
    got.history.clear()
    assert len(store.get(job.id).history) == 1


# ── discard (human only) ────────────────────────────────────────────
def test_discardable_states_are_all_live_states_except_reverting():
    live = {s for s in S if s not in TERMINAL_JOB_STATES}
    assert set(DISCARDABLE_STATES) == live - {S.REVERTING, S.DISCARDED}
    assert S.ANALYZING in DISCARDABLE_STATES


@pytest.mark.parametrize("actor", ["mcp", "ai", "HUMAN-CLI", "human-cli ", "", "gateway", None])
def test_discard_by_non_human_actor_is_refused(store, actor):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, S.ANALYZING)
    with pytest.raises(StateViolation) as ei:
        store.discard(job.id, actor)
    assert ei.value.details["job_id"] == job.id
    assert store.get(job.id).state == S.ANALYZING


def test_discard_by_human_then_revert_then_done(store):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, S.ANALYZING)
    got = store.discard(job.id, "human-cli", reason="sample is junk")
    assert got.state == S.DISCARDED
    assert got.history[-1]["from"] == "ANALYZING" and got.history[-1]["to"] == "DISCARDED"
    assert got.history[-1]["actor"] == "human-cli" and got.history[-1]["reason"] == "sample is junk"
    store.transition(job.id, S.REVERTING, reason="revert", expect_from=S.DISCARDED)
    assert store.transition(job.id, S.DONE, reason="clean").state == S.DONE


@pytest.mark.parametrize("start", sorted(DISCARDABLE_STATES, key=lambda s: s.value))
def test_discard_allowed_from_every_discardable_state(store, start):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, start)
    assert store.discard(job.id, DISCARD_ACTOR).state == S.DISCARDED


@pytest.mark.parametrize("start", [S.REVERTING, S.DISCARDED, S.DONE, S.FAILED])
def test_discard_refused_from_reverting_discarded_and_terminal(store, start):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, start)
    with pytest.raises(StateViolation):
        store.discard(job.id, DISCARD_ACTOR)
    assert store.get(job.id).state == start


# ── update ──────────────────────────────────────────────────────────
def test_update_sets_non_state_fields_and_persists(root):
    s = make_store(root).open()
    job = s.create("win10", GUEST_ROOT)
    got = s.update(job.id, epoch=3, restarts=2, backend_id="x64", flags={"needs": "x"},
                   error={"code": "E"}, manifest_path="/m")
    assert (got.epoch, got.restarts, got.backend_id) == (3, 2, "x64")
    assert got.state == S.CREATED and got.history == []
    assert intent_lines(job)[-1]["op"] == "update"
    assert sorted(intent_lines(job)[-1]["fields"]) == sorted(
        ["epoch", "restarts", "backend_id", "flags", "error", "manifest_path"])
    s.close()
    s2 = make_store(root).open()
    assert s2.get(job.id) == got
    s2.close()


@pytest.mark.parametrize("field_name",
                         ["state", "history", "id", "created_at", "updated_at", "profile",
                          "host_root", "guest_root", "bogus"])
def test_update_rejects_state_bookkeeping_and_unknown_fields(store, field_name):
    job = store.create("win10", GUEST_ROOT)
    with pytest.raises(TypeError):
        store.update(job.id, **{field_name: "DONE"})
    assert store.get(job.id).state == S.CREATED


@pytest.mark.parametrize("bad", [{"x": object()}, {"x": float("nan")}])
def test_update_with_non_json_value_writes_nothing(store, bad):
    job = store.create("win10", GUEST_ROOT)
    n = len(intent_lines(job))
    with pytest.raises((TypeError, ValueError)):
        store.update(job.id, flags=bad)
    assert len(intent_lines(job)) == n
    assert store.get(job.id).flags == {}


@pytest.mark.parametrize(("field_name", "value"),
                         [("epoch", "1"), ("epoch", -1), ("epoch", True), ("restarts", 1.5),
                          ("flags", []), ("error", "x"), ("backend_id", 3), ("manifest_path", 3)])
def test_update_type_checks_fields(store, field_name, value):
    job = store.create("win10", GUEST_ROOT)
    with pytest.raises((TypeError, ValueError)):
        store.update(job.id, **{field_name: value})


def test_update_works_on_terminal_job_for_bookkeeping(store):
    job = store.create("win10", GUEST_ROOT)
    drive(store, job.id, S.DONE)
    assert store.update(job.id, manifest_path="/late").manifest_path == "/late"


# ── persistence protocol ────────────────────────────────────────────
def test_state_survives_reopen(root):
    s = make_store(root).open()
    job = drive(s, s.create("win10", GUEST_ROOT).id, S.COLLECTED)
    s.close()
    s2 = make_store(root).open()
    assert s2.get(job.id) == job
    assert s2.active("win10").id == job.id
    s2.close()


def test_intent_is_appended_and_synced_before_state_is_replaced(store, monkeypatch):
    job = store.create("win10", GUEST_ROOT)
    jd = Path(job.host_root)
    real_replace = os.replace
    seen: list[dict] = []

    def spy(src, dst, *a, **kw):
        if Path(dst).name == "state.json":
            seen.append(json.loads((jd / "intent.log").read_text().splitlines()[-1]))
            # the replacement must come from a fully written temp file in the same dir
            assert Path(src).parent == jd
            json.loads(Path(src).read_text())
        return real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", spy)
    store.transition(job.id, S.PREPARING_VM, reason="revert clean")
    assert seen and seen[-1]["op"] == "transition"
    assert seen[-1]["from"] == "CREATED" and seen[-1]["to"] == "PREPARING_VM"
    assert seen[-1]["reason"] == "revert clean"


def test_fsync_is_called_for_intent_and_state(store, monkeypatch):
    job = store.create("win10", GUEST_ROOT)
    calls: list[int] = []
    real_fsync = os.fsync

    def spy(fd):
        calls.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    store.transition(job.id, S.PREPARING_VM, reason="r")
    # intent file + temp state file (+ directory on POSIX)
    assert len(calls) >= (3 if POSIX else 2)


def test_failed_state_write_keeps_previous_state_everywhere(root, monkeypatch):
    s = make_store(root).open()
    job = s.create("win10", GUEST_ROOT)
    jd = Path(job.host_root)

    def boom(src, dst, *a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        s.transition(job.id, S.PREPARING_VM, reason="r")
    monkeypatch.undo()
    assert s.get(job.id).state == S.CREATED
    assert json.loads((jd / "state.json").read_text())["state"] == "CREATED"
    assert not [p.name for p in jd.iterdir() if p.name.endswith(".tmp")]
    # the store keeps working after the failure
    assert s.transition(job.id, S.PREPARING_VM, reason="retry").state == S.PREPARING_VM
    s.close()


def test_recover_scan_reports_interrupted_transition(root, monkeypatch):
    s = make_store(root).open()
    job = s.create("win10", GUEST_ROOT)
    drive(s, job.id, S.ANALYZING)

    def boom(src, dst, *a, **kw):
        raise OSError("power loss")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        s.transition(job.id, S.COLLECTING, reason="collect")
    monkeypatch.undo()
    s.close()
    s2 = make_store(root).open()
    [rec] = s2.recover_scan()
    assert rec.state == S.ANALYZING
    assert rec.flags["needs_recovery"] is True
    interrupted = rec.flags["interrupted_transition"]
    assert interrupted["from"] == "ANALYZING" and interrupted["to"] == "COLLECTING"
    s2.close()


def test_completed_transition_is_not_reported_as_interrupted(root):
    s = make_store(root).open()
    job = drive(s, s.create("win10", GUEST_ROOT).id, S.ANALYZING)
    s.transition(job.id, S.ANALYZING, reason="debugger restart", epoch=1)
    s.close()
    s2 = make_store(root).open()
    [rec] = s2.recover_scan()
    assert "interrupted_transition" not in rec.flags
    s2.close()


# ── recovery scan ───────────────────────────────────────────────────
def test_recover_scan_flags_nonterminal_jobs_without_changing_state(root):
    s = make_store(root).open()
    a = drive(s, s.create("p1", GUEST_ROOT).id, S.ANALYZING)
    b = drive(s, s.create("p2", GUEST_ROOT).id, S.DONE)
    c = s.create("p3", GUEST_ROOT)
    d = drive(s, s.create("p4", GUEST_ROOT).id, S.DISCARDED)
    s.close()

    s2 = make_store(root).open()
    out = s2.recover_scan()
    assert all(isinstance(r, Job) for r in out)
    assert {j.id for j in out} == {a.id, c.id, d.id}
    for j in out:
        assert j.flags["needs_recovery"] is True
    assert s2.get(a.id).state == S.ANALYZING and s2.get(d.id).state == S.DISCARDED
    assert len(s2.get(a.id).history) == len(a.history)
    s2.close()

    s3 = make_store(root).open()
    assert s3.get(a.id).flags["needs_recovery"] is True
    assert "needs_recovery" not in s3.get(b.id).flags
    s3.close()


def test_recover_scan_on_empty_root(store):
    assert store.recover_scan() == []


def test_recover_scan_ignores_foreign_entries(store, root):
    (root / "notes").mkdir()
    (root / "README.txt").write_text("x")
    (root / "20261123-000000-ABCDEF").mkdir()
    job = store.create("win10", GUEST_ROOT)
    assert [r.id for r in store.recover_scan()] == [job.id]


@pytest.mark.parametrize(
    "content",
    [
        b"{not json",
        b"",
        b"[1,2]",
        b'{"id": "20261123-000000-000001"}',
        b"\xff\xfe garbage",
    ],
)
def test_corrupt_state_is_renamed_and_reported_without_crashing(root, content):
    s = make_store(root).open()
    good = s.create("a", GUEST_ROOT)
    bad = s.create("b", GUEST_ROOT)
    s.close()
    jd = Path(bad.host_root)
    (jd / "state.json").write_bytes(content)

    s2 = make_store(root).open()  # must not crash
    with pytest.raises(JobNotFound):
        s2.get(bad.id)
    out = s2.recover_scan()
    corrupt = [r for r in out if isinstance(r, CorruptJob)]
    jobs = [r for r in out if isinstance(r, Job)]
    assert [c.job_id for c in corrupt] == [bad.id]
    assert [j.id for j in jobs] == [good.id]
    assert corrupt[0].reason
    assert (jd / "state.json.corrupt-1").read_bytes() == content
    assert not (jd / "state.json").exists()
    assert str(jd / "state.json.corrupt-1") in corrupt[0].corrupt_files
    # a later scan still reports the job (no valid state.json) without renaming again
    again = [r for r in s2.recover_scan() if isinstance(r, CorruptJob)]
    assert [c.job_id for c in again] == [bad.id]
    assert sorted(p.name for p in jd.iterdir() if p.name.startswith("state.json")) == [
        "state.json.corrupt-1"]
    s2.close()


def test_repeated_corruption_uses_next_free_suffix(root):
    s = make_store(root).open()
    bad = s.create("b", GUEST_ROOT)
    jd = Path(bad.host_root)
    (jd / "state.json").write_text("nope")
    s.recover_scan()
    (jd / "state.json").write_text("nope again")
    [rec] = s.recover_scan()
    assert isinstance(rec, CorruptJob)
    assert (jd / "state.json.corrupt-1").read_text() == "nope"
    assert (jd / "state.json.corrupt-2").read_text() == "nope again"
    assert len(rec.corrupt_files) == 2
    s.close()


def test_state_with_mismatched_id_is_corrupt(root):
    s = make_store(root).open()
    a = s.create("a", GUEST_ROOT)
    b = s.create("b", GUEST_ROOT)
    s.close()
    # copy a's state into b's directory: the id no longer matches the directory name
    (Path(b.host_root) / "state.json").write_bytes((Path(a.host_root) / "state.json").read_bytes())
    s2 = make_store(root).open()
    out = s2.recover_scan()
    assert [r.job_id for r in out if isinstance(r, CorruptJob)] == [b.id]
    s2.close()


def test_job_dir_without_state_is_reported_as_corrupt(store, root):
    jd = root / "20261123-000000-0000aa"
    jd.mkdir()
    [rec] = store.recover_scan()
    assert isinstance(rec, CorruptJob) and rec.job_id == "20261123-000000-0000aa"
    assert rec.corrupt_files == ()


def test_corrupt_job_record_is_json_serialisable(store, root):
    jd = root / "20261123-000000-0000aa"
    jd.mkdir()
    (jd / "state.json").write_text("{")
    [rec] = store.recover_scan()
    data = json.loads(json.dumps(rec.to_json()))
    assert data["job_id"] == "20261123-000000-0000aa" and data["corrupt"] is True


def test_host_root_follows_the_actual_directory(root, tmp_path):
    s = make_store(root).open()
    job = s.create("win10", GUEST_ROOT)
    s.close()
    moved = tmp_path / "moved"
    root.rename(moved)
    s2 = make_store(moved).open()
    assert s2.get(job.id).host_root == str(moved.resolve() / job.id)
    s2.close()


# ── thread safety ───────────────────────────────────────────────────
def test_concurrent_transitions_are_serialized(store):
    job = drive(store, store.create("win10", GUEST_ROOT).id, S.ANALYZING)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            for _ in range(20):
                store.transition(job.id, S.ANALYZING, reason="tick", expect_from=S.ANALYZING)
        except BaseException as e:  # noqa: BLE001 - collected for the assertion below
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors
    expected = len(PATH[S.ANALYZING]) + 160
    assert len(store.get(job.id).history) == expected
    on_disk = json.loads((Path(job.host_root) / "state.json").read_text())
    assert len(on_disk["history"]) == expected


def test_concurrent_create_for_same_profile_yields_one_job(store):
    barrier = threading.Barrier(8)
    made: list[Job] = []
    refused: list[StateViolation] = []

    def worker() -> None:
        barrier.wait(timeout=10)
        try:
            made.append(store.create("win10", GUEST_ROOT))
        except StateViolation as e:
            refused.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(made) == 1 and len(refused) == 7
    assert [j.id for j in store.list("win10")] == [made[0].id]


# ── process lock ────────────────────────────────────────────────────
def test_store_must_be_opened_before_use(root):
    s = make_store(root)
    with pytest.raises(RuntimeError):
        s.create("win10", GUEST_ROOT)
    with pytest.raises(RuntimeError):
        s.list()


def test_context_manager_opens_and_releases_lock(root):
    with make_store(root) as s:
        assert (root / ".lock").exists()
        s.create("win10", GUEST_ROOT)
    assert not (root / ".lock").exists()
    with pytest.raises(RuntimeError):
        s.list()


def test_lock_file_records_owner_pid(store, root):
    data = json.loads((root / ".lock").read_text())
    assert data["pid"] == OWN_PID


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits")
def test_root_and_lock_are_private(store, root):
    assert mode(root) == 0o700
    assert mode(root / ".lock") == 0o600


def test_second_store_is_refused_while_owner_is_alive(root):
    a = make_store(root, pid=111).open()
    b = make_store(root, pid=222, alive=lambda p: p in (111, 222))
    with pytest.raises(LockTimeout) as ei:
        b.open()
    assert ei.value.details["owner_pid"] == 111
    a.close()
    b.open()
    assert json.loads((root / ".lock").read_text())["pid"] == 222
    b.close()


def test_open_waits_up_to_timeout_using_clock(root):
    clock = FakeClock()
    a = make_store(root, pid=111).open()
    b = make_store(root, pid=222, alive=lambda p: p in (111, 222), clock=clock)
    with pytest.raises(LockTimeout):
        b.open(timeout_s=3.0)
    assert clock.sleeps and sum(clock.sleeps) >= 3.0
    a.close()


def test_stale_lock_from_dead_pid_is_reclaimed(root):
    crashed = make_store(root, pid=111).open()
    crashed.create("win10", GUEST_ROOT)
    # pid 111 "died" without close(); pid 222 sees it as not alive
    b = make_store(root, pid=222, alive=lambda p: p == 222).open()
    assert json.loads((root / ".lock").read_text())["pid"] == 222
    assert b.active("win10") is not None
    # the crashed instance must not remove the lock it no longer owns
    crashed.close()
    assert json.loads((root / ".lock").read_text())["pid"] == 222
    b.close()
    assert not (root / ".lock").exists()


@pytest.mark.parametrize("content", ["", "garbage", "{}", '{"pid": "x"}'])
def test_unreadable_lock_is_treated_as_stale(root, content):
    root.mkdir(parents=True)
    (root / ".lock").write_text(content)
    s = make_store(root).open()
    assert json.loads((root / ".lock").read_text())["pid"] == OWN_PID
    s.close()


def test_lock_from_other_host_is_never_reclaimed(root):
    root.mkdir(parents=True)
    (root / ".lock").write_text(json.dumps({"pid": 1, "host": "some-other-host", "nonce": "x"}))
    with pytest.raises(LockTimeout) as ei:
        make_store(root, alive=lambda p: False).open()
    assert ei.value.details["owner_host"] == "some-other-host"


def test_open_is_idempotent_and_close_is_idempotent(root):
    s = make_store(root)
    assert s.open() is s
    assert s.open() is s
    s.close()
    s.close()
    assert not (root / ".lock").exists()


def test_lock_excludes_a_real_second_process_and_stale_lock_is_reclaimed(root, tmp_path):
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from x64dbg_vm_gateway.errors import LockTimeout\n"
        "from x64dbg_vm_gateway.jobs import JobStore\n"
        "try:\n"
        "    JobStore(Path(sys.argv[1])).open()\n"
        "except LockTimeout:\n"
        "    sys.exit(3)\n"
        "sys.exit(0)\n"  # exits WITHOUT close(): leaves a stale lock behind
    )

    def child() -> subprocess.CompletedProcess[bytes]:
        return subprocess.run([sys.executable, "-c", code, str(root)], cwd=tmp_path,
                              capture_output=True, timeout=60, check=False)

    s = JobStore(root).open()  # real pid, real liveness check
    r = child()
    assert r.returncode == 3, r.stderr
    s.close()
    r = child()
    assert r.returncode == 0, r.stderr
    assert (root / ".lock").exists()  # child died holding the lock
    s2 = JobStore(root).open()  # dead child's lock is reclaimed
    assert json.loads((root / ".lock").read_text())["pid"] == os.getpid()
    s2.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="uses /proc process start times")
def test_lock_with_reused_pid_is_reclaimed(root):
    import socket

    root.mkdir(parents=True)
    # our own (live) pid, but recorded by an earlier process that had another start time
    (root / ".lock").write_text(json.dumps({"pid": os.getpid(), "host": socket.gethostname(),
                                            "nonce": "old", "start": "other-boot:1"}))
    s = JobStore(root).open()
    assert json.loads((root / ".lock").read_text())["nonce"] != "old"
    s.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="uses /proc process start times")
def test_second_store_in_same_live_process_is_refused(root):
    a = JobStore(root).open()
    with pytest.raises(LockTimeout):
        JobStore(root).open()
    a.close()


def test_failed_lock_write_leaves_no_lock_behind(root, monkeypatch):
    s = make_store(root)

    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError):
        s.open()
    monkeypatch.undo()
    assert not (root / ".lock").exists()
    s.open()
    s.close()


def test_update_without_fields_writes_nothing(store):
    job = store.create("win10", GUEST_ROOT)
    n = len(intent_lines(job))
    assert store.update(job.id) == job
    assert len(intent_lines(job)) == n


def test_unknown_job_is_refused_by_mutators(store):
    for call in (lambda: store.transition("20261123-000000-ffffff", S.FAILED, reason="x"),
                 lambda: store.update("20261123-000000-ffffff", epoch=1),
                 lambda: store.discard("20261123-000000-ffffff", DISCARD_ACTOR)):
        with pytest.raises(JobNotFound):
            call()


def test_pid_alive_default_implementation():
    assert pid_alive(os.getpid())
    assert not pid_alive(0)
    assert not pid_alive(-1)
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait(timeout=30)
    assert not pid_alive(p.pid)
