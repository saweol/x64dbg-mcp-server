"""Tests for policy.py: risk tiers, VM-op invariants, snapshot protection and
retention, the isolation gate and the host path allowlist.

Plan refs: docs/VM_ORCHESTRATION_PLAN.md sections 4.1 (invariants), 5.3 (path
limits), 5.6 (tool risk tiers), 5.7 (clean snapshot contract, retention) and 9.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from x64dbg_vm_gateway.config import ProfileConfig, RetentionConfig
from x64dbg_vm_gateway.contracts import TERMINAL_JOB_STATES, IsolationReport, JobState
from x64dbg_vm_gateway.errors import (
    IsolationRequired,
    PathNotAllowed,
    ProtectedSnapshotError,
    StateViolation,
)
from x64dbg_vm_gateway.jobs import Job
from x64dbg_vm_gateway.policy import (
    GATEWAY_TOOL_TIERS,
    VM_BUSY_STATES,
    VM_OPS,
    RiskTier,
    assert_revert_for_job,
    assert_vm_op_allowed,
    check_snapshot_delete,
    gateway_snapshot_name,
    host_path_allowed,
    isolation_gate,
    retention_plan,
    tier_for_mirror,
    tier_of,
)

S = JobState
JID = "20261123-153012-0a9fbc"


def job_in(state: JobState, job_id: str = JID) -> Job:
    return Job(id=job_id, profile="win10", state=state, created_at="t", updated_at="t",
               guest_root=f"C:\\mcp\\jobs\\{job_id}", host_root=f"/tmp/{job_id}")


def profile(**kw) -> ProfileConfig:
    base = {
        "name": "win10",
        "clean_snapshot": "MCP_CLEAN",
        "protected_snapshots": ("MCP_CLEAN", "MCP_BASE", "remote_base"),
        "snapshot_prefix": "gw-",
    }
    base.update(kw)
    return ProfileConfig(**base)


# ── risk tiers (plan 5.6) ───────────────────────────────────────────
def test_gateway_tool_tiers_match_plan():
    expected = {
        "session_status": RiskTier.OBSERVE,
        "gateway_doctor": RiskTier.OBSERVE,
        "vm_snapshots_list": RiskTier.OBSERVE,
        "vm_screenshot": RiskTier.OBSERVE,
        "file_upload": RiskTier.GUEST_MUTATE,
        "debugger_restart": RiskTier.GUEST_MUTATE,
        "debugger_select": RiskTier.GUEST_MUTATE,
        "debugger_call": RiskTier.GUEST_MUTATE,
        "analysis_start": RiskTier.GUEST_MUTATE,
        "analysis_collect": RiskTier.GUEST_MUTATE,
        "vm_snapshot_revert": RiskTier.HOST_DESTRUCTIVE,
        "vm_snapshot_take": RiskTier.HOST_DESTRUCTIVE,
        "analysis_finish": RiskTier.HOST_DESTRUCTIVE,
        "file_download": RiskTier.HOST_DESTRUCTIVE,
        "vm_power": RiskTier.HOST_DESTRUCTIVE,
        "vm_snapshot_delete": RiskTier.HOST_DESTRUCTIVE,
    }
    assert dict(GATEWAY_TOOL_TIERS) == expected
    for name, tier in expected.items():
        assert tier_of(name) is tier


def test_tier_table_is_immutable():
    with pytest.raises(TypeError):
        GATEWAY_TOOL_TIERS["vm_power"] = RiskTier.OBSERVE  # type: ignore[index]


@pytest.mark.parametrize("name", ["SetBreakpoint", "", "VM_POWER", "vm_power ", "dbg_run"])
def test_tier_of_unknown_tool_raises_key_error(name):
    with pytest.raises(KeyError):
        tier_of(name)


def test_tiers_are_ordered_by_risk():
    assert RiskTier.OBSERVE < RiskTier.GUEST_MUTATE < RiskTier.HOST_DESTRUCTIVE


def test_mirror_tools_tier_from_read_only_hint():
    assert tier_for_mirror(read_only=True) is RiskTier.OBSERVE
    assert tier_for_mirror(read_only=False) is RiskTier.GUEST_MUTATE


# ── VM op invariants (plan 4.1 invariant 1, 2) ──────────────────────
def test_vm_ops_and_busy_states_constants():
    assert set(VM_OPS) == {"revert", "power", "snapshot_take", "snapshot_delete"}
    assert set(VM_BUSY_STATES) == {S.UPLOADING, S.COLLECTING, S.REVERTING}


@pytest.mark.parametrize("op", sorted(VM_OPS))
def test_every_op_allowed_without_active_job(op):
    assert_vm_op_allowed(op, None)


@pytest.mark.parametrize("op", sorted(VM_OPS))
@pytest.mark.parametrize("state", [S.UPLOADING, S.COLLECTING, S.REVERTING])
def test_every_op_refused_while_job_is_busy(op, state):
    with pytest.raises(StateViolation) as ei:
        assert_vm_op_allowed(op, job_in(state))
    assert ei.value.details["job_id"] == JID
    assert ei.value.details["state"] == state.value
    assert ei.value.details["op"] == op


@pytest.mark.parametrize("op", ["revert", "power"])
@pytest.mark.parametrize("state", list(S))
def test_revert_and_power_only_when_collected_or_discarded(op, state):
    job = job_in(state)
    if state in (S.COLLECTED, S.DISCARDED) or state in TERMINAL_JOB_STATES:
        assert_vm_op_allowed(op, job)
    else:
        with pytest.raises(StateViolation) as ei:
            assert_vm_op_allowed(op, job)
        assert ei.value.details == {"job_id": JID, "state": state.value, "op": op}


@pytest.mark.parametrize("op", ["snapshot_take", "snapshot_delete"])
@pytest.mark.parametrize("state", list(S))
def test_snapshot_ops_refused_only_while_busy(op, state):
    if state in VM_BUSY_STATES:
        with pytest.raises(StateViolation):
            assert_vm_op_allowed(op, job_in(state))
    else:
        assert_vm_op_allowed(op, job_in(state))


@pytest.mark.parametrize("op", ["delete", "", "REVERT", "start"])
def test_unknown_vm_op_is_a_programming_error(op):
    with pytest.raises(ValueError):
        assert_vm_op_allowed(op, None)  # type: ignore[arg-type]


@pytest.mark.parametrize("state", list(S))
def test_assert_revert_for_job_requires_collected_or_discarded(state):
    if state in (S.COLLECTED, S.DISCARDED):
        assert_revert_for_job(job_in(state))
    else:
        with pytest.raises(StateViolation) as ei:
            assert_revert_for_job(job_in(state))
        assert ei.value.details["job_id"] == JID
        assert ei.value.details["state"] == state.value


# ── snapshot protection (plan 5.7) ──────────────────────────────────
@pytest.mark.parametrize("name", [f"gw-job-{JID}", f"gw-pre-revert-{JID}", "gw-anything"])
def test_prefixed_snapshots_are_deletable(name):
    check_snapshot_delete(name, profile())


@pytest.mark.parametrize(
    "name",
    [
        "MCP_CLEAN",
        "mcp_clean",
        " MCP_CLEAN ",
        "MCP_BASE",
        "remote_base",
        "some user snapshot",
        "GW-job-x",  # prefix match is case-sensitive: unknown owner, refuse
        "",
        "gw-",
        f"gw-job-{JID}/MCP_CLEAN",  # vmrun path syntax could address a protected child
        "gw-x\\y",
        "gw-x\x00",
        "gw-x\n",
    ],
)
def test_unsafe_or_protected_snapshot_names_are_refused(name):
    with pytest.raises(ProtectedSnapshotError) as ei:
        check_snapshot_delete(name, profile())
    assert ei.value.details["snapshot"] == name


def test_protected_name_with_gateway_prefix_is_refused():
    p = profile(protected_snapshots=("gw-keep",), clean_snapshot="gw-clean")
    for name in ("gw-keep", "GW-KEEP", "gw-clean"):
        with pytest.raises(ProtectedSnapshotError):
            check_snapshot_delete(name, p)
    check_snapshot_delete("gw-other", p)


def test_empty_prefix_makes_nothing_deletable():
    p = profile(snapshot_prefix="")
    with pytest.raises(ProtectedSnapshotError):
        check_snapshot_delete("anything", p)


def test_gateway_snapshot_names():
    assert gateway_snapshot_name("job", JID, "gw-") == f"gw-job-{JID}"
    assert gateway_snapshot_name("pre-revert", JID, "gw-") == f"gw-pre-revert-{JID}"
    check_snapshot_delete(gateway_snapshot_name("job", JID, "gw-"), profile())


@pytest.mark.parametrize("kind", ["", "clean", "JOB", "job/../x"])
def test_gateway_snapshot_name_rejects_unknown_kind(kind):
    with pytest.raises(ValueError):
        gateway_snapshot_name(kind, JID, "gw-")


@pytest.mark.parametrize("job_id", ["../x", "20261123-153012-0A9FBC", "", "x" * 22])
def test_gateway_snapshot_name_validates_job_id(job_id):
    with pytest.raises(PathNotAllowed):
        gateway_snapshot_name("job", job_id, "gw-")


@pytest.mark.parametrize("prefix", ["", "a/b", "a\\b", "a\x00"])
def test_gateway_snapshot_name_rejects_bad_prefix(prefix):
    with pytest.raises(ValueError):
        gateway_snapshot_name("job", JID, prefix)


# ── retention (plan 5.7) ────────────────────────────────────────────
NOW = datetime(2026, 11, 23, 12, 0, 0, tzinfo=UTC)


def snap(kind: str, day: int, n: int, prefix: str = "gw-") -> str:
    return gateway_snapshot_name(kind, f"202611{day:02d}-000000-{n:06x}", prefix)


def test_retention_keeps_newest_n_and_returns_oldest_first():
    names = [snap("job", d, d) for d in range(10, 23)]  # 13 snapshots, Nov 10..22
    noise = ["MCP_CLEAN", "MCP_BASE", "gw-random", "gw-job-bad", "user-snap"]
    plan = retention_plan(names + noise, "gw-", RetentionConfig(max_gateway_snapshots=5, max_age_days=365),
                          NOW)
    assert plan == names[:-5]


def test_retention_drops_snapshots_older_than_max_age():
    names = [snap("pre-revert", d, d) for d in range(10, 23)]
    plan = retention_plan(names, "gw-", RetentionConfig(max_gateway_snapshots=100, max_age_days=7), NOW)
    # Nov 16 00:00 is 7.5 days before NOW -> too old; Nov 17 00:00 is 6.5 days -> kept
    assert plan == [snap("pre-revert", d, d) for d in range(10, 17)]


def test_retention_combines_count_and_age_and_mixes_kinds():
    names = [snap("job", 22, 1), snap("pre-revert", 21, 2), snap("job", 20, 3), snap("job", 1, 4)]
    plan = retention_plan(names, "gw-", RetentionConfig(max_gateway_snapshots=2, max_age_days=14), NOW)
    assert plan == [snap("job", 1, 4), snap("job", 20, 3)]


def test_retention_never_returns_protected_names():
    old = [snap("job", d, d) for d in range(1, 5)]
    plan = retention_plan(old, "gw-", RetentionConfig(max_gateway_snapshots=0, max_age_days=1), NOW,
                          protected=(old[0], old[1].upper()))
    assert plan == old[2:]


def test_retention_ignores_unparseable_and_foreign_names():
    names = [
        "gw-job-20261399-000000-aaaaaa",  # impossible date
        "gw-job-20261101-250000-aaaaaa",  # impossible time
        "gw-job-20261101-000000-AAAAAA",
        "gw-job-20261101-000000-aaaaaa-extra",
        "gw-clean-20261101-000000-aaaaaa",
        "xx-job-20261101-000000-aaaaaa",
        "MCP_CLEAN",
    ]
    assert retention_plan(names, "gw-", RetentionConfig(0, 0), NOW) == []


def test_retention_deduplicates_names():
    a = snap("job", 1, 1)
    assert retention_plan([a, a, a], "gw-", RetentionConfig(0, 30), NOW) == [a]


def test_retention_accepts_naive_now_as_utc():
    names = [snap("job", d, d) for d in range(10, 23)]
    r = RetentionConfig(max_gateway_snapshots=100, max_age_days=7)
    assert retention_plan(names, "gw-", r, NOW.replace(tzinfo=None)) == retention_plan(names, "gw-", r, NOW)


def test_retention_future_snapshots_are_not_old():
    future = snap("job", 30, 1)
    assert retention_plan([future], "gw-", RetentionConfig(10, 1), NOW) == []


def test_retention_honours_custom_prefix():
    names = [snap("job", 1, 1, prefix="lab_"), snap("job", 2, 2, prefix="gw-")]
    assert retention_plan(names, "lab_", RetentionConfig(0, 30), NOW) == [names[0]]


@pytest.mark.parametrize("retention", [RetentionConfig(-1, 14), RetentionConfig(10, -1)])
def test_retention_rejects_negative_limits(retention):
    with pytest.raises(ValueError):
        retention_plan([], "gw-", retention, NOW)


def test_retention_with_empty_prefix_deletes_nothing():
    names = [f"job-{JID}"]
    assert retention_plan(names, "", RetentionConfig(0, 0), NOW + timedelta(days=400)) == []


def test_retention_results_pass_delete_check():
    names = [snap("job", d, d) for d in range(1, 23)]
    p = profile()
    for name in retention_plan(names, p.snapshot_prefix, RetentionConfig(3, 5), NOW,
                               protected=p.protected_snapshots):
        check_snapshot_delete(name, p)


# ── isolation gate (plan 5.7 items 5, 6) ────────────────────────────
def test_isolated_vm_passes():
    rep = IsolationReport(False, False, ("hostonly",))
    assert isolation_gate(rep, require=True) == []
    assert isolation_gate(rep, require=False) == []
    assert isolation_gate(IsolationReport(False, None, ()), require=True) == []
    assert isolation_gate(IsolationReport(False, False, ("none", "disconnected")), require=True) == []


def test_violations_raise_when_required_and_list_each_problem():
    rep = IsolationReport(True, True, ("bridged", "hostonly", "nat"))
    with pytest.raises(IsolationRequired) as ei:
        isolation_gate(rep, require=True)
    v = ei.value.details["violations"]
    assert len(v) == 4
    joined = " ".join(v)
    assert "enabled" in joined and "writable" in joined and "bridged" in joined and "nat" in joined
    assert ei.value.details["network_types"] == ["bridged", "hostonly", "nat"]


def test_violations_are_warnings_when_not_required():
    rep = IsolationReport(True, False, ("nat",))
    warnings = isolation_gate(rep, require=False)
    assert len(warnings) == 2 and any("nat" in w for w in warnings)


def test_unknown_shared_folder_state_fails_closed():
    rep = IsolationReport(None, None, ("hostonly",))
    with pytest.raises(IsolationRequired) as ei:
        isolation_gate(rep, require=True)
    assert len(ei.value.details["violations"]) == 1


def test_writable_flag_on_disabled_shared_folders_is_not_a_violation():
    assert isolation_gate(IsolationReport(False, True, ("hostonly",)), require=True) == []


@pytest.mark.parametrize("net", ["custom", "vmnet8", "", "HostOnly"])
def test_unknown_network_types_are_violations_case_insensitively(net):
    rep = IsolationReport(False, False, (net,))
    if net.lower() == "hostonly":
        assert isolation_gate(rep, require=True) == []
    else:
        with pytest.raises(IsolationRequired):
            isolation_gate(rep, require=True)


# ── host path allowlist (plan 5.3) ──────────────────────────────────
@pytest.fixture
def lab(tmp_path: Path) -> Path:
    root = tmp_path / "samples"
    root.mkdir()
    (root / "a.exe").write_bytes(b"MZ")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret").write_text("s")
    return root


def test_path_inside_root_is_allowed_and_resolved(lab):
    assert host_path_allowed(lab / "a.exe", [lab]) == (lab / "a.exe").resolve()
    assert host_path_allowed(str(lab / "sub" / ".." / "a.exe"), [str(lab)]) == (lab / "a.exe").resolve()


def test_nonexistent_path_inside_root_is_allowed(lab):
    assert host_path_allowed(lab / "new" / "b.bin", [lab]) == (lab / "new" / "b.bin").resolve()


def test_second_root_matches(lab, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    assert host_path_allowed(other / "x", [lab, other]) == (other / "x").resolve()


@pytest.mark.parametrize("rel", ["../outside/secret", "a.exe/../../outside/secret", "../samples2/x"])
def test_traversal_outside_root_is_refused(lab, rel):
    (lab.parent / "samples2").mkdir(exist_ok=True)
    with pytest.raises(PathNotAllowed) as ei:
        host_path_allowed(f"{lab}/{rel}", [lab])
    assert "path" in ei.value.details


def test_symlink_escaping_root_is_refused(lab):
    link = lab / "link"
    try:
        link.symlink_to(lab.parent / "outside", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not supported")
    with pytest.raises(PathNotAllowed):
        host_path_allowed(link / "secret", [lab])


def test_symlinked_root_is_resolved(lab, tmp_path):
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(lab, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not supported")
    assert host_path_allowed(alias / "a.exe", [alias]) == (lab / "a.exe").resolve()
    assert host_path_allowed(lab / "a.exe", [alias]) == (lab / "a.exe").resolve()


def test_nul_byte_is_refused(lab):
    with pytest.raises(PathNotAllowed):
        host_path_allowed(f"{lab}/a.exe\x00.txt", [lab])


def test_relative_path_is_refused(lab, monkeypatch):
    monkeypatch.chdir(lab)
    with pytest.raises(PathNotAllowed):
        host_path_allowed("a.exe", [lab])


def test_no_roots_means_nothing_is_allowed(lab):
    with pytest.raises(PathNotAllowed):
        host_path_allowed(lab / "a.exe", [])


def test_root_with_nul_is_ignored(lab):
    with pytest.raises(PathNotAllowed):
        host_path_allowed(lab / "a.exe", [f"{lab}\x00"])


def test_home_expansion(lab, monkeypatch):
    monkeypatch.setenv("HOME", str(lab.parent))
    monkeypatch.setenv("USERPROFILE", str(lab.parent))
    assert host_path_allowed("~/samples/a.exe", ["~/samples"]) == (lab / "a.exe").resolve()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink loop semantics")
def test_symlink_loop_is_refused_not_crashing(lab):
    (lab / "loop").symlink_to(lab / "loop")
    with pytest.raises(PathNotAllowed):
        host_path_allowed(lab / "loop" / "x", [lab.parent / "elsewhere"])
