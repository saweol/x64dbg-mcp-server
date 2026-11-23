"""Gateway policy: tool risk tiers, VM-operation invariants, snapshot protection
and retention, the isolation gate and the host path allowlist.

Plan refs (docs/VM_ORCHESTRATION_PLAN.md): 4.1 invariants 1-2, 5.3 path
limits, 5.6 risk tiers, 5.7 clean-snapshot contract and retention, 9 risks.

These checks are the gateway's hard guarantees; they do not rely on the MCP
client asking a human. Every check fails closed: when the input is unknown,
ambiguous or malformed, the operation is refused.

Thread-safety: all functions are pure (``host_path_allowed`` only reads the
filesystem to resolve symlinks) and all module tables are read-only, so
everything here is safe to call from any thread.
"""

from __future__ import annotations

import enum
import functools
import os
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Literal, get_args

from .config import ProfileConfig, RetentionConfig
from .contracts import IsolationReport, JobState
from .errors import IsolationRequired, PathNotAllowed, ProtectedSnapshotError, StateViolation
from .jobs import JOB_ID_RE, Job, validate_job_id

__all__ = [
    "GATEWAY_TOOL_TIERS",
    "REVERT_READY_STATES",
    "SNAPSHOT_KINDS",
    "VM_BUSY_STATES",
    "VM_OPS",
    "RiskTier",
    "VmOp",
    "assert_revert_for_job",
    "assert_vm_op_allowed",
    "check_snapshot_delete",
    "gateway_snapshot_name",
    "host_path_allowed",
    "isolation_gate",
    "retention_plan",
    "tier_for_mirror",
    "tier_of",
]


# ── risk tiers (plan 5.6) ───────────────────────────────────────────
@functools.total_ordering
class RiskTier(enum.Enum):
    """Risk tier of a tool. Members compare by risk: OBSERVE < GUEST_MUTATE < HOST_DESTRUCTIVE."""

    OBSERVE = "observe"
    GUEST_MUTATE = "guest_mutate"
    HOST_DESTRUCTIVE = "host_destructive"

    @property
    def rank(self) -> int:
        return list(RiskTier).index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        return self.rank < other.rank


GATEWAY_TOOL_TIERS: Mapping[str, RiskTier] = MappingProxyType({
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
})
"""Risk tier of every gateway-native tool (mirrored x64dbg tools: see ``tier_for_mirror``)."""


def tier_of(name: str) -> RiskTier:
    """Tier of a gateway tool. Raises KeyError for anything else (no default tier)."""
    return GATEWAY_TOOL_TIERS[name]


def tier_for_mirror(*, read_only: bool) -> RiskTier:
    """Tier of a mirrored plugin tool, derived from its ``readOnlyHint``."""
    return RiskTier.OBSERVE if read_only else RiskTier.GUEST_MUTATE


# ── VM operation invariants (plan 4.1) ──────────────────────────────
VmOp = Literal["revert", "power", "snapshot_take", "snapshot_delete"]
VM_OPS: frozenset[str] = frozenset(get_args(VmOp))

VM_BUSY_STATES: frozenset[JobState] = frozenset({JobState.UPLOADING, JobState.COLLECTING, JobState.REVERTING})
"""Invariant 2: while the active job is here, every other VM-changing operation is refused."""

REVERT_READY_STATES: frozenset[JobState] = frozenset({JobState.COLLECTED, JobState.DISCARDED})
"""Invariant 1: the only states from which the VM may be reverted (fail-closed collection)."""

_STATE_GATED_OPS = frozenset({"revert", "power"})


def assert_vm_op_allowed(op: VmOp, active_job: Job | None) -> None:
    """Refuse a VM-changing operation requested by a tool (not by the orchestrator).

    - With no live job, everything is allowed.
    - While the job is UPLOADING, COLLECTING or REVERTING, everything is refused.
    - ``revert`` and ``power`` are refused unless the job is COLLECTED or
      DISCARDED, so artifacts cannot be lost by reverting before collection.

    The orchestrator's own revert inside ``analysis_finish`` (the job is then
    REVERTING) is checked with ``assert_revert_for_job`` before it enters
    REVERTING, not with this function.
    """
    if op not in VM_OPS:
        raise ValueError(f"unknown VM operation: {op!r}")
    if active_job is None or active_job.terminal:
        return
    state = JobState(active_job.state)
    details = {"job_id": active_job.id, "state": state.value, "op": op}
    if state in VM_BUSY_STATES:
        raise StateViolation(
            f"VM operation {op!r} refused: job {active_job.id} is {state.value}",
            details=details,
            hint="wait until the job leaves this step, then retry",
            next_tool="session_status",
        )
    if op in _STATE_GATED_OPS and state not in REVERT_READY_STATES:
        raise StateViolation(
            f"VM operation {op!r} refused: job {active_job.id} is {state.value} and not collected",
            details=details,
            hint="call analysis_collect first; only a human can discard uncollected results",
            next_tool="analysis_collect",
        )


def assert_revert_for_job(job: Job) -> None:
    """Gate for the orchestrator's revert of ``job`` (before entering REVERTING)."""
    state = JobState(job.state)
    if state not in REVERT_READY_STATES:
        raise StateViolation(
            f"job {job.id} is {state.value}; it must be COLLECTED or DISCARDED before revert",
            details={"job_id": job.id, "state": state.value},
            hint="call analysis_collect first",
            next_tool="analysis_collect",
        )


# ── snapshots (plan 5.7) ────────────────────────────────────────────
SNAPSHOT_KINDS: tuple[str, ...] = ("job", "pre-revert")


def _fold(name: str) -> str:
    return name.strip().casefold()


def _reject_single_path(value: object, what: str) -> None:
    # A lone str would be iterated character by character ("/x/y" -> "/", "x", ...),
    # silently turning an allowlist or protection list into something else.
    if isinstance(value, str | bytes | os.PathLike):
        raise TypeError(f"{what} must be a collection of names or paths, not a single string")


def _folded_names(names: Iterable[str], what: str) -> set[str]:
    _reject_single_path(names, what)
    return {_fold(n) for n in names if isinstance(n, str)}


def _unsafe_snapshot_text(text: str) -> bool:
    # "/" is vmrun's snapshot path separator ("parent/child"); a name containing
    # it could address a different (protected) snapshot. Control characters
    # have no business in a snapshot name.
    return any(c in "/\\" or ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def check_snapshot_delete(name: str, profile: ProfileConfig) -> None:
    """Raise ProtectedSnapshotError unless ``name`` is a gateway-owned, unprotected snapshot.

    Deletable means: it starts with ``profile.snapshot_prefix`` (case-sensitive,
    with something after it), is not the clean snapshot and is not in
    ``protected_snapshots`` (both compared case-insensitively). An empty prefix
    makes nothing deletable.
    """

    def refuse(why: str) -> ProtectedSnapshotError:
        return ProtectedSnapshotError(f"snapshot {name!r} may not be deleted: {why}",
                                      details={"snapshot": name, "reason": why})

    if not isinstance(name, str) or not name:
        raise refuse("empty snapshot name")
    if _unsafe_snapshot_text(name):
        raise refuse("name contains a path separator or control character")
    prefix = profile.snapshot_prefix
    if not prefix:
        raise refuse("no gateway snapshot prefix is configured")
    if not name.startswith(prefix) or len(name) == len(prefix):
        raise refuse(f"only gateway snapshots ({prefix}*) may be deleted")
    protected = _folded_names(profile.protected_snapshots, "protected_snapshots")
    if profile.clean_snapshot:
        protected.add(_fold(profile.clean_snapshot))
    if _fold(name) in protected:
        raise refuse("snapshot is protected")


def _check_prefix(prefix: str) -> None:
    if not isinstance(prefix, str) or not prefix or _unsafe_snapshot_text(prefix):
        raise ValueError("snapshot prefix must be a non-empty name without separators or control characters")


def gateway_snapshot_name(kind: str, job_id: str, prefix: str) -> str:
    """``f"{prefix}{kind}-{job_id}"`` for kind in ``SNAPSHOT_KINDS``, e.g. ``gw-job-<id>``."""
    if kind not in SNAPSHOT_KINDS:
        raise ValueError(f"unknown gateway snapshot kind: {kind!r}")
    validate_job_id(job_id)
    _check_prefix(prefix)
    return f"{prefix}{kind}-{job_id}"


def _job_id_time(job_id: str) -> datetime | None:
    try:
        return datetime.strptime(job_id[:15], "%Y%m%d-%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def retention_plan(
    snapshot_names: Iterable[str],
    prefix: str,
    retention: RetentionConfig,
    now: datetime,
    protected: Iterable[str] = (),
    *,
    exclude_job_ids: Iterable[str] = (),
) -> list[str]:
    """Gateway snapshots to delete, oldest first.

    Only ``{prefix}{kind}-{job_id}`` names whose job id carries a valid UTC
    timestamp are considered; everything else is never touched. Of those, the
    newest ``max_gateway_snapshots`` are kept, and any whose job id is older
    than ``max_age_days`` is dropped even if within the count (age is the job's
    creation time embedded in its id, not the snapshot's).

    Both limits are literal: ``max_gateway_snapshots=0`` keeps none by count
    and ``max_age_days=0`` allows no age, so either deletes every eligible
    snapshot. Never returned: ``protected`` names (case-insensitive; pass the
    profile's clean snapshot here too), snapshots of ``exclude_job_ids`` (pass
    the live job, whose ``pre-revert``/``job`` snapshots are still needed),
    and foreign names. ``protected`` and ``exclude_job_ids`` must be
    collections; a single string raises TypeError. A naive ``now`` is taken as
    UTC. Callers should still pass each result through ``check_snapshot_delete``.
    """
    if retention.max_gateway_snapshots < 0 or retention.max_age_days < 0:
        raise ValueError("retention limits must be non-negative")
    blocked = _folded_names(protected, "protected")
    _reject_single_path(exclude_job_ids, "exclude_job_ids")
    excluded = {validate_job_id(j) for j in exclude_job_ids}
    if not prefix:
        return []
    _check_prefix(prefix)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    pattern = re.compile(re.escape(prefix) + r"(job|pre-revert)-([0-9]{8}-[0-9]{6}-[0-9a-f]{6})")
    stamps: dict[str, datetime] = {}
    for name in snapshot_names:
        if not isinstance(name, str) or name in stamps or _fold(name) in blocked:
            continue
        m = pattern.fullmatch(name)
        if m is None or JOB_ID_RE.fullmatch(m.group(2)) is None or m.group(2) in excluded:
            continue
        ts = _job_id_time(m.group(2))
        if ts is not None:
            stamps[name] = ts
    newest_first = sorted(stamps, key=lambda n: (stamps[n], n), reverse=True)
    keep = set(newest_first[: retention.max_gateway_snapshots])
    cutoff = now - timedelta(days=retention.max_age_days)
    doomed = [n for n in stamps if n not in keep or stamps[n] < cutoff]
    return sorted(doomed, key=lambda n: (stamps[n], n))


# ── isolation gate (plan 5.7 items 5-6) ─────────────────────────────
_ISOLATED_NETWORKS = frozenset({"hostonly", "none", "disconnected"})


def isolation_gate(report: IsolationReport, require: bool) -> list[str]:
    """Check shared folders and network type before analysis starts.

    Returns the list of violations as warnings when ``require`` is False.
    When ``require`` is True and anything is wrong, raises IsolationRequired
    whose ``details["violations"]`` lists each problem. An unknown shared
    folder state counts as a violation (fail closed); a writable flag on
    disabled shared folders does not.

    An empty ``network_types`` is also a violation: it cannot be told apart
    from "adapters could not be determined". A provider that knows the VM has
    no network adapter reports ``("none",)``.

    This gate, not ``IsolationReport.isolated``, is authoritative: that
    property treats an unknown (None) shared folder state and an empty
    adapter list as isolated.
    """
    violations: list[str] = []
    enabled = report.shared_folders_enabled
    if enabled is None:
        violations.append("shared folder state could not be determined (treated as enabled)")
    elif enabled:
        violations.append("shared folders are enabled")
    if report.shared_folders_writable and enabled is not False:
        violations.append("shared folders are writable from the guest")
    if not report.network_types:
        violations.append("network adapter types could not be determined (none reported; treated as "
                          "not host-only)")
    for net in report.network_types:
        if not isinstance(net, str) or net.strip().lower() not in _ISOLATED_NETWORKS:
            violations.append(f"network adapter type {net!r} is not host-only")
    if violations and require:
        raise IsolationRequired(
            "VM is not isolated: " + "; ".join(violations),
            stage="isolation",
            details={
                "violations": list(violations),
                "shared_folders_enabled": enabled,
                "shared_folders_writable": report.shared_folders_writable,
                "network_types": list(report.network_types),
            },
            hint="disable shared folders and use a host-only network (plan 5.7)",
            next_tool="gateway_doctor",
        )
    return violations


# ── host path allowlist (plan 5.3) ──────────────────────────────────
def _clip(text: str, limit: int = 300) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _resolve_root(root: str | os.PathLike[str]) -> Path | None:
    try:
        raw = os.fspath(root)
        if not isinstance(raw, str) or "\x00" in raw:
            return None
        p = Path(raw).expanduser()
        if not p.is_absolute():
            return None  # a relative root would depend on the gateway's cwd
        return p.resolve(strict=False)
    except (OSError, RuntimeError, ValueError, TypeError):
        return None


def host_path_allowed(path: str | os.PathLike[str], roots: Iterable[str | os.PathLike[str]]) -> Path:
    """Resolve ``path`` and return it if it lies inside one of ``roots``.

    Both sides are expanded (``~``) and resolved (symlinks followed,
    ``strict=False``) before comparing whole path components, so ``..``,
    symlinks pointing out of a root and sibling-prefix tricks (``/a/b2`` vs
    ``/a/b``) are refused. Relative paths and paths with NUL bytes are refused.

    Open the returned path, not the original; a symlink swapped in after this
    check (TOCTOU) is outside what a pure check can prevent.

    ``roots`` must be a collection; a single str/bytes/path raises TypeError
    (iterating ``"/x/samples"`` would make ``"/"`` a root and allow everything).
    """
    _reject_single_path(roots, "roots")
    try:
        raw = os.fspath(path)
    except TypeError:
        raise PathNotAllowed("host path must be a string path") from None
    if not isinstance(raw, str):
        raise PathNotAllowed("host path must be a string path")
    if "\x00" in raw:
        raise PathNotAllowed("host path contains a NUL byte", details={"path": _clip(repr(raw))})
    try:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            raise PathNotAllowed("host path must be absolute", details={"path": _clip(raw)})
        resolved = candidate.resolve(strict=False)
    except PathNotAllowed:
        raise
    except (OSError, RuntimeError, ValueError) as e:  # RuntimeError: symlink loop
        raise PathNotAllowed(f"host path cannot be resolved ({type(e).__name__})",
                             details={"path": _clip(raw)}) from None
    allowed = [r for r in (_resolve_root(x) for x in roots) if r is not None]
    for root in allowed:
        if resolved.is_relative_to(root):
            return resolved
    raise PathNotAllowed(
        "host path is outside the allowed roots",
        details={"path": _clip(raw), "resolved": _clip(str(resolved)),
                 "allowed_roots": [str(r) for r in allowed]},
    )
