"""Typed gateway errors.

Every error carries a stable ``code`` that is surfaced to the MCP client in the
error schema ``{code, message, stage, retryable, hint, next_tool, details}``
(see docs/VM_ORCHESTRATION_PLAN.md section 5.6). Codes are part of the public
contract: never rename one, only add new ones.
"""

from __future__ import annotations

from typing import Any


class GatewayError(Exception):
    code = "GATEWAY_ERROR"
    retryable = False

    def __init__(
        self,
        message: str,
        *,
        stage: str | None = None,
        hint: str | None = None,
        next_tool: str | None = None,
        details: dict[str, Any] | None = None,
        retryable: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.stage = stage
        self.hint = hint
        self.next_tool = next_tool
        self.details = dict(details or {})
        if retryable is not None:
            self.retryable = retryable

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "stage": self.stage,
            "retryable": self.retryable,
            "hint": self.hint,
            "next_tool": self.next_tool,
            "details": self.details,
        }


# ── arguments ───────────────────────────────────────────────────────
class InvalidArgument(GatewayError):
    """A tool argument is malformed or inconsistent with the others (checked by the
    orchestrator, after the front-end's schema validation, ``INVALID_ARGUMENTS``)."""

    code = "INVALID_ARGUMENT"


# ── configuration / platform ────────────────────────────────────────
class ConfigError(GatewayError):
    code = "CONFIG_INVALID"


class VmrunNotFound(GatewayError):
    code = "VMRUN_NOT_FOUND"


# ── vmrun / VM ──────────────────────────────────────────────────────
class VmrunError(GatewayError):
    """A vmrun invocation failed. ``details`` holds masked argv, returncode, stdout, stderr."""

    code = "VMRUN_ERROR"


class VmrunTimeout(VmrunError):
    code = "VMRUN_TIMEOUT"
    retryable = True


class VmNotRunning(VmrunError):
    code = "VM_NOT_RUNNING"


class VmNotReady(GatewayError):
    code = "VM_NOT_READY"
    retryable = True


class ToolsNotRunning(VmrunError):
    code = "TOOLS_NOT_RUNNING"
    retryable = True


class GuestAuthFailed(VmrunError):
    code = "GUEST_AUTH"


class SnapshotNotFound(VmrunError):
    code = "SNAPSHOT_NOT_FOUND"


class VmLocked(VmrunError):
    code = "VM_LOCKED"
    retryable = True


class GuestOperationError(VmrunError):
    code = "GUEST_OP_FAILED"


# ── policy / state ──────────────────────────────────────────────────
class ProtectedSnapshotError(GatewayError):
    code = "PROTECTED_SNAPSHOT"


class StateViolation(GatewayError):
    code = "STATE_VIOLATION"


class JobNotFound(StateViolation):
    code = "JOB_NOT_FOUND"


class IsolationRequired(GatewayError):
    code = "ISOLATION_REQUIRED"


class LockTimeout(GatewayError):
    code = "LOCK_TIMEOUT"
    retryable = True


class CancelledByVmOp(GatewayError):
    code = "CANCELLED_BY_VM_OP"


# ── transfer ────────────────────────────────────────────────────────
class TransferError(GatewayError):
    code = "TRANSFER_FAILED"


class IntegrityError(TransferError):
    code = "INTEGRITY_MISMATCH"


class UnsafeArchiveError(TransferError):
    code = "UNSAFE_ARCHIVE"


class DatabaseFormatError(GatewayError):
    """An x64dbg database (.dd64/.dd32) cannot be read: LZ4-compressed (x64dbg's default
    unless ``[Engine] DisableDatabaseCompression=1``), not UTF-8 or not a JSON object."""

    code = "DATABASE_FORMAT"


class PathNotAllowed(GatewayError):
    code = "PATH_NOT_ALLOWED"


class InvalidJobId(PathNotAllowed):
    """Malformed job id (also a path-safety violation, hence the subclass)."""

    code = "INVALID_JOB_ID"


# ── backend (x64dbg plugin) ─────────────────────────────────────────
class BackendError(GatewayError):
    code = "BACKEND_ERROR"


class BackendUnavailable(BackendError):
    code = "BACKEND_UNAVAILABLE"
    retryable = True


class BackendAuthError(BackendError):
    code = "BACKEND_AUTH"


class BackendProtocolError(BackendError):
    code = "BACKEND_PROTOCOL"


class BackendTimeout(BackendError):
    code = "BACKEND_TIMEOUT"


class BackendThrottled(BackendError):
    """The plugin answered HTTP 429: it locked this client's address out after repeated
    authentication failures (plugin v1.10 ``AuthMaxFailures`` / ``AuthLockoutSeconds``).

    The backend is alive: it must never be relaunched or killed for this, and calls are
    never retried automatically. ``details["retry_after_s"]`` holds the remaining lockout
    in seconds (None when the plugin did not say).
    """

    code = "BACKEND_THROTTLED"
    retryable = True

    def __init__(self, message: str, *, retry_after_s: float | None = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.details.setdefault("retry_after_s", retry_after_s)


class BackendRestarted(BackendError):
    """Debugger was relaunched (epoch changed); prior debuggee state is gone."""

    code = "BACKEND_RESTARTED"


class ResultUnknown(BackendError):
    """A non-idempotent call timed out or lost its connection; it was NOT retried."""

    code = "RESULT_UNKNOWN"


class CrashLoop(BackendError):
    code = "CRASH_LOOP"
