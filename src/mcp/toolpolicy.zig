//! Which tool calls take the global "mutating tool" lock (pure).
//!
//! State-changing tool handlers are serialised so two clients (or two
//! parallel calls from one client) cannot interleave debugger commands.
//! Read-only tools never take the lock, and neither do the tools that must
//! stay usable while a long `run` holds it: PauseDebug (to interrupt it),
//! WaitForEvent / WaitForPause (observers) and GetDebugState (health check).

const std = @import("std");

/// How long a mutating call waits for the lock before failing with BUSY.
pub const LOCK_WAIT_MS: u64 = 10_000;

const lock_free_tools = [_][]const u8{ "PauseDebug", "WaitForEvent", "WaitForPause", "GetDebugState" };

pub fn bypassesMutationLock(name: []const u8, read_only: bool) bool {
    if (read_only) return true;
    for (lock_free_tools) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "read-only tools bypass the lock" {
    try testing.expect(bypassesMutationLock("ReadMemory", true));
    try testing.expect(bypassesMutationLock("GetServerInfo", true));
}

test "interrupt and observer tools bypass the lock even if mutating" {
    try testing.expect(bypassesMutationLock("PauseDebug", false));
    try testing.expect(bypassesMutationLock("WaitForEvent", false));
    try testing.expect(bypassesMutationLock("WaitForPause", false));
    try testing.expect(bypassesMutationLock("GetDebugState", false));
}

test "state-changing tools take the lock" {
    for ([_][]const u8{ "run", "StepOver", "LoadBinary", "SetBreakpoint", "ExecuteDebuggerCommand", "SetArtifactDir", "DumpMemory", "pausedebug" }) |n| {
        try testing.expect(!bypassesMutationLock(n, false));
    }
}
