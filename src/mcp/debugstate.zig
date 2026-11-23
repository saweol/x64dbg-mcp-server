//! Status word reported by GetDebugState (pure logic, unit-tested on the host).
//!
//! x64dbg holds its run lock (DbgIsRunLocked) for the whole time the debuggee is
//! stopped, so a stopped target must not be reported as "LOCKED": measured on the
//! spike VM (x64dbg 2025-08), GetDebugState said LOCKED at the system breakpoint, at
//! the entry breakpoint and after WaitForPause, while the [state] line said PAUSED.

const std = @import("std");

pub fn statusWord(debugging: bool, running: bool) []const u8 {
    if (!debugging) return "NO_TARGET";
    return if (running) "RUNNING" else "PAUSED";
}

test "a stopped target is PAUSED, whatever the run lock says" {
    try std.testing.expectEqualStrings("PAUSED", statusWord(true, false));
}

test "running and no target" {
    try std.testing.expectEqualStrings("RUNNING", statusWord(true, true));
    try std.testing.expectEqualStrings("NO_TARGET", statusWord(false, false));
    try std.testing.expectEqualStrings("NO_TARGET", statusWord(false, true));
}
