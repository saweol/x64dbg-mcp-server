//! Tracks how the current debuggee was launched so RestartDebug can repeat
//! it with the same arguments and working directory (pure, host-testable).
//!
//! LoadBinary/RestartDebug register a *pending* launch before issuing the
//! x64dbg `init` command; x64dbg then reports CB_INITDEBUG with the path it
//! actually started. If that path matches the pending one, the pending
//! arguments/working directory become current. A CB_INITDEBUG without a
//! matching pending launch (e.g. File > Open in the GUI) keeps the current
//! arguments only when it is the same executable again (GUI restart), and
//! clears them for a different executable.
//!
//! Thread-safety: `LaunchState` is internally locked (CB_INITDEBUG runs on
//! the debugger thread, tools run on HTTP client threads).

const std = @import("std");
const sync = @import("sync.zig");

pub const MAX_LEN = 1024;

pub const Launch = struct {
    path_buf: [MAX_LEN]u8 = undefined,
    path_len: usize = 0,
    args_buf: [MAX_LEN]u8 = undefined,
    args_len: usize = 0,
    workdir_buf: [MAX_LEN]u8 = undefined,
    workdir_len: usize = 0,

    pub fn path(self: *const Launch) []const u8 {
        return self.path_buf[0..self.path_len];
    }
    pub fn args(self: *const Launch) []const u8 {
        return self.args_buf[0..self.args_len];
    }
    pub fn workdir(self: *const Launch) []const u8 {
        return self.workdir_buf[0..self.workdir_len];
    }
};

pub const LaunchState = struct {
    lock: sync.RwLock = .{},
    current: Launch = .{},
    pending: Launch = .{},
    has_pending: bool = false,

    pub fn setPending(self: *LaunchState, path: []const u8, args: []const u8, workdir: []const u8) error{TooLong}!void {
        _ = self;
        _ = path;
        _ = args;
        _ = workdir;
    }

    pub fn clearPending(self: *LaunchState) void {
        _ = self;
    }

    /// Called from CB_INITDEBUG with the executable x64dbg started.
    pub fn onInitDebug(self: *LaunchState, path: []const u8) void {
        _ = self;
        _ = path;
    }

    /// Copies the current launch into `out`.
    pub fn snapshot(self: *LaunchState, out: *Launch) void {
        _ = self;
        out.* = .{};
    }
};

/// Windows path equality: ASCII case-insensitive, '/' == '\'.
pub fn samePath(a: []const u8, b: []const u8) bool {
    _ = a;
    _ = b;
    return false;
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "matching CB_INITDEBUG adopts the pending arguments" {
    var st: LaunchState = .{};
    try st.setPending("C:\\s\\a.exe", "-x 1", "C:\\s");
    st.onInitDebug("C:\\s\\a.exe");
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("C:\\s\\a.exe", cur.path());
    try testing.expectEqualStrings("-x 1", cur.args());
    try testing.expectEqualStrings("C:\\s", cur.workdir());
    try testing.expect(!st.has_pending);
}

test "path comparison ignores case and slash direction" {
    try testing.expect(samePath("c:/tools/A.exe", "C:\\Tools\\a.EXE"));
    try testing.expect(!samePath("C:\\a.exe", "C:\\b.exe"));
    try testing.expect(!samePath("C:\\a.exe", "C:\\a.exe2"));
    var st: LaunchState = .{};
    try st.setPending("c:/tools/A.exe", "arg", "");
    st.onInitDebug("C:\\Tools\\a.EXE");
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("arg", cur.args());
    // The path reported by x64dbg wins.
    try testing.expectEqualStrings("C:\\Tools\\a.EXE", cur.path());
}

test "a different executable clears arguments" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "C:\\w");
    st.onInitDebug("C:\\a.exe");
    st.onInitDebug("C:\\other.exe");
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("C:\\other.exe", cur.path());
    try testing.expectEqualStrings("", cur.args());
    try testing.expectEqualStrings("", cur.workdir());
}

test "the same executable without a pending launch keeps arguments (GUI restart)" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "C:\\w");
    st.onInitDebug("C:\\a.exe");
    st.onInitDebug("C:\\a.exe");
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("arg", cur.args());
    try testing.expectEqualStrings("C:\\w", cur.workdir());
}

test "pending launch for another path does not leak into a GUI load" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "C:\\w");
    st.onInitDebug("C:\\gui.exe");
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("C:\\gui.exe", cur.path());
    try testing.expectEqualStrings("", cur.args());
    try testing.expect(!st.has_pending);
}

test "clearPending forgets the pending launch" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "");
    st.clearPending();
    st.onInitDebug("C:\\a.exe");
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("", cur.args());
}

test "overlong values are rejected" {
    var st: LaunchState = .{};
    const long = "a" ** MAX_LEN;
    try testing.expectError(error.TooLong, st.setPending(long, "", ""));
    try testing.expectError(error.TooLong, st.setPending("C:\\a.exe", long, ""));
    try testing.expectError(error.TooLong, st.setPending("C:\\a.exe", "", long));
    try testing.expect(!st.has_pending);
}
