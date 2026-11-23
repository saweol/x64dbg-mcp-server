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
        if (path.len >= MAX_LEN or args.len >= MAX_LEN or workdir.len >= MAX_LEN) return error.TooLong;
        self.lock.lock();
        defer self.lock.unlock();
        copyInto(&self.pending.path_buf, &self.pending.path_len, path);
        copyInto(&self.pending.args_buf, &self.pending.args_len, args);
        copyInto(&self.pending.workdir_buf, &self.pending.workdir_len, workdir);
        self.has_pending = true;
    }

    pub fn clearPending(self: *LaunchState) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.has_pending = false;
    }

    /// Called from CB_INITDEBUG with the executable x64dbg started.
    pub fn onInitDebug(self: *LaunchState, path: []const u8) void {
        self.lock.lock();
        defer self.lock.unlock();
        const cur = &self.current;
        if (self.has_pending and samePath(self.pending.path(), path)) {
            copyInto(&cur.args_buf, &cur.args_len, self.pending.args());
            copyInto(&cur.workdir_buf, &cur.workdir_len, self.pending.workdir());
        } else if (!samePath(cur.path(), path)) {
            cur.args_len = 0;
            cur.workdir_len = 0;
        }
        self.has_pending = false;
        if (path.len < MAX_LEN) {
            copyInto(&cur.path_buf, &cur.path_len, path);
        } else {
            // Cannot be replayed faithfully; report the path as unknown.
            cur.* = .{};
        }
    }

    /// Copies the current launch into `out`.
    pub fn snapshot(self: *LaunchState, out: *Launch) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        copyInto(&out.path_buf, &out.path_len, self.current.path());
        copyInto(&out.args_buf, &out.args_len, self.current.args());
        copyInto(&out.workdir_buf, &out.workdir_len, self.current.workdir());
    }
};

fn copyInto(buf: *[MAX_LEN]u8, len: *usize, s: []const u8) void {
    const n = @min(s.len, MAX_LEN);
    @memcpy(buf[0..n], s[0..n]);
    len.* = n;
}

/// Windows path equality: ASCII case-insensitive, '/' == '\'.
pub fn samePath(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        const nx = if (x == '/') '\\' else std.ascii.toLower(x);
        const ny = if (y == '/') '\\' else std.ascii.toLower(y);
        if (nx != ny) return false;
    }
    return true;
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
