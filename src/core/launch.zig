//! Tracks how the current debuggee was launched so RestartDebug can repeat
//! it with the same arguments and working directory (pure, host-testable).
//!
//! LoadBinary/RestartDebug register a *pending* launch before issuing the
//! x64dbg `init` command; x64dbg then reports CB_INITDEBUG with the path it
//! actually started. The first CB_INITDEBUG for the same executable file
//! name (x64dbg may spell the directory differently: relative vs absolute,
//! `..`, doubled separators) within PENDING_TTL_MS adopts the pending
//! arguments/working directory. The pending launch is intentionally kept
//! when LoadBinary/RestartDebug time out, because a slow load can still
//! start the session afterwards; it expires after PENDING_TTL_MS so a
//! failed `init` cannot leak its arguments into a much later GUI load.
//! A CB_INITDEBUG without a matching pending launch (e.g. File > Open in the
//! GUI) keeps the current arguments only when it is the same executable
//! again (GUI restart), clears them for a different executable, and leaves
//! a non-matching pending launch in place.
//! Limitation: an 8.3 short file name that x64dbg expands to the long name
//! (or the reverse) does not match.
//!
//! Thread-safety: `LaunchState` is internally locked (CB_INITDEBUG runs on
//! the debugger thread, tools run on HTTP client threads). Time is injected
//! (milliseconds from any monotonic clock).

const std = @import("std");
const sync = @import("sync.zig");

pub const MAX_LEN = 1024;

/// How long a pending launch waits for its CB_INITDEBUG: the longest
/// LoadBinary timeout (120 s) plus a margin.
pub const PENDING_TTL_MS: u64 = 130_000;

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
    pending_since_ms: u64 = 0,

    pub fn setPending(self: *LaunchState, path: []const u8, args: []const u8, workdir: []const u8, now_ms: u64) error{TooLong}!void {
        if (path.len >= MAX_LEN or args.len >= MAX_LEN or workdir.len >= MAX_LEN) return error.TooLong;
        self.lock.lock();
        defer self.lock.unlock();
        copyInto(&self.pending.path_buf, &self.pending.path_len, path);
        copyInto(&self.pending.args_buf, &self.pending.args_len, args);
        copyInto(&self.pending.workdir_buf, &self.pending.workdir_len, workdir);
        self.has_pending = true;
        self.pending_since_ms = now_ms;
    }

    pub fn clearPending(self: *LaunchState) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.has_pending = false;
    }

    /// Called from CB_INITDEBUG with the executable x64dbg started.
    pub fn onInitDebug(self: *LaunchState, path: []const u8, now_ms: u64) void {
        self.lock.lock();
        defer self.lock.unlock();
        const cur = &self.current;
        if (self.has_pending and now_ms -| self.pending_since_ms > PENDING_TTL_MS) self.has_pending = false;
        if (self.has_pending and sameExecutable(self.pending.path(), path)) {
            copyInto(&cur.args_buf, &cur.args_len, self.pending.args());
            copyInto(&cur.workdir_buf, &cur.workdir_len, self.pending.workdir());
            self.has_pending = false;
        } else if (!samePath(cur.path(), path)) {
            cur.args_len = 0;
            cur.workdir_len = 0;
        }
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

/// Final path component (after the last backslash or slash).
fn fileName(p: []const u8) []const u8 {
    const i = std.mem.lastIndexOfAny(u8, p, "\\/") orelse return p;
    return p[i + 1 ..];
}

/// Same executable file name (ASCII case-insensitive), whatever the
/// directory spelling. Empty names never match.
pub fn sameExecutable(a: []const u8, b: []const u8) bool {
    const fa = fileName(a);
    const fb = fileName(b);
    return fa.len > 0 and std.ascii.eqlIgnoreCase(fa, fb);
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
    try st.setPending("C:\\s\\a.exe", "-x 1", "C:\\s", 1000);
    st.onInitDebug("C:\\s\\a.exe", 1200);
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
    try st.setPending("c:/tools/A.exe", "arg", "", 0);
    st.onInitDebug("C:\\Tools\\a.EXE", 10);
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("arg", cur.args());
    // The path reported by x64dbg wins.
    try testing.expectEqualStrings("C:\\Tools\\a.EXE", cur.path());
}

test "sameExecutable compares file names only" {
    try testing.expect(sameExecutable("C:\\x\\A.EXE", "a.exe"));
    try testing.expect(sameExecutable("C:/x/a.exe", "D:\\y\\A.exe"));
    try testing.expect(sameExecutable("C:\\s\\..\\s\\a.exe", "C:\\s\\a.exe"));
    try testing.expect(!sameExecutable("C:\\x\\a.exe", "C:\\x\\b.exe"));
    try testing.expect(!sameExecutable("C:\\x\\", "C:\\y\\"));
    try testing.expect(!sameExecutable("", ""));
}

test "a differently spelled path still adopts the pending arguments" {
    // LoadBinary was given a relative / non-canonical path; x64dbg reports
    // the full one in CB_INITDEBUG.
    const given = [_][]const u8{ "sample.exe", ".\\bin\\sample.exe", "C:\\s\\..\\s\\sample.exe", "C:\\s\\\\sample.exe" };
    for (given) |g| {
        var st: LaunchState = .{};
        try st.setPending(g, "--flag", "C:\\w", 0);
        st.onInitDebug("C:\\s\\sample.exe", 50);
        var cur: Launch = .{};
        st.snapshot(&cur);
        try testing.expectEqualStrings("C:\\s\\sample.exe", cur.path());
        try testing.expectEqualStrings("--flag", cur.args());
        try testing.expectEqualStrings("C:\\w", cur.workdir());
    }
}

test "a session that starts after LoadBinary timed out keeps its arguments" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "C:\\w", 0);
    // LoadBinary gave up after 10 s; the slow load completes at 25 s.
    st.onInitDebug("C:\\a.exe", 25_000);
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("arg", cur.args());
    try testing.expectEqualStrings("C:\\w", cur.workdir());
}

test "a stale pending launch expires" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "C:\\w", 0);
    // init failed (e.g. missing file); much later the user opens the same
    // executable in the GUI.
    st.onInitDebug("C:\\a.exe", PENDING_TTL_MS + 1);
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("C:\\a.exe", cur.path());
    try testing.expectEqualStrings("", cur.args());
    try testing.expect(!st.has_pending);
}

test "a different executable clears arguments" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "C:\\w", 0);
    st.onInitDebug("C:\\a.exe", 10);
    st.onInitDebug("C:\\other.exe", 20);
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("C:\\other.exe", cur.path());
    try testing.expectEqualStrings("", cur.args());
    try testing.expectEqualStrings("", cur.workdir());
}

test "the same executable without a pending launch keeps arguments (GUI restart)" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "C:\\w", 0);
    st.onInitDebug("C:\\a.exe", 10);
    st.onInitDebug("C:\\a.exe", 1_000_000);
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("arg", cur.args());
    try testing.expectEqualStrings("C:\\w", cur.workdir());
}

test "an unrelated GUI load neither takes nor consumes the pending launch" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "C:\\w", 0);
    st.onInitDebug("C:\\gui.exe", 10);
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("C:\\gui.exe", cur.path());
    try testing.expectEqualStrings("", cur.args());
    try testing.expect(st.has_pending);
    // Our own init still arrives afterwards.
    st.onInitDebug("C:\\a.exe", 20);
    st.snapshot(&cur);
    try testing.expectEqualStrings("arg", cur.args());
    try testing.expect(!st.has_pending);
}

test "clearPending forgets the pending launch" {
    var st: LaunchState = .{};
    try st.setPending("C:\\a.exe", "arg", "", 0);
    st.clearPending();
    st.onInitDebug("C:\\a.exe", 10);
    var cur: Launch = .{};
    st.snapshot(&cur);
    try testing.expectEqualStrings("", cur.args());
}

test "overlong values are rejected" {
    var st: LaunchState = .{};
    const long = "a" ** MAX_LEN;
    try testing.expectError(error.TooLong, st.setPending(long, "", "", 0));
    try testing.expectError(error.TooLong, st.setPending("C:\\a.exe", long, "", 0));
    try testing.expectError(error.TooLong, st.setPending("C:\\a.exe", "", long, 0));
    try testing.expect(!st.has_pending);
}
