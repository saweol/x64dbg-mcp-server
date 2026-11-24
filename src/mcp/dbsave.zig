//! SaveDatabase with a file path: what x64dbg did, told from the file (pure logic, unit-tested on the host).
//!
//! x64dbg's `dbsave` always reports success: DbSave writes the JSON database or, while the
//! session has no labels, comments, bookmarks, breakpoints or functions, deletes the file; a
//! file it cannot create is only logged. DbgCmdExec only queues the command (measured on the
//! spike VM, 2026-11-24: "Database saved to ..." for an empty session, and no file). Running
//! it directly (DbgCmdExecDirect) would make the plugin's connection thread wait for the GUI
//! thread (DbSave asks the GUI for the debuggee notes). So the plugin makes sure a file is at
//! the path first (a 0-byte placeholder when there is none, which also shows that the
//! directory is writable), queues dbsave and watches that file:
//!   gone                  -> x64dbg took its empty-database branch: not_written
//!   changed, then stable  -> saved (empty after the change: x64dbg truncated it but could
//!                            not write, e.g. a full disk -> failed)
//!   unchanged at the end  -> x64dbg did not write it: failed (a placeholder is removed)

const std = @import("std");

pub const wait_ms: u32 = 10_000;
pub const poll_ms: u32 = 50;

/// What GetFileAttributesExW says about the path.
pub const Stat = union(enum) {
    file: Stamp,
    /// ERROR_FILE_NOT_FOUND: the directory exists, the file does not
    missing,
    /// ERROR_PATH_NOT_FOUND: the directory does not exist either
    missing_dir,
    directory,
    /// access denied, any other error: cannot tell
    unknown,
};

pub const Stamp = struct { size: u64, write_time: u64 };

pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// `ok` is GetFileAttributesExW's result; the other fields come from its
/// WIN32_FILE_ATTRIBUTE_DATA (or GetLastError when it failed).
pub fn statFromWin32(ok: bool, last_error: u32, attrs: u32, size_high: u32, size_low: u32, write_low: u32, write_high: u32) Stat {
    if (!ok) return switch (last_error) {
        ERROR_FILE_NOT_FOUND => .missing,
        ERROR_PATH_NOT_FOUND => .missing_dir,
        else => .unknown,
    };
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) return .directory;
    return .{ .file = .{
        .size = (@as(u64, size_high) << 32) | size_low,
        .write_time = (@as(u64, write_high) << 32) | write_low,
    } };
}

pub const Outcome = enum { saved, not_written, failed };

/// Watches the file after dbsave was queued. `observe` is called once per poll; `done`
/// becomes true when the outcome is final.
pub const Watch = struct {
    before: Stamp,
    last: ?Stamp = null,
    outcome: Outcome = .failed,
    done: bool = false,

    pub fn observe(self: *Watch, s: Stat) void {
        if (self.done) return;
        switch (s) {
            .missing => {
                self.outcome = .not_written;
                self.done = true;
            },
            // the directory vanished meanwhile: that is not x64dbg's empty-database branch
            .missing_dir, .directory, .unknown => {},
            .file => |now| {
                const changed = now.size != self.before.size or now.write_time != self.before.write_time;
                if (changed) {
                    // finished only once two polls in a row agree (x64dbg may still be writing)
                    if (self.last) |prev| {
                        if (prev.size == now.size and prev.write_time == now.write_time) {
                            // a real database is never empty: truncated, then the write failed
                            self.outcome = if (now.size == 0) .failed else .saved;
                            self.done = true;
                        }
                    }
                    self.last = now;
                } else {
                    self.last = null;
                }
            },
        }
    }
};

/// The host gateway matches this prefix (x64dbg_vm_gateway.app.NO_DATABASE_MARKER).
pub const not_written_prefix = "No database file written";

/// Writes the reply for a save to `path` into `out`.
pub fn reply(out: []u8, o: Outcome, path: []const u8) error{NoSpaceLeft}!struct { text: []const u8, is_error: bool } {
    return switch (o) {
        .saved => .{ .text = try std.fmt.bufPrint(out, "Database saved to \"{s}\".", .{path}), .is_error = false },
        .not_written => .{
            .text = try std.fmt.bufPrint(out, not_written_prefix ++ " to \"{s}\": the session has no labels, comments, " ++
                "bookmarks, breakpoints or functions (x64dbg removed the file instead of writing it).", .{path}),
            .is_error = false,
        },
        .failed => .{
            .text = try std.fmt.bufPrint(out, "Error: x64dbg did not write the database to \"{s}\" within {d} s " ++
                "(see the x64dbg log). The dbsave command may still be queued behind a long command and run " ++
                "later; call SaveDatabase again.", .{ path, wait_ms / 1000 }),
            .is_error = true,
        },
    };
}

const testing = std.testing;

test "stat: only file-not-found and path-not-found mean missing" {
    try testing.expectEqual(Stat.missing, statFromWin32(false, ERROR_FILE_NOT_FOUND, 0, 0, 0, 0, 0));
    try testing.expectEqual(Stat.missing_dir, statFromWin32(false, ERROR_PATH_NOT_FOUND, 0, 0, 0, 0, 0));
    try testing.expectEqual(Stat.unknown, statFromWin32(false, 5, 0, 0, 0, 0, 0)); // access denied
    try testing.expectEqual(Stat.unknown, statFromWin32(false, 32, 0, 0, 0, 0, 0)); // sharing violation
    try testing.expectEqual(Stat.directory, statFromWin32(true, 0, FILE_ATTRIBUTE_DIRECTORY, 0, 0, 0, 0));
    const s = statFromWin32(true, 0, 0x20, 1, 2, 3, 4);
    try testing.expectEqual(@as(u64, (1 << 32) | 2), s.file.size);
    try testing.expectEqual(@as(u64, (4 << 32) | 3), s.file.write_time);
}

test "watch: a removed file is an empty session" {
    var w = Watch{ .before = .{ .size = 0, .write_time = 7 } };
    w.observe(.{ .file = .{ .size = 0, .write_time = 7 } });
    try testing.expect(!w.done);
    w.observe(.missing);
    try testing.expect(w.done);
    try testing.expectEqual(Outcome.not_written, w.outcome);
}

test "watch: a changed file is saved once it is stable" {
    var w = Watch{ .before = .{ .size = 0, .write_time = 7 } };
    w.observe(.{ .file = .{ .size = 100, .write_time = 8 } }); // being written
    try testing.expect(!w.done);
    w.observe(.{ .file = .{ .size = 422, .write_time = 9 } });
    try testing.expect(!w.done);
    w.observe(.{ .file = .{ .size = 422, .write_time = 9 } });
    try testing.expect(w.done);
    try testing.expectEqual(Outcome.saved, w.outcome);
}

test "watch: a same-size rewrite counts by its write time" {
    var w = Watch{ .before = .{ .size = 422, .write_time = 9 } };
    w.observe(.{ .file = .{ .size = 422, .write_time = 12 } });
    w.observe(.{ .file = .{ .size = 422, .write_time = 12 } });
    try testing.expectEqual(Outcome.saved, w.outcome);
}

test "watch: an untouched file is a failed save; unknown polls change nothing" {
    var w = Watch{ .before = .{ .size = 0, .write_time = 7 } };
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        w.observe(.{ .file = .{ .size = 0, .write_time = 7 } });
        w.observe(.unknown);
    }
    try testing.expect(!w.done);
    try testing.expectEqual(Outcome.failed, w.outcome);
}

test "watch: a file left empty after the change is a failed write" {
    var w = Watch{ .before = .{ .size = 0, .write_time = 7 } };
    w.observe(.{ .file = .{ .size = 0, .write_time = 8 } }); // truncated by CREATE_ALWAYS, nothing written
    w.observe(.{ .file = .{ .size = 0, .write_time = 8 } });
    try testing.expect(w.done);
    try testing.expectEqual(Outcome.failed, w.outcome);
}

test "watch: a vanished directory is not an empty session" {
    var w = Watch{ .before = .{ .size = 0, .write_time = 7 } };
    w.observe(.missing_dir);
    w.observe(.directory);
    try testing.expect(!w.done);
    try testing.expectEqual(Outcome.failed, w.outcome);
}

test "watch: the outcome is final once done" {
    var w = Watch{ .before = .{ .size = 0, .write_time = 7 } };
    w.observe(.missing);
    w.observe(.{ .file = .{ .size = 9, .write_time = 9 } });
    w.observe(.{ .file = .{ .size = 9, .write_time = 9 } });
    try testing.expectEqual(Outcome.not_written, w.outcome);
}

test "replies carry the path, the marker and the error flag" {
    var buf: [512]u8 = undefined;
    const p = "C:\\mcp\\jobs\\j\\out\\a.dd64";
    const s = try reply(&buf, .saved, p);
    try testing.expectEqualStrings("Database saved to \"C:\\mcp\\jobs\\j\\out\\a.dd64\".", s.text);
    try testing.expect(!s.is_error);
    const n = try reply(&buf, .not_written, p);
    try testing.expect(std.mem.startsWith(u8, n.text, not_written_prefix));
    try testing.expect(std.mem.indexOf(u8, n.text, p) != null);
    try testing.expect(!n.is_error);
    const f = try reply(&buf, .failed, p);
    try testing.expect(std.mem.startsWith(u8, f.text, "Error:"));
    try testing.expect(std.mem.indexOf(u8, f.text, "within 10 s") != null);
    try testing.expect(std.mem.indexOf(u8, f.text, "call SaveDatabase again") != null);
    try testing.expect(f.is_error);
}

test "a reply that does not fit is reported, not truncated" {
    var small: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, reply(&small, .saved, "C:\\x.dd64"));
}
