//! Builders for x64dbg command strings that embed quoted arguments
//! (pure, host-testable).
//!
//! x64dbg's command parser (src/dbg/command.cpp) treats a backslash inside a
//! quoted argument as an escape for the next character: `\"` yields a
//! literal quote and `\x` (x != quote) yields both characters unchanged.
//! There is no way to express a backslash that is immediately followed by
//! the closing quote or by a literal quote when it is preceded by an odd
//! run of backslashes, so such values are rejected (`Unrepresentable`),
//! except for working directories where a trailing backslash is doubled
//! (Windows collapses repeated separators). Control characters are
//! rejected because a command is a single line.
//! NOTE: this quoting model follows the x64dbg source as recalled for this
//! change; it is not verified against a running x64dbg (plan item V5).
//!
//! All functions are pure and thread-safe. Outputs are NUL-terminated.

const std = @import("std");

pub const Error = error{ Unrepresentable, BufferTooSmall };

/// True when `s` can be embedded in a quoted x64dbg argument.
pub fn isRepresentable(s: []const u8) bool {
    var run: usize = 0; // length of the current run of backslashes
    for (s) |c| {
        if (c < 0x20 or c == 0x7F) return false;
        if (c == '\\') {
            run += 1;
            continue;
        }
        // An odd run would pair its last backslash with our escape for '"'.
        if (c == '"' and run % 2 == 1) return false;
        run = 0;
    }
    // An odd trailing run would escape the closing quote.
    return run % 2 == 0;
}

/// Appends to a fixed buffer, always leaving room for a NUL terminator.
const Builder = struct {
    buf: []u8,
    len: usize = 0,

    fn raw(self: *Builder, s: []const u8) Error!void {
        if (self.buf.len == 0 or self.len + s.len > self.buf.len - 1) return error.BufferTooSmall;
        @memcpy(self.buf[self.len..][0..s.len], s);
        self.len += s.len;
    }

    fn print(self: *Builder, comptime fmt: []const u8, args: anytype) Error!void {
        if (self.buf.len == 0) return error.BufferTooSmall;
        const room = self.buf[self.len .. self.buf.len - 1];
        const s = std.fmt.bufPrint(room, fmt, args) catch return error.BufferTooSmall;
        self.len += s.len;
    }

    fn quoted(self: *Builder, s: []const u8) Error!void {
        if (!isRepresentable(s)) return error.Unrepresentable;
        try self.raw("\"");
        for (s) |c| {
            if (c == '"') try self.raw("\\\"") else try self.raw(&.{c});
        }
        try self.raw("\"");
    }

    fn finish(self: *Builder) [:0]const u8 {
        self.buf[self.len] = 0;
        return self.buf[0..self.len :0];
    }
};

/// `init "<path>"[, "<args>"[, "<workdir>"]]`.
/// x64dbg drops empty quoted arguments, so when only a working directory is
/// given the command line is passed as a single space.
pub fn buildInit(buf: []u8, path: []const u8, args: []const u8, workdir: []const u8) Error![:0]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.raw("init ");
    try b.quoted(path);
    if (args.len > 0 or workdir.len > 0) {
        try b.raw(", ");
        try b.quoted(if (args.len > 0) args else " ");
    }
    if (workdir.len > 0) {
        try b.raw(", ");
        if (std.mem.endsWith(u8, workdir, "\\") and !isRepresentable(workdir)) {
            // "C:\work\" -> "C:\work\\": the extra separator is harmless for
            // a directory and keeps the closing quote unescaped.
            if (!isRepresentable(workdir[0 .. workdir.len - 1])) return error.Unrepresentable;
            try b.raw("\"");
            try b.raw(workdir);
            try b.raw("\\\"");
        } else {
            try b.quoted(workdir);
        }
    }
    return b.finish();
}

/// `dbsave` or `dbsave "<path>"`.
pub fn buildDbSave(buf: []u8, path: ?[]const u8) Error![:0]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.raw("dbsave");
    if (path) |p| {
        try b.raw(" ");
        try b.quoted(p);
    }
    return b.finish();
}

/// `modexport <module>, "<path>"`.
pub fn buildModExport(buf: []u8, module: []const u8, path: []const u8) Error![:0]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.print("modexport {s}, ", .{module});
    try b.quoted(path);
    return b.finish();
}

/// `savedata "<path>", <addr_expr>, <size>`.
pub fn buildSaveData(buf: []u8, path: []const u8, addr_expr: []const u8, size: i64) Error![:0]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.raw("savedata ");
    try b.quoted(path);
    try b.print(", {s}, {d}", .{ addr_expr, size });
    return b.finish();
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "isRepresentable follows x64dbg escaping rules" {
    try testing.expect(isRepresentable("C:\\a b\\c.exe"));
    try testing.expect(isRepresentable("say \"hi\""));
    try testing.expect(isRepresentable("a\\\\\"b")); // even run before quote
    try testing.expect(isRepresentable("ends-even\\\\"));
    try testing.expect(isRepresentable(""));
    try testing.expect(!isRepresentable("a\\\"b")); // odd run before quote
    try testing.expect(!isRepresentable("ends-odd\\"));
    try testing.expect(!isRepresentable("x\\\\\\"));
    try testing.expect(!isRepresentable("line\nbreak"));
    try testing.expect(!isRepresentable("nul\x00"));
}

test "buildInit with path only keeps the v1.9 form" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("init \"C:\\t\\a.exe\"", try buildInit(&buf, "C:\\t\\a.exe", "", ""));
}

test "buildInit with arguments escapes quotes" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "init \"C:\\a.exe\", \"-f \\\"C:\\in put.txt\\\" -v\"",
        try buildInit(&buf, "C:\\a.exe", "-f \"C:\\in put.txt\" -v", ""),
    );
}

test "buildInit with working directory" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "init \"C:\\a.exe\", \"x\", \"C:\\work\"",
        try buildInit(&buf, "C:\\a.exe", "x", "C:\\work"),
    );
    // Only a working directory: arguments become a single space.
    try testing.expectEqualStrings(
        "init \"C:\\a.exe\", \" \", \"C:\\work\"",
        try buildInit(&buf, "C:\\a.exe", "", "C:\\work"),
    );
    // Trailing backslash on the directory is doubled so it cannot escape
    // the closing quote.
    try testing.expectEqualStrings(
        "init \"C:\\a.exe\", \" \", \"C:\\\\\"",
        try buildInit(&buf, "C:\\a.exe", "", "C:\\"),
    );
}

test "buildInit rejects values x64dbg cannot parse" {
    var buf: [256]u8 = undefined;
    try testing.expectError(error.Unrepresentable, buildInit(&buf, "C:\\a.exe", "trailing\\", ""));
    try testing.expectError(error.Unrepresentable, buildInit(&buf, "C:\\a.exe", "a\\\"b", ""));
    try testing.expectError(error.Unrepresentable, buildInit(&buf, "C:\\dir\\\"x.exe", "", ""));
    try testing.expectError(error.Unrepresentable, buildInit(&buf, "C:\\a.exe", "", "C:\\w\\\"x\\"));
    // Any odd trailing run in a working directory is fixed by one more '\'.
    try testing.expectEqualStrings(
        "init \"C:\\a.exe\", \" \", \"C:\\w\\\\\\\\\"",
        try buildInit(&buf, "C:\\a.exe", "", "C:\\w\\\\\\"),
    );
    try testing.expectError(error.Unrepresentable, buildInit(&buf, "C:\\a.exe", "x\ny", ""));
}

test "builders report a too-small buffer and NUL-terminate" {
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, buildInit(&tiny, "C:\\a.exe", "", ""));
    var buf: [64]u8 = undefined;
    const cmd = try buildDbSave(&buf, null);
    try testing.expectEqualStrings("dbsave", cmd);
    try testing.expectEqual(@as(u8, 0), cmd.ptr[cmd.len]);
}

test "buildModExport quotes the path and rejects an escaping trailing backslash" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("modexport kernel32, \"C:\\o\\k.dll\"", try buildModExport(&buf, "kernel32", "C:\\o\\k.dll"));
    try testing.expectError(error.Unrepresentable, buildModExport(&buf, "kernel32", "C:\\o\\"));
}

test "buildDbSave and buildSaveData quote the path" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("dbsave \"C:\\out\\a b.dd64\"", try buildDbSave(&buf, "C:\\out\\a b.dd64"));
    try testing.expectEqualStrings(
        "savedata \"C:\\out\\m.bin\", 0x401000, 4096",
        try buildSaveData(&buf, "C:\\out\\m.bin", "0x401000", 4096),
    );
}
