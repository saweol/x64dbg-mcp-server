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
//! rejected because a command is a single line. Arguments are separated by
//! a bare ',' (no space): whether x64dbg drops or keeps a space outside
//! quotes after a comma is the least certain part of the model, and a kept
//! space would prefix a path with ' '. Commas, braces, '$' and ';' inside
//! quotes are plain characters under this model.
//! NOTE: this quoting model follows the x64dbg source as recalled for this
//! change; it is not verified against a running x64dbg (plan item V5). The
//! tests below encode it as an executable reference tokenizer (with both
//! space variants) so V5 only has to confirm that model.
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

/// `init "<path>"[,"<args>"[,"<workdir>"]]`.
/// x64dbg drops empty quoted arguments, so when only a working directory is
/// given the command line is passed as a single space.
pub fn buildInit(buf: []u8, path: []const u8, args: []const u8, workdir: []const u8) Error![:0]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.raw("init ");
    try b.quoted(path);
    if (args.len > 0 or workdir.len > 0) {
        try b.raw(",");
        try b.quoted(if (args.len > 0) args else " ");
    }
    if (workdir.len > 0) {
        try b.raw(",");
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

/// `modexport <module>,"<path>"`.
pub fn buildModExport(buf: []u8, module: []const u8, path: []const u8) Error![:0]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.print("modexport {s},", .{module});
    try b.quoted(path);
    return b.finish();
}

/// `savedata "<path>",<addr_expr>,<size>`.
pub fn buildSaveData(buf: []u8, path: []const u8, addr_expr: []const u8, size: i64) Error![:0]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.raw("savedata ");
    try b.quoted(path);
    try b.print(",{s},{d}", .{ addr_expr, size });
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
        "init \"C:\\a.exe\",\"-f \\\"C:\\in put.txt\\\" -v\"",
        try buildInit(&buf, "C:\\a.exe", "-f \"C:\\in put.txt\" -v", ""),
    );
}

test "buildInit with working directory" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "init \"C:\\a.exe\",\"x\",\"C:\\work\"",
        try buildInit(&buf, "C:\\a.exe", "x", "C:\\work"),
    );
    // Only a working directory: arguments become a single space.
    try testing.expectEqualStrings(
        "init \"C:\\a.exe\",\" \",\"C:\\work\"",
        try buildInit(&buf, "C:\\a.exe", "", "C:\\work"),
    );
    // Trailing backslash on the directory is doubled so it cannot escape
    // the closing quote.
    try testing.expectEqualStrings(
        "init \"C:\\a.exe\",\" \",\"C:\\\\\"",
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
        "init \"C:\\a.exe\",\" \",\"C:\\w\\\\\\\\\"",
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
    try testing.expectEqualStrings("modexport kernel32,\"C:\\o\\k.dll\"", try buildModExport(&buf, "kernel32", "C:\\o\\k.dll"));
    try testing.expectError(error.Unrepresentable, buildModExport(&buf, "kernel32", "C:\\o\\"));
}

test "buildDbSave and buildSaveData quote the path" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("dbsave \"C:\\out\\a b.dd64\"", try buildDbSave(&buf, "C:\\out\\a b.dd64"));
    try testing.expectEqualStrings(
        "savedata \"C:\\out\\m.bin\",0x401000,4096",
        try buildSaveData(&buf, "C:\\out\\m.bin", "0x401000", 4096),
    );
}

// Reference model of x64dbg's command tokenizer (src/dbg/command.cpp,
// Command::Command) as recalled for this change. Outside quotes a comma ends
// an argument and a backslash escapes a following space, comma or quote.
// Inside quotes, backslash + quote is a literal quote and a backslash before
// any other character keeps both characters; the closing quote ends the
// argument, and empty arguments are dropped. What a space outside quotes
// does after the command name is the part we are least sure of, so the
// model has both variants and every builder must round-trip under both.
// Plan item V5 verifies this model against a running x64dbg.
const SpaceMode = enum { dropped, kept };

fn tokenizeModel(alloc: std.mem.Allocator, cmd: []const u8, mode: SpaceMode) !std.ArrayList([]u8) {
    var tokens = std.ArrayList([]u8).init(alloc);
    errdefer {
        for (tokens.items) |t| alloc.free(t);
        tokens.deinit();
    }
    var data = std.ArrayList(u8).init(alloc);
    defer data.deinit();
    const St = enum { default, escaped, text, text_escaped };
    var st: St = .default;
    for (cmd) |ch| {
        switch (st) {
            .default => switch (ch) {
                ' ' => {
                    if (tokens.items.len == 0) {
                        try finishToken(alloc, &tokens, &data);
                    } else if (mode == .kept) try data.append(ch);
                },
                ',' => try finishToken(alloc, &tokens, &data),
                '\\' => st = .escaped,
                '"' => st = .text,
                else => try data.append(ch),
            },
            .escaped => {
                switch (ch) {
                    ' ', ',', '"' => try data.append(ch),
                    else => try data.appendSlice(&.{ '\\', ch }),
                }
                st = .default;
            },
            .text => switch (ch) {
                '\\' => st = .text_escaped,
                '"' => {
                    try finishToken(alloc, &tokens, &data);
                    st = .default;
                },
                else => try data.append(ch),
            },
            .text_escaped => {
                if (ch == '"') try data.append(ch) else try data.appendSlice(&.{ '\\', ch });
                st = .text;
            },
        }
    }
    if (st == .escaped or st == .text_escaped) try data.append('\\');
    try finishToken(alloc, &tokens, &data);
    return tokens;
}

fn finishToken(alloc: std.mem.Allocator, tokens: *std.ArrayList([]u8), data: *std.ArrayList(u8)) !void {
    if (data.items.len == 0) return;
    try tokens.append(try alloc.dupe(u8, data.items));
    data.clearRetainingCapacity();
}

fn expectTokens(cmd: []const u8, want: []const []const u8) !void {
    for ([_]SpaceMode{ .dropped, .kept }) |mode| {
        var got = try tokenizeModel(testing.allocator, cmd, mode);
        defer {
            for (got.items) |t| testing.allocator.free(t);
            got.deinit();
        }
        if (got.items.len != want.len) {
            std.debug.print("{s} ({s}): want {d} tokens, got {d}\n", .{ cmd, @tagName(mode), want.len, got.items.len });
            for (got.items) |t| std.debug.print("  [{s}]\n", .{t});
            return error.TestUnexpectedResult;
        }
        for (want, got.items) |w, g| try testing.expectEqualStrings(w, g);
    }
}

test "tokenizer model sanity: a space after a comma is the ambiguous case" {
    var kept = try tokenizeModel(testing.allocator, "init \"a\", \"b\"", .kept);
    defer {
        for (kept.items) |t| testing.allocator.free(t);
        kept.deinit();
    }
    // Under the "kept" variant the v1.9-style separator would prefix the
    // argument with a space; the builders therefore use a bare ','.
    try testing.expectEqualStrings(" b", kept.items[2]);
}

test "buildInit round-trips through the tokenizer model" {
    const cases = [_][3][]const u8{
        .{ "C:\\t\\a.exe", "", "" },
        .{ "C:\\Program Files\\x y\\a.exe", "-f \"C:\\in put.txt\" -v", "C:\\work dir" },
        .{ "C:\\a.exe", "a,b,c {rax} $x ;y", "C:\\w,1" },
        .{ "C:\\a.exe", "x\\\\\"q\" end\\\\", "" },
        .{ "C:\\a.exe", "\\\\server\\share \\d", "C:\\" },
        .{ "C:\\a.exe", "", "C:\\work" },
    };
    var buf: [1024]u8 = undefined;
    for (cases) |c| {
        const cmd = try buildInit(&buf, c[0], c[1], c[2]);
        if (c[1].len == 0 and c[2].len == 0) {
            try expectTokens(cmd, &.{ "init", c[0] });
        } else if (c[2].len == 0) {
            try expectTokens(cmd, &.{ "init", c[0], c[1] });
        } else {
            const args = if (c[1].len > 0) c[1] else " ";
            // A trailing '\\' on the directory is doubled (harmless).
            const dir = if (std.mem.endsWith(u8, c[2], "\\") and !isRepresentable(c[2]))
                try std.fmt.allocPrint(testing.allocator, "{s}\\", .{c[2]})
            else
                try testing.allocator.dupe(u8, c[2]);
            defer testing.allocator.free(dir);
            try expectTokens(cmd, &.{ "init", c[0], args, dir });
        }
    }
}

test "dump and dbsave builders round-trip through the tokenizer model" {
    var buf: [512]u8 = undefined;
    try expectTokens(try buildSaveData(&buf, "C:\\out dir\\m,1.bin", "0x401000", 4096), &.{ "savedata", "C:\\out dir\\m,1.bin", "0x401000", "4096" });
    try expectTokens(try buildModExport(&buf, "kernel32", "C:\\o\\k {1}.dll"), &.{ "modexport", "kernel32", "C:\\o\\k {1}.dll" });
    try expectTokens(try buildDbSave(&buf, "C:\\o\\a b.dd64"), &.{ "dbsave", "C:\\o\\a b.dd64" });
    try expectTokens(try buildDbSave(&buf, null), &.{"dbsave"});
}
