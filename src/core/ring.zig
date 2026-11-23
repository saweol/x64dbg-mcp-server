//! Fixed-capacity FIFO of short text messages (no heap allocation).
//!
//! Used for the debugger event log and for the pending-event queue that is
//! appended to tool responses. When full, pushing overwrites the oldest
//! message. Messages longer than `msg_size` are truncated.
//!
//! `MessageRing` is NOT thread-safe; `LockedRing` wraps it with an SRWLOCK
//! (see sync.zig) and copies data out so callers never hold pointers into
//! storage that another thread may overwrite.

const std = @import("std");
const sync = @import("sync.zig");

pub fn MessageRing(comptime capacity: usize, comptime msg_size: usize) type {
    comptime std.debug.assert(capacity > 0 and msg_size > 0);
    return struct {
        const Self = @This();

        msgs: [capacity][msg_size]u8 = undefined,
        lens: [capacity]usize = [_]usize{0} ** capacity,
        /// Index of the oldest message.
        head: usize = 0,
        count: usize = 0,

        pub fn push(self: *Self, msg: []const u8) void {
            _ = self;
            _ = msg;
        }

        pub fn len(self: *const Self) usize {
            _ = self;
            return 0;
        }

        /// Copies message `index` (0 = oldest) into `out` and returns the
        /// copied slice (truncated to out.len). Out-of-range returns "".
        pub fn copyAt(self: *const Self, index: usize, out: []u8) []u8 {
            _ = self;
            _ = index;
            return out[0..0];
        }

        /// Removes the oldest message, copying it into `out`.
        pub fn popOldest(self: *Self, out: []u8) ?[]u8 {
            _ = self;
            _ = out;
            return null;
        }

        /// Pops messages into `out`, separated by `sep`, while each whole
        /// message fits. Messages that do not fit stay queued, except that a
        /// single message larger than an empty `out` is truncated so the
        /// queue always makes progress. Returns the number of bytes written.
        pub fn drainJoined(self: *Self, out: []u8, sep: u8) usize {
            _ = self;
            _ = out;
            _ = sep;
            return 0;
        }

        pub fn clear(self: *Self) void {
            _ = self;
        }
    };
}

/// Thread-safe wrapper around `MessageRing`.
pub fn LockedRing(comptime capacity: usize, comptime msg_size: usize) type {
    return struct {
        const Self = @This();
        pub const Ring = MessageRing(capacity, msg_size);
        pub const max_msg_len = msg_size;

        lock: sync.RwLock = .{},
        ring: Ring = .{},

        pub fn push(self: *Self, msg: []const u8) void {
            _ = self;
            _ = msg;
        }

        pub fn len(self: *Self) usize {
            _ = self;
            return 0;
        }

        pub fn copyAt(self: *Self, index: usize, out: []u8) []u8 {
            _ = self;
            _ = index;
            return out[0..0];
        }

        pub fn popOldest(self: *Self, out: []u8) ?[]u8 {
            _ = self;
            _ = out;
            return null;
        }

        pub fn drainJoined(self: *Self, out: []u8, sep: u8) usize {
            _ = self;
            _ = out;
            _ = sep;
            return 0;
        }

        pub fn clear(self: *Self) void {
            _ = self;
        }
    };
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "push and copyAt keep FIFO order" {
    var r: MessageRing(4, 16) = .{};
    r.push("one");
    r.push("two");
    try testing.expectEqual(@as(usize, 2), r.len());
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("one", r.copyAt(0, &buf));
    try testing.expectEqualStrings("two", r.copyAt(1, &buf));
    try testing.expectEqualStrings("", r.copyAt(2, &buf));
}

test "full ring overwrites the oldest message" {
    var r: MessageRing(3, 8) = .{};
    r.push("a");
    r.push("b");
    r.push("c");
    r.push("d");
    try testing.expectEqual(@as(usize, 3), r.len());
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("b", r.copyAt(0, &buf));
    try testing.expectEqualStrings("d", r.copyAt(2, &buf));
}

test "messages longer than msg_size are truncated" {
    var r: MessageRing(2, 4) = .{};
    r.push("abcdefgh");
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("abcd", r.copyAt(0, &buf));
}

test "copyAt truncates to the output buffer" {
    var r: MessageRing(2, 16) = .{};
    r.push("hello world");
    var small: [5]u8 = undefined;
    try testing.expectEqualStrings("hello", r.copyAt(0, &small));
}

test "popOldest drains in order and empties the ring" {
    var r: MessageRing(4, 16) = .{};
    r.push("x");
    r.push("y");
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("x", r.popOldest(&buf).?);
    try testing.expectEqualStrings("y", r.popOldest(&buf).?);
    try testing.expect(r.popOldest(&buf) == null);
    try testing.expectEqual(@as(usize, 0), r.len());
}

test "drainJoined joins with separator and leaves what does not fit" {
    var r: MessageRing(4, 16) = .{};
    r.push("aaaa");
    r.push("bbbb");
    r.push("cccc");
    var out: [10]u8 = undefined;
    const n = r.drainJoined(&out, '\n');
    try testing.expectEqualStrings("aaaa\nbbbb", out[0..n]);
    try testing.expectEqual(@as(usize, 1), r.len());
    const n2 = r.drainJoined(&out, '\n');
    try testing.expectEqualStrings("cccc", out[0..n2]);
    try testing.expectEqual(@as(usize, 0), r.len());
}

test "drainJoined truncates a single oversized message to make progress" {
    var r: MessageRing(2, 16) = .{};
    r.push("0123456789");
    var out: [4]u8 = undefined;
    const n = r.drainJoined(&out, '\n');
    try testing.expectEqualStrings("0123", out[0..n]);
    try testing.expectEqual(@as(usize, 0), r.len());
}

test "clear empties the ring" {
    var r: MessageRing(2, 8) = .{};
    r.push("a");
    r.clear();
    try testing.expectEqual(@as(usize, 0), r.len());
    r.push("b");
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("b", r.copyAt(0, &buf));
}

test "LockedRing survives concurrent producers and a consumer" {
    const Ring = LockedRing(16, 32);
    const Ctx = struct {
        ring: Ring = .{},
        popped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        fn produce(self: *@This()) void {
            for (0..2000) |_| self.ring.push("event-text-0123456789");
        }
        fn consume(self: *@This(), stop: *std.atomic.Value(bool)) void {
            var buf: [32]u8 = undefined;
            while (!stop.load(.acquire)) {
                if (self.ring.popOldest(&buf)) |m| {
                    // Every message must come out whole and intact.
                    if (!std.mem.eql(u8, m, "event-text-0123456789")) @panic("torn message");
                    _ = self.popped.fetchAdd(1, .monotonic);
                }
            }
        }
    };
    var ctx: Ctx = .{};
    var stop = std.atomic.Value(bool).init(false);
    const consumer = try std.Thread.spawn(.{}, Ctx.consume, .{ &ctx, &stop });
    var producers: [3]std.Thread = undefined;
    for (&producers) |*t| t.* = try std.Thread.spawn(.{}, Ctx.produce, .{&ctx});
    for (producers) |t| t.join();
    stop.store(true, .release);
    consumer.join();
    try testing.expect(ctx.ring.len() <= 16);
    var buf: [32]u8 = undefined;
    while (ctx.ring.popOldest(&buf)) |_| {}
    try testing.expectEqual(@as(usize, 0), ctx.ring.len());
}
