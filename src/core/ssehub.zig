//! SSE client table with per-client bounded outbound buffers
//! (pure, host-testable).
//!
//! Producers (the x64dbg callback thread via notifyEvent, HTTP threads
//! answering POST /messages) only *queue* frames; they never touch a
//! socket, so a stalled SSE client can never block the debugger. Each SSE
//! connection's own thread reads the queued bytes and writes them with a
//! send timeout.
//!
//! Each client owns one fixed byte ring of `Limits.max_queued_bytes`,
//! allocated once by `add` (on the HTTP thread accepting the SSE
//! connection). Queueing a frame only copies bytes into that ring under the
//! lock: it never allocates, so the debugger callback thread does no
//! VirtualAlloc per event. A frame is queued whole or not at all; a client
//! whose unsent bytes would exceed its ring is marked dead and its owner
//! thread closes the connection. Readers see a plain byte stream (SSE needs
//! no frame boundaries); when `read` returns nothing, the stream is at a
//! frame boundary.
//!
//! Slots carry a generation number so a stale handle held by an exiting
//! thread can never remove or kill a newer client that reused the slot.
//!
//! Session ids are 64 random bits as 16 lowercase hex digits (unique among
//! live clients), so one client cannot guess another client's id and push
//! frames into its stream through POST /messages.
//!
//! Thread-safety: all methods are internally locked.

const std = @import("std");
const sync = @import("sync.zig");

const Allocator = std.mem.Allocator;

pub const MAX_CLIENTS = 8;
pub const SESSION_ID_MAX = 16;

pub const Limits = struct {
    /// Size of each client's outbound ring (allocated when it connects).
    /// It must hold the largest frame (a tools/call response of up to
    /// 128 KiB pushed through POST /messages) plus a backlog.
    max_queued_bytes: usize = 1 << 20,
};

pub const Handle = struct { idx: u8, gen: u32 };

const State = enum { free, active, dead };

const Slot = struct {
    state: State = .free,
    gen: u32 = 0,
    session_buf: [SESSION_ID_MAX]u8 = undefined,
    session_len: usize = 0,
    /// Outbound byte ring; owned by the slot from add() until remove().
    ring: []u8 = &.{},
    /// Index of the oldest unsent byte.
    head: usize = 0,
    /// Number of unsent bytes.
    len: usize = 0,
};

pub const Hub = struct {
    allocator: Allocator,
    limits: Limits,
    /// Source of session ids; only used under `lock`.
    random: std.Random,
    lock: sync.RwLock = .{},
    slots: [MAX_CLIENTS]Slot = [_]Slot{.{}} ** MAX_CLIENTS,

    /// Session ids come from the OS CSPRNG (std.crypto.random).
    pub fn init(allocator: Allocator, limits: Limits) Hub {
        return initWithRandom(allocator, limits, std.crypto.random);
    }

    /// Like init, with an explicit random source (tests).
    pub fn initWithRandom(allocator: Allocator, limits: Limits, random: std.Random) Hub {
        return .{ .allocator = allocator, .limits = limits, .random = random };
    }

    /// Frees every client buffer. No other thread may use the hub afterwards.
    pub fn deinit(self: *Hub) void {
        for (&self.slots) |*s| {
            self.allocator.free(s.ring);
            s.* = .{ .gen = s.gen };
        }
    }

    /// Registers a new client; null when the table is full or its buffer
    /// cannot be allocated.
    pub fn add(self: *Hub) ?Handle {
        // Allocate before taking the lock so producers never wait for it.
        const ring = self.allocator.alloc(u8, self.limits.max_queued_bytes) catch return null;
        const handle: ?Handle = blk: {
            self.lock.lock();
            defer self.lock.unlock();
            for (&self.slots, 0..) |*s, i| {
                if (s.state != .free) continue;
                self.newSessionId(&s.session_buf);
                s.session_len = SESSION_ID_MAX;
                s.state = .active;
                s.gen +%= 1;
                s.ring = ring;
                s.head = 0;
                s.len = 0;
                break :blk .{ .idx = @intCast(i), .gen = s.gen };
            }
            break :blk null;
        };
        if (handle == null) self.allocator.free(ring);
        return handle;
    }

    /// Copies the client's session id into `out`.
    pub fn sessionId(self: *Hub, h: Handle, out: *[SESSION_ID_MAX]u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const s = self.slotFor(h) orelse return null;
        @memcpy(out[0..s.session_len], s.session_buf[0..s.session_len]);
        return out[0..s.session_len];
    }

    /// Releases the slot and its buffer (no-op for a stale handle).
    pub fn remove(self: *Hub, h: Handle) void {
        const ring: []u8 = blk: {
            self.lock.lock();
            defer self.lock.unlock();
            const s = self.slotFor(h) orelse return;
            const r = s.ring;
            s.* = .{ .gen = s.gen };
            break :blk r;
        };
        self.allocator.free(ring);
    }

    pub fn isAlive(self: *Hub, h: Handle) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const s = self.slotFor(h) orelse return false;
        return s.state == .active;
    }

    pub fn markDead(self: *Hub, h: Handle) void {
        self.lock.lock();
        defer self.lock.unlock();
        const s = self.slotFor(h) orelse return;
        kill(s);
    }

    /// Marks every client dead (server shutdown).
    pub fn killAll(self: *Hub) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (&self.slots) |*s| {
            if (s.state == .active) kill(s);
        }
    }

    /// Queues "event: <event>\ndata: <data>\n\n" for every live client.
    /// Returns how many clients accepted the frame. Never allocates.
    pub fn broadcast(self: *Hub, event: []const u8, data: []const u8) usize {
        self.lock.lock();
        defer self.lock.unlock();
        var n: usize = 0;
        for (&self.slots) |*s| {
            if (s.state != .active) continue;
            if (enqueue(s, event, data)) n += 1;
        }
        return n;
    }

    /// Queues a frame for the live client with `session_id`. Never allocates.
    pub fn sendTo(self: *Hub, session_id: []const u8, event: []const u8, data: []const u8) bool {
        self.lock.lock();
        defer self.lock.unlock();
        for (&self.slots) |*s| {
            if (s.state != .active) continue;
            if (!std.mem.eql(u8, s.session_buf[0..s.session_len], session_id)) continue;
            return enqueue(s, event, data);
        }
        return false;
    }

    /// Moves up to `out.len` of the oldest unsent bytes of a live client
    /// into `out` and returns them; empty when nothing is queued or the
    /// handle is dead or stale. Frames may be split across calls.
    pub fn read(self: *Hub, h: Handle, out: []u8) []u8 {
        self.lock.lock();
        defer self.lock.unlock();
        const s = self.slotFor(h) orelse return out[0..0];
        if (s.state != .active) return out[0..0];
        const n = @min(out.len, s.len);
        if (n == 0) return out[0..0];
        const first = @min(n, s.ring.len - s.head);
        @memcpy(out[0..first], s.ring[s.head..][0..first]);
        @memcpy(out[first..n], s.ring[0 .. n - first]);
        s.head = (s.head + n) % s.ring.len;
        s.len -= n;
        // Start again at the front once drained, so an attentive client
        // keeps touching only the first pages of its buffer.
        if (s.len == 0) s.head = 0;
        return out[0..n];
    }

    pub fn activeCount(self: *Hub) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var n: usize = 0;
        for (&self.slots) |*s| {
            if (s.state == .active) n += 1;
        }
        return n;
    }

    // ── internals (caller holds the lock) ──

    /// Writes a random id that no live client uses.
    fn newSessionId(self: *Hub, out: *[SESSION_ID_MAX]u8) void {
        while (true) {
            var raw: [SESSION_ID_MAX / 2]u8 = undefined;
            self.random.bytes(&raw);
            const hex = "0123456789abcdef";
            for (raw, 0..) |b, i| {
                out[i * 2] = hex[b >> 4];
                out[i * 2 + 1] = hex[b & 0x0f];
            }
            if (!self.sessionInUse(out)) return;
        }
    }

    fn sessionInUse(self: *Hub, id: []const u8) bool {
        for (&self.slots) |*s| {
            if (s.state == .free) continue;
            if (std.mem.eql(u8, s.session_buf[0..s.session_len], id)) return true;
        }
        return false;
    }

    fn slotFor(self: *Hub, h: Handle) ?*Slot {
        if (h.idx >= MAX_CLIENTS) return null;
        const s = &self.slots[h.idx];
        if (s.state == .free or s.gen != h.gen) return null;
        return s;
    }

    /// Marks the client dead and drops what it had not received yet.
    fn kill(s: *Slot) void {
        s.state = .dead;
        s.head = 0;
        s.len = 0;
    }

    /// Copies a whole frame into the client's ring; when it does not fit
    /// the client is killed (a half-delivered stream is useless) and false
    /// is returned.
    fn enqueue(s: *Slot, event: []const u8, data: []const u8) bool {
        const parts = [_][]const u8{ "event: ", event, "\ndata: ", data, "\n\n" };
        var size: usize = 0;
        for (parts) |p| size += p.len;
        if (size > s.ring.len - s.len) {
            kill(s);
            return false;
        }
        for (parts) |p| ringWrite(s, p);
        return true;
    }

    /// Appends `bytes` behind the unsent data. The caller checked the room.
    fn ringWrite(s: *Slot, bytes: []const u8) void {
        if (bytes.len == 0) return;
        const tail = (s.head + s.len) % s.ring.len;
        const first = @min(bytes.len, s.ring.len - tail);
        @memcpy(s.ring[tail..][0..first], bytes[0..first]);
        @memcpy(s.ring[0 .. bytes.len - first], bytes[first..]);
        s.len += bytes.len;
    }
};

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

/// Reads everything queued for `h` in small chunks (so frames are split
/// across reads and the ring wraps) and compares it with `want`.
fn expectStream(hub: *Hub, h: Handle, want: []const u8) !void {
    var got = std.ArrayList(u8).init(testing.allocator);
    defer got.deinit();
    var chunk: [7]u8 = undefined;
    while (true) {
        const n = hub.read(h, &chunk);
        if (n.len == 0) break;
        try got.appendSlice(n);
    }
    try testing.expectEqualStrings(want, got.items);
}

fn sseFrame(comptime event: []const u8, comptime data: []const u8) []const u8 {
    return "event: " ++ event ++ "\ndata: " ++ data ++ "\n\n";
}

test "add assigns unique session ids up to MAX_CLIENTS" {
    var hub = Hub.init(testing.allocator, .{});
    defer hub.deinit();
    var handles: [MAX_CLIENTS]Handle = undefined;
    var ids: [MAX_CLIENTS][SESSION_ID_MAX]u8 = undefined;
    var lens: [MAX_CLIENTS]usize = undefined;
    for (&handles, 0..) |*h, i| {
        h.* = hub.add() orelse return error.TestUnexpectedResult;
        lens[i] = hub.sessionId(h.*, &ids[i]).?.len;
    }
    try testing.expectEqual(@as(?Handle, null), hub.add());
    try testing.expectEqual(@as(usize, MAX_CLIENTS), hub.activeCount());
    for (0..MAX_CLIENTS) |i| for (i + 1..MAX_CLIENTS) |j| {
        try testing.expect(!std.mem.eql(u8, ids[i][0..lens[i]], ids[j][0..lens[j]]));
    };
}

fn isLowerHex(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return false;
    return true;
}

test "session ids are random 64-bit hex values, not counters" {
    var hub = Hub.init(testing.allocator, .{});
    defer hub.deinit();
    var prev: [SESSION_ID_MAX]u8 = undefined;
    var prev_len: usize = 0;
    for (0..4) |_| {
        const h = hub.add().?;
        var buf: [SESSION_ID_MAX]u8 = undefined;
        const sid = hub.sessionId(h, &buf).?;
        try testing.expectEqual(@as(usize, 16), sid.len);
        try testing.expect(isLowerHex(sid));
        try testing.expect(!std.mem.eql(u8, sid, "1") and !std.mem.eql(u8, sid, "2"));
        if (prev_len > 0) try testing.expect(!std.mem.eql(u8, prev[0..prev_len], sid));
        @memcpy(prev[0..sid.len], sid);
        prev_len = sid.len;
        hub.remove(h);
    }
}

test "session ids stay unique when the random source repeats itself" {
    // Returns the same 8 bytes twice, then different ones.
    const Repeating = struct {
        calls: usize = 0,
        fn fill(self: *@This(), buf: []u8) void {
            const v: u8 = if (self.calls < 2) 0xAB else @intCast(self.calls);
            @memset(buf, v);
            self.calls += 1;
        }
    };
    var src: Repeating = .{};
    var hub = Hub.initWithRandom(testing.allocator, .{}, std.Random.init(&src, Repeating.fill));
    defer hub.deinit();
    const a = hub.add().?;
    const b = hub.add().?;
    var ba: [SESSION_ID_MAX]u8 = undefined;
    var bb: [SESSION_ID_MAX]u8 = undefined;
    const ida = hub.sessionId(a, &ba).?;
    const idb = hub.sessionId(b, &bb).?;
    try testing.expectEqualStrings("abababababababab", ida);
    try testing.expect(!std.mem.eql(u8, ida, idb));
    try testing.expect(src.calls >= 3);
}

test "broadcast queues SSE frames for every live client in FIFO order" {
    var hub = Hub.init(testing.allocator, .{});
    defer hub.deinit();
    const a = hub.add().?;
    const b = hub.add().?;
    try testing.expectEqual(@as(usize, 2), hub.broadcast("message", "{\"n\":1}"));
    try testing.expectEqual(@as(usize, 2), hub.broadcast("message", "{\"n\":2}"));
    try expectStream(&hub, a, comptime (sseFrame("message", "{\"n\":1}") ++ sseFrame("message", "{\"n\":2}")));
    var none: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), hub.read(a, &none).len);
    try expectStream(&hub, b, comptime (sseFrame("message", "{\"n\":1}") ++ sseFrame("message", "{\"n\":2}")));
}

test "queueing a frame never allocates (the debugger callback thread)" {
    // Only the per-client buffer (allocated by add) may come from the
    // allocator; every later allocation fails.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    var hub = Hub.init(failing.allocator(), .{ .max_queued_bytes = 4096 });
    defer hub.deinit();
    const h = hub.add().?;
    for (0..500) |i| {
        try testing.expectEqual(@as(usize, 1), hub.broadcast("message", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}"));
        if (i % 10 == 9) {
            var sink: [1024]u8 = undefined;
            while (hub.read(h, &sink).len > 0) {}
        }
    }
    try testing.expect(hub.isAlive(h));
    try testing.expectEqual(@as(usize, 1), failing.allocations);
}

test "add fails cleanly when the client buffer cannot be allocated" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var hub = Hub.init(failing.allocator(), .{});
    defer hub.deinit();
    try testing.expectEqual(@as(?Handle, null), hub.add());
    try testing.expectEqual(@as(usize, 0), hub.activeCount());
}

test "the client buffer wraps around without corrupting frames" {
    const f = comptime sseFrame("m", "0123456789");
    var hub = Hub.init(testing.allocator, .{ .max_queued_bytes = f.len * 2 + 5 });
    defer hub.deinit();
    const h = hub.add().?;
    var chunk: [5]u8 = undefined;
    var got = std.ArrayList(u8).init(testing.allocator);
    defer got.deinit();
    var wrapped = false;
    for (0..200) |i| {
        try testing.expectEqual(@as(usize, 1), hub.broadcast("m", "0123456789"));
        // Read a little less than was queued so unsent bytes stay behind
        // and the write position travels around the ring; drain fully now
        // and then before the backlog outgrows the buffer.
        for (0..5) |_| try got.appendSlice(hub.read(h, &chunk));
        if (hub.slots[h.idx].head + hub.slots[h.idx].len > hub.slots[h.idx].ring.len) wrapped = true;
        if (i % 10 == 9) {
            while (true) {
                const n = hub.read(h, &chunk);
                if (n.len == 0) break;
                try got.appendSlice(n);
            }
        }
    }
    try testing.expect(wrapped);
    while (true) {
        const n = hub.read(h, &chunk);
        if (n.len == 0) break;
        try got.appendSlice(n);
    }
    try testing.expect(hub.isAlive(h));
    try testing.expectEqual(@as(usize, 200 * f.len), got.items.len);
    var i: usize = 0;
    while (i < got.items.len) : (i += f.len) try testing.expectEqualStrings(f, got.items[i..][0..f.len]);
}

test "sendTo targets one session" {
    var hub = Hub.init(testing.allocator, .{});
    defer hub.deinit();
    const a = hub.add().?;
    const b = hub.add().?;
    var idb: [SESSION_ID_MAX]u8 = undefined;
    const sid_b = hub.sessionId(b, &idb).?;
    try testing.expect(hub.sendTo(sid_b, "message", "x"));
    try expectStream(&hub, a, "");
    try expectStream(&hub, b, comptime sseFrame("message", "x"));
    try testing.expect(!hub.sendTo("999999", "message", "x"));
}

test "queue overflow kills only the client that stopped reading" {
    const f = comptime sseFrame("m", "1");
    var hub = Hub.init(testing.allocator, .{ .max_queued_bytes = 3 * f.len });
    defer hub.deinit();
    const slow = hub.add().?;
    const fast = hub.add().?;
    for (0..3) |_| try testing.expectEqual(@as(usize, 2), hub.broadcast("m", "1"));
    try expectStream(&hub, fast, f ++ f ++ f);
    // slow never drains: the fourth frame overflows its buffer.
    try testing.expectEqual(@as(usize, 1), hub.broadcast("m", "1"));
    try testing.expect(!hub.isAlive(slow));
    try testing.expect(hub.isAlive(fast));
    try expectStream(&hub, slow, "");
    try expectStream(&hub, fast, f);
}

test "a frame larger than the client buffer kills the client" {
    var hub = Hub.init(testing.allocator, .{ .max_queued_bytes = 64 });
    defer hub.deinit();
    const h = hub.add().?;
    try testing.expectEqual(@as(usize, 0), hub.broadcast("m", "x" ** 100));
    try testing.expect(!hub.isAlive(h));
    try testing.expectEqual(@as(usize, 0), hub.broadcast("m", "y"));
}

test "dead and removed clients receive nothing" {
    var hub = Hub.init(testing.allocator, .{});
    defer hub.deinit();
    const h = hub.add().?;
    var idbuf: [SESSION_ID_MAX]u8 = undefined;
    const sid = try testing.allocator.dupe(u8, hub.sessionId(h, &idbuf).?);
    defer testing.allocator.free(sid);
    _ = hub.broadcast("m", "queued before death");
    hub.markDead(h);
    try testing.expect(!hub.isAlive(h));
    try expectStream(&hub, h, "");
    try testing.expectEqual(@as(usize, 0), hub.broadcast("m", "x"));
    try testing.expect(!hub.sendTo(sid, "m", "x"));
    hub.remove(h);
    try testing.expectEqual(@as(usize, 0), hub.activeCount());
}

test "stale handles cannot touch a client that reused the slot" {
    var hub = Hub.init(testing.allocator, .{});
    defer hub.deinit();
    const old = hub.add().?;
    hub.remove(old);
    const new = hub.add().?;
    try testing.expectEqual(old.idx, new.idx);
    try testing.expect(old.gen != new.gen);
    hub.markDead(old);
    hub.remove(old);
    try testing.expect(hub.isAlive(new));
    try testing.expect(!hub.isAlive(old));
    try testing.expectEqual(@as(usize, 1), hub.broadcast("m", "x"));
    try expectStream(&hub, old, "");
    try expectStream(&hub, new, comptime sseFrame("m", "x"));
}

test "killAll marks every client dead" {
    var hub = Hub.init(testing.allocator, .{});
    defer hub.deinit();
    const a = hub.add().?;
    const b = hub.add().?;
    hub.killAll();
    try testing.expect(!hub.isAlive(a));
    try testing.expect(!hub.isAlive(b));
}

test "concurrent producers and a consumer keep frames intact" {
    const f = comptime sseFrame("message", "{\"k\":\"v\"}");
    var hub = Hub.init(testing.allocator, .{ .max_queued_bytes = 1 << 20 });
    defer hub.deinit();
    const h = hub.add().?;
    const Producer = struct {
        fn run(hb: *Hub) void {
            for (0..500) |_| _ = hb.broadcast("message", "{\"k\":\"v\"}");
        }
    };
    var ts: [3]std.Thread = undefined;
    for (&ts) |*t| t.* = try std.Thread.spawn(.{}, Producer.run, .{&hub});
    var got = std.ArrayList(u8).init(testing.allocator);
    defer got.deinit();
    var chunk: [64]u8 = undefined;
    var spins: usize = 0;
    while (got.items.len < 1500 * f.len and spins < 50_000_000) : (spins += 1) {
        try got.appendSlice(hub.read(h, &chunk));
    }
    for (ts) |t| t.join();
    while (true) {
        const n = hub.read(h, &chunk);
        if (n.len == 0) break;
        try got.appendSlice(n);
    }
    try testing.expect(hub.isAlive(h));
    try testing.expectEqual(@as(usize, 1500 * f.len), got.items.len);
    var i: usize = 0;
    while (i < got.items.len) : (i += f.len) try testing.expectEqualStrings(f, got.items[i..][0..f.len]);
}
