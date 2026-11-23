//! SSE client table with per-client bounded outbound queues
//! (pure, host-testable).
//!
//! Producers (the x64dbg callback thread via notifyEvent, HTTP threads
//! answering POST /messages) only *enqueue* frames; they never touch a
//! socket, so a stalled SSE client can never block the debugger. Each SSE
//! connection's own thread pops frames and writes them with a send timeout.
//! A client whose queue overflows (by count or bytes) is marked dead and its
//! owner thread closes the connection.
//!
//! Slots carry a generation number so a stale handle held by an exiting
//! thread can never remove or kill a newer client that reused the slot.
//!
//! Session ids are 64 random bits as 16 lowercase hex digits (unique among
//! live clients), so one client cannot guess another client's id and push
//! frames into its stream through POST /messages.
//!
//! Thread-safety: all methods are internally locked. Frames returned by
//! `pop` are owned by the caller and must be released with `free`.

const std = @import("std");
const sync = @import("sync.zig");

const Allocator = std.mem.Allocator;

pub const MAX_CLIENTS = 8;
pub const SESSION_ID_MAX = 16;

pub const Limits = struct {
    max_queued_frames: usize = 64,
    max_queued_bytes: usize = 1 << 20,
};

pub const Handle = struct { idx: u8, gen: u32 };

const State = enum { free, active, dead };

const Slot = struct {
    state: State = .free,
    gen: u32 = 0,
    session_buf: [SESSION_ID_MAX]u8 = undefined,
    session_len: usize = 0,
    queue: std.ArrayListUnmanaged([]u8) = .{},
    queued_bytes: usize = 0,
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

    /// Frees every queued frame. No other thread may use the hub afterwards.
    pub fn deinit(self: *Hub) void {
        for (&self.slots) |*s| self.clearQueue(s);
    }

    /// Registers a new client; null when the table is full.
    pub fn add(self: *Hub) ?Handle {
        self.lock.lock();
        defer self.lock.unlock();
        for (&self.slots, 0..) |*s, i| {
            if (s.state != .free) continue;
            self.newSessionId(&s.session_buf);
            s.session_len = SESSION_ID_MAX;
            s.state = .active;
            s.gen +%= 1;
            return .{ .idx = @intCast(i), .gen = s.gen };
        }
        return null;
    }

    /// Copies the client's session id into `out`.
    pub fn sessionId(self: *Hub, h: Handle, out: *[SESSION_ID_MAX]u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const s = self.slotFor(h) orelse return null;
        @memcpy(out[0..s.session_len], s.session_buf[0..s.session_len]);
        return out[0..s.session_len];
    }

    /// Releases the slot (no-op for a stale handle) and frees its queue.
    pub fn remove(self: *Hub, h: Handle) void {
        self.lock.lock();
        defer self.lock.unlock();
        const s = self.slotFor(h) orelse return;
        self.clearQueue(s);
        s.state = .free;
        s.session_len = 0;
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
        self.kill(s);
    }

    /// Marks every client dead (server shutdown).
    pub fn killAll(self: *Hub) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (&self.slots) |*s| {
            if (s.state == .active) self.kill(s);
        }
    }

    /// Queues "event: <event>\ndata: <data>\n\n" for every live client.
    /// Returns how many clients accepted the frame.
    pub fn broadcast(self: *Hub, event: []const u8, data: []const u8) usize {
        self.lock.lock();
        defer self.lock.unlock();
        var n: usize = 0;
        for (&self.slots) |*s| {
            if (s.state != .active) continue;
            if (self.enqueue(s, event, data)) n += 1;
        }
        return n;
    }

    /// Queues a frame for the live client with `session_id`.
    pub fn sendTo(self: *Hub, session_id: []const u8, event: []const u8, data: []const u8) bool {
        self.lock.lock();
        defer self.lock.unlock();
        for (&self.slots) |*s| {
            if (s.state != .active) continue;
            if (!std.mem.eql(u8, s.session_buf[0..s.session_len], session_id)) continue;
            return self.enqueue(s, event, data);
        }
        return false;
    }

    /// Takes the oldest queued frame of a live client.
    pub fn pop(self: *Hub, h: Handle) ?[]u8 {
        self.lock.lock();
        defer self.lock.unlock();
        const s = self.slotFor(h) orelse return null;
        if (s.state != .active or s.queue.items.len == 0) return null;
        const f = s.queue.orderedRemove(0);
        s.queued_bytes -= f.len;
        return f;
    }

    pub fn free(self: *Hub, frame: []u8) void {
        self.allocator.free(frame);
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

    fn kill(self: *Hub, s: *Slot) void {
        s.state = .dead;
        self.clearQueue(s);
    }

    fn clearQueue(self: *Hub, s: *Slot) void {
        for (s.queue.items) |f| self.allocator.free(f);
        s.queue.deinit(self.allocator);
        s.queue = .{};
        s.queued_bytes = 0;
    }

    /// Appends a frame; on overflow or allocation failure the client is
    /// killed (a half-delivered stream is useless) and false is returned.
    fn enqueue(self: *Hub, s: *Slot, event: []const u8, data: []const u8) bool {
        const size = "event: ".len + event.len + "\ndata: ".len + data.len + "\n\n".len;
        if (s.queue.items.len + 1 > self.limits.max_queued_frames or
            s.queued_bytes + size > self.limits.max_queued_bytes)
        {
            self.kill(s);
            return false;
        }
        const f = std.fmt.allocPrint(self.allocator, "event: {s}\ndata: {s}\n\n", .{ event, data }) catch {
            self.kill(s);
            return false;
        };
        s.queue.append(self.allocator, f) catch {
            self.allocator.free(f);
            self.kill(s);
            return false;
        };
        s.queued_bytes += f.len;
        return true;
    }
};

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

fn expectPop(hub: *Hub, h: Handle, want: []const u8) !void {
    const f = hub.pop(h) orelse return error.TestExpectedFrame;
    defer hub.free(f);
    try testing.expectEqualStrings(want, f);
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
    try expectPop(&hub, a, "event: message\ndata: {\"n\":1}\n\n");
    try expectPop(&hub, a, "event: message\ndata: {\"n\":2}\n\n");
    try testing.expectEqual(@as(?[]u8, null), hub.pop(a));
    try expectPop(&hub, b, "event: message\ndata: {\"n\":1}\n\n");
    // b still has one frame queued; deinit must free it (leak-checked).
}

test "sendTo targets one session" {
    var hub = Hub.init(testing.allocator, .{});
    defer hub.deinit();
    const a = hub.add().?;
    const b = hub.add().?;
    var idb: [SESSION_ID_MAX]u8 = undefined;
    const sid_b = hub.sessionId(b, &idb).?;
    try testing.expect(hub.sendTo(sid_b, "message", "x"));
    try testing.expectEqual(@as(?[]u8, null), hub.pop(a));
    try expectPop(&hub, b, "event: message\ndata: x\n\n");
    try testing.expect(!hub.sendTo("999999", "message", "x"));
}

test "queue overflow by count kills only that client" {
    var hub = Hub.init(testing.allocator, .{ .max_queued_frames = 2 });
    defer hub.deinit();
    const slow = hub.add().?;
    const fast = hub.add().?;
    _ = hub.broadcast("m", "1");
    _ = hub.broadcast("m", "2");
    hub.free(hub.pop(fast).?);
    hub.free(hub.pop(fast).?);
    // slow never drains: the third frame overflows its queue.
    try testing.expectEqual(@as(usize, 1), hub.broadcast("m", "3"));
    try testing.expect(!hub.isAlive(slow));
    try testing.expect(hub.isAlive(fast));
    try testing.expectEqual(@as(?[]u8, null), hub.pop(slow));
    try expectPop(&hub, fast, "event: m\ndata: 3\n\n");
}

test "queue overflow by bytes kills the client" {
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
    hub.markDead(h);
    try testing.expect(!hub.isAlive(h));
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
    try testing.expectEqual(@as(?[]u8, null), hub.pop(old));
    try expectPop(&hub, new, "event: m\ndata: x\n\n");
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
    var hub = Hub.init(std.heap.page_allocator, .{ .max_queued_frames = 1 << 20, .max_queued_bytes = 1 << 30 });
    defer hub.deinit();
    const h = hub.add().?;
    const Producer = struct {
        fn run(hb: *Hub) void {
            for (0..500) |_| _ = hb.broadcast("message", "{\"k\":\"v\"}");
        }
    };
    var ts: [3]std.Thread = undefined;
    for (&ts) |*t| t.* = try std.Thread.spawn(.{}, Producer.run, .{&hub});
    var got: usize = 0;
    var spins: usize = 0;
    while (got < 1500 and spins < 50_000_000) : (spins += 1) {
        if (hub.pop(h)) |f| {
            defer hub.free(f);
            try testing.expectEqualStrings("event: message\ndata: {\"k\":\"v\"}\n\n", f);
            got += 1;
        }
    }
    for (ts) |t| t.join();
    while (hub.pop(h)) |f| {
        hub.free(f);
        got += 1;
    }
    try testing.expectEqual(@as(usize, 1500), got);
}
