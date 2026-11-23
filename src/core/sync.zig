//! Locking primitives for the plugin.
//!
//! `RwLock` is a raw Win32 SRWLOCK on Windows, which is the only platform
//! the plugin runs on. It is zero-initialised, never needs to be destroyed
//! and is NOT recursive. On other hosts (unit tests only) it falls back to
//! std.Thread.RwLock so the pure modules can be tested with the same code.
//!
//! Thread-safety: every method may be called from any thread. A lock must be
//! released by the thread that acquired it, in the same mode.

const std = @import("std");
const builtin = @import("builtin");

pub const RwLock = if (builtin.os.tag == .windows) SrwLock else StdRwLock;

const SrwLock = struct {
    raw: std.os.windows.SRWLOCK = .{},

    pub fn lock(self: *SrwLock) void {
        _ = self;
    }
    pub fn unlock(self: *SrwLock) void {
        _ = self;
    }
    pub fn tryLock(self: *SrwLock) bool {
        _ = self;
        return false;
    }
    pub fn lockShared(self: *SrwLock) void {
        _ = self;
    }
    pub fn unlockShared(self: *SrwLock) void {
        _ = self;
    }
    pub fn tryLockShared(self: *SrwLock) bool {
        _ = self;
        return false;
    }
};

const StdRwLock = struct {
    inner: std.Thread.RwLock = .{},

    pub fn lock(self: *StdRwLock) void {
        _ = self;
    }
    pub fn unlock(self: *StdRwLock) void {
        _ = self;
    }
    pub fn tryLock(self: *StdRwLock) bool {
        _ = self;
        return false;
    }
    pub fn lockShared(self: *StdRwLock) void {
        _ = self;
    }
    pub fn unlockShared(self: *StdRwLock) void {
        _ = self;
    }
    pub fn tryLockShared(self: *StdRwLock) bool {
        _ = self;
        return false;
    }
};

/// Tries to take `l` exclusively, polling until `timeout_ms` elapses.
/// Returns false when the lock could not be acquired in time.
pub fn tryLockFor(l: *RwLock, timeout_ms: u64) bool {
    _ = l;
    _ = timeout_ms;
    return false;
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "exclusive lock excludes other exclusive and shared holders" {
    var l: RwLock = .{};
    l.lock();
    try testing.expect(!l.tryLock());
    try testing.expect(!l.tryLockShared());
    l.unlock();
    try testing.expect(l.tryLock());
    l.unlock();
}

test "shared lock admits other readers but not writers" {
    var l: RwLock = .{};
    l.lockShared();
    try testing.expect(l.tryLockShared());
    try testing.expect(!l.tryLock());
    l.unlockShared();
    l.unlockShared();
    try testing.expect(l.tryLock());
    l.unlock();
}

test "tryLockFor times out while the lock is held" {
    var l: RwLock = .{};
    l.lock();
    defer l.unlock();
    var timer = try std.time.Timer.start();
    try testing.expect(!tryLockFor(&l, 30));
    try testing.expect(timer.read() >= 25 * std.time.ns_per_ms);
}

test "tryLockFor succeeds once another thread releases" {
    var l: RwLock = .{};
    l.lock();
    const Releaser = struct {
        fn run(lk: *RwLock) void {
            std.Thread.sleep(20 * std.time.ns_per_ms);
            lk.unlock();
        }
    };
    const t = try std.Thread.spawn(.{}, Releaser.run, .{&l});
    try testing.expect(tryLockFor(&l, 5000));
    l.unlock();
    t.join();
}

test "lock serialises concurrent increments" {
    const Shared = struct {
        l: RwLock = .{},
        counter: usize = 0,
        fn work(self: *@This()) void {
            for (0..20000) |_| {
                self.l.lock();
                // Non-atomic read-modify-write: only correct under the lock.
                const v = self.counter;
                std.mem.doNotOptimizeAway(v);
                self.counter = v + 1;
                self.l.unlock();
            }
        }
    };
    var s: Shared = .{};
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Shared.work, .{&s});
    for (threads) |t| t.join();
    try testing.expectEqual(@as(usize, 80000), s.counter);
}
