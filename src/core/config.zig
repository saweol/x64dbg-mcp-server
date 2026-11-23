// Configuration dialog and persistence for x64dbg-MCP Server.
// Uses raw Win32 API to create a modal config dialog.

const std = @import("std");
const bridge = @import("bridge.zig");
const mcp = @import("mcp_server.zig");
const cfgjson = @import("cfgjson.zig");
const netpolicy = @import("netpolicy.zig");
const pathutil = @import("pathutil.zig");
const sync = @import("sync.zig");
const tools = @import("../mcp/tools.zig");

// ── Win32 types ────────────────────────────────────────────────────
const HWND = ?*anyopaque;
const HMENU = ?*anyopaque;
const HINSTANCE = ?*anyopaque;
const HFONT = ?*anyopaque;
const HBRUSH = ?*anyopaque;
const HICON = ?*anyopaque;
const HCURSOR = ?*anyopaque;
const HDC = ?*anyopaque;
const HANDLE = ?*anyopaque;
const WPARAM = usize;
const LPARAM = isize;
const LRESULT = isize;
const BOOL = i32;
const RECT = extern struct { left: i32, top: i32, right: i32, bottom: i32 };

const WNDCLASSEXA = extern struct {
    cbSize: u32 = @sizeOf(WNDCLASSEXA),
    style: u32 = 0,
    lpfnWndProc: *const fn (HWND, u32, WPARAM, LPARAM) callconv(.winapi) LRESULT,
    cbClsExtra: c_int = 0,
    cbWndExtra: c_int = 0,
    hInstance: HINSTANCE = null,
    hIcon: HICON = null,
    hCursor: HCURSOR = null,
    hbrBackground: HBRUSH = null,
    lpszMenuName: ?[*:0]const u8 = null,
    lpszClassName: [*:0]const u8,
    hIconSm: HICON = null,
};

// ── Win32 imports ──────────────────────────────────────────────────
extern "user32" fn RegisterClassExA(lpWndClass: *const WNDCLASSEXA) callconv(.winapi) u16;
extern "user32" fn CreateWindowExA(dwExStyle: u32, lpClassName: [*:0]const u8, lpWindowName: ?[*:0]const u8, dwStyle: u32, x: c_int, y: c_int, nWidth: c_int, nHeight: c_int, hWndParent: HWND, hMenu: HMENU, hInstance: HINSTANCE, lpParam: ?*anyopaque) callconv(.winapi) HWND;
extern "user32" fn DestroyWindow(hWnd: HWND) callconv(.winapi) BOOL;
extern "user32" fn ShowWindow(hWnd: HWND, nCmdShow: c_int) callconv(.winapi) BOOL;
extern "user32" fn UpdateWindow(hWnd: HWND) callconv(.winapi) BOOL;
extern "user32" fn GetMessageA(lpMsg: *MSG, hWnd: HWND, wMsgFilterMin: u32, wMsgFilterMax: u32) callconv(.winapi) BOOL;
extern "user32" fn TranslateMessage(lpMsg: *const MSG) callconv(.winapi) BOOL;
extern "user32" fn DispatchMessageA(lpMsg: *const MSG) callconv(.winapi) LRESULT;
extern "user32" fn PostQuitMessage(nExitCode: c_int) callconv(.winapi) void;
extern "user32" fn SendMessageA(hWnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT;
extern "user32" fn GetWindowTextA(hWnd: HWND, lpString: [*]u8, nMaxCount: c_int) callconv(.winapi) c_int;
extern "user32" fn SetFocus(hWnd: HWND) callconv(.winapi) HWND;
extern "user32" fn SetForegroundWindow(hWnd: HWND) callconv(.winapi) BOOL;
extern "user32" fn EnableWindow(hWnd: HWND, bEnable: BOOL) callconv(.winapi) BOOL;
extern "user32" fn IsDialogMessageA(hDlg: HWND, lpMsg: *MSG) callconv(.winapi) BOOL;
extern "user32" fn GetSystemMetrics(nIndex: c_int) callconv(.winapi) c_int;
extern "user32" fn SetWindowPos(hWnd: HWND, hWndInsertAfter: HWND, x: c_int, y: c_int, cx: c_int, cy: c_int, uFlags: u32) callconv(.winapi) BOOL;
extern "user32" fn MessageBoxA(hWnd: HWND, lpText: [*:0]const u8, lpCaption: [*:0]const u8, uType: u32) callconv(.winapi) c_int;
extern "gdi32" fn CreateFontA(cHeight: c_int, cWidth: c_int, cEscapement: c_int, cOrientation: c_int, cWeight: c_int, bItalic: u32, bUnderline: u32, bStrikeOut: u32, iCharSet: u32, iOutPrecision: u32, iClipPrecision: u32, iQuality: u32, iPitchAndFamily: u32, pszFaceName: [*:0]const u8) callconv(.winapi) HFONT;
extern "gdi32" fn DeleteObject(ho: ?*anyopaque) callconv(.winapi) BOOL;
extern "user32" fn DefWindowProcA(hWnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT;
extern "user32" fn OpenClipboard(hWndNewOwner: HWND) callconv(.winapi) BOOL;
extern "user32" fn CloseClipboard() callconv(.winapi) BOOL;
extern "user32" fn EmptyClipboard() callconv(.winapi) BOOL;
extern "user32" fn SetClipboardData(uFormat: u32, hMem: HANDLE) callconv(.winapi) HANDLE;
extern "gdi32" fn GetStockObject(i: c_int) callconv(.winapi) ?*anyopaque;
extern "gdi32" fn SetBkColor(hdc: HDC, color: u32) callconv(.winapi) u32;

extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(.winapi) HINSTANCE;
extern "kernel32" fn CreateFileA(name: [*:0]const u8, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: ?*anyopaque) callconv(.winapi) HANDLE;
extern "kernel32" fn ReadFile(h: ?*anyopaque, buf: [*]u8, len: u32, read: *u32, ov: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn WriteFile(h: ?*anyopaque, buf: [*]const u8, len: u32, written: *u32, ov: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn CloseHandle(h: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn GetModuleFileNameA(hModule: HINSTANCE, lpFilename: [*]u8, nSize: u32) callconv(.winapi) u32;
extern "kernel32" fn CreateThread(sa: ?*anyopaque, stackSize: usize, startAddr: *const fn (?*anyopaque) callconv(.winapi) u32, param: ?*anyopaque, flags: u32, id: ?*u32) callconv(.winapi) HANDLE;
extern "kernel32" fn GlobalAlloc(uFlags: u32, dwBytes: usize) callconv(.winapi) HANDLE;
extern "kernel32" fn GlobalLock(hMem: HANDLE) callconv(.winapi) ?[*]u8;
extern "kernel32" fn GlobalUnlock(hMem: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn GetFileSizeEx(h: ?*anyopaque, size: *i64) callconv(.winapi) BOOL;
extern "kernel32" fn MoveFileExA(existing: [*:0]const u8, new: [*:0]const u8, flags: u32) callconv(.winapi) BOOL;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

const MSG = extern struct {
    hwnd: HWND,
    message: u32,
    wParam: WPARAM,
    lParam: LPARAM,
    time: u32,
    pt_x: i32,
    pt_y: i32,
};

// ── Win32 constants ────────────────────────────────────────────────
const WS_OVERLAPPED: u32 = 0x00000000;
const WS_CAPTION: u32 = 0x00C00000;
const WS_SYSMENU: u32 = 0x00080000;
const WS_CHILD: u32 = 0x40000000;
const WS_VISIBLE: u32 = 0x10000000;
const WS_TABSTOP: u32 = 0x00010000;
const WS_GROUP: u32 = 0x00020000;
const WS_BORDER: u32 = 0x00800000;
const WS_EX_DLGMODALFRAME: u32 = 0x00000001;
const WS_EX_CLIENTEDGE: u32 = 0x00000200;
const ES_AUTOHSCROLL: u32 = 0x0080;
const BS_DEFPUSHBUTTON: u32 = 0x0001;
const BS_AUTOCHECKBOX: u32 = 0x0003;
const BM_SETCHECK: u32 = 0x00F1;
const BM_GETCHECK: u32 = 0x00F0;
const BST_CHECKED: u32 = 1;
const WM_CREATE: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_CLOSE: u32 = 0x0010;
const WM_COMMAND: u32 = 0x0111;
const WM_SETFONT: u32 = 0x0030;
const WM_SETTEXT: u32 = 0x000C;
const SM_CXSCREEN: c_int = 0;
const SM_CYSCREEN: c_int = 1;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOACTIVATE: u32 = 0x0010;
const WM_DPICHANGED: u32 = 0x02E0;
const USER_DEFAULT_SCREEN_DPI: u32 = 96;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_SHARE_READ: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const CREATE_ALWAYS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE: HANDLE = @ptrFromInt(@as(usize, @truncate(@as(u128, 0xFFFFFFFFFFFFFFFF))));
const ES_READONLY: u32 = 0x0800;
const IDC_IP: c_int = 101;
const IDC_PORT: c_int = 102;
const IDC_URL: c_int = 103;
const IDC_AUTOSTART: c_int = 104;
const IDC_TOKEN: c_int = 105;
const IDC_GENERATE: c_int = 106;
const IDC_COPY_TOKEN: c_int = 107;
const IDC_SAVE: c_int = 1;
const IDC_CANCEL: c_int = 2;
const BN_CLICKED: u32 = 0;
const WM_CTLCOLORSTATIC: u32 = 0x0138;
const CF_TEXT: u32 = 1;
const GMEM_MOVEABLE: u32 = 0x0002;
const WHITE_BRUSH: c_int = 0;

// ── DPI awareness (runtime-resolved for Win7/8 compat) ─────────────
const DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2: ?*anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -4))));

extern "kernel32" fn GetProcAddress(hModule: HINSTANCE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "user32" fn GetDlgItem(hDlg: HWND, nIDDlgItem: c_int) callconv(.winapi) HWND;

const SetThreadDpiAwarenessContextFn = *const fn (?*anyopaque) callconv(.winapi) ?*anyopaque;
const GetDpiForSystemFn = *const fn () callconv(.winapi) u32;
const GetDpiForWindowFn = *const fn (HWND) callconv(.winapi) u32;

var pfnSetThreadDpiAwarenessContext: ?SetThreadDpiAwarenessContextFn = null;
var pfnGetDpiForSystem: ?GetDpiForSystemFn = null;
var pfnGetDpiForWindow: ?GetDpiForWindowFn = null;
var dpi_funcs_resolved: bool = false;

fn resolveDpiFuncs() void {
    if (dpi_funcs_resolved) return;
    dpi_funcs_resolved = true;
    const user32 = GetModuleHandleA("user32.dll\x00");
    if (user32 == null) return;
    pfnSetThreadDpiAwarenessContext = @ptrCast(GetProcAddress(user32, "SetThreadDpiAwarenessContext\x00"));
    pfnGetDpiForSystem = @ptrCast(GetProcAddress(user32, "GetDpiForSystem\x00"));
    pfnGetDpiForWindow = @ptrCast(GetProcAddress(user32, "GetDpiForWindow\x00"));
}

fn setPerMonitorV2() bool {
    resolveDpiFuncs();
    if (pfnSetThreadDpiAwarenessContext) |f| return f(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) != null;
    return false;
}

fn getDpiForSystem() u32 {
    if (pfnGetDpiForSystem) |f| return f();
    return USER_DEFAULT_SCREEN_DPI;
}

fn getDpiForWindow(hwnd: HWND) u32 {
    if (pfnGetDpiForWindow) |f| {
        const dpi = f(hwnd);
        if (dpi != 0) return dpi;
    }
    return getDpiForSystem();
}

/// Scale a 96-DPI design unit by the current DPI.
fn sd(design: c_int, dpi: u32) c_int {
    return @intCast(@divTrunc(@as(i64, design) * dpi, USER_DEFAULT_SCREEN_DPI));
}

/// RtlGenRandom (SystemFunction036); false when it fails.
fn osRandom(buf: []u8) bool {
    std.os.windows.RtlGenRandom(buf) catch return false;
    return true;
}

/// Generates a 32-character hex token. False when the OS random source
/// failed; the caller must then not store any token.
fn generateToken(buf: *[cfgjson.GENERATED_TOKEN_LEN]u8) bool {
    return cfgjson.generateToken(osRandom, buf);
}

// ── Config data ────────────────────────────────────────────────────
//
// mcp_config.json is parsed and written by cfgjson.zig (std.json, no
// fixed-size buffers). The dialog edits the four v1.9 fields; every other
// key (AllowExternal, AllowedClients, MaxClients, EnableSse, ArtifactDir,
// AuthMaxFailures, AuthLockoutSeconds and unknown keys) is file-only and is
// preserved when the dialog saves.
//
// Thread-safety: load()/save() are serialised by `file_lock` (they run on
// the plugin setup thread and on the dialog thread).

pub const LoadStatus = enum {
    /// File parsed (a missing AuthToken was generated and saved).
    ok,
    /// No file existed; defaults with a fresh token were written.
    created,
    /// The file exists but could not be read or parsed. Defaults are
    /// returned, the file is left untouched and the server must not start.
    invalid,
};

pub const Loaded = struct {
    owned: cfgjson.Owned,
    status: LoadStatus,
    /// Static description of why the file is invalid ("" otherwise).
    problem: []const u8 = "",

    pub fn deinit(self: *Loaded) void {
        self.owned.deinit();
    }
};

const config_allocator = std.heap.page_allocator;
var file_lock: sync.RwLock = .{};

pub fn defaultPort() u16 {
    return if (@sizeOf(usize) == 8) 9094 else 9095;
}

var config_path: [512]u8 = undefined;
var config_path_len: usize = 0;

fn getConfigPath() [*:0]const u8 {
    if (config_path_len > 0) return @ptrCast(&config_path);

    var module_path: [512]u8 = undefined;
    const len = GetModuleFileNameA(null, &module_path, 512);
    if (len == 0 or len >= 512) {
        const fallback = "mcp_config.json";
        @memcpy(config_path[0..fallback.len], fallback);
        config_path[fallback.len] = 0;
        config_path_len = fallback.len;
        return @ptrCast(&config_path);
    }

    // Find last backslash
    var last_sep: usize = 0;
    for (0..len) |i| {
        if (module_path[i] == '\\') last_sep = i;
    }

    const filename = "mcp_config.json";
    if (last_sep + 1 + filename.len + 1 > config_path.len) {
        @memcpy(config_path[0..filename.len], filename);
        config_path[filename.len] = 0;
        config_path_len = filename.len;
        return @ptrCast(&config_path);
    }
    @memcpy(config_path[0 .. last_sep + 1], module_path[0 .. last_sep + 1]);
    @memcpy(config_path[last_sep + 1 .. last_sep + 1 + filename.len], filename);
    config_path[last_sep + 1 + filename.len] = 0;
    config_path_len = last_sep + 1 + filename.len;
    return @ptrCast(&config_path);
}

const ReadError = error{ FileNotFound, TooLarge, ReadFailed, OutOfMemory };

/// Reads the whole config file into a heap buffer owned by the caller.
fn readConfigFile(allocator: std.mem.Allocator) ReadError![]u8 {
    const h = CreateFileA(getConfigPath(), GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    if (h == INVALID_HANDLE or h == null) {
        const err = GetLastError();
        return if (err == ERROR_FILE_NOT_FOUND or err == ERROR_PATH_NOT_FOUND) error.FileNotFound else error.ReadFailed;
    }
    defer _ = CloseHandle(h);

    var size: i64 = 0;
    if (GetFileSizeEx(h, &size) == 0 or size < 0) return error.ReadFailed;
    if (size > cfgjson.MAX_CONFIG_BYTES) return error.TooLarge;
    const total: usize = @intCast(size);
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    var got: usize = 0;
    while (got < total) {
        var n: u32 = 0;
        if (ReadFile(h, buf[got..].ptr, @intCast(total - got), &n, null) == 0) return error.ReadFailed;
        if (n == 0) break;
        got += n;
    }
    return buf[0..got];
}

/// Stores a freshly generated token in `owned`. False (token left as it
/// was) when no random token could be generated.
fn generateTokenInto(owned: *cfgjson.Owned) bool {
    var tok: [cfgjson.GENERATED_TOKEN_LEN]u8 = undefined;
    if (!generateToken(&tok)) {
        logLine("Could not generate a random AuthToken (RtlGenRandom failed).", .{});
        return false;
    }
    owned.config.auth_token = owned.dupe(&tok) catch return false;
    return true;
}

fn logLine(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrintZ(&buf, "[x64dbg-MCP Server] " ++ fmt, args) catch return;
    bridge.logPuts(s.ptr);
}

fn invalidLoaded(problem: []const u8) Loaded {
    return .{ .owned = cfgjson.initDefault(config_allocator, defaultPort()), .status = .invalid, .problem = problem };
}

/// Loads mcp_config.json (next to the x64dbg executable).
pub fn load() Loaded {
    file_lock.lock();
    defer file_lock.unlock();

    const text = readConfigFile(config_allocator) catch |err| switch (err) {
        error.FileNotFound => {
            var owned = cfgjson.initDefault(config_allocator, defaultPort());
            // Without a token the server refuses to start (MissingToken), so
            // do not write a file that would look configured.
            if (generateTokenInto(&owned) and !saveLocked(&owned.config)) logLine("Could not write mcp_config.json.", .{});
            return .{ .owned = owned, .status = .created };
        },
        error.TooLarge => {
            logLine("mcp_config.json is larger than 64 KiB; ignoring it.", .{});
            return invalidLoaded("the file is larger than 64 KiB");
        },
        error.ReadFailed, error.OutOfMemory => {
            logLine("mcp_config.json could not be read.", .{});
            return invalidLoaded("the file could not be read");
        },
    };
    defer config_allocator.free(text);

    var diag: cfgjson.Diagnostic = .{};
    var owned = cfgjson.parse(config_allocator, text, defaultPort(), &diag) catch |err| {
        if (diag.key.len > 0) {
            logLine("mcp_config.json: \"{s}\" {s}.", .{ diag.key, diag.reason });
        } else {
            logLine("mcp_config.json is invalid ({s}: {s}).", .{ @errorName(err), diag.reason });
        }
        return invalidLoaded(if (diag.reason.len > 0) diag.reason else "the file is not valid");
    };
    if (owned.config.auth_token.len == 0) {
        if (generateTokenInto(&owned) and !saveLocked(&owned.config)) logLine("Could not write mcp_config.json.", .{});
    }
    return .{ .owned = owned, .status = .ok };
}

/// Writes the config atomically (temp file + MoveFileEx). Returns false on
/// failure; the previous file is then left as it was.
pub fn save(cfg: *const cfgjson.Config) bool {
    file_lock.lock();
    defer file_lock.unlock();
    return saveLocked(cfg);
}

fn saveLocked(cfg: *const cfgjson.Config) bool {
    const text = cfgjson.serialize(config_allocator, cfg) catch return false;
    defer config_allocator.free(text);

    const path = getConfigPath();
    var tmp_buf: [config_path.len + 8]u8 = undefined;
    const tmp = std.fmt.bufPrintZ(&tmp_buf, "{s}.tmp", .{std.mem.span(path)}) catch return false;

    {
        const h = CreateFileA(tmp.ptr, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
        if (h == INVALID_HANDLE or h == null) return false;
        defer _ = CloseHandle(h);
        var written: u32 = 0;
        if (WriteFile(h, text.ptr, @intCast(text.len), &written, null) == 0 or written != text.len) return false;
    }
    return MoveFileExA(tmp.ptr, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

/// Pushes a configuration into the running plugin (server settings and the
/// runtime ArtifactDir). The server picks the settings up on its next start.
pub fn applyToRuntime(cfg: *const cfgjson.Config) void {
    mcp.applyConfig(cfg);
    tools.artifact_dir.set(cfg.artifact_dir) catch |err| {
        logLine("ArtifactDir ignored: {s}.", .{pathutil.describe(err)});
    };
}

fn parsePort(s: []const u8) ?u16 {
    var val: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        val = val * 10 + (c - '0');
        if (val > 65535) return null;
    }
    if (val == 0) return null;
    return @intCast(val);
}

fn fmtU16(val: u16, buf: *[6]u8) usize {
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    var v = val;
    var i: usize = 0;
    while (v > 0) : (i += 1) {
        buf[5 - i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
    // Shift to start
    var j: usize = 0;
    while (j < i) : (j += 1) {
        buf[j] = buf[6 - i + j];
    }
    return i;
}

// ── Dialog ─────────────────────────────────────────────────────────

var dlg_hwnd: HWND = null;
var edit_ip: HWND = null;
var edit_port: HWND = null;
var edit_token: HWND = null;
var lbl_url: HWND = null;
var chk_autostart: HWND = null;
var ui_font: HFONT = null;
var ui_font_bold: HFONT = null;
var ui_font_small: HFONT = null;
var class_registered: bool = false;
var parent_hwnd: HWND = null;
/// Config loaded when the dialog opened; kept so Save preserves the
/// file-only keys. Only touched by the dialog thread.
var dialog_cfg: ?Loaded = null;

const DLG_W = 450;
const DLG_H = 370;
const CLASS_NAME = "MCPServerConfig\x00";

var cur_dpi: u32 = 96;

pub fn showDialog(parentHwnd: usize) void {
    parent_hwnd = @ptrFromInt(parentHwnd);
    _ = CreateThread(null, 0, dialogThread, null, 0, null);
}

fn dialogThread(_: ?*anyopaque) callconv(.winapi) u32 {
    // Opt this thread (and the dialog it creates) into per-monitor DPI scaling
    // without changing the awareness of the host x64dbg process.
    if (!setPerMonitorV2()) {
        // Pre-Win10 Creators Update: fall back to system DPI.
    }

    const hInst = GetModuleHandleA(null);

    if (!class_registered) {
        const wc = WNDCLASSEXA{
            .lpfnWndProc = wndProc,
            .hInstance = hInst,
            .hbrBackground = @ptrFromInt(@as(usize, @intCast(1 + @as(c_int, 15)))),
            .lpszClassName = CLASS_NAME,
            .hCursor = null,
        };
        _ = RegisterClassExA(&wc);
        class_registered = true;
    }

    cur_dpi = getDpiForSystem();
    createFonts();

    dlg_hwnd = CreateWindowExA(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        "MCP Server Configuration\x00",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        100,
        100,
        sd(DLG_W, cur_dpi),
        sd(DLG_H, cur_dpi),
        parent_hwnd,
        null,
        hInst,
        null,
    );

    if (dlg_hwnd == null) return 1;

    // Disable parent
    if (parent_hwnd != null) _ = EnableWindow(parent_hwnd, 0);

    // Center on screen
    const sw = GetSystemMetrics(SM_CXSCREEN);
    const sh = GetSystemMetrics(SM_CYSCREEN);
    _ = SetWindowPos(dlg_hwnd, null, @divTrunc(sw - sd(DLG_W, cur_dpi), 2), @divTrunc(sh - sd(DLG_H, cur_dpi), 2), 0, 0, SWP_NOZORDER | SWP_NOSIZE);

    _ = ShowWindow(dlg_hwnd, 5);
    _ = UpdateWindow(dlg_hwnd);

    var msg: MSG = undefined;
    while (GetMessageA(&msg, null, 0, 0) > 0) {
        if (IsDialogMessageA(dlg_hwnd, &msg) == 0) {
            _ = TranslateMessage(&msg);
            _ = DispatchMessageA(&msg);
        }
    }

    if (ui_font != null) { _ = DeleteObject(ui_font); ui_font = null; }
    if (ui_font_bold != null) { _ = DeleteObject(ui_font_bold); ui_font_bold = null; }
    if (ui_font_small != null) { _ = DeleteObject(ui_font_small); ui_font_small = null; }

    return 0;
}

fn createFonts() void {
    if (ui_font != null) _ = DeleteObject(ui_font);
    if (ui_font_bold != null) _ = DeleteObject(ui_font_bold);
    if (ui_font_small != null) _ = DeleteObject(ui_font_small);
    ui_font = CreateFontA(-sd(14, cur_dpi), 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI\x00");
    ui_font_bold = CreateFontA(-sd(14, cur_dpi), 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI\x00");
    ui_font_small = CreateFontA(-sd(12, cur_dpi), 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI\x00");
}

fn createCtrl(class: [*:0]const u8, text: ?[*:0]const u8, style: u32, x: c_int, y: c_int, w: c_int, h: c_int, id: c_int) HWND {
    const hInst = GetModuleHandleA(null);
    const hwnd = CreateWindowExA(
        if (std.mem.eql(u8, std.mem.span(class), "EDIT")) WS_EX_CLIENTEDGE else 0,
        class,
        text,
        WS_CHILD | WS_VISIBLE | style,
        sd(x, cur_dpi),
        sd(y, cur_dpi),
        sd(w, cur_dpi),
        sd(h, cur_dpi),
        dlg_hwnd,
        @ptrFromInt(@as(usize, @intCast(id))),
        hInst,
        null,
    );
    if (hwnd != null and ui_font != null) {
        _ = SendMessageA(hwnd, WM_SETFONT, @intFromPtr(ui_font.?), 1);
    }
    return hwnd;
}

fn wndProc(hwnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT {
    switch (msg) {
        WM_CREATE => {
            dlg_hwnd = hwnd;
            if (dialog_cfg) |*old| old.deinit();
            dialog_cfg = load();
            const cfg = &dialog_cfg.?.owned.config;

            // Use the actual monitor DPI for the window we just created.
            cur_dpi = getDpiForWindow(hwnd);
            createFonts();

            // Row 1: IP Address
            _ = createCtrl("STATIC\x00", "IP Address:\x00", 0, 20, 24, 85, 20, 0);
            edit_ip = createCtrl("EDIT\x00", null, WS_TABSTOP | ES_AUTOHSCROLL, 112, 20, 190, 24, IDC_IP);
            // Only suggest what starts without the file-only keys; the notes
            // below explain AllowExternal + AllowedClients.
            const ip_hint = createCtrl("STATIC\x00", netpolicy.BIND_ADDRESS_HINT ++ "\x00", 0, 310, 24, 120, 20, 0);
            if (ip_hint != null and ui_font_small != null)
                _ = SendMessageA(ip_hint, WM_SETFONT, @intFromPtr(ui_font_small.?), 1);

            // Row 2: Port
            _ = createCtrl("STATIC\x00", "Port:\x00", 0, 20, 60, 85, 20, 0);
            edit_port = createCtrl("EDIT\x00", null, WS_TABSTOP | ES_AUTOHSCROLL, 112, 56, 100, 24, IDC_PORT);
            const port_hint = createCtrl("STATIC\x00", "(1 - 65535)\x00", 0, 220, 60, 80, 20, 0);
            if (port_hint != null and ui_font_small != null)
                _ = SendMessageA(port_hint, WM_SETFONT, @intFromPtr(ui_font_small.?), 1);

            // Row 3: Auto Start checkbox
            chk_autostart = createCtrl("BUTTON\x00", "Auto start server on plugin load\x00", WS_TABSTOP | BS_AUTOCHECKBOX, 20, 96, 250, 20, IDC_AUTOSTART);
            if (chk_autostart != null and cfg.auto_start)
                _ = SendMessageA(chk_autostart, BM_SETCHECK, BST_CHECKED, 0);

            // Row 4: Auth Token
            _ = createCtrl("STATIC\x00", "Auth Token:\x00", 0, 20, 132, 85, 20, 0);
            edit_token = createCtrl("EDIT\x00", null, WS_TABSTOP | ES_AUTOHSCROLL | ES_READONLY, 112, 128, 190, 24, IDC_TOKEN);
            _ = createCtrl("BUTTON\x00", "Generate\x00", WS_TABSTOP, 310, 128, 65, 24, IDC_GENERATE);
            _ = createCtrl("BUTTON\x00", "Copy\x00", WS_TABSTOP, 380, 128, 45, 24, IDC_COPY_TOKEN);

            const auth_hint = createCtrl("STATIC\x00", "Token is auto-generated on first run and persists across restarts.\x00", 0, 112, 155, 320, 16, 0);
            if (auth_hint != null and ui_font_small != null)
                _ = SendMessageA(auth_hint, WM_SETFONT, @intFromPtr(ui_font_small.?), 1);

            // Row 5: URL preview
            _ = createCtrl("STATIC\x00", "Server URL:\x00", 0, 20, 185, 85, 20, 0);
            lbl_url = createCtrl("STATIC\x00", null, 0, 112, 185, 310, 20, IDC_URL);
            if (lbl_url != null and ui_font_bold != null)
                _ = SendMessageA(lbl_url, WM_SETFONT, @intFromPtr(ui_font_bold.?), 1);

            // Help notes
            const notes = createCtrl("STATIC\x00",
                "127.0.0.1 = local only (default). Any other bind address\r\nneeds AllowExternal + AllowedClients in mcp_config.json.\r\nSave will automatically restart the MCP server.\x00",
                0, 20, 210, 400, 52, 0);
            if (notes != null and ui_font_small != null)
                _ = SendMessageA(notes, WM_SETFONT, @intFromPtr(ui_font_small.?), 1);

            // Buttons
            _ = createCtrl("BUTTON\x00", "Save\x00", WS_TABSTOP | BS_DEFPUSHBUTTON, 240, 280, 90, 30, IDC_SAVE);
            _ = createCtrl("BUTTON\x00", "Cancel\x00", WS_TABSTOP, 340, 280, 90, 30, IDC_CANCEL);
            // Set initial values
            if (edit_ip != null) {
                var ip_z: [cfgjson.MAX_IP_LEN + 1]u8 = undefined;
                const n = @min(cfg.ip_address.len, cfgjson.MAX_IP_LEN);
                @memcpy(ip_z[0..n], cfg.ip_address[0..n]);
                ip_z[n] = 0;
                _ = SendMessageA(edit_ip, WM_SETTEXT, 0, @bitCast(@intFromPtr(&ip_z)));
            }
            if (edit_port != null) {
                var port_buf: [6]u8 = undefined;
                const port_len = fmtU16(cfg.port, &port_buf);
                port_buf[port_len] = 0;
                _ = SendMessageA(edit_port, WM_SETTEXT, 0, @bitCast(@intFromPtr(&port_buf)));
            }
            if (edit_token != null and cfg.auth_token.len > 0) {
                var tok_z: [cfgjson.MAX_TOKEN_LEN + 1]u8 = undefined;
                const n = @min(cfg.auth_token.len, cfgjson.MAX_TOKEN_LEN);
                @memcpy(tok_z[0..n], cfg.auth_token[0..n]);
                tok_z[n] = 0;
                _ = SendMessageA(edit_token, WM_SETTEXT, 0, @bitCast(@intFromPtr(&tok_z)));
            }
            updateUrlPreview();

            if (edit_ip != null) _ = SetFocus(edit_ip);

            if (dialog_cfg.?.status == .invalid) {
                var msg_buf: [256]u8 = undefined;
                const text = std.fmt.bufPrintZ(&msg_buf, "mcp_config.json could not be loaded ({s}).\r\nSaving here replaces it with a new file containing these settings.", .{dialog_cfg.?.problem}) catch "mcp_config.json could not be loaded.";
                _ = MessageBoxA(hwnd, text.ptr, "MCP Server Configuration\x00", 0x30);
            }
            return 0;
        },
        WM_COMMAND => {
            const id: c_int = @intCast(wParam & 0xFFFF);
            const notify: u32 = @intCast((wParam >> 16) & 0xFFFF);

            if (id == IDC_SAVE and notify == BN_CLICKED) {
                onSave(hwnd);
                return 0;
            }
            if (id == IDC_CANCEL and notify == BN_CLICKED) {
                restoreParent();
                _ = DestroyWindow(hwnd);
                return 0;
            }
            if (id == IDC_GENERATE and notify == BN_CLICKED) {
                if (edit_token != null) {
                    var tok_z: [cfgjson.GENERATED_TOKEN_LEN + 1]u8 = undefined;
                    if (!generateToken(tok_z[0..cfgjson.GENERATED_TOKEN_LEN])) {
                        _ = MessageBoxA(hwnd, "Could not generate a random token (the Windows random source failed). The current token is unchanged.\x00", "MCP Server Configuration\x00", 0x10);
                        return 0;
                    }
                    tok_z[cfgjson.GENERATED_TOKEN_LEN] = 0;
                    _ = SendMessageA(edit_token, WM_SETTEXT, 0, @bitCast(@intFromPtr(&tok_z)));
                }
                return 0;
            }
            if (id == IDC_COPY_TOKEN and notify == BN_CLICKED) {
                if (edit_token != null) {
                    // nMaxCount includes the NUL, so 64-char tokens need 65.
                    var tbuf: [cfgjson.MAX_TOKEN_LEN + 1]u8 = undefined;
                    const tlen: usize = @intCast(GetWindowTextA(edit_token, &tbuf, tbuf.len));
                    if (tlen > 0) {
                        if (OpenClipboard(hwnd) != 0) {
                            _ = EmptyClipboard();
                            const hmem = GlobalAlloc(GMEM_MOVEABLE, tlen + 1);
                            if (hmem != null) {
                                const ptr = GlobalLock(hmem);
                                if (ptr) |p| {
                                    @memcpy(p[0..tlen], tbuf[0..tlen]);
                                    p[tlen] = 0;
                                    _ = GlobalUnlock(hmem);
                                    _ = SetClipboardData(CF_TEXT, hmem);
                                }
                            }
                            _ = CloseClipboard();
                        }
                    }
                }
                return 0;
            }
            // Update URL preview on text change (EN_CHANGE = 0x0300)
            if (notify == 0x0300 and (id == IDC_IP or id == IDC_PORT)) {
                updateUrlPreview();
            }
            return 0;
        },
        WM_CTLCOLORSTATIC => {
            const ctrl: HWND = @ptrFromInt(@as(usize, @bitCast(lParam)));
            if (ctrl == edit_token) {
                const hdc: HDC = @ptrFromInt(wParam);
                _ = SetBkColor(hdc, 0x00FFFFFF);
                return @bitCast(@intFromPtr(GetStockObject(WHITE_BRUSH)));
            }
            return DefWindowProcA(hwnd, msg, wParam, lParam);
        },
        WM_DPICHANGED => {
            const new_dpi: u32 = @intCast(wParam & 0xFFFF);
            if (new_dpi == 0 or new_dpi == cur_dpi) return 0;
            cur_dpi = new_dpi;
            const rect: *const RECT = @ptrCast(@alignCast(@as([*]const u8, @ptrFromInt(@as(usize, @bitCast(lParam))))[0..@sizeOf(RECT)].ptr));
            _ = SetWindowPos(
                hwnd,
                null,
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            createFonts();
            relayoutChildren();
            return 0;
        },
        WM_CLOSE => {
            restoreParent();
            _ = DestroyWindow(hwnd);
            return 0;
        },
        WM_DESTROY => {
            dlg_hwnd = null;
            if (dialog_cfg) |*d| d.deinit();
            dialog_cfg = null;
            PostQuitMessage(0);
            return 0;
        },
        else => return DefWindowProcA(hwnd, msg, wParam, lParam),
    }
}

fn restoreParent() void {
    if (parent_hwnd != null) {
        _ = EnableWindow(parent_hwnd, 1);
        _ = SetForegroundWindow(parent_hwnd);
    }
}

/// Reposition every child control (design coordinates, 96-DPI base) after a DPI change.
fn moveCtrl(h: HWND, x: c_int, y: c_int, w: c_int, hgt: c_int) void {
    if (h == null) return;
    _ = SetWindowPos(h, null, sd(x, cur_dpi), sd(y, cur_dpi), sd(w, cur_dpi), sd(hgt, cur_dpi), SWP_NOZORDER | SWP_NOACTIVATE);
}

fn relayoutChildren() void {
    moveCtrl(edit_ip, 112, 20, 190, 24);
    moveCtrl(edit_port, 112, 56, 100, 24);
    moveCtrl(chk_autostart, 20, 96, 250, 20);
    moveCtrl(edit_token, 112, 128, 190, 24);
    moveCtrl(lbl_url, 112, 185, 310, 20);
    if (dlg_hwnd != null) {
        var h: HWND = GetDlgItem(dlg_hwnd, IDC_SAVE);
        moveCtrl(h, 240, 280, 90, 30);
        h = GetDlgItem(dlg_hwnd, IDC_CANCEL);
        moveCtrl(h, 340, 280, 90, 30);
        h = GetDlgItem(dlg_hwnd, IDC_GENERATE);
        moveCtrl(h, 310, 128, 65, 24);
        h = GetDlgItem(dlg_hwnd, IDC_COPY_TOKEN);
        moveCtrl(h, 380, 128, 45, 24);
    }
}

fn updateUrlPreview() void {
    if (lbl_url == null or edit_ip == null or edit_port == null) return;

    var ip_buf: [64]u8 = undefined;
    const ip_len: usize = @intCast(GetWindowTextA(edit_ip, &ip_buf, 64));

    var port_buf: [8]u8 = undefined;
    const port_len: usize = @intCast(GetWindowTextA(edit_port, &port_buf, 8));

    var url: [128]u8 = undefined;
    const prefix = "http://";
    @memcpy(url[0..prefix.len], prefix);
    var pos: usize = prefix.len;

    if (ip_len == 0) {
        // An empty address is rejected on Save (it no longer means 0.0.0.0).
        url[pos] = '?';
        pos += 1;
    } else {
        @memcpy(url[pos .. pos + ip_len], ip_buf[0..ip_len]);
        pos += ip_len;
    }

    url[pos] = ':';
    pos += 1;

    if (port_len == 0) {
        url[pos] = '0';
        pos += 1;
    } else {
        @memcpy(url[pos .. pos + port_len], port_buf[0..port_len]);
        pos += port_len;
    }

    url[pos] = '/';
    pos += 1;
    url[pos] = 0;

    _ = SendMessageA(lbl_url, WM_SETTEXT, 0, @bitCast(@intFromPtr(&url)));
}

fn onSave(hwnd: HWND) void {
    var ip_buf: [cfgjson.MAX_IP_LEN + 1]u8 = undefined;
    const ip_len: usize = @intCast(GetWindowTextA(edit_ip, &ip_buf, ip_buf.len));
    const ip = ip_buf[0..ip_len];

    if (ip_len == 0) {
        _ = MessageBoxA(hwnd, "IP address cannot be empty.\x00", "Validation Error\x00", 0x30);
        return;
    }
    // The server refuses to start on an unparsable address (fail closed), so
    // catch typos here instead of silently binding nothing.
    _ = netpolicy.parseIpv4(ip) catch {
        _ = MessageBoxA(hwnd, "IP address must be a dotted IPv4 address such as 127.0.0.1.\x00", "Validation Error\x00", 0x30);
        return;
    };

    var port_buf: [8]u8 = undefined;
    const port_len: usize = @intCast(GetWindowTextA(edit_port, &port_buf, 8));
    const port = parsePort(port_buf[0..port_len]) orelse {
        _ = MessageBoxA(hwnd, "Port must be a number between 1 and 65535.\x00", "Validation Error\x00", 0x30);
        return;
    };

    const auto_start = if (chk_autostart != null)
        SendMessageA(chk_autostart, BM_GETCHECK, 0, 0) == BST_CHECKED
    else
        true;

    var tok_buf: [cfgjson.MAX_TOKEN_LEN + 1]u8 = undefined;
    const tok_len: usize = if (edit_token != null)
        @intCast(GetWindowTextA(edit_token, &tok_buf, tok_buf.len))
    else
        0;

    // The token box is read-only, but validate anyway: never save a file
    // that the loader would reject (that would stop the server from
    // starting on the next x64dbg launch).
    const tok = tok_buf[0..tok_len];
    if (tok_len > 0 and !cfgjson.isValidToken(tok)) {
        _ = MessageBoxA(hwnd, "Auth token must be 1-64 characters without control characters or leading/trailing spaces. Click Generate for a new one.\x00", "Validation Error\x00", 0x30);
        return;
    }

    if (dialog_cfg == null) dialog_cfg = load();
    const loaded = &dialog_cfg.?;
    const cfg = &loaded.owned.config;
    cfg.ip_address = loaded.owned.dupe(ip) catch return;
    cfg.port = port;
    cfg.auto_start = auto_start;
    if (tok_len > 0) {
        cfg.auth_token = loaded.owned.dupe(tok) catch return;
    } else if (!generateTokenInto(&loaded.owned)) {
        _ = MessageBoxA(hwnd, "Could not generate a random token (the Windows random source failed). Nothing was saved.\x00", "MCP Server Configuration\x00", 0x10);
        return;
    }

    if (!save(cfg)) {
        _ = MessageBoxA(hwnd, "Could not write mcp_config.json next to the x64dbg executable.\x00", "MCP Server Configuration\x00", 0x10);
        return;
    }

    // Same check the server runs at start: warn now instead of letting the
    // user find a "Refusing to start" line in the log later.
    var diag: netpolicy.StartupDiag = .{};
    if (netpolicy.planStartup(.{
        .ip_address = cfg.ip_address,
        .allow_external = cfg.allow_external,
        .allowed_clients = cfg.allowed_clients,
        .token = cfg.auth_token,
    }, &diag)) |_| {} else |err| {
        var msg_buf: [512]u8 = undefined;
        const text = std.fmt.bufPrintZ(&msg_buf, "{s}\r\nThe settings are saved, but the server will refuse to start until this is fixed in mcp_config.json.", .{netpolicy.describeStartupError(err)}) catch "The settings are saved, but the server will refuse to start (see the log).";
        _ = MessageBoxA(hwnd, text.ptr, "MCP Server Configuration\x00", 0x30);
    }

    mcp.stop();
    applyToRuntime(cfg);
    if (cfg.auto_start) mcp.start();

    bridge.logPuts("[x64dbg-MCP Server] Configuration saved.\x00");
    restoreParent();
    _ = DestroyWindow(hwnd);
}
