<p align="center"><img src="https://raw.githubusercontent.com/duty1g/x64dbg-mcp-server/main/logo.png" width="75%"/></p>

<h1 align="center">x64dbg-MCP Server</h1>
<h4 align="center">MCP-powered agentic reverse engineering for x64dbg.</h4>

<p align="center">
  <img src="https://img.shields.io/github/stars/duty1g/x64dbg-mcp-server" alt="Stars"/>
  <a href="https://github.com/duty1g/x64dbg-mcp-server/releases"><img src="https://img.shields.io/github/v/release/duty1g/x64dbg-mcp-server" alt="Version"/></a>
  <a href="https://github.com/duty1g/x64dbg-mcp-server/releases"><img src="https://img.shields.io/github/downloads/duty1g/x64dbg-mcp-server/total" alt="Downloads"/></a>
  <img src="https://img.shields.io/github/languages/top/duty1g/x64dbg-mcp-server" alt="Language"/>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="License"/></a>
  <a href="https://duty1g.online"><img src="https://img.shields.io/badge/Red-Team-red" alt="Red Team"/></a>
  <a href="https://duty1g.online"><img src="https://img.shields.io/badge/Reverse%20Engineering-purple" alt="Reverse Engineering"/></a>
  <a href="https://twitter.com/duty_1g"><img src="https://img.shields.io/twitter/follow/duty_1g.svg?logo=twitter" alt="Twitter"/></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#tools">Tools</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#building">Building</a> •
  <a href="#project-structure">Structure</a>
</p>

#

x64dbg-MCP Server is a native [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) plugin for [x64dbg](https://x64dbg.com/) that exposes the debugger's full functionality over HTTP. Connect any MCP-compatible AI assistant and control x64dbg programmatically: set breakpoints, step through code, read memory, dump registers, and more.

Built with [Zig](https://ziglang.org/) — zero dependencies, single-binary output, cross-compiles to both x32 and x64 from any host. No .NET, no Python, no runtime — just drop the plugin into your x64dbg plugins folder and go.

> **MCP 2024-11-05** — Streamable HTTP + SSE transports, JSON-RPC 2.0.


## Features

- **82 MCP Tools:** Full debugger control — disassembly, stepping, breakpoints, memory allocation, registers, modules, threads, call stack, pattern scanning, string extraction, xrefs, symbols, bookmarks, PE analysis, OEP detection, module dumping, PEB/SEH inspection, tracing, and more.
- **22 Event Callbacks:** Full debugger event coverage — init, stop, breakpoint, exception, step, attach/detach, DLL load/unload, threads, and more.
- **Zero Dependencies:** Pure native plugin, no runtime or framework needed.
- **x32 and x64:** Single codebase, builds both architectures from one command.
- **Dual Transport:** Streamable HTTP + SSE — compatible with any MCP client (new and legacy). SSE can be switched off.
- **Bearer Auth:** Mandatory token authentication — auto-generated on first run, required on every request (compared in constant time, with a per-IP lockout of remote clients and a short lockout of local clients after repeated failures).
- **Hardened Networking:** Loopback by default, fail-closed bind, client IP allowlist, request timeouts, bounded client threads, exclusive port binding.
- **Config Dialog:** Change IP/port/token from the Plugins menu, auto-restarts the server on save.
- **Auto-Start:** MCP server starts automatically when x64dbg launches.
- **Cross-Compile:** Build Windows plugins from Linux, macOS, or WSL.


## Install

Download the latest release or build from source:

1. Copy the contents of `dist/` into your x64dbg root folder (deploys both x32 and x64)
2. Launch x64dbg

The MCP server starts automatically. Default addresses (loopback only):
- **x64:** `127.0.0.1:9094`
- **x32:** `127.0.0.1:9095`


## Usage

Add to your MCP client config (`.mcp.json`, etc.):

**Streamable HTTP (recommended):**
```json
{
  "mcpServers": {
    "x64dbg": {
      "type": "http",
      "url": "http://localhost:9094/",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

**SSE (legacy clients):**
```json
{
  "mcpServers": {
    "x64dbg": {
      "type": "sse",
      "url": "http://localhost:9094/sse",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

If connecting from WSL or a remote machine, prefer an SSH tunnel to `127.0.0.1`. To bind another address (for example `0.0.0.0`) you must also opt in through `mcp_config.json`: set `"AllowExternal": true`, list the permitted clients in `"AllowedClients"`, and use a token of at least 32 characters (see [Remote access](#remote-access)). Otherwise the server refuses to start. The traffic is plain HTTP, so only expose it on a trusted, isolated network.

**Example — AI-assisted reverse engineering session:**
```
You:    Load calc.exe and break at the entry point
AI: [calls LoadBinary, SetBreakpoint, run, WaitForPause]
        Loaded calc.exe, hit breakpoint at 0x7FF7A1234000 in calc.exe

You:    What are the current registers?
AI: [calls GetAllRegisters]
        RAX: 0x0, RCX: 0x7FF7A1234000, RDX: 0x1, ...

You:    Read 64 bytes at the current instruction pointer
AI: [calls ReadMemory]
        48 83 EC 28 E8 12 34 00 00 ...

You:    Step over the next 3 instructions and show me the stack
AI: [calls StepOver x3, GetCallStack]
        Stepped to 0x7FF7A1234010, call stack: ...
```


## Tools

82 MCP tools covering the full x64dbg debugging workflow.

### Always available
| Tool | Description |
|------|-------------|
| `GetDebugState` | Current debugger state, PID, instruction pointer |
| `GetServerInfo` | Identify the backend: arch, version, x64dbg PID, debuggee path, ArtifactDir (JSON) |
| `LoadBinary` | Load an executable (optional arguments / working directory) and wait until it is paused |
| `SetArtifactDir` | Set the directory that relative dump/database paths are written to |
| `ExecuteDebuggerCommand` | Run any x64dbg command |
| `ListCommandsByCategory` | List available MCP tools |
| `SearchForStrings` | Search process memory for text |
| `GetEventLog` | Last N debugger events (exceptions, breakpoints, DLL loads) |
| `ClearEventLog` | Clear the event log |
| `EvalExpression` | Evaluate any x64dbg expression (address, register, arithmetic) |
| `AttachProcess` | Attach to a running process by PID |
| `Echo` | Echo input back |
| `WaitForEvent` | Long-poll for debugger events (breakpoint, pause, resume, exception) |

### Requires active debug session
| Tool | Description |
|------|-------------|
| `GetCurrentAddress` | Current EIP/RIP with label and comment |
| `Disassemble` | Disassemble N instructions at an address |
| `DisassembleFunction` | Disassemble an entire function by boundaries |
| `ReadMemory` | Hex dump of process memory |
| `WaitForPause` | Block until target pauses |
| `run` | Resume execution (F9) |
| `StepInto` | Single-step into calls (F7) |
| `StepOver` | Step over calls (F8) |
| `StepOut` | Run until return (Ctrl+F9) |
| `PauseDebug` | Pause the target (F12) |
| `StopDebug` | Terminate debug session |
| `RestartDebug` | Restart debug session (reuses `LoadBinary`'s arguments / working directory) |
| `SetBreakpoint` | Set INT3 breakpoint at address/symbol |
| `SetHardwareBreakpoint` | Set hardware breakpoint (DR0-DR3, read/write/execute; `size` 1, 2, 4 or 8, 8 on x64 only) |
| `SetConditionalBreakpoint` | Set breakpoint with condition expression and optional log |
| `EnableBreakpoint` | Enable a breakpoint at a given address |
| `DisableBreakpoint` | Disable a breakpoint without deleting it |
| `ToggleBreakpoint` | Toggle a breakpoint between enabled and disabled |
| `DeleteBreakpoint` | Remove a breakpoint |
| `DeleteAllBreakpoints` | Remove all breakpoints (normal, hardware, memory) |
| `ResetHitCount` | Reset a breakpoint's hit counter to zero |
| `ListBreakpoints` | List all active breakpoints |
| `GetAllRegisters` | Dump all general-purpose registers |
| `SetRegister` | Set a CPU register value |
| `GetCallStack` | Current thread call stack |
| `GetThreads` | List all threads with IDs and instruction pointers |
| `SwitchThread` | Switch active thread context |
| `SuspendThread` | Suspend a thread by its thread ID |
| `ResumeThread` | Resume a suspended thread |
| `ListModules` | List loaded modules with base addresses and sizes |
| `GetMemoryMap` | Memory regions with addresses, sizes, and protection |
| `GetDumpableRegions` | List committed, readable memory regions |
| `AllocateMemory` | Allocate memory in the target process |
| `FreeMemory` | Free allocated memory in the target process |
| `WriteMemToAddress` | Patch memory with hex bytes |
| `RestorePatches` | Restore all patches to original bytes |
| `Assemble` | Assemble an instruction at an address |
| `CommentOrLabelAtAddress` | Add comment/label in disassembly |
| `SetBookmark` | Set a bookmark at an address |
| `DeleteBookmark` | Delete a bookmark |
| `ListBookmarks` | List all bookmarks |
| `GetImports` | Show module import table |
| `GetExports` | Show module export table |
| `SearchSymbols` | Search for symbols matching a pattern |
| `ListSymbols` | List exported symbols of a module |
| `GetPatches` | List all memory patches |
| `FindPattern` | Scan module memory for byte pattern with ?? wildcards |
| `GetStrings` | Extract ASCII strings from a module's memory |
| `GetReferences` | Find CALL/JMP xrefs to a target address |
| `GetFunctions` | List analyzed functions with addresses and labels |
| `AnalyzeModule` | PE structure analysis: sections, EP, image size |
| `DetectOEP` | Detect Original Entry Point for packed executables |
| `DumpMemory` | Save memory region to file on disk (relative paths go to ArtifactDir) |
| `DumpModule` | Dump an entire module to a file (relative paths go to ArtifactDir) |
| `RunToAddress` | Run until hitting a specific address |
| `TraceInto` | Step N instructions recording address + disassembly |
| `FollowPointer` | Dereference pointer chain N levels deep |
| `WatchExpressions` | Evaluate multiple expressions in one call |
| `GetSEHChain` | Walk Structured Exception Handler chain (x32) |
| `GetPEB` | Read Process Environment Block fields |
| `GetArguments` | Read function arguments from stack/registers |
| `SetMemoryBreakpoint` | Set memory breakpoint (read/write/execute) |
| `SetExceptionBreakpoint` | Configure exception breakpoint (break or ignore, first/second/all chance) |
| `DeleteExceptionBreakpoint` | Delete an exception breakpoint |
| `AnalyzeCode` | Run code analysis (function, module, or control flow) |
| `TraceOver` | Trace N instructions stepping over calls |
| `SetBreakpointCommand` | Set a command to execute when a breakpoint is hit |
| `SetBreakpointFastResume` | Enable/disable fast resume (auto-continue) on a breakpoint |
| `SaveDatabase` | Save the x64dbg database (.dd64/.dd32), optionally to a given file (`filePath` omitted or `""` = default location) |


## Configuration

Go to **Plugins > x64dbg-MCP Server > Configure MCP Server...** to change the bind address, port, auto-start and auth token.

- `127.0.0.1` — local-only access (default)
- any other address (e.g. `0.0.0.0`) — needs the file-only keys described under [Remote access](#remote-access)

Saving restarts the server. Config is persisted to `mcp_config.json` next to the x64dbg executable (x32dbg and x64dbg each have their own file and token).

**A restart can be delayed.** The port is bound with `SO_EXCLUSIVEADDRUSE`, so the restarted server cannot bind it while connections accepted by the previous instance are still open (for example a `run`, `WaitForPause` or `ExecuteDebuggerCommand` call that is still waiting for the target). It retries the bind once per second and logs `Port <n> is in use (another process, or connections of the previous server instance are still open); retrying every 1 s.` (once a minute) until those connections have drained, then starts listening. If the port is still busy 30 seconds after the last old connection closed (11 minutes at most), the server logs that and stops; see [Remote access](#remote-access).

### Authentication

A Bearer token is auto-generated on first run and required on every request, for every HTTP method (including `OPTIONS`, which is answered with `405` once authenticated; the server sends no CORS headers because MCP clients are not browsers). The MCP server has full debugger control and can read/write process memory — all requests without a valid token receive `401 Unauthorized`. Click **Generate** in the config dialog to rotate the token, or **Copy** to copy it to clipboard. Clients must include the token as an `Authorization: Bearer <token>` header.

Tokens are compared in constant time. After `AuthMaxFailures` failed attempts within 60 seconds the client is locked out: every request from it is still read and then answered with `429 Too Many Requests` (even one with the correct token) until the lockout expires, with a `Retry-After` header and a JSON body `{"error": "Too many failed authentication attempts", "retry_after_s": <seconds>}`. A client can therefore tell "locked out" (`429`) from "wrong token" (`401`) and "server down" (connection refused); connections are never dropped because of a lockout.

- **Remote clients** are tracked per IP address and locked out for `AuthLockoutSeconds`.
- **Loopback clients** (`127.0.0.0/8`) count as one client (a local process can pick any `127.x.y.z` source address) and are locked out for only 5 seconds (or `AuthLockoutSeconds`, if that is shorter). Every local process shares that lockout, so it is kept short: it throttles a local token guesser without letting another process keep your MCP client out for long. Loopback requests without any `Authorization` header are answered with `401` but not counted: a web page open in a local browser can make it send such requests to `127.0.0.1`, but cannot add an `Authorization` header to a cross-origin request without a CORS preflight, which this server never approves, so ordinary web pages cannot trigger the lockout.

A remote client such as a gateway should stop after a `401` instead of retrying with the same token, and wait `Retry-After` seconds after a `429`.

### mcp_config.json

The dialog edits the first four keys; all other keys are **file-only** (edit the JSON while x64dbg is closed, or edit it and then press **Save** in the dialog to restart the server; unknown keys are preserved when the dialog saves).

| Key | Default | Description |
|-----|---------|-------------|
| `IpAddress` | `"127.0.0.1"` | IPv4 address to bind. Must be a valid dotted IPv4 address — an invalid value makes the server refuse to start (it no longer falls back to `0.0.0.0`). |
| `Port` | `9094` (x64) / `9095` (x32) | TCP port, 1–65535. |
| `AutoStart` | `true` | Start the server when the plugin loads. |
| `AuthToken` | generated | 1–64 characters, no control characters and no leading/trailing space (those can never match an `Authorization` header). Generated tokens are 32 hex characters. Tokens with inner spaces or non-ASCII characters (accepted by v1.9) still load, but the server logs a warning because some HTTP clients cannot send them. |
| `AllowExternal` | `false` | Must be `true` to bind any non-loopback address. Then the token must be at least 32 characters. |
| `AllowedClients` | `[]` | IPv4 addresses or CIDR ranges (`"192.168.56.0/24"`, `"10.0.0.5"`) allowed to connect, max 64. Required (non-empty) for a non-loopback bind. Loopback clients are always allowed. |
| `MaxClients` | `16` | Maximum concurrent connections (1–256); extra connections are closed immediately. |
| `EnableSse` | `true` | Serve the legacy SSE transport (`/sse`, `/messages`). Set `false` when exposing the server; Streamable HTTP keeps working. |
| `ArtifactDir` | `""` | Absolute directory (drive or UNC path) for relative `filePath` arguments of `DumpMemory`, `DumpModule` and `SaveDatabase`. |
| `AuthMaxFailures` | `5` | Failed authentications (within 60 s) before a lockout, 1–1000. Counted per remote IP; all loopback clients share one count, which only includes requests that sent an `Authorization` header and is not reset by a successful request (it may come from another local process). |
| `AuthLockoutSeconds` | `300` | Lockout duration for remote clients in seconds, 1–86400. Loopback clients are locked out for 5 seconds (or this value, if shorter). |

If `mcp_config.json` exists but cannot be parsed (invalid JSON, a duplicate key, a wrong type or an out-of-range value), the plugin logs the offending key, leaves the file untouched and does not start the server. Fix the file, or open the dialog and press **Save** to replace it.

### Remote access

The server speaks plain HTTP. Prefer an SSH tunnel to `127.0.0.1`. If you must listen on another interface (for example for a host-side gateway talking to a VM over a host-only network):

```json
{
  "IpAddress": "0.0.0.0",
  "Port": 9094,
  "AutoStart": true,
  "AuthToken": "<at least 32 characters>",
  "AllowExternal": true,
  "AllowedClients": ["192.168.56.1"],
  "EnableSse": false
}
```

Hardening that applies to every bind:

- The request line and headers must arrive within 5 seconds and the whole request within 10 seconds of connecting; responses use a 10 second send timeout.
- At most `MaxClients` connections are served at once; the peer address is checked against `AllowedClients` **before** a thread is created for it (rejected peers get a connection reset). Locked-out peers, loopback or remote, are admitted and answered with `429` (plus `Retry-After`) after their request has been read.
- The port is bound with `SO_EXCLUSIVEADDRUSE`, so another process cannot share it. If the port is busy when the server (re)starts, it retries once per second while connections of the previous server instance are still open and for 30 seconds after that (11 minutes at most), then logs that the port is in use and stops; start it again from the plugin menu (or with the `StartMCPServer` command) once the port is free. A port owned by another process (for example a second x64dbg) therefore fails after about 30 seconds instead of looking "running".
- SSE session ids are random 64-bit values, so one SSE client cannot address another client's stream.
- SSE notifications are queued per client in a 1 MiB buffer allocated when the client connects (queueing an event copies into it and never allocates on the debugger thread); a client that stops reading is dropped when its buffer is full or after a 5 second send timeout, and never blocks the debugger thread.
- State-changing tools are serialised (**new in v1.10**: v1.9 let them interleave). While one runs, another state-changing call waits up to 10 seconds and then returns `BUSY` without executing. A blocking `run` or `ExecuteDebuggerCommand` holds the lock until the target pauses, its timeout expires, or its HTTP client disconnects; so, for example, `SetBreakpoint` while a `run` is waiting returns `BUSY` — call `PauseDebug` (or `WaitForPause`) and retry. Read-only tools, `PauseDebug`, `WaitForEvent`, `WaitForPause` and `GetDebugState` are never blocked.

### Artifact directory

`GetServerInfo` reports the current `artifact_dir`. Set it in `mcp_config.json` (`ArtifactDir`) or at runtime with `SetArtifactDir` (runtime only; saving the dialog or reloading the plugin restores the file value). Relative `filePath` values are joined to it; absolute paths are used as-is. Paths with `..`, alternate data streams (`file:stream`), device prefixes (`\\?\`, `\\.\`), reserved names (`CON`, `NUL`, ...) or control characters are rejected. Without an `ArtifactDir`, relative paths are passed to x64dbg unchanged, as before.


## Building

Requires [Zig 0.14.0](https://ziglang.org/download/#release-0.14.0) (the version CI uses). Builds on Windows, WSL, Linux, or macOS.

```console
zig build -Doptimize=ReleaseSafe --prefix dist
```

Run the unit tests (pure logic: JSON, config parsing, network policy, path resolution, queues; they run on the build host):

```console
zig build test
```

Output mirrors x64dbg's folder structure — copy the contents of `dist/` into your x64dbg root to deploy both architectures at once:
```
dist/
├── x32/
│   └── plugins/
│       └── x64dbg-MCP-Server.dp32
└── x64/
    └── plugins/
        └── x64dbg-MCP-Server.dp64
```


## Project Structure

```
├── build.zig                     # build config — x32 + x64 cross-compilation
├── build.zig.zon                 # package manifest
└── src/
    ├── main.zig                  # plugin entry point, menu, callbacks
    ├── core/
    │   ├── bridge.zig            # x64dbg SDK bindings (runtime-resolved)
    │   ├── config.zig            # Win32 config dialog and persistence
    │   ├── cfgjson.zig           # mcp_config.json parse/serialize (tested)
    │   ├── http.zig              # HTTP request framing helpers (tested)
    │   ├── launch.zig            # LoadBinary/RestartDebug launch tracking (tested)
    │   ├── mcp_server.zig        # HTTP server and JSON-RPC dispatch
    │   ├── netpolicy.zig         # bind policy, allowlist, token, lockout (tested)
    │   ├── pathutil.zig          # ArtifactDir path resolution (tested)
    │   ├── ring.zig              # locked event queues (tested)
    │   ├── ssehub.zig            # SSE client table and per-client send buffers (tested)
    │   └── sync.zig              # SRWLOCK wrapper (tested)
    ├── mcp/
    │   ├── cmdline.zig           # x64dbg command quoting and numbers (tested)
    │   ├── json.zig              # JSON writer and parser helpers (tested)
    │   ├── serverinfo.zig        # GetServerInfo payload (tested)
    │   ├── toolpolicy.zig        # which tools are serialised (tested)
    │   └── tools.zig             # MCP tool definitions and handlers
    └── resources/
        └── icons.zig             # embedded PNG icon data
```


## How It Works

The plugin loads into x64dbg at startup, resolves the debugger's API symbols at runtime from `x64bridge.dll` and `x64dbg.dll`, then spins up an HTTP server on a background thread. MCP clients connect over HTTP and send JSON-RPC requests to invoke tools — each tool maps directly to x64dbg SDK calls (breakpoints, memory reads, command execution, etc.).

No polling, no external processes — the plugin lives inside x64dbg's address space with direct access to the debugger API.


---

## Disclaimer

> This tool is intended for legitimate reverse engineering, malware analysis, security research, and educational purposes only. It provides full debugger control over running processes — including memory read/write, code execution, and process manipulation — over a network interface.
>
> By using this software, you accept full responsibility for how it is used. The author is not liable for any misuse, damage, or legal consequences resulting from the use of this tool. Always ensure you have proper authorization before debugging or analyzing any software.
>
> Do not expose the MCP server to untrusted networks. While Bearer token authentication is enforced, the server communicates over unencrypted HTTP, and anyone holding the token can run arbitrary debugger commands (and therefore code) on the debugging machine.


---

### License

MIT. See [LICENSE](./LICENSE).

Made with 🖤 by [@duty1g](https://github.com/duty1g)
