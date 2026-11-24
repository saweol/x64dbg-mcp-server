# x64dbg-vm-gateway

Host-side MCP gateway for the x64dbg-MCP plugin. An AI client (Claude Code) connects to the
gateway, never to the plugin. The gateway drives a VMware analysis VM: it reverts snapshots,
uploads the sample, keeps x64dbg/x32dbg alive inside the guest, mirrors the plugin's debugger
tools and collects the artifacts back to the host. Its lifetime is independent of the VM and of
the debugger, so a crashed x64dbg or a reverted VM does not drop the MCP connection.

```
Claude Code ──stdio──▶ x64dbg-vm-gateway ──vmrun/VIX──▶ VMware guest (Windows)
remote client ─HTTPS─▶   (host, Python)  ──HTTP+Bearer─▶ x64dbg :9094 / x32dbg :9095 + plugin
```

Design and rationale: [`../docs/VM_ORCHESTRATION_PLAN.md`](../docs/VM_ORCHESTRATION_PLAN.md).

## Requirements

- Python 3.11+ and [uv](https://docs.astral.sh/uv/).
- VMware Workstation (Linux or Windows host, `vmrun -T ws`) or VMware Fusion on an Intel Mac
  (`-T fusion`). Apple Silicon cannot run an x86 Windows guest: use an `endpoint` profile.
- A Windows 10/11 guest with VMware Tools, x64dbg (both `x64\` and `x32\`) and the x64dbg-MCP
  plugin (`x64dbg-MCP-Server.dp64` / `.dp32`). Plugin v1.3 and later work; the gateway detects
  features (for example `GetServerInfo`, `SetArtifactDir`) from the plugin's tool list.
- A host-only network for the guest and shared folders disabled (see [Safety](#safety)).

## Install

From the repository root:

```console
uv tool install ./host            # puts x64dbg-vm-gateway on PATH
x64dbg-vm-gateway --help
```

Without installing: `uvx --from ./host x64dbg-vm-gateway --help`.

## Configure

`init` writes the per-user config file (mode 0600) and refuses to overwrite an existing one
unless `--force` is given:

| Host OS | Config file |
|---|---|
| Linux / macOS | `$XDG_CONFIG_HOME/x64dbg-vm-gateway/config.toml` (default `~/.config/...`) |
| Windows | `%APPDATA%\x64dbg-vm-gateway\config.toml` |

`X64DBG_VM_GATEWAY_CONFIG` or the global `--config PATH` option point to another file.

```console
x64dbg-vm-gateway init                          # interactive wizard
x64dbg-vm-gateway init --non-interactive \
    --vmx /vms/win10/win10.vmx --guest-user analyst \
    --x64dbg-root 'C:\tools\x64dbg\release'     # optional: --profile-name, --clean-snapshot,
                                                # --guest-password-env, --jobs-root, --vmrun
```

`init` looks for `vmrun` (`/usr/bin/vmrun`, the Workstation registry key and install directory,
the Fusion bundle) and prints what it found. The result looks like this:

```toml
[gateway]
jobs_root = '~/mcp-lab/jobs'          # artifacts live here, outside any repository
default_profile = 'win10'

[profiles.win10]
mode = 'vmware'
vmx = '/vms/win10/win10.vmx'
vmrun = 'auto'
clean_snapshot = 'MCP_CLEAN'
protected_snapshots = ['MCP_CLEAN']   # never deleted, never reverted over by accident
guest_user = 'analyst'
guest_password_env = 'X64DBG_GW_GUEST_PW'   # the NAME of an environment variable
require_isolation = true
token_source = 'guest-config'         # plugin tokens are read from the guest's mcp_config.json

[profiles.win10.backends.x64]
port = 9094
exe = 'C:\tools\x64dbg\release\x64\x64dbg.exe'
config = 'C:\tools\x64dbg\release\x64\mcp_config.json'
launch_task = 'MCP-x64dbg'

[profiles.win10.backends.x32]
port = 9095
exe = 'C:\tools\x64dbg\release\x32\x32dbg.exe'
config = 'C:\tools\x64dbg\release\x32\mcp_config.json'
launch_task = 'MCP-x32dbg'
```

Secrets are never stored in the file: keys ending in `_env` name environment variables. Export
the guest password before running the gateway:

```console
export X64DBG_GW_GUEST_PW='...'        # PowerShell: $env:X64DBG_GW_GUEST_PW = '...'
```

An `endpoint` profile talks to plugins at fixed URLs without a VM
(`init --non-interactive --mode endpoint --x64-url http://10.0.0.20:9094 --x64-token-env REMOTE_X64_TOKEN`).

## Prepare the guest and the clean snapshot

The gateway expects the clean-snapshot contract of plan section 5.7: a powered-on snapshot
(memory included) in which the analysis user is logged on, both debuggers run elevated with the
plugin listening, `C:\mcp\jobs` exists and is empty, shared folders are off and the network is
host-only.

1. In the guest: install VMware Tools, unpack x64dbg, create the analysis user (with a password).
2. Copy a plugin build into the guest (optional when the plugin is already installed):

   ```console
   x64dbg-vm-gateway install-plugin --dist path/to/zig-out/bin   # --x64dbg-root, --no-relaunch
   ```

3. Provision. This writes both `mcp_config.json` files (keeping valid tokens, generating
   missing or corrupt ones), registers the elevated `AtLogOn` scheduled tasks `MCP-x64dbg` and
   `MCP-x32dbg`, configures auto-logon, creates `C:\mcp\jobs`, reboots, waits until both plugins
   answer and finally takes the clean snapshot:

   ```console
   x64dbg-vm-gateway provision --x64dbg-root 'C:\tools\x64dbg\release' --snapshot MCP_CLEAN
   #   --user U          interactive user (default: guest_user of the profile)
   #   --bind ADDR       plugin bind address in the guest (default 0.0.0.0, host-only network)
   #   --no-autologon    skip auto-logon (then the password is not needed)
   #   --no-reboot       do not reboot; --wait-ready S  how long to wait for the plugins (300)
   ```

   Auto-logon needs the guest password from `guest_password_env`. A memory snapshot of a 4 GB
   guest takes about three minutes.

4. Check everything:

   ```console
   x64dbg-vm-gateway doctor          # exit code 1 if a check fails; each failure has a hint
   ```

## Use it from Claude Code

```console
claude mcp add x64dbg-vm -- x64dbg-vm-gateway serve
# another profile:  claude mcp add x64dbg-lab -- x64dbg-vm-gateway serve --profile lab
```

Start Claude Code from a shell where the password variable is exported (avoid `claude mcp add -e`,
which writes the value into Claude's config file). Run only one gateway per jobs root at a time;
remote users connect to the same gateway over HTTP instead of starting a second one.

The gateway lists all tools at session start: its own tools plus the plugin's x64dbg tools under
their original names (`SetBreakpoint`, `run`, `DumpMemory`, ...). `debugger_call` reaches any
backend tool that is not listed.

### The analysis loop

1. `session_status` - VM, backends, active job, warnings.
2. `analysis_start(sample_path)` - isolation check, revert to the clean snapshot, upload with hash
   verification, start the matching debugger, load the sample paused at the system breakpoint.
   The sample is never run automatically.
3. Mirrored debugger tools. Write dumps into the job's guest `out` directory
   (`C:\mcp\jobs\<job>\out\`).
4. `analysis_collect` - saves the debugger database, zips `out`, copies it to the host, extracts it
   safely and returns the manifest with host paths.
5. `analysis_finish` - reverts to the clean snapshot (refused until collection succeeded);
   `keep_snapshot=true` keeps the infected state as `gw-job-<id>`.

Long operations (`analysis_start`, `vm_snapshot_revert`, `vm_power`, `analysis_finish`) return
`{"state": "in_progress", ...}` after `wait_s` (at most 3600 s; the work continues in the
background); poll `session_status`. After a debugger restart the next mutating call fails with
`BACKEND_RESTARTED`; call `session_status` (which acknowledges it) and re-check addresses. The
acknowledgement is gateway-wide: whichever client session calls `session_status` first clears the
guard for all of them.

| Tier | Gateway tools |
|---|---|
| observe (read-only) | `session_status`, `gateway_doctor`, `vm_snapshots_list`, `vm_screenshot`, `static_rebase`, `jobs_list`, `jobs_show` |
| guest-mutating | `file_upload`, `debugger_select`, `debugger_restart`, `debugger_call`, `analysis_start`, `analysis_collect`, `static_export_annotations`, `static_import_annotations` |
| host/VM-destructive | `vm_snapshot_take`, `vm_snapshot_revert`, `vm_snapshot_delete`, `vm_power`, `file_download`, `analysis_finish` |

Errors come back as `isError` results with
`{code, message, stage, retryable, hint, next_tool, details}`.

Further behaviour worth knowing:

- `vm_power start` is allowed during an analysis (to resume a VM that host sleep suspended);
  `stop`, `suspend` and `reset` are refused until the job is collected or discarded. `start` of a
  VM that already runs only re-checks readiness and does not interrupt running debugger calls.
- A job whose revert was interrupted by a gateway restart (state `REVERTING`) can only be finished
  with `analysis_finish(revert=true)`, which redoes the revert.
- A v1.10 plugin that locked the gateway out after failed logins answers HTTP 429: calls fail with
  `BACKEND_THROTTLED` (`details.retry_after_s`), the backend shows as `THROTTLED` in
  `session_status`, and it is never restarted for that.
- With `analysis_start(reload_on_restart=true)` a relaunched debugger gets the sample again before
  `BACKEND_RESTARTED` is reported; `details.reloaded` says whether it is loaded.
- `static_rebase`, `static_export_annotations` (writes `<job>/artifacts/static_sync.json`) and
  `static_import_annotations` connect the session to the static-analysis tool (IDA, Ghidra,
  radare2/rizin or Cutter, configured under `[static]`; addresses are static image base + RVA);
  see `ida/README.md`. The former names `ida_rebase`, `ida_export_annotations` and
  `ida_import_annotations` still work but are not listed. When the debugger
  should still hold the sample but its live module map is unavailable, the map recorded by
  `analysis_collect` is used and `warnings` says so.
- x64dbg writes no database file while a session has no labels, comments, bookmarks, breakpoints or
  functions (and deletes an existing one). The plugin's `SaveDatabase` with `filePath` (builds
  from 2026-11-24) watches the file for up to 10 s and answers `Database saved to "..."`,
  `No database file written to "..."` or an error (including a directory it cannot write to). After the second, `static_export_annotations` returns an empty document with
  `database.source = "not_written"` and a warning, and `analysis_collect` succeeds without a
  database. Older builds only queue the save and answer "Database saved" either way: the gateway
  waits up to 5 s for the file and, if it does not appear, says in `warnings` that an empty session
  cannot be told from a failed save (export: empty document; collection: complete with plugin
  v1.10, partial with older plugins, whose default database file stays expected).
- `jobs_list` / `jobs_show` list the jobs of the serving gateway (a second process cannot open
  its job store).
- While a gateway serves a jobs root, CLI commands that need it (`discard`, `status`, `doctor`,
  `provision`, `install-plugin`) stop with `LOCK_TIMEOUT` naming the gateway's pid. `provision` and
  `install-plugin` run with supervision paused and the VM lock held, and start new backend epochs
  after a plugin install. A job whose debugger held the sample is marked `flags.debuggee_lost`
  (the CLI names it), and the next gateway's recovery hint says the sample is no longer loaded.

## Remote access (M3)

`serve --transport http` exposes the same tools over MCP streamable HTTP at `/mcp`. Prefer an SSH
tunnel (`ssh -L 9100:127.0.0.1:9100 lab-host`) with the default loopback bind. To accept other
machines directly, configure:

```toml
[http]
enabled = true
bind = "0.0.0.0"
port = 9100
tls_cert = "~/.config/x64dbg-vm-gateway/gw.crt"   # required for any non-loopback bind
tls_key  = "~/.config/x64dbg-vm-gateway/gw.key"
allow_clients = ["10.0.0.0/24"]                   # CIDRs; empty = loopback only
token_envs = { read = "GW_TOKEN_READ", analyze = "GW_TOKEN_ANALYZE", admin = "GW_TOKEN_ADMIN" }
```

```console
export GW_TOKEN_READ=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')   # one per scope
openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=lab-host" \
    -addext "subjectAltName=DNS:lab-host,IP:10.0.0.5" \
    -keyout ~/.config/x64dbg-vm-gateway/gw.key -out ~/.config/x64dbg-vm-gateway/gw.crt
x64dbg-vm-gateway serve --transport http
```

| Scope | Tools |
|---|---|
| `read` | observe tier + read-only mirrored tools |
| `analyze` | + guest-mutating tier + mutating mirrored tools |
| `admin` | everything |

- The server refuses to start without at least one token (tokens must be at least 16 characters,
  distinct per scope) and refuses a non-loopback bind without TLS. Scopes whose variable is not
  set are disabled.
- Requests are checked in this order: client allowlist (403), per-client rate limit (429),
  bearer token (401). `X-Forwarded-For` is ignored.
- The rate limit is keyed by client address (IPv6: by /64) and runs before the token check, so
  token guessing is throttled. The trade-off: any process that sends requests from the same
  address, including bad-token requests from another local user on `127.0.0.1`, uses up the
  same bucket and can get a legitimate client there answered with 429. On a multi-user host any
  local user can do this to loopback clients; give remote clients addresses of their own.
- A `read` token cannot change the guest or the VM, but its `session_status` calls also
  acknowledge a debugger restart for every other session (see "The analysis loop").
- A session belongs to the scope that opened it; using its id with another token returns 404.
- Every tool call and every denied request is appended to
  `<jobs_root>/_audit/http-YYYYMMDD.jsonl` (time, client, scope, tool, outcome; never arguments or
  tokens).

Client side:

```console
claude mcp add --transport http x64dbg-remote https://lab-host:9100/mcp \
    --header "Authorization: Bearer $GW_TOKEN_ANALYZE"
export NODE_EXTRA_CA_CERTS=/path/to/gw.crt     # Node-based clients and a self-signed certificate
```

## Command line

| Command | Purpose |
|---|---|
| `serve [--transport stdio\|http]` | MCP server (stdio for Claude Code) |
| `doctor` | configuration and environment checks |
| `status` | session status (VM, backends, job) |
| `init` | write the config file |
| `jobs [list \| show JOB_ID]` | read-only view of the job directories (works while a gateway runs) |
| `discard JOB_ID [--yes]` | human-only: mark a job DISCARDED so it may be reverted without collection |
| `provision --x64dbg-root PATH ...` | prepare the guest (see above) |
| `install-plugin --dist DIR ...` | copy a plugin build into the guest |

Global options, before or after the command: `--config PATH`, `--profile NAME`, `--json`
(machine-readable stdout), `-v`. Exit codes: 0 success, 1 failure (prints `error [CODE]: message`
and a hint), 2 usage error.

## Safety

- **The guest is hostile.** Run samples only in the VM. Keep the guest on a host-only network
  and disable shared folders; with `require_isolation = true` (default) `analysis_start` refuses
  a VM with shared folders or a non-host-only adapter (`ISOLATION_REQUIRED`).
- **Guest output is untrusted.** Text from the guest is stripped of control characters and
  wrapped in `<untrusted_guest_output>`; the model is told never to follow instructions inside
  it. Collected files and downloads are untrusted data: never execute them on the host. On
  Windows hosts artifacts are kept in an encrypted zip by default.
- **Destructive tools.** Reverts, power changes, snapshot deletion and `analysis_finish` cannot be
  undone. The gateway enforces its own rules (protected snapshots, no revert before collection,
  only `gw-*` snapshots deletable, no `force` flag), but you should still require human approval
  for the host/VM-destructive tools in your MCP client's permission settings. Only a human can
  discard a job, with `x64dbg-vm-gateway discard`.
- **Tokens.** A plugin token grants code execution in the guest and malware in the guest can
  read it; it is also stored in the snapshot files. Gateway HTTP tokens grant VM control: keep
  them in environment variables, one per scope.

## Troubleshooting

- **vmrun noise.** `vmrun` prints `[AppLoader]` and libxml warnings on some hosts; the gateway
  filters them. Guest operation failures appear as `Error: ...` with exit code 255 and are mapped
  to typed errors such as `GUEST_OP_FAILED` or `GUEST_AUTH`.
- **`vmrun start` blocks.** `vmrun start <vmx> nogui` can block for minutes even when the VM is
  already running. The gateway calls it with a timeout and then checks the real power state; a
  slow start shows up as `state: in_progress` - poll `session_status` instead of retrying.
- **Corrupt or missing token config.** A guest `mcp_config.json` can end up zero-filled or empty
  (seen on the x32 side), so no token can be read from it and `doctor` fails the backend's token
  check. Re-run `x64dbg-vm-gateway provision --x64dbg-root ...`: it rewrites both configs, keeping
  valid tokens and regenerating missing or corrupt ones. Then take a new clean snapshot.
- **The plugins do not answer after a revert or reboot.** They start through the `AtLogOn` tasks,
  so auto-logon must work; after a reboot they answered within about 45 s on the reference VM.
  `vm_screenshot` shows a stuck logon screen or a modal dialog.
- **`LOCK_TIMEOUT` on the jobs root.** Another gateway process owns it. Stop it, or use `jobs`
  (read-only) instead.
- **`serve --transport http` refuses to start.** The error names the missing piece: `http.enabled`,
  an unset token variable, a token shorter than 16 characters, or TLS for a non-loopback bind.

## Development

```console
uv sync
uv run pytest            # unit tests (no VM)
uv run pytest -m vm      # real-VM tests (needs the spike VM + env vars)
uv run ruff check src tests
```

### Testing

`uv run pytest` runs the unit tests only (`-m 'not vm'` is the default): the VM, the guest and
the plugin are fakes (`tests/fakes/`), and the plugin speaks real HTTP on loopback.

The real-VM end-to-end suite `tests/vm/test_e2e_spike.py` (marker `vm`) drives a real VMware VM
through the gateway. **It changes that VM**: it reverts it to the profile's clean snapshot,
starts it, uploads and runs the benign samples, and kills `x64dbg.exe` once. Run it only against
a disposable clone such as the spike VM, never a production analysis VM.

1. Build the samples (needs Zig 0.14): `tests/vm/samples/build.sh /path/to/samples` writes
   `e2e_sample_x86_64.exe` and `e2e_sample_x86.exe`.
2. Write a gateway config for the clone (see [Configure](#configure)). Its default profile is
   used unless `X64DBG_VM_E2E_PROFILE` names another one; `gateway.upload_roots` must contain the
   sample directory, the guest password variable must be set, and the guest must run plugin
   v1.10 (`install-plugin`) with a clean snapshot taken after `provision`.
3. Run it:

   ```console
   export X64DBG_VM_E2E_CONFIG=~/mcp-lab/spike.toml
   export X64DBG_VM_E2E_SAMPLE_X64=/path/to/samples/e2e_sample_x86_64.exe
   export X64DBG_VM_E2E_SAMPLE_X32=/path/to/samples/e2e_sample_x86.exe
   uv run pytest -m vm tests/vm -v
   ```

Without `X64DBG_VM_E2E_CONFIG` every test is skipped; without a sample variable the loop of that
architecture is skipped. No other gateway may serve the same jobs root while it runs (the stdio
smoke test starts its own `serve`). The suite covers:

| Test | What it checks |
|---|---|
| `test_a_doctor_...` | `doctor` is all green, including `single_vm_instance` |
| `test_b_full_loop_x64`, `test_c_full_loop_x32` | `analysis_start` (polling `session_status` while `in_progress`), `GetServerInfo`, `ListModules`, `SetBreakpoint kernel32.Sleep`, `run` until paused there, `GetCallStack`, `DumpMemory` to a relative `filePath`, `analysis_collect` (the dump and the `.dd64`/`.dd32` are collected), `static_export_annotations`, `analysis_finish(revert)` |
| `test_d_killed_debugger_...` | x64dbg killed in the guest while ANALYZING: the next mutating call answers `BACKEND_RESTARTED`, `session_status` acknowledges, `LoadBinary` works again |
| `test_e_mcp_stdio_smoke` | `serve` over stdio with the `mcp` SDK client: the first `tools/list` has the v1.10 tools (`GetServerInfo`, `SetArtifactDir`, `ProbeFile`), `session_status` answers |

After every VM operation the suite asserts that exactly one `vmware-vmx` process runs the .vmx
(`platform.find_vmx_processes` when available, else `pgrep -af vmware-vmx`): a second instance
of the same VM shares its MAC and IP, so HTTP and vmrun could reach different instances.

`tests/vm/test_vm_kvm.py` (same marker and config variable) checks the guest-level fixes without
changing the VM's power state or snapshots: program arguments round-trip through vmrun
(quotes, trailing backslashes, empty strings, Unicode), a PowerShell `-Command` one-liner,
`instance_report()`, and the guest boot time used for reboot detection.

Last full run on the spike VM (2026-11-24, clean snapshot `MCP_CLEAN_V110E`): 10 passed in 3 min 32 s; see
`docs/PHASE0_RESULTS.md` for the timings and the defects this suite found.
