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
- A host-only network for the guest and shared folders disabled (see [Safety](#safety)). Host-only
  is required, not just allowed: the gateway reaches the plugins in the guest over HTTP, so an
  adapter that is not connected passes the isolation check but the guest cannot be driven. Keys the check reads
  in the `.vmx`: every present, connected `ethernetN.connectionType` must be `"hostonly"` (a missing
  `connectionType` means bridged; VMware's "Custom" choice writes `"custom"`), and shared folders
  count as off with `isolation.tools.hgfs.disable = "TRUE"` or no enabled `sharedFolderN` entry.
- A guest password used nowhere else: Windows auto-logon (set up by `provision`) stores it in the
  guest registry (`Winlogon\DefaultPassword`), so it is in every snapshot and readable by malware
  in the guest.

## Install

Releases will be published at <https://github.com/saweol/x64dbg-mcp-server/releases>; there is
no release yet, so for now build the wheel from a checkout (Zig 0.14 and uv):

```console
scripts/build-release.sh
(cd release && sha256sum -c SHA256SUMS)
uv tool install release/x64dbg_vm_gateway-*.whl      # puts x64dbg-vm-gateway on PATH (--force to reinstall)
x64dbg-vm-gateway --help
```

A release wheel will carry the prebuilt plugin, so no Zig is needed then: download the wheel and
`SHA256SUMS`, run `sha256sum -c --ignore-missing SHA256SUMS`, then
`uv tool install ./x64dbg_vm_gateway-<version>-py3-none-any.whl`. If the shell does not find
`x64dbg-vm-gateway` afterwards, run `uv tool update-shell` and open a new shell.

`scripts/build-release.sh` (Zig 0.14 and uv; runs from any directory) builds the plugin and the
benign demo samples, bundles them into the package and writes `release/`: the wheel, the sdist,
`x64dbg-mcp-plugin-<version>.zip` (`x64/plugins`, `x32/plugins`) and `SHA256SUMS`. The wheel
also carries the static-tool sync scripts ([Static analysis tools](#static-analysis-tools)).
Pushing a `v*` tag runs it in GitHub Actions and attaches `release/*` to the release. The tag
is the gateway version: `vX.Y.Z` must equal `version` in `host/pyproject.toml` (the wheel's
version), otherwise the workflow stops before building anything
(`scripts/check-release-tag.sh vX.Y.Z` checks a tag locally). The plugin zip keeps the plugin
version from `build.zig.zon`. `uv tool install ./host` from a checkout also works; it has no
bundled plugin unless the script ran first, so `install-plugin` then needs `--dist`.

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

1. Clone the VM first if it is an analysis VM you already use: setup changes the guest and every
   analysis reverts it. In the guest: install VMware Tools, unpack x64dbg, create a local analysis
   user with a lab-only password (see [Requirements](#requirements)).
2. On the host, with the VM running and the guest password exported, run everything at once:

   ```console
   x64dbg-vm-gateway setup --dry-run      # the plan; nothing is contacted or changed
   x64dbg-vm-gateway setup                # init (if no config), doctor, install-plugin, provision, doctor
   ```

   Without a config, `setup` runs the `init` wizard (or takes its flags: `--non-interactive --vmx
   ... --guest-user ... --x64dbg-root ...`). It stops with the doctor's hints when a check it cannot
   fix fails (vmrun, .vmx, VM power, VMware Tools, guest credentials, guest IP, isolation, a second
   VM instance, job roots), installs the bundled plugin (`--dist DIR` for another build), runs
   `provision` with `--snapshot` (default: the profile's `clean_snapshot`), checks again and prints
   the `claude mcp add` command. `--skip-plugin` and `--skip-provision` run parts of it. It never
   replaces an existing snapshot: use `--snapshot NEW_NAME`, then set `clean_snapshot` (and
   `protected_snapshots`) in the config to it yourself. Without auto-logon someone has to log on in
   the VM after the reboot, within `--wait-ready` seconds.
   `setup` with its values given as flags ran on the real VM (248 s from the precheck to the
   registration commands); its terminal questions and `--save-password-file` are covered by unit
   tests only. What is verified where is listed in one place, the
   [verification status of the Korean README](../README.md#검증-현황).
3. Copy the plugin into the guest (the bundled build, or `--dist DIR` holding `x64/plugins` and
   `x32/plugins`; `--x64dbg-root` defaults to the profile's backend paths). On a guest that is not
   provisioned yet add `--no-relaunch`: the logon tasks that relaunch the debuggers come with step 4.

   ```console
   x64dbg-vm-gateway install-plugin                # --dist DIR, --x64dbg-root, --no-relaunch
   ```

4. Provision. This writes both `mcp_config.json` files (keeping valid tokens, generating
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

5. Check everything:

   ```console
   x64dbg-vm-gateway doctor          # exit code 1 if a check fails; each failure has a hint
   ```

## Use it from Claude Code

```console
claude mcp add x64dbg-vm -- x64dbg-vm-gateway serve
# one serve drives every profile of the config (see "Several VMs"); --profile NAME sets the default
```

`x64dbg-vm-gateway mcp-config` prints this command for your config (with
`-e X64DBG_VM_GATEWAY_CONFIG=<path>` when the config is not at the default location), followed by
the commands for the static-analysis tools ([below](#static-analysis-tools)).

Start Claude Code from a shell where the password variable is exported (avoid `claude mcp add -e`,
which writes the value into Claude's config file). Run only one gateway per jobs root at a time;
remote users connect to the same gateway over HTTP instead of starting a second one.

The gateway lists all tools at session start: its own 22 tools plus the plugin's x64dbg tools
under their original names (`SetBreakpoint`, `run`, `DumpMemory`, ...; 83 with plugin v1.10, so 105
in all). `debugger_call` reaches any backend tool that is not listed.

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
| observe (read-only) | `session_status`, `gateway_doctor`, `vm_snapshots_list`, `vm_screenshot`, `static_rebase`, `jobs_list`, `jobs_show`, `analysis_report` |
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
  see [Static analysis tools](#static-analysis-tools). The former names `ida_rebase`,
  `ida_export_annotations` and `ida_import_annotations` still work but are not listed. When the
  debugger should still hold the sample but its live module map is unavailable, the map recorded
  by `analysis_collect` is used and `warnings` says so.
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
- `analysis_report(job_id?, format="markdown"|"json")` summarises a job from its host job
  directory: states with timestamps, the sample (name, size, sha256, arch), epoch and debugger
  restarts, the collected files (original guest path, size, sha256, host path), the module map,
  screenshots, downloads, the static export and warnings / errors. Default job: the active one,
  else the newest. Every Markdown value is a code span in a list (no Markdown or HTML in a guest
  name is rendered), and whatever may come from the guest (file and module names, messages,
  state reasons, flags) stays inside `<untrusted_guest_output>` blocks (JSON: listed under
  `guest_derived`; at most 1000 files, `files_truncated`). It reads `<jobs_root>/<job id>` only and
  returns text; `x64dbg-vm-gateway jobs report JOB_ID --out FILE [--force]` writes it (0600, an
  existing file only with `--force`), also while a gateway serves.
- MCP prompts (`prompts/list`, `prompts/get`, every HTTP scope): `analyze-sample` (`sample_path`,
  `arch`), `trace-api` (`sample_path`, `api` such as `kernel32.CreateFileW`), `find-oep`
  (`sample_path`), `static-dynamic` (`sample_path`, `static_address`, `imagebase`, `module`) and
  `report` (`job_id`). Each is a step-by-step plan with the real tool names and the safety rules;
  bad arguments answer `INVALID_PARAMS`. Claude Code lists them as commands such as
  `/x64dbg-vm:analyze-sample (MCP)` and runs `/mcp__x64dbg-vm__analyze-sample /path/to/sample.exe`
  (the middle part is the server name given to `claude mcp add`; arguments are split on
  whitespace, in the order above). The prompts are covered by unit tests; the Claude Code naming is
  taken from Claude Code's documentation.
- While a gateway serves a jobs root, CLI commands that need it (`discard`, `status`, `doctor`,
  `provision`, `install-plugin`) stop with `LOCK_TIMEOUT` naming the gateway's pid. `provision` and
  `install-plugin` run with supervision paused and the VM lock held, and start new backend epochs
  after a plugin install. A job whose debugger held the sample is marked `flags.debuggee_lost`
  (the CLI names it), and the next gateway's recovery hint says the sample is no longer loaded.

### Several VMs

One `serve` handles every profile in the config (`--profile` only sets the default), and each
profile (VM) can have its own live job at the same time. Each VM has its own VM lock, operation
runner, debugger supervision and epochs: a revert, power change or debugger restart of one VM never
waits for, reverts or bumps the epochs of another. Two profiles that name the same `.vmx` share one
operation runner and never have live jobs at once.

- `analysis_start(profile=...)` makes that VM the *target* of the client session (each MCP session
  has its own; stdio has one). `debugger_select(profile=..., backend_id=...)` switches it.
- Mirrored x64dbg tools, `debugger_call`, `vm_screenshot`, `vm_snapshots_list` without `profile`
  and job tools without `job_id` go to: the session's target, else the only profile, else the VM
  with the only live job, else the default profile. Tools that change a VM or kill a debugger
  (`vm_snapshot_*`, `vm_power`, `debugger_restart`, `analysis_start`) skip the live-job step:
  another client's job never picks the VM they change. With live jobs on several VMs and no target
  the call is refused with `TARGET_AMBIGUOUS` (the jobs and the `debugger_select` call are in the
  error); nothing is sent. A profile whose job directory is unreadable counts as busy.
  `debugger_call` and `debugger_restart` also take `profile`.
- Every mirrored result ends with `[gateway] epoch=N backend=ID profile=NAME retried=...`.
- `session_status` without `profile` lists every VM compactly (VM, backends, live job, running
  operation) and shows the session's `target`, the `routing` decision and the `active_jobs`; it
  acknowledges restarts only on the routed VM. `session_status(profile=...)` shows (and
  acknowledges) one VM in full; `BACKEND_RESTARTED` from another VM names that call in its hint.
- A polled `analysis_finish` without `job_id` answers only the client session that started it.
- Over HTTP a target needs an MCP session (handshake protocol versions, whose session id the SDK
  validates). Requests of the stateless 2026 protocol keep no target: pass `profile` / `job_id`,
  or rely on a single live job or the default profile.
- A `read` HTTP token cannot call `debugger_select` (guest-mutating tier), so while several VMs
  have live jobs its mirrored calls are refused with `TARGET_AMBIGUOUS`; `session_status` still
  shows every VM.
- `serve` and the CLI accept a config with several profiles and no `default_profile`; commands
  such as `doctor` then need `--profile`.

## Static analysis tools

The gateway does not run IDA, Ghidra or radare2. Each tool's own MCP server is registered in the
MCP client next to the gateway, and the gateway converts between x64dbg runtime addresses and the
tool's `image base + RVA`: `static_rebase`, `static_export_annotations` and
`static_import_annotations` (tool-neutral document `x64dbg-ida-sync/1`, keyed by module + RVA).
List the tools you use; the first one is the default the gateway names in its instructions:

```toml
[static]
tools = ["ida", "ghidra", "radare2"]   # default ["ida"]; ids: ida, ghidra, radare2, cutter

[static.servers.ghidra]                 # optional: fills in or replaces the default recipe
args = ["--transport", "stdio", "--project-path", "/path/to/ghidra-projects", "--project-name", "lab",
        "--wait-for-analysis", "/path/to/sample.exe"]
env = { GHIDRA_INSTALL_DIR = "/path/to/ghidra_12.2_PUBLIC", JAVA_HOME = "/path/to/jdk-25" }
```

`[static.servers.<id>]` takes `command` (program and arguments; the program is an absolute path or a
bare name found on `PATH`), `args` (arguments for the default program), `url` with `transport`
(`http` or `sse`), `env` (environment of a stdio server) and `name` (the MCP server name; not
`x64dbg-vm`, which is the gateway's). `mcp-config` prints `command`, `args`, `url` and `env`
verbatim, so the config refuses whatever looks like a secret: a URL with `user:password@` or a
query parameter such as `token=`, and options, `NAME=VALUE` / `Name: value` pairs and `env` names
with a name segment such as TOKEN, KEY, SECRET, PASS(WORD), AUTH, BEARER, COOKIE or CREDENTIALS
(`--api-key`, `GH_TOKEN`, `DB_PASS`; KEYBOARD, COMPASS or BYPASS are fine, and so is a name ending
in FILE, PATH or ENV, such as `--token-file`). Keep secrets in the MCP server's own configuration
or environment. Control characters (TAB, CR, LF, NUL, ESC, C1) and Unicode bidi controls are
refused there too, so the printed commands are exactly the configured ones.

Register them:

```console
x64dbg-vm-gateway mcp-config          # `claude mcp add` for the gateway and every [static] tool
x64dbg-vm-gateway mcp-config --json   # the same as a list
x64dbg-vm-gateway mcp-config --client json      # an mcpServers document (Claude Desktop, Cursor, VS Code)
x64dbg-vm-gateway mcp-config --tool ghidra --set binary=/srv/a.exe --set project-dir=/srv/ghidra ...
x64dbg-vm-gateway mcp-config --apply  # run the commands that need nothing filled in (asks; --yes)
x64dbg-vm-gateway mcp-config --permissions      # Claude Code settings.json permissions (strict)
x64dbg-vm-gateway mcp-config --permissions --permissions-mode lab   # broader, for disposable lab VMs
```

The gateway's command names this installation's executable by its absolute path when it can be
resolved (the running `x64dbg-vm-gateway`, else the one on PATH; the PATH search never looks in
the current directory, for `claude` either). `--tool ID` limits the output to
`gateway` or one static tool; `--set NAME=VALUE` fills the `<NAME>` placeholder (refused: control
characters and values that look like a secret, as in the config). `--apply` runs `claude mcp add`
only for registrations without placeholders, after a y/N question on a terminal or with `--yes`,
never with an argument that looks like a secret (and, with an npm `claude.cmd` on Windows, never
with an argument cmd.exe would misread), and reports each command and its output (a server that is
already registered is reported as such; answering N registers nothing and exits 0).
`--permissions` prints `{"permissions": {"allow": [...], "ask": [...]}}` for the gateway's server
name, by exact tool name (`mcp__x64dbg-vm__<tool>`); merge it into `.claude/settings.json` or
`~/.claude/settings.json`. Strict (the default) allows the observe-tier gateway tools,
`analysis_start`, `analysis_collect`, `file_upload`, the `static_*` tools and the plugin tools the
builtin lists mark read-only, and asks for everything else (`debugger_call`, the debugger controls,
`SetBreakpoint`, `run`, `WriteMemToAddress`, `ExecuteDebuggerCommand`, the dump tools, ... and the
host/VM-destructive gateway tools). `--permissions-mode lab`, for disposable lab VMs that are reverted
after every job, also allows every tool that only changes the guest; an endpoint profile is always
strict.

On Windows the printed commands are for PowerShell (every argument that is not a plain word is
single-quoted, including `'--'`); elsewhere they are for a POSIX shell.

User-specific parts stay as `<...>` placeholders and are listed under `fill in`. Each tool's entry
also names its install command, its sync script in this installation and its caveats; `setup` ends
with the same block.

| Tool | MCP server (default registration) | Verified with | Sync script (`static-scripts`) |
|---|---|---|---|
| IDA Pro | ida-multi-mcp: `python3 -m ida_multi_mcp` (tools `rename`, `set_comments`, `decompile`, `idb_save`) | ida-multi-mcp | `ida/x64dbg_sync.py`: IDA menu actions or File > Script file |
| Ghidra | pyghidra-mcp 0.3.0, headless (`pip install pyghidra-mcp`): `pyghidra-mcp --transport stdio --project-path <project-dir> --project-name <project-name> --wait-for-analysis <binary>` with `GHIDRA_INSTALL_DIR` and `JAVA_HOME` | Ghidra 12.2 with JDK 25 | `ghidra/x64dbg_sync_ghidra.py`: `support/pyghidraRun -H` (plain `analyzeHeadless` cannot run Python scripts) or the Script Manager of a Ghidra started with `pyghidraRun` |
| radare2 | r2mcp 1.9.0 (`r2pm -ci r2mcp`): `r2pm -r r2mcp`. It has no project-save tool: changes made through it are lost when it exits | radare2 6.2.6 | `radare2/x64dbg_sync_r2.py` (radare2 and rizin; `--project` keeps the changes) |
| Cutter | none by default (see the warning) | sync script in Cutter 2.5.0 and 2.4.1 | `radare2/x64dbg_sync_r2.py` in Cutter's Python console |

pyghidra-mcp answers the client's first `initialize` only after Ghidra's analysis when
`--wait-for-analysis` is given: raise the client's start-up timeout (Claude Code: `MCP_TIMEOUT`) or
drop the option. Its `rename_function` renames functions only, `save` writes the project, and
`binary_name` comes from `list_project_binaries`. Alternative for Ghidra: LaurieWired GhidraMCP 2.0
headless (`ghidra_mcp-2.0.0[headless]` wheel and `GhidraMCP.jar` from its release zip), registered
with `[static.servers.ghidra] command = ["ghidra-mcp", "--headless", "--binary", ...,
"--extension-jar", ...]` and the same two variables; its GUI mode was not verified.

> **CutterMCP is unsafe as shipped.** CutterMCP 2.0's Cutter plugin listens on all interfaces
> (port 8000) without authentication and pastes request parameters unescaped into `cutter.cmd`, so
> anyone who reaches the port runs rizin commands, including `!` shell commands. Its
> `set_decompiler_comment` is broken as well. The gateway therefore registers no MCP server for
> Cutter: use the sync script inside Cutter, or radare2's r2mcp on the same binary. If you still
> use CutterMCP, patch its plugin to bind `127.0.0.1` first, then set `[static.servers.cutter]
> command`. (Cutter 2.5.0's Qt6 AppImage cannot load Python plugins at all, rizinorg/cutter#3659.)

The wheel carries the sync scripts (byte copies of [`../static/`](../static/README.md)):
`x64dbg-vm-gateway static-scripts` prints where they are installed, and
`x64dbg-vm-gateway static-scripts --dest DIR` copies them with their layout (it refuses to
overwrite files unless `--force` is given). How to run each one: [`../static/README.md`](../static/README.md)
and, for IDA, [`../static/ida/README.md`](../static/ida/README.md). `doctor` (and the MCP tool
`gateway_doctor`) reports in its `static_tools` check whether each tool and its MCP server's
program are found; it only warns, and it shows the program's name and the number of arguments,
never the command line.

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
| `init` | write the config file (`--upload-root DIR`, repeatable: `gateway.upload_roots`, default `~`) |
| `jobs [list \| show JOB_ID]` | read-only view of the job directories (works while a gateway runs) |
| `jobs report JOB_ID [--out FILE [--force]] [--format markdown\|json]` | the job's report (see `analysis_report`), printed or written to FILE |
| `demo [--arch x64\|x32\|both]` | installation self-test on the VM with the bundled benign sample (see below) |
| `discard JOB_ID [--yes]` | human-only: mark a job DISCARDED so it may be reverted without collection |
| `provision --x64dbg-root PATH ...` | prepare the guest (see above) |
| `install-plugin [--dist DIR] ...` | copy a plugin build (default: the bundled one) into the guest |
| `setup [--dry-run] ...` | init (no config yet), doctor, install-plugin, provision, doctor, registration commands; on a terminal it asks for the VM, guest user, guest password (not echoed) and x64dbg folder (offering a search in the guest) unless `--non-interactive` |
| `setup --save-password-file [PATH] [--force]` | also write the guest user and password to a 0600 env file, once the doctor precheck shows the guest accepts them (default: the file `gateway.env_file` names, else `<profile>.env` in the per-user config folder); a new config gets `gateway.env_file` once the file is written, an existing config is not edited (the line to add is printed); `--force` updates an existing file's two lines |
| `snapshot refresh --name NEW [--set-clean]` | human-only: take a new clean snapshot of the running guest after the readiness checks (no unfinished job, one VM instance, plugins answer); `--set-clean` also sets `clean_snapshot` / `protected_snapshots` in a config written by init or setup, otherwise the lines are printed |
| `snapshot prune --keep N [--yes]` | human-only: list the `gw-*` snapshots and the recorded old clean snapshots beyond the newest N of each; deletes them only with `--yes`; the clean and protected snapshots of every profile on the VM, and names VMware lists more than once, are never deleted; recorded snapshots VMware no longer lists are forgotten |
| `mcp-config [--client claude\|json] [--tool ID] [--set NAME=VALUE] [--apply [--yes]] [--permissions [--permissions-mode strict\|lab]]` | registration commands (or mcpServers JSON) for the gateway and the configured static tools; `--apply` runs them, `--permissions` prints Claude Code permissions |
| `static-scripts [--dest DIR] [--force]` | where the static-tool sync scripts are installed, or a copy of them |

Global options, before or after the command: `--config PATH`, `--profile NAME`, `--json`
(machine-readable stdout), `-v`. Exit codes: 0 success, 1 failure (prints `error [CODE]: message`
and a hint), 2 usage error.

`demo` analyses the benign E2E sample bundled with release wheels (`data/samples/`, built from
`tests/vm/samples/hello.zig` by `scripts/build-release.sh`) for each architecture the profile has a
backend for (or `--arch`): `analysis_start`, `SetBreakpoint kernel32.Sleep`, `run` until it stops in
kernel32 (at most 4 times), `GetCallStack`, `analysis_collect`, `analysis_finish(revert=true)`. It
prints every step with its time, then `PASS` or `FAIL` with hints (exit 0 / 1, 130 after Ctrl-C;
`--json` for one document). The stop must be `PAUSED` in kernel32 at the address `EvalExpression`
gives for `kernel32:Sleep` (when it resolves). The sample is copied to a private directory below
`~/.cache/x64dbg-vm-gateway/demo`, which is the only upload root of the demo's own gateway (the config
file is not changed). A failed or interrupted step cleans up the demo's own job only (the job of its
successful `analysis_start`, or a new job of the profile holding its sample): collect, discard if
still partial, finish with revert; a job it cannot clean up (an operation still running, a failed
revert) is named with the command to handle it, and the next architecture is not started. It
refuses next to a serving gateway (`LOCK_TIMEOUT`), a live or unreadable job, an endpoint profile and
missing samples (with how to build them). It reverts the VM to the clean snapshot.

## Safety

- **The guest is hostile.** Run samples only in the VM. Keep the guest on a host-only network
  and disable shared folders; with `require_isolation = true` (default) `analysis_start` refuses
  a VM with shared folders or a non-host-only adapter (`ISOLATION_REQUIRED`).
- **Guest output is untrusted.** Text from the guest is stripped of control characters and
  wrapped in `<untrusted_guest_output>`; the model is told never to follow instructions inside
  it. Collected files and downloads are untrusted data: never execute them on the host. On
  Windows hosts `analysis_collect` keeps the archive `artifacts/raw/out.zip` without extracting it
  by default (`extract=true` extracts it).
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
- **`LOCK_TIMEOUT` on the jobs root.** Another gateway process owns it, usually the `serve` that
  Claude Code started. Close the client, or use the MCP tools
  `gateway_doctor` / `session_status`, or `jobs` (read-only) instead. A second Claude Code window
  cannot start its own gateway on the same jobs root for the same reason.
- **`x64dbg-vm-gateway: command not found` after `uv tool install`.** Run `uv tool update-shell` and
  open a new shell (`uv tool dir --bin` shows the directory).
- **The MCP server shows as failed in Claude Code** (`/mcp`, `claude mcp list`). Re-register with
  the command `mcp-config --tool gateway` prints (it names the executable by absolute path, which
  changes when you reinstall elsewhere); make sure no other gateway holds the jobs root; `claude mcp
  add` registers for the current directory unless `--scope user` is given. Slow servers such as
  pyghidra-mcp with `--wait-for-analysis` need a longer start-up timeout: `MCP_TIMEOUT=120000 claude`
  (milliseconds).
- **`ISOLATION_REQUIRED`.** Power the VM off and fix the `.vmx` keys listed under
  [Requirements](#requirements).
- **`TARGET_AMBIGUOUS`.** Live jobs on several VMs and no target for this client session: call
  `debugger_select(profile=...)` or pass `profile` / `job_id` (see [Several VMs](#several-vms)).
- **`serve --transport http` refuses to start.** The error names the missing piece: `http.enabled`,
  an unset token variable, a token shorter than 16 characters, or TLS for a non-loopback bind.

The Korean README has a troubleshooting table by symptom and an index of every error code:
[문제 해결](../README.md#문제-해결).

## Development

```console
uv sync
uv run pytest            # unit tests (no VM)
uv run pytest -m vm      # real-VM tests (needs the spike VM + env vars)
uv run ruff check src tests
```

### Testing

`uv run pytest` runs the unit tests only (`-m 'not vm'` is the default): the VM, the guest and
the plugin are fakes (`tests/fakes/`), and the plugin speaks real HTTP on loopback. It also runs
the sync-script suites `../static/tests` and `../static/ida/tests` (no IDA, Ghidra or radare2
needed) in a subprocess, and checks that the packaged copies in `src/x64dbg_vm_gateway/data/static/`
are byte-identical to `../static/`.

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
[`docs/PHASE0_RESULTS.md`](../docs/PHASE0_RESULTS.md) for the timings and the defects this suite
found, and the [verification status](../README.md#검증-현황) for what is verified on the real VM and
what only by unit tests.
