# x64dbg ⇄ static tools sync (Ghidra, radare2, rizin, Cutter)

The gateway exchanges annotations between x64dbg (dynamic, runtime addresses) and a
static tool (image base addresses) through one tool-neutral JSON document, schema
`x64dbg-ida-sync/1`, keyed by **module + RVA** (see [ida/README.md](../ida/README.md)
for the schema and the IDA side):

```
runtime = module_base_runtime + rva          (x64dbg, ListModules)
static  = image base of the static tool + rva   (Ghidra: program image base, r2/rizin: baddr)
```

This directory holds the per-tool sync scripts for the other supported static tools,
and the shared core they are built on:

| File | Runs in | What it does |
|---|---|---|
| `common/x64dbg_sync_core.py` | plain Python 3.9+ | Loads/validates a document, matches the module by file name, builds the import plan for an image base, holds the name/comment rules per tool, applies a plan through a small tool adapter (merge-not-overwrite comments, counters), builds export documents. Mirrors the rules of `ida/x64dbg_sync.py` (parity tests). No tool module is imported. |
| `ghidra/x64dbg_sync_ghidra.py` | Ghidra ≥ 11.3 with PyGhidra (Python 3) | Import / export, from the Script Manager or headless. |
| `radare2/x64dbg_sync_r2.py` | radare2 (r2pipe), rizin (rzpipe), Cutter (`cutter.cmd`) | One script for all three through a command adapter. Import / export, from the command line, from inside a session (`#!pipe`), or from Cutter's Python console. |

Both scripts find `x64dbg_sync_core.py` at run time: next to the script first, then in
`../common/`. Keep the directory layout, or copy the core next to the script.

## What import and export do

**Import** (document → tool), at `image base + rva` of the module that matches the
program's file name (case-insensitive, then a unique match without extension:
`sample.bin` matches `sample.exe`; or name the module explicitly):

* A name renames the **function** that starts at the address. Without a function there:
  Ghidra adds a primary `USER_DEFINED` label (other labels at the address stay as
  secondary labels); radare2/rizin set a flag in the `x64dbg` flagspace (an earlier
  import's flag at the address is replaced, flags of other flagspaces are never touched).
* Comments are **merged** into the existing comment, never overwritten. A comment that is
  already present as a whole line is not added again, so importing the same document twice
  changes nothing (the second report shows everything as `unchanged`).
* Bookmarks and breakpoints become a tag in the comment, as in IDA:
  `[x64dbg: bookmark; hardware bp, disabled, condition rcx==1]`.
* A name with no character the tool can use (for example all Korean for radare2) does not
  rename anything; it is kept in the tag as `[x64dbg: label 복호화_루틴]`.
* Addresses outside the program's memory/sections are counted as `unmapped`.

**Export** (tool → document) writes RVAs relative to the tool's image base, ready for the
gateway's `ida_import_annotations` / `plan_import` (items `{rva, name?, comment?}`; the
module entry carries the image base as `ida_imagebase`, the field name the schema uses for
the static tool's image base):

* Ghidra: `USER_DEFINED` label and function names, and all comment kinds (plate, pre,
  EOL, post, repeatable, joined with ` | `), minus the markup the PE loader adds (section
  names in the `Headers` block, `IMAGE_*` structure names, `<<not bound>>` IAT slots,
  `.NET PDB Info`). `--all-comments` keeps those too.
* radare2/rizin/Cutter: function names that are not generated (`fcn.*`, `sym.*`, `entry0`,
  `main`, `switch.*`, `case.*`, ... are left out), flags of the `x64dbg` flagspace and flags
  without a flagspace, and comments minus the section banners
  (`[00] -r-x section size ... named .text`) and switch-table notes the tools add.

### Name rules per tool

Names from the document are made safe for the target tool before they are used. The rules
were measured on the versions listed under *Verified versions*:

| Tool | Allowed | Adjustments |
|---|---|---|
| IDA (`ida/x64dbg_sync.py`) | `[A-Za-z0-9_$?@]` | leading digit and IDA dummy names (`sub_401000`, ...) get a `_` prefix; ≤ 511 chars |
| Ghidra | anything except whitespace, control/format characters and `SymbolUtilities.EXTRA_INVALID_CODEPOINTS` (each run becomes `_`) | names Ghidra reserves for its default names (`FUN_140001000`, `DAT_...`, `LAB_...`; checked with `SymbolUtilities.isReservedDynamicLabelName`) get a `_` prefix; ≤ 2000 chars |
| radare2 / rizin / Cutter | `[A-Za-z0-9_.]` (each run of other characters becomes `_`) | leading `_`/`.` stripped (rizin strips a leading `_`, radare2 refuses a leading `.`), a leading digit gets `lbl_`; ≤ 255 chars. Only these characters are ever written into an r2/rizin command line. |

Comments are one line in the document (control, bidi and zero-width characters removed).
In radare2/rizin they are written with `CCu base64:<text> @ addr`, so arbitrary text
(`;`, `|`, `` ` ``, `@`, quotes, non-ASCII) never reaches the command parser; this syntax
replaces the comment at the address and keeps the text byte for byte on radare2 6.2.6 and
rizin 0.9.1 (plain `CC base64:` decodes on radare2 but drops backslashes, and stores the
literal `base64:` text on rizin).

## Ghidra

Requirements: Ghidra ≥ 11.3 (the first release with PyGhidra built in), started in
PyGhidra mode. Ghidra 12.2 needs JDK 25 (`application.java.min=25` in
`Ghidra/application.properties`); other releases state their minimum in the same file.

**Script Manager:** add `static/ghidra` to the script directories (*Script Manager → Manage
Script Directories*), or copy `x64dbg_sync_ghidra.py` together with
`x64dbg_sync_core.py` into a script directory such as `~/ghidra_scripts`. Start Ghidra
with `support/pyghidraRun` so that Python 3 scripts can run, then run
*x64dbg → x64dbg_sync_ghidra.py*. It asks for the action, the file, and for imports the
comment kind (EOL or pre). When no module of the document matches the program, it asks
for the module name.

**Headless:** Python 3 scripts need the PyGhidra launcher. Plain `support/analyzeHeadless`
refuses them with *"Ghidra was not started with PyGhidra. Python is not available"*. Use
`support/pyghidraRun -H`, which takes the `analyzeHeadless` arguments:

```sh
# import (analysis runs first, as with any -postScript)
<ghidra>/support/pyghidraRun -H <project_dir> <project> -import <sample.exe> \
    -postScript <repo>/static/ghidra/x64dbg_sync_ghidra.py import <doc.json> [module] [--comment=eol|pre]

# again on the existing program (idempotent), or export
<ghidra>/support/pyghidraRun -H <project_dir> <project> -process <sample.exe> -noanalysis \
    -postScript <repo>/static/ghidra/x64dbg_sync_ghidra.py import <doc.json>
<ghidra>/support/pyghidraRun -H <project_dir> <project> -process <sample.exe> -noanalysis -readOnly \
    -postScript <repo>/static/ghidra/x64dbg_sync_ghidra.py export <out.json> [--all-comments]
```

`pyghidraRun` uses the active Python virtual environment, so activate one that has
`pyghidra` (the Ghidra release ships it: `pip install --no-index -f
<ghidra>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra`), and set `JAVA_HOME` to the JDK.
The report goes to the Ghidra log (`INFO x64dbg_sync_ghidra.py> x64dbg sync (ghidra): ...`).
Errors are printed with `printerr` (no traceback), for example a document with a wrong
schema or no matching module.

## radare2, rizin and Cutter

Requirements: Python 3.9+ with `r2pipe` (radare2) or `rzpipe` (rizin), and the tool on
`PATH`.

```sh
# radare2 (default) or rizin; -A runs "aa" first so that functions exist and can be renamed
python3 static/radare2/x64dbg_sync_r2.py --binary sample.exe -A import doc.json --project <projects_dir>/sample
python3 static/radare2/x64dbg_sync_r2.py --binary sample.exe export out.json --project <projects_dir>/sample
python3 static/radare2/x64dbg_sync_r2.py --tool rizin --binary sample.exe import doc.json --project sample.rzdb
```

Options may come before or after the action. `--module NAME` picks the module of the
document. `--project`: a radare2 project name (stored in `dir.projects`) or `DIR/NAME`
(passed as `-e dir.projects=DIR`), or a rizin `.rzdb` file. The project is loaded when it
exists and saved after an import. Without `--project`, a command-line import only lasts as
long as the r2/rizin process it starts, so either give a project or run the script inside
your own session:

```
[0x14000102c]> #!pipe python3 /path/to/static/radare2/x64dbg_sync_r2.py import /path/to/doc.json
[0x14000102c]> #!pipe python3 /path/to/static/radare2/x64dbg_sync_r2.py export /path/to/out.json
```

Both radare2 and rizin run `#!pipe` (it sets `R2PIPE_IN`/`R2PIPE_OUT` or
`RZ_PIPE_IN`/`RZ_PIPE_OUT`; the script detects which). Save your project yourself afterwards.

**Cutter** runs rizin, and its Python console (*Windows → Python*) has `cutter.cmd`:

```python
import sys; sys.path.insert(0, "/path/to/static/radare2")
import x64dbg_sync_r2 as xs
xs.cutter_import("/path/to/doc.json")          # or xs.cutter_import(path, module="sample.exe")
xs.cutter_export("/path/to/out.json")
```

`cutter_import` calls `cutter.refresh()` afterwards so the views show the new names.

Cutter 2.5.0's Qt6 AppImage cannot load Python *plugins*
([rizinorg/cutter#3659](https://github.com/rizinorg/cutter/issues/3659)). Code in its
embedded Python still runs, and the script works there. The Qt5 AppImage and Cutter
2.4.1 load Python plugins.

## MCP servers per tool

Each static tool's own MCP server is registered next to the gateway. The gateway converts
addresses (`ida_rebase`, the export/import tools), and the tool's server reads and edits the
database at `image base + rva`. These are the servers this directory was checked against.
All are stdio servers. Replace `<...>` with your paths.

| Tool | MCP server | Register (Claude Code) | rename | comment | decompile |
|---|---|---|---|---|---|
| IDA | ida-multi-mcp | see [ida/README.md](../ida/README.md) | `rename` | `set_comments` | `decompile` |
| Ghidra (headless) | [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp) 0.3.0 (`pip install pyghidra-mcp`) | `claude mcp add pyghidra -e GHIDRA_INSTALL_DIR=<ghidra> -e JAVA_HOME=<jdk25> -- <venv>/bin/pyghidra-mcp --transport stdio --project-path <projects_dir> --project-name <name> --wait-for-analysis <sample.exe>` | `rename_function(binary_name, name_or_address, new_name)` (functions only) | `set_comment(binary_name, target, comment, comment_type=eol\|pre\|post\|plate\|repeatable\|decompiler)` | `decompile_function(binary_name, name_or_address)` |
| Ghidra (headless or GUI) | [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) 2.0 (release wheel `ghidra_mcp-2.0.0[headless]` + the extension's `GhidraMCP.jar`) | headless: `claude mcp add ghidra -e GHIDRA_INSTALL_DIR=<ghidra> -e JAVA_HOME=<jdk25> -- <venv>/bin/ghidra-mcp --headless --binary <sample.exe> --project <project_dir> --extension-jar <GhidraMCP.jar>`; GUI: `... ghidra-mcp --ghidra-server http://127.0.0.1:8080/` with the extension enabled in Ghidra | `rename_function_by_address(function_address, new_name)`, `rename_function(old_name, new_name)`, `rename_data(address, new_name)` | `set_disassembly_comment(address, comment)` (EOL), `set_decompiler_comment(address, comment)` (PRE) | `decompile_function_by_address(address)` |
| radare2 | [r2mcp](https://github.com/radareorg/radare2-mcp) 1.9.0 (`r2pm -ci r2mcp`) | `claude mcp add radare2 -- r2pm -r r2mcp` (`r2pm` and `radare2` on `PATH`) | `rename_function(address, name)` (needs a function: call `analyze` first), `rename_flag(address, name, new_name)` | `set_comment(address, message)` | `decompile_function(address)` (r2's `pdc` by default) |
| Cutter (rizin) | [CutterMCP](https://github.com/ap425q/CutterMCP) 2.0: Cutter Python plugin + `bridge_mcp_cutter.py` | `claude mcp add cutter -- <venv>/bin/python <CutterMCP>/bridge_mcp_cutter.py` (Cutter must be running with the plugin) | `rename_function_by_address(function_address, new_name)` | `set_decompiler_comment(address, comment)`: **broken in 2.0** (the bridge posts to `/set_decompiler_comment`, the plugin serves `/setDecompilerComment`; the call returns an `Error 404` text) | `decompile_function_by_address(address)` (rz-ghidra `pdg`) |

Notes:

* **pyghidra-mcp** answers `initialize` only after the analysis when `--wait-for-analysis` is
  given, so the first start of a new project takes as long as Ghidra's analysis. Raise the
  client's MCP start-up timeout (Claude Code: `MCP_TIMEOUT`), or drop the option. The
  `binary_name` argument is the project path that `list_project_binaries` returns (for
  example `/sample.exe-d7eff5`). There is no label-rename tool, and `save` writes the
  project.
* **GhidraMCP 2.0** is built for Ghidra 12.1.4. With `--extension-jar` it also ran against
  Ghidra 12.2 headless. According to its `--help`, `--project` keeps the project and saves
  changes on exit, and without it a temporary project is discarded. Saving was not checked
  here.
* **r2mcp** works on its own in-memory session: there is no tool that saves a project, so
  renames and comments made through it are gone when the server stops. Use
  `x64dbg_sync_r2.py --project` (or your own r2 session and `#!pipe`) for anything that
  must persist. Do not enable `-r` (the `run_*` tools run arbitrary r2 commands).
* **CutterMCP 2.0 is not safe as shipped.** The plugin binds its HTTP server to all
  interfaces (`('', 8000)`) without authentication. It also passes request parameters
  unescaped into `cutter.cmd` (`afn {new_name} @ {address}`, `CCu {comment} @ {address}`,
  `afs ...`, `afl~...`). Anyone who can reach port 8000 can run rizin commands, including
  `!` shell commands. Before using it, change the bind address to `127.0.0.1`. The plugin
  imports PySide6, so it needs a Qt6 Cutter that loads Python plugins: Cutter 2.4.1 works,
  the 2.5.0 Qt6 AppImage does not (#3659), and the Qt5 AppImages have only PySide2. Its
  requirements pin `mcp==1.5.0`, which fails to import with a current pydantic
  (`ImportError: eval_type_backport` with pydantic 2.14.4); `pydantic==2.10.6` works.

## Verified versions

Real-tool runs on the benign E2E sample (PE32+, image base `0x140000000`, entry point at
RVA `0x102C`) with the document `{"rva": "0x102c", "name": "gw_probe_entry", "comment":
"set by x64dbg_sync import probe"}` + `{"rva": "0x102c", "bookmark": true}`. Each run
imported, checked the name and comment at `0x14000102C`, imported again (no change),
exported, and checked that the item was in the exported document. The exports were also
fed to the gateway's `plan_import`:

| Tool | Version | Result |
|---|---|---|
| Ghidra | 12.2 (JDK 25.0.5, PyGhidra 3.2.0, Python 3.12) headless via `pyghidraRun -H` | function `entry` → `gw_probe_entry` (`USER_DEFINED`), EOL comment `set by x64dbg_sync import probe\n[x64dbg: bookmark]`; `--comment=pre` writes the pre comment; idempotent; export = exactly that item. The Script Manager prompts (`askChoice`/`askFile`) ran against the real API in headless mode with answers from a `.properties` file; the GUI itself was not run. |
| radare2 | 6.2.6 (built from the release tarball), r2pipe 2.1.0 | `afn` path after `-A` and flag path without analysis, then a flag import followed by an analysed re-import; comment byte for byte; idempotent; export; `#!pipe` inside a session. 25/25 checks. |
| rizin | 0.9.1 (static Linux release), rzpipe 0.6.2 | same 25/25 checks, including `#!pipe` |
| Cutter | 2.5.0 Qt6 AppImage (rizin 0.9.1, Python 3.12.4), 2.5.0 Qt5 AppImage (Python 3.11.11), under Xvfb | `cutter_import` (function renamed after `-A 1`), comment, second import unchanged, `cutter_export`, project saved, all through the real `cutter.cmd` |

Not verified: the Ghidra GUI itself (only headless), Ghidra 11.x, radare2/rizin builds older
than the ones above, and Cutter's interactive console (the same embedded interpreter was
driven from a plugin module).

## Tests

```sh
cd host
uv run pytest ../static/tests -q      # core (with parity checks against ida/x64dbg_sync.py),
                                      # the r2/rizin/Cutter adapter (fake pipe), the Ghidra script (fakes)
```

The tests need no reverse-engineering tool and run on Python 3.9 and newer. `static/tests`
sits outside the host project's `testpaths`, so run it explicitly, as with `ida/tests`.
