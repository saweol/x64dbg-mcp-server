# x64dbg ⇄ IDA sync (interpretation D)

x64dbg debugs the sample at **runtime addresses** (ASLR moves every module on
each run). IDA analyses it at the **IDB image base**. Both agree on
**module + RVA**, so every exchange goes through that pair:

```
runtime = module_base_runtime + rva          (x64dbg, from ListModules)
ida     = ida_imagebase      + rva           (IDA, idaapi.get_imagebase())
```

There are two parts:

| Part | Where | What it does |
|---|---|---|
| `x64dbg_vm_gateway.ida_sync` | host gateway (`host/src/…/ida_sync.py`) | Parses `ListModules` into a module map, rebases addresses, parses x64dbg databases (`.dd64`/`.dd32`), builds export documents and import plans. It is a pure library; the gateway exposes it as `ida_rebase`, `ida_export_annotations` and `ida_import_annotations` (see `app_api.GatewayApp`) once those are wired. |
| `ida/x64dbg_sync.py` | IDA Pro 8.4 / 9.x | Menu actions to import an export document into the IDB, and to export the IDB's names/comments for x64dbg. |

## Using it with ida-multi-mcp (AI workflow)

The AI talks to two MCP servers: the gateway (x64dbg in the VM) and
ida-multi-mcp (IDA on the host). The gateway converts the addresses, and
ida-multi-mcp edits the IDB.

**Dynamic finding → IDA** (for example a decryption routine found at a breakpoint):

1. Gateway: `ida_rebase(address="0x7FF6A1231234", direction="runtime_to_ida", ida_imagebase="0x140000000")`.
   The module is found from the live module map (`ListModules`), and the result is
   `{"module": "sample.exe", "rva": "0x1234", "ida": "0x140001234", ...}`.
   `ida_imagebase` is the IDB's image base, `idaapi.get_imagebase()` in IDA. If it is
   omitted, the module's preferred (PE) image base is used, but only when the gateway
   knows it. Without that, the call fails and asks for it.
2. ida-multi-mcp: call `rename` / `set_comments` (or `decompile`) at `0x140001234` on the
   instance that holds `sample.exe`, then `idb_save`.

**IDA knowledge → x64dbg** (for example names recovered statically):

1. Collect `{rva | ida_address, name?, comment?}` items, either from ida-multi-mcp
   output or from the *Export* action below (its `items` can be passed as-is).
2. Gateway: `ida_import_annotations(items, module="sample.exe", ida_imagebase="0x140000000")`.
   It returns `[{runtime_address, rva, label, comment}]`, with labels and comments already
   made x64dbg-safe.
3. Gateway (mirrored tool): `CommentOrLabelAtAddress(address=runtime_address, value=label, mode="Label")`,
   and the same call with `mode="Comment"`.

**x64dbg database → IDA** (all labels, comments, bookmarks and breakpoints of a session):

1. Gateway (mirrored tool): `SaveDatabase(filePath="…\\out\\sample.dd64")`. With an explicit
   path x64dbg writes **uncompressed** JSON (`dbsave <path>` skips LZ4). The default
   location is LZ4-compressed and is rejected by the parser.
2. `analysis_collect` brings the file to the host, and `ida_export_annotations` turns it
   into an `x64dbg-ida-sync/1` document.
3. Open the document in IDA with the *Import* action, or let the AI apply the items through
   ida-multi-mcp (`rename` / `set_comments` at `ida_imagebase + rva`).

Rebase directions (`ida_rebase` / `ida_sync.rebase`):

| direction | input | needs | notes |
|---|---|---|---|
| `runtime_to_rva` | runtime address | module map | The module is found by `base <= addr < base+size`. If the size is unknown, the nearest lower base is used and `approximate: true` is set. |
| `rva_to_runtime` | RVA | `module` | The RVA is bounds-checked against the module size. |
| `runtime_to_ida` | runtime address | `ida_imagebase` or a known preferred base | |
| `ida_to_runtime` | IDA address | `module` and `ida_imagebase` | There is no default, because a rebased IDB would silently give wrong addresses. |

Module names are matched case-insensitively. They can be given as a file name, a path or
a name without extension (`sample`). If the same DLL is loaded twice, each copy is keyed
as `name@0x<base>`, and the bare name is rejected as ambiguous.

## Running the IDA script

* **As a plugin:** copy `x64dbg_sync.py` into IDA's `plugins` directory, or into
  `$IDAUSR/plugins`. The default `$IDAUSR` is `%APPDATA%\Hex-Rays\IDA Pro` on Windows and
  `~/.idapro` on Linux/macOS. Two menu entries appear:
  * *File → Load file → Import x64dbg annotations (x64dbg-ida-sync JSON)*
  * *File → Produce file → Export IDA names/comments for x64dbg (x64dbg-ida-sync JSON)*

  *Edit → Plugins → x64dbg sync* asks which of the two to run.
* **Once, as a script:** *File → Script file…* (Alt+F7) on `x64dbg_sync.py` registers the
  same menu entries and asks Import / Export / Cancel.

Import details:

* The module is the one whose name matches the IDB input file. It is matched
  case-insensitively, then by a unique name without extension, so `sample.bin` matches
  `sample.exe`. If nothing matches, IDA asks for the module name.
* Names are set with `ida_name.set_name(ea, name, SN_NOWARN | SN_FORCE | SN_NOCHECK | SN_NODUMMY)`
  (each flag only if the IDA version has it). Before that they are limited to
  `[A-Za-z0-9_$?@]`, and names that look like IDA dummy names (`sub_401000`) or start
  with a digit get a `_` prefix.
* Comments are appended to the existing regular comment, never overwriting it. Importing
  the same file twice does not duplicate them. Bookmarks and breakpoints become a tag such
  as `[x64dbg: bookmark; hardware bp, disabled, condition rcx==1]`.
* Addresses that are not mapped in the IDB are counted as `unmapped` and skipped. A report
  with all the counters is shown at the end.

The export writes every non-dummy name (`idautils.Names()`) and every regular or
repeatable comment, plus function comments, outside extern (`SEG_XTRN`) segments. RVAs
are relative to the current image base.

## Schema `x64dbg-ida-sync/1`

```json
{
  "schema": "x64dbg-ida-sync/1",
  "generated_by": "x64dbg-vm-gateway 0.1.0",
  "modules": {
    "sample.exe": {
      "base_runtime": "0x7FF6A1230000",
      "items": [
        {"rva": "0x1000", "name": "decrypt_config",
         "breakpoint": {"type": "normal", "enabled": true}},
        {"rva": "0x1010", "comment": "decrypts the embedded config", "bookmark": true},
        {"rva": "0x1500", "name": "c2_beacon_loop",
         "breakpoint": {"type": "hardware", "enabled": false, "condition": "rcx==1"}}
      ]
    }
  },
  "skipped": {"no_module": 1, "not_address_bound": 2, "filtered": 0, "empty": 0},
  "warnings": []
}
```

| field | type | meaning |
|---|---|---|
| `schema` | string | Always `x64dbg-ida-sync/1`. Readers reject other values, including other `/N` versions. |
| `generated_by` | string | The producer, either the gateway or `x64dbg_sync.py … (IDA)`. |
| `modules` | object | Keyed by lower-cased module file name. |
| `modules.*.base_runtime` | hex string or null | The runtime base in x64dbg, when known. It is informational only, and importers use RVAs. |
| `modules.*.ida_imagebase` | hex string | Only in IDA exports: the image base the RVAs were computed from. |
| `modules.*.items[]` | array | Sorted by RVA, one entry per address. |
| `items[].rva` | hex string | Offset from the module base. Always present. |
| `items[].name` | string | A label or name. The gateway export already makes it x64dbg-safe. |
| `items[].comment` | string | A one-line comment. |
| `items[].bookmark` | `true` | An x64dbg bookmark. |
| `items[].breakpoint` | object | `{type: normal\|hardware\|memory, enabled: bool, condition?: string}` |
| `skipped`, `warnings` | object, array | Diagnostics. Readers ignore them. |

Addresses are written as `0x` followed by upper-case hex. Readers accept any `0x` hex
string or a JSON integer, and ignore keys they do not know.

## Limits and safety

Databases, export files and guest output come from the analysis VM and are treated as
untrusted:

* **Size and count caps.** Database files are capped at 64 MiB and documents at 64 MiB.
  Each database category, export and import batch is capped at 50 000 items, and
  `ListModules` text at 16 MiB / 10 000 modules.
* **Comment cleaning.** Strings are cleaned of control characters, bidi and zero-width
  characters, and line breaks.
* **x64dbg length limits.** x64dbg labels are capped at 254 bytes and comments at 510
  UTF-8 bytes, which is what `LabelSet` / `CommentSet` accept.
* **x64dbg label charset.** x64dbg labels are limited to `[A-Za-z0-9_@?$.:<>~]`. They are
  never empty, and a label that starts with a digit gets a `_` prefix.
* **Rejected batches.** `ida_import_annotations` rejects the whole batch at the first
  invalid item and names it (`items[3]: …`).

Not handled:

* The default LZ4-compressed x64dbg databases. Save with an explicit path instead.
* Function ranges (they are parsed, but not exported).
* DLL and exception breakpoints, which are not bound to an address.
* More than one module per IDB.

## Tests

```sh
cd host
uv run pytest tests/unit/test_ida_sync.py -q   # gateway library
uv run pytest ../ida/tests -q                  # IDA script against stub ida_* modules
```

The fixtures (`host/tests/fixtures/ida/`) are synthetic. They follow the plugin's
`ListModules` formatter and x64dbg's database writer. No real sample or database is
included.
