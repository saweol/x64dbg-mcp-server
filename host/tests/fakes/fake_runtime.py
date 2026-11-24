"""A complete fake lab for orchestrator tests: FakeVm + FakeGuest + PowerShell emulator +
threaded fake plugin servers, wired together by the REAL ``wiring.build_runtime``.

    lab = make_lab(tmp_path)                 # one x64 backend, plugin v1.9 tool list
    gw = lab.gateway()                       # app.Gateway over the lab's runtime
    res = gw.analysis_start(str(lab.sample()))
    lab.kill_debugger("x64")                 # x64dbg dies: HTTP refused, process gone
    lab.close()

Guest-side programs are dispatched by executable:

- ``powershell.exe`` -> :class:`tests.fakes.fake_powershell.GuestPowerShell`;
- ``schtasks.exe /run /tn <task>`` -> relaunch of the matching backend (process added,
  plugin server started again on the same port);
- anything else exits 0.

The guest IP is 127.0.0.1 so the real ``HttpBackendClient`` reaches the fake servers,
whose ports become the backends' configured ports.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any

from tests.fakes.fake_guest import FakeGuest
from tests.fakes.fake_guest import norm_path as fake_guest_norm
from tests.fakes.fake_plugin_server import FakePluginServer
from tests.fakes.fake_powershell import GuestPowerShell, is_powershell
from tests.fakes.fake_vm import FakeClock, FakeVm
from x64dbg_vm_gateway.app import Gateway
from x64dbg_vm_gateway.config import BackendConfig, GatewayConfig, ProfileConfig
from x64dbg_vm_gateway.contracts import Snapshot
from x64dbg_vm_gateway.wiring import Runtime, build_runtime

PROFILE = "lab"
PW_ENV = "GW_TEST_GUEST_PW"
GUEST_ROOT = "C:\\mcp\\jobs"
DBG_ROOT = "C:\\dbg"
EXE = {"x64": f"{DBG_ROOT}\\x64\\x64dbg.exe", "x32": f"{DBG_ROOT}\\x32\\x32dbg.exe"}
CFG = {"x64": f"{DBG_ROOT}\\x64\\mcp_config.json", "x32": f"{DBG_ROOT}\\x32\\mcp_config.json"}
TASK = {"x64": "MCP-x64dbg", "x32": "MCP-x32dbg"}
TOKEN_ENV = {"x64": "GW_TEST_X64_TOKEN", "x32": "GW_TEST_X32_TOKEN"}
SCHTASKS = "c:\\windows\\system32\\schtasks.exe"


def token_for(backend_id: str) -> str:
    return hashlib.sha256(f"lab-{backend_id}".encode()).hexdigest()[:32]


def wire_tools(version: str) -> list[dict[str, Any]]:
    """Builtin catalog ``version`` ("1.9" or "1.10") in the plugin's tools/list wire format.

    "1.3" maps to the 1.9 list: the live v1.3 plugin exposes the same 80 tools with the
    same LoadBinary / SaveDatabase schemas (tests/fixtures/plugin_v1.3/tools_list.http).
    """
    name = "1.10" if version == "1.10" else "1.9"
    data = json.loads(resources.files("x64dbg_vm_gateway").joinpath(f"data/tools-v{name}.json")
                      .read_text(encoding="utf-8"))
    return [{"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"],
             "annotations": {"readOnlyHint": bool(t["read_only"]), "openWorldHint": False},
             "_debug_only": bool(t.get("debug_only", False))} for t in data["tools"]]


def make_pe(*, machine: int = 0x8664, dll: bool = False, pad: bytes = b"", image_base: int = 0) -> bytes:
    """Minimal structurally valid PE image (headers + one raw section)."""
    magic = 0x20B if machine == 0x8664 else 0x10B
    dd_rel = 112 if magic == 0x20B else 96
    size_opt = dd_rel + 8 * 16
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    chars = 0x0002 | (0x2000 if dll else 0)
    fh = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, size_opt, chars)
    opt = bytearray(size_opt)
    struct.pack_into("<H", opt, 0, magic)
    struct.pack_into("<I", opt, dd_rel - 4, 16)
    if magic == 0x20B:
        struct.pack_into("<Q", opt, 24, image_base)  # IMAGE_OPTIONAL_HEADER64.ImageBase
    else:
        struct.pack_into("<I", opt, 28, image_base)  # IMAGE_OPTIONAL_HEADER32.ImageBase
    headers_len = len(dos) + len(fh) + size_opt + 40
    raw_ptr = (headers_len + 0x1FF) & ~0x1FF
    sect = struct.pack("<8sIIIIIIHHI", b".text", 0x1000, 0x1000, 0x200, raw_ptr, 0, 0, 0, 0, 0x60000020)
    img = bytearray(dos + fh + opt + sect)
    img += b"\0" * (raw_ptr - len(img))
    return bytes(img + bytearray(0x200)) + pad


@dataclass
class FakeLab:
    tmp: Path
    clock: FakeClock
    vm: FakeVm
    guest: FakeGuest
    ps: GuestPowerShell
    servers: dict[str, FakePluginServer]
    config: GatewayConfig
    environ: dict[str, str]
    samples: Path
    launches: list[str] = field(default_factory=list)
    gateways: list[Gateway] = field(default_factory=list)
    runtimes: list[Runtime] = field(default_factory=list)
    vmrun_path: str = "/usr/bin/vmrun"
    #: what the fake SaveDatabase writes (tests put an x64dbg JSON database here). None models
    #: a session without annotations: real x64dbg then writes no file (and deletes an old one)
    #: while the plugin still answers "Database saved to ..." (measured on the spike VM).
    db_content: bytes | None = b"x64dbg database"
    #: True models plugin builds before 2026-11-24: "Database saved to ..." even when x64dbg wrote
    #: nothing. False: the rebuilt plugin's "No database file written ..." (filePath saves only).
    legacy_dbsave_reply: bool = False

    @property
    def profile(self) -> ProfileConfig:
        return self.config.profile(PROFILE)

    def set_profile(self, **changes: Any) -> None:
        prof = replace(self.profile, **changes)
        self.config = replace(self.config, profiles={PROFILE: prof})

    def set_config(self, **changes: Any) -> None:
        self.config = replace(self.config, **changes)

    # ── wiring ──────────────────────────────────────────────────────
    def runtime(self) -> Runtime:
        rt = build_runtime(self.config, PROFILE, environ=self.environ, clock=self.clock, vm=self.vm,
                           channel=self.guest, cache_dir=self.tmp / "cache")
        self.runtimes.append(rt)
        return rt

    def gateway(self, **kwargs: Any) -> Gateway:
        rt = self.runtime()

        def factory(name: str) -> Runtime:
            assert name == PROFILE, name
            return rt

        kwargs.setdefault("host_system", "Linux")
        kwargs.setdefault("find_vmrun", lambda configured="auto", **_kw: self.vmrun_path)
        kwargs.setdefault("vmrun_version", lambda path: "1.17.0 build-24583834")
        gw = Gateway(self.config, runtime_factory=factory, clock=self.clock, **kwargs)
        self.gateways.append(gw)
        return gw

    # ── guest helpers ───────────────────────────────────────────────
    def dispatch(self, exe: str, args: tuple, **kw: Any) -> int | None:
        if is_powershell(exe):
            return self.ps(exe, args, **kw)
        if exe.lower() == SCHTASKS and len(args) == 3 and args[:2] == ("/run", "/tn"):
            for bid, task in TASK.items():
                if args[2] == task and bid in self.servers:
                    self.launches.append(bid)
                    self.start_debugger(bid)
                    return 0
            return 1
        return 0 if kw.get("wait", True) else None

    def start_debugger(self, backend_id: str) -> None:
        if not any(p.image_name == EXE[backend_id].rsplit("\\", 1)[-1].lower() for p in self.guest.processes):
            self.guest.add_process(f'"{EXE[backend_id]}"')
        self.servers[backend_id].start()

    def kill_debugger(self, backend_id: str = "x64") -> None:
        """x64dbg dies: its HTTP server stops and its process disappears."""
        self.servers[backend_id].stop()
        image = EXE[backend_id].rsplit("\\", 1)[-1].lower()
        self.guest.processes = [p for p in self.guest.processes if p.image_name != image]

    def write_guest_token_config(self, backend_id: str, data: bytes | None = None) -> None:
        if data is None:
            data = json.dumps({"IpAddress": "0.0.0.0", "Port": self.servers[backend_id].port,  # noqa: S104
                               "AutoStart": True, "AuthToken": token_for(backend_id)}).encode()
        self.guest.write(CFG[backend_id], data)

    def sample(self, name: str = "sample.exe", *, machine: int = 0x8664, dll: bool = False,
               data: bytes | None = None, image_base: int = 0) -> Path:
        p = self.samples / name
        p.write_bytes(data if data is not None
                      else make_pe(machine=machine, dll=dll, pad=name.encode(), image_base=image_base))
        return p

    def close(self) -> None:
        for gw in self.gateways:
            gw.close()
        for srv in self.servers.values():
            srv.stop()


def make_lab(
    tmp_path: Path,
    *,
    backends: tuple[str, ...] = ("x64",),
    plugin_version: str = "1.9",
    token_source: str = "guest-config",  # noqa: S107 - token source kind, not a secret
    **profile_changes: Any,
) -> FakeLab:
    clock = FakeClock()
    vm = FakeVm()
    vm.ip = "127.0.0.1"
    vm.snapshots = [Snapshot("MCP_CLEAN"), Snapshot("BASE")]
    guest = FakeGuest()
    ps = GuestPowerShell(guest)
    # connection_close: every response framed like the real plugin v1.10 (Connection: close)
    servers = {b: FakePluginServer(token=token_for(b), version=plugin_version,
                                   tools=wire_tools(plugin_version), connection_close=True).start()
               for b in backends}
    environ = {PW_ENV: "guest-pw"}
    if token_source == "env":
        environ.update({TOKEN_ENV[b]: token_for(b) for b in backends})
    vmx = tmp_path / "vm" / "lab.vmx"
    vmx.parent.mkdir(parents=True, exist_ok=True)
    vmx.write_text('displayName = "lab"\n', encoding="utf-8")
    samples = tmp_path / "samples"
    samples.mkdir()
    profile = ProfileConfig(
        name=PROFILE,
        mode="vmware",
        vmx=str(vmx),
        clean_snapshot="MCP_CLEAN",
        protected_snapshots=("MCP_CLEAN", "BASE"),
        guest_user="mcp",
        guest_password_env=PW_ENV,
        guest_host="auto",
        job_root_guest=GUEST_ROOT,
        require_isolation=True,
        token_source=token_source,
        backends=tuple(
            BackendConfig(id=b, arch=b, port=servers[b].port, exe=EXE[b], config=CFG[b], launch_task=TASK[b],
                          token_env=TOKEN_ENV[b] if token_source == "env" else None)
            for b in backends),
    )
    profile = replace(profile, **profile_changes)
    config = GatewayConfig(jobs_root=str(tmp_path / "jobs"), default_profile=PROFILE, max_call_s=110.0,
                           profiles={PROFILE: profile}, upload_roots=(str(samples),))
    lab = FakeLab(tmp=tmp_path, clock=clock, vm=vm, guest=guest, ps=ps, servers=servers, config=config,
                  environ=environ, samples=samples)
    guest.on_run_program = lab.dispatch
    guest.mkdir(GUEST_ROOT)
    for b in backends:
        lab.write_guest_token_config(b)
        guest.add_process(f'"{EXE[b]}"')
        _install_debugger_behaviour(lab, b)
    return lab


#: Runtime bases the fake debugger reports in ListModules (the sample, then ntdll.dll).
SAMPLE_BASE, SAMPLE_SIZE = 0x00400000, 0x2000
NTDLL_BASE, NTDLL_SIZE = 0x7FF800000000, 0x1F0000


def _install_debugger_behaviour(lab: FakeLab, backend_id: str) -> None:
    """LoadBinary remembers the file; SaveDatabase writes ``lab.db_content`` into the guest
    (``filePath`` when given, else x64dbg's default ``<exe dir>\\db\\<file name>.dd64``);
    ListModules reports the loaded file at ``SAMPLE_BASE`` and ntdll.dll, in the plugin's
    ``0x{base:X} | 0x{size:X} | {name}`` format."""
    srv = lab.servers[backend_id]
    loaded: dict[str, str] = {}
    ext = "dd64" if backend_id == "x64" else "dd32"

    def load(args: dict[str, Any]) -> str:
        loaded["path"] = str(args.get("filePath", ""))
        return f"Loaded {loaded['path']}"

    def save(args: dict[str, Any]) -> str:
        """Synchronous model: the file exists when the reply is sent (older plugins only queue
        dbsave; tests that need the delay wrap the guest's file_exists)."""
        path = str(args.get("filePath") or "")
        given = bool(path)
        if not path:
            name = loaded.get("path", "unknown").rsplit("\\", 1)[-1]
            path = f"{EXE[backend_id].rsplit(chr(92), 1)[0]}\\db\\{name}.{ext}"
        if lab.db_content is None:
            lab.guest.files.pop(fake_guest_norm(path), None)
            if given and not lab.legacy_dbsave_reply:
                return (f'No database file written to "{path}": x64dbg writes none while the session has '
                        "no labels, comments, bookmarks, breakpoints or functions.")
        else:
            lab.guest.write(path, lab.db_content)
        return f'Database saved to "{path}".' if given else "Database saved."

    def modules(args: dict[str, Any]) -> str:
        name = loaded.get("path", "").rsplit("\\", 1)[-1] or "sample.exe"
        return (f"0x{SAMPLE_BASE:08X} | 0x{SAMPLE_SIZE:08X} | {name}\n"
                f"0x{NTDLL_BASE:X} | 0x{NTDLL_SIZE:X} | ntdll.dll")

    srv.on_tool("LoadBinary", load)
    srv.on_tool("SaveDatabase", save)
    srv.on_tool("ListModules", modules)
    srv.on_tool("WaitForPause", "Debugger paused at 0x7ff800001234 (system breakpoint)")
