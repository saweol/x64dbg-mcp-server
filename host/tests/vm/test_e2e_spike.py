"""Real-VM end-to-end suite (spike VM). Opt-in: ``uv run pytest -m vm tests/vm``.

Environment:

- ``X64DBG_VM_E2E_CONFIG``: gateway config file (TOML) whose default profile (or the
  profile named by ``X64DBG_VM_E2E_PROFILE``) is the spike VM. Every test is skipped
  when it is unset. The guest password variable named by the profile must be set (or
  come from ``gateway.env_file``), and ``gateway.upload_roots`` must contain the sample
  directory.
- ``X64DBG_VM_E2E_SAMPLE_X64`` / ``X64DBG_VM_E2E_SAMPLE_X32``: the benign samples built
  by ``tests/vm/samples/build.sh`` (``e2e_sample_x86_64.exe`` / ``e2e_sample_x86.exe``);
  the loop for an architecture is skipped when its variable is unset.

These tests change the VM: they revert it to the profile's clean snapshot, start it,
upload and run the samples, and kill x64dbg.exe once (chaos test). Run them only
against a disposable clone (never a production analysis VM). After every VM operation
they assert that exactly one ``vmware-vmx`` process runs for the .vmx (E1).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path, PureWindowsPath
from typing import Any

import anyio
import pytest

from x64dbg_vm_gateway import platform as gw_platform
from x64dbg_vm_gateway.config import load_config
from x64dbg_vm_gateway.errors import BackendRestarted, GatewayError
from x64dbg_vm_gateway.wiring import build_app

pytestmark = pytest.mark.vm

CONFIG_ENV = "X64DBG_VM_E2E_CONFIG"
PROFILE_ENV = "X64DBG_VM_E2E_PROFILE"
SAMPLE_ENV = {"x64": "X64DBG_VM_E2E_SAMPLE_X64", "x32": "X64DBG_VM_E2E_SAMPLE_X32"}
DB_EXT = {"x64": ".dd64", "x32": ".dd32"}
OP_TIMEOUT_S = 900.0
POLL_S = 2.0
V110_TOOLS = {"GetServerInfo", "SetArtifactDir", "ProbeFile"}


# ── fixtures ────────────────────────────────────────────────────────
def _config_path() -> str:
    path = os.environ.get(CONFIG_ENV)
    if not path:
        pytest.skip(f"set {CONFIG_ENV} to a gateway config for the spike VM to run the real-VM E2E suite")
    if not Path(path).expanduser().is_file():
        pytest.fail(f"{CONFIG_ENV} points at a missing file: {path}")
    return str(Path(path).expanduser())


@pytest.fixture
def config_path() -> str:
    return _config_path()


@pytest.fixture
def gw(config_path: str) -> Iterator[Any]:
    """A gateway for one test; any job the test leaves is finished (reverted) at teardown."""
    config = load_config(config_path)
    app = build_app(config, profile=os.environ.get(PROFILE_ENV) or None)
    try:
        yield app
    finally:
        try:
            if _finish_leftover_job(app):
                assert_single_instance(str(app.runtime().profile.vmx), "the teardown revert")
        finally:
            app.close()


@pytest.fixture
def vmx(gw: Any) -> str:
    vmx = gw.runtime().profile.vmx
    assert vmx, "the E2E profile must be a vmware profile"
    return str(vmx)


def _sample(arch: str) -> str:
    path = os.environ.get(SAMPLE_ENV[arch])
    if not path:
        pytest.skip(f"set {SAMPLE_ENV[arch]} (tests/vm/samples/build.sh) to run the {arch} loop")
    if not Path(path).is_file():
        pytest.fail(f"{SAMPLE_ENV[arch]} points at a missing file: {path}")
    return str(Path(path).resolve())


# ── helpers ─────────────────────────────────────────────────────────
def vmx_processes(vmx: str) -> list[int]:
    """Host ``vmware-vmx`` processes running this .vmx (platform helper when present, else pgrep)."""
    finder = getattr(gw_platform, "find_vmx_processes", None)
    if callable(finder):
        return sorted(int(getattr(p, "pid", p)) for p in finder(vmx))
    pgrep = shutil.which("pgrep")
    if pgrep is None:
        pytest.fail("neither platform.find_vmx_processes nor pgrep is available")
    proc = subprocess.run([pgrep, "-af", "vmware-vmx"], capture_output=True, text=True, check=False)
    target = os.path.realpath(vmx)
    pids = []
    for line in proc.stdout.splitlines():
        pid, _, cmd = line.strip().partition(" ")
        last = cmd.split()[-1] if cmd.split() else ""
        if pid.isdigit() and (cmd.endswith(vmx) or os.path.realpath(last) == target):
            pids.append(int(pid))
    return sorted(pids)


def assert_single_instance(vmx: str, when: str) -> None:
    pids = vmx_processes(vmx)
    assert len(pids) == 1, f"after {when}: expected exactly one vmware-vmx for {vmx}, found {pids}"


def finished(gw: Any, result: Any, *, timeout_s: float = OP_TIMEOUT_S) -> Any:
    """The final outcome of a long operation (polls session_status while it is in progress)."""
    if not (isinstance(result, dict) and result.get("state") == "in_progress"):
        return result
    op_id = result.get("op_id")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        time.sleep(POLL_S)
        op = gw.session_status().get("operation") or {}
        if op.get("op_id") != op_id or op.get("state") == "running":
            continue
        if op.get("state") == "done":
            return op.get("result")
        pytest.fail(f"{result.get('op')} failed: {json.dumps(op.get('error'), default=str)[:2000]}")
    pytest.fail(f"{result.get('op')} still in progress after {timeout_s:g}s")


def call(gw: Any, tool: str, args: dict[str, Any] | None = None, *, ok: bool = True) -> str:
    res = gw.call_mirrored(tool, args or {})
    text = "\n".join(res["texts"])
    if ok:
        assert res["is_error"] is False, f"{tool} failed: {text[:2000]}"
    return text


def wait_healthy(gw: Any, backend: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    entry: dict[str, Any] = {}
    while time.monotonic() < deadline:
        entry = gw.session_status()["backends"][backend]
        if entry["health"] == "HEALTHY":
            return entry
        time.sleep(POLL_S)
    pytest.fail(f"backend {backend} not healthy after {timeout_s:g}s: {entry}")


def _finish_leftover_job(gw: Any) -> bool:
    """Collect and finish (revert) the job a test left behind; True if the VM was reverted."""
    try:
        job = gw.session_status().get("job")
    except GatewayError:
        return False
    if not job or job["state"] in ("DONE", "FAILED"):
        return False
    job_id = job["job_id"]
    try:
        if job["state"] not in ("COLLECTED", "DISCARDED", "REVERTING"):
            finished(gw, gw.analysis_collect(job_id))
        finished(gw, gw.analysis_finish(job_id, revert=True))
    except (GatewayError, pytest.fail.Exception):
        gw.discard_job(job_id, actor="e2e-teardown")
        finished(gw, gw.analysis_finish(job_id, revert=True))
    return True


def start_analysis(gw: Any, vmx: str, arch: str) -> dict[str, Any]:
    res = finished(gw, gw.analysis_start(_sample(arch), arch=arch))
    assert_single_instance(vmx, "analysis_start (revert + start)")
    assert res["state"] == "ANALYZING", res
    assert res["loaded"] is True and res["paused"] is True, res
    assert res["backend_id"] in gw.runtime().backends
    return res


def run_to_sleep(gw: Any) -> str:
    """run until the debuggee is paused inside kernel32 (the Sleep breakpoint); entry and
    other start-up breakpoints may stop it first."""
    state = ""
    for _ in range(5):
        call(gw, "run", {"timeoutMs": 60_000})
        state = call(gw, "GetDebugState")
        assert "status: PAUSED" in state, state
        if re.search(r"currentModule:\s*kernel32", state, re.IGNORECASE):
            return state
    pytest.fail(f"never paused in kernel32.Sleep: {state}")


def full_loop(gw: Any, vmx: str, arch: str) -> None:
    res = start_analysis(gw, vmx, arch)
    job_id = res["job_id"]
    info = call(gw, "GetServerInfo")
    assert "1.10" in info, info
    modules = call(gw, "ListModules")
    assert "kernel32" in modules.lower() and "ntdll" in modules.lower(), modules
    call(gw, "SetBreakpoint", {"target": "kernel32.Sleep"})
    run_to_sleep(gw)
    stack = call(gw, "GetCallStack")
    assert stack.strip(), "empty call stack"
    dump_name = f"e2e_dump_{arch}.bin"
    dumped = call(gw, "DumpMemory", {"address": "cip", "size": 256, "filePath": dump_name})
    assert "Memory dumped to" in dumped, dumped

    collected = finished(gw, gw.analysis_collect(job_id))
    assert collected["state"] == "COLLECTED" and collected["partial"] is False, collected
    originals = [str(f["original_path"]) for f in collected["files"]]
    assert any(PureWindowsPath(p).name == dump_name for p in originals), originals
    assert any(p.lower().endswith(DB_EXT[arch]) for p in originals), originals
    manifest = json.loads(Path(collected["manifest_path"]).read_text(encoding="utf-8"))
    assert manifest["entries"], manifest

    exported = finished(gw, gw.ida_export_annotations(job_id))
    assert Path(exported["host_path"]).is_file(), exported

    done = finished(gw, gw.analysis_finish(job_id, revert=True))
    assert done["state"] == "DONE" and done["reverted"] is True, done
    assert_single_instance(vmx, "analysis_finish (revert + start)")


# ── (a) doctor ──────────────────────────────────────────────────────
def test_a_doctor_is_all_green_including_the_single_vm_instance(gw, vmx):
    report = gw.doctor()
    checks = {c["name"]: c for c in report["checks"]}
    assert "single_vm_instance" in checks, sorted(checks)
    assert checks["single_vm_instance"]["ok"], checks["single_vm_instance"]
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    if gw.runtime().vm.power_state().value == "running":
        assert_single_instance(vmx, "doctor")


# ── (b) / (c) the full analysis loop ────────────────────────────────
def test_b_full_loop_x64(gw, vmx):
    full_loop(gw, vmx, "x64")


def test_c_full_loop_x32(gw, vmx):
    full_loop(gw, vmx, "x32")


# ── (d) chaos: the debugger dies while ANALYZING ────────────────────
def test_d_killed_debugger_is_relaunched_and_reported(gw, vmx):
    res = start_analysis(gw, vmx, "x64")
    bid = res["backend_id"]
    rt = gw.runtime()
    image = PureWindowsPath(str(rt.backend(bid).exe)).name.lower()
    victims = [p.pid for p in rt.channel.list_processes() if p.image_name == image]
    assert victims, f"no {image} in the guest"
    for pid in victims:
        rt.channel.kill_process(pid)

    with pytest.raises(BackendRestarted) as ei:
        gw.call_mirrored("SetBreakpoint", {"target": "kernel32.Sleep"})
    assert ei.value.details["epoch"] > res["epoch"], ei.value.details
    assert rt.supervisor.epoch(bid) > res["epoch"]

    entry = wait_healthy(gw, bid)  # session_status acknowledges the new epoch
    assert entry["acked_epoch"] == entry["epoch"], entry
    assert gw.runtime().channel is not None
    call(gw, "LoadBinary", {"filePath": res["sample"]["guest_path"]})
    waited = call(gw, "WaitForPause", {"timeoutMs": 30_000})
    assert waited.strip(), waited
    assert "status: PAUSED" in call(gw, "GetDebugState")


# ── (e) MCP stdio smoke ─────────────────────────────────────────────
def test_e_mcp_stdio_smoke(config_path):
    from mcp import Client, StdioServerParameters

    args = ["-c", "import sys; from x64dbg_vm_gateway.frontends.cli import main; sys.exit(main())",
            "--config", config_path]
    if os.environ.get(PROFILE_ENV):
        args += ["--profile", os.environ[PROFILE_ENV]]
    params = StdioServerParameters(command=sys.executable, args=[*args, "serve"], env=dict(os.environ))

    async def main() -> tuple[set[str], Any]:
        with anyio.fail_after(180):
            async with Client(params, mode="legacy", cache=None) as client:
                listed = await client.list_tools()
                status = await client.call_tool("session_status", {})
                return {t.name for t in listed.tools}, status

    names, status = anyio.run(main)
    assert V110_TOOLS <= names, sorted(names)  # E5: the live v1.10 list at the first tools/list
    assert status.is_error is False
    payload = json.loads(status.content[0].text)
    assert {"profile", "vm", "backends", "job"} <= set(payload), payload
