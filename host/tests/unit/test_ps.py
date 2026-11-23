"""Tests for the PowerShell helper (EncodedCommand / -File fallback / output capture).

PowerShell itself is emulated: ``GuestPowerShell`` decodes what the helper hands to
``powershell.exe`` through ``FakeGuest.run_program``, extracts the caller's script
and the guest output file from the wrapper, and writes scripted output there.
"""

from __future__ import annotations

import base64
import codecs
import logging
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.fakes.fake_guest import FakeGuest
from x64dbg_vm_gateway.errors import PathNotAllowed, ToolsNotRunning, TransferError
from x64dbg_vm_gateway.ps import (
    DEFAULT_GUEST_TMP_DIR,
    MAX_ENCODED_CHARS,
    POWERSHELL_EXE,
    PsResult,
    build_wrapper,
    decode_command,
    encode_command,
    ps_quote,
    run_powershell,
    run_powershell_file,
)

PS_BASE = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
_BODY_RE = re.compile(r"\n& \{\n(.*)\n\} \*>&1", re.DOTALL)
_OUT_RE = re.compile(r"StreamWriter\('([^']+)'")

Handler = Callable[[str], tuple[int, "str | bytes | None"]]


class GuestPowerShell:
    """Emulates ``powershell.exe`` for a FakeGuest.

    ``handler(body) -> (exit_code, output)`` receives the caller's script (as it
    appears inside the wrapper); ``output`` is written to the wrapper's output file
    (str -> UTF-8, bytes verbatim, None -> no file). Programs other than
    powershell.exe go to ``other`` (default: exit 0 / None for wait=False).
    """

    def __init__(self, guest: FakeGuest, handler: Handler | None = None,
                 other: Callable[..., int | None] | None = None) -> None:
        self.guest = guest
        self.handler: Handler = handler or (lambda body: (0, ""))
        self.other = other
        self.runs: list[dict] = []
        guest.on_run_program = self

    def __call__(self, exe: str, args: tuple, **kw) -> int | None:
        if exe != POWERSHELL_EXE:
            if self.other is not None:
                return self.other(exe, args, **kw)
            return 0 if kw.get("wait", True) else None
        argv = list(args)
        assert argv[:4] == PS_BASE
        assert len(argv) == 6
        if argv[4] == "-EncodedCommand":
            mode, wrapper = "encoded", decode_command(argv[5])
        else:
            assert argv[4] == "-File"
            raw = self.guest.read(argv[5])
            assert raw.startswith(codecs.BOM_UTF8), "temp .ps1 must carry a UTF-8 BOM for PowerShell 5.1"
            mode, wrapper = "file", raw[len(codecs.BOM_UTF8):].decode("utf-8")
        m = _BODY_RE.search(wrapper)
        assert m, wrapper
        out = _OUT_RE.search(wrapper)
        run = {"mode": mode, "wrapper": wrapper, "body": m.group(1), "out": out.group(1) if out else None,
               "args": argv, "kw": kw}
        self.runs.append(run)
        code, output = self.handler(run["body"])
        if run["out"] is not None and output is not None:
            data = output if isinstance(output, bytes) else output.encode("utf-8")
            self.guest.write(run["out"], data)
        return code


@pytest.fixture
def host_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "hosttmp"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d


# ── encoding / quoting ──────────────────────────────────────────────
def test_encode_command_is_base64_of_utf16le_and_round_trips() -> None:
    script = 'Write-Output "double" \'single\' `$x 한글 \u2019\r\nexit 3'
    enc = encode_command(script)
    assert enc == base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    assert re.fullmatch(r"[A-Za-z0-9+/=]+", enc)
    assert decode_command(enc) == script


def test_ps_quote_doubles_every_single_quote_variant() -> None:
    assert ps_quote("C:\\a b\\c") == "'C:\\a b\\c'"
    assert ps_quote("it's") == "'it''s'"
    assert ps_quote("x\u2018y\u2019z") == "'x\u2018\u2018y\u2019\u2019z'"
    assert ps_quote('say "hi" $env:X `n') == "'say \"hi\" $env:X `n'"
    with pytest.raises(ValueError):
        ps_quote("a\x00b")


def test_build_wrapper_captures_all_streams_as_utf8() -> None:
    w = build_wrapper("Get-Date", out_path="C:\\mcp\\tmp\\ps-1.out", tmp_dir="C:\\mcp\\tmp")
    assert "\n& {\nGet-Date\n} *>&1" in w
    assert "StreamWriter('C:\\mcp\\tmp\\ps-1.out'" in w
    assert "UTF8Encoding($false)" in w
    assert "AutoFlush = $true" in w
    assert w.rstrip().endswith("exit $__mcpRc")
    quiet = build_wrapper("Get-Date", out_path=None, tmp_dir="C:\\mcp\\tmp")
    assert "StreamWriter" not in quiet and "Out-Null" in quiet
    assert "\n& {\nGet-Date\n} *>&1" in quiet


# ── run_powershell: EncodedCommand path ────────────────────────────
def test_run_powershell_uses_encoded_command_without_quoting(fake_guest: FakeGuest, host_tmp: Path) -> None:
    emu = GuestPowerShell(fake_guest, lambda body: (0, "ok\r\n"))
    script = "Write-Output \"quoted\" 'single'\n$x = @{ a = 1 }"
    res = run_powershell(fake_guest, script, timeout_s=42)
    assert res == PsResult(exit_code=0, output="ok\n")
    assert res.ok
    (run,) = emu.runs
    assert run["mode"] == "encoded"
    assert run["body"] == script  # verbatim, double quotes intact
    assert run["kw"]["wait"] is True
    (call_args, call_kw) = fake_guest.calls_of("run_program")[0]
    assert call_args[0] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert call_kw["timeout_s"] == 42
    # No argument needs command-line quoting, so vmrun's argument joining cannot break it.
    assert '"' not in subprocess.list2cmdline(list(call_args[1]))
    assert len(call_args[1][5]) <= MAX_ENCODED_CHARS


def test_run_powershell_output_file_is_unique_and_removed(fake_guest: FakeGuest, host_tmp: Path) -> None:
    emu = GuestPowerShell(fake_guest, lambda body: (0, "x"))
    run_powershell(fake_guest, "1")
    run_powershell(fake_guest, "2")
    outs = [r["out"] for r in emu.runs]
    assert outs[0] != outs[1]
    for out in outs:
        assert out.lower().startswith(DEFAULT_GUEST_TMP_DIR.lower() + "\\")
        assert not fake_guest.file_exists(out)
    deleted = [a[0] for a, _ in fake_guest.calls_of("delete_file")]
    assert outs == deleted
    assert list(host_tmp.iterdir()) == []


def test_run_powershell_strips_bom_and_normalises_newlines(fake_guest: FakeGuest, host_tmp: Path) -> None:
    GuestPowerShell(fake_guest, lambda body: (0, codecs.BOM_UTF8 + "é\r\nzwei\r\n".encode()))
    assert run_powershell(fake_guest, "x").output == "é\nzwei\n"


def test_run_powershell_falls_back_to_cp949(fake_guest: FakeGuest, host_tmp: Path) -> None:
    GuestPowerShell(fake_guest, lambda body: (0, "파일이 없습니다.\r\n".encode("cp949")))
    assert run_powershell(fake_guest, "x").output == "파일이 없습니다.\n"


def test_run_powershell_returns_nonzero_exit_code(fake_guest: FakeGuest, host_tmp: Path) -> None:
    GuestPowerShell(fake_guest, lambda body: (7, "ERROR: boom\r\n"))
    res = run_powershell(fake_guest, "exit 7")
    assert res.exit_code == 7 and not res.ok
    assert res.output == "ERROR: boom\n"


def test_run_powershell_missing_output_file_gives_empty_output(fake_guest: FakeGuest, host_tmp: Path) -> None:
    GuestPowerShell(fake_guest, lambda body: (1, None))
    res = run_powershell(fake_guest, "x")
    assert res == PsResult(1, "")
    assert list(host_tmp.iterdir()) == []


def test_run_powershell_capture_false_skips_output_file(fake_guest: FakeGuest, host_tmp: Path) -> None:
    emu = GuestPowerShell(fake_guest, lambda body: (0, "ignored"))
    res = run_powershell(fake_guest, "Stop-Service x", capture=False)
    assert res == PsResult(0, "")
    assert emu.runs[0]["out"] is None
    assert fake_guest.calls_of("copy_from_guest") == []


def test_run_powershell_output_is_bounded(fake_guest: FakeGuest, host_tmp: Path) -> None:
    GuestPowerShell(fake_guest, lambda body: (0, "a" * 5000))
    res = run_powershell(fake_guest, "x", max_output_bytes=1000)
    assert res.output.startswith("a" * 1000)
    assert "truncated" in res.output
    assert len(res.output) < 1100


# ── run_powershell: -File fallback ─────────────────────────────────
def test_long_script_is_copied_and_run_with_file(fake_guest: FakeGuest, host_tmp: Path) -> None:
    script = "Write-Output 'line'  # 한글\n" * 400
    assert len(encode_command(script)) > MAX_ENCODED_CHARS
    seen: dict = {}

    def handler(body: str):
        seen["ps1_present"] = any(k.endswith(".ps1") for k in fake_guest.files)
        return 0, "done"

    emu = GuestPowerShell(fake_guest, handler)
    res = run_powershell(fake_guest, script)
    assert res == PsResult(0, "done")
    (run,) = emu.runs
    assert run["mode"] == "file"
    assert run["body"] == script
    ps1 = run["args"][5]
    assert ps1.lower().startswith(DEFAULT_GUEST_TMP_DIR.lower() + "\\") and ps1.endswith(".ps1")
    assert ("C:\\mcp\\tmp",) in [a for a, _ in fake_guest.calls_of("mkdir")]
    assert seen["ps1_present"]
    assert not fake_guest.file_exists(ps1)
    assert not any(k.endswith((".ps1", ".out")) for k in fake_guest.files)
    assert list(host_tmp.iterdir()) == []


def test_max_encoded_chars_threshold_is_configurable(fake_guest: FakeGuest, host_tmp: Path) -> None:
    emu = GuestPowerShell(fake_guest)
    run_powershell(fake_guest, "Get-Date", max_encoded_chars=10)
    assert emu.runs[0]["mode"] == "file"


# ── errors / validation ─────────────────────────────────────────────
def test_environment_errors_propagate_and_cleanup_never_masks_them(fake_guest: FakeGuest,
                                                                   host_tmp: Path) -> None:
    GuestPowerShell(fake_guest)
    fake_guest.fail_next("run_program", ToolsNotRunning("tools down"))
    fake_guest.fail_next("delete_file", ToolsNotRunning("tools down"), times=3)
    with pytest.raises(ToolsNotRunning):
        run_powershell(fake_guest, "x")
    assert list(host_tmp.iterdir()) == []


@pytest.mark.parametrize("bad", ["C:\\my tmp", "C:\\it's", "relative\\dir", "\\\\server\\share", "C:\\a\tb"])
def test_guest_tmp_dir_is_validated(fake_guest: FakeGuest, bad: str) -> None:
    GuestPowerShell(fake_guest)
    with pytest.raises(PathNotAllowed):
        run_powershell(fake_guest, "x", guest_tmp_dir=bad)
    assert fake_guest.calls_of("run_program") == []


def test_script_must_be_text(fake_guest: FakeGuest) -> None:
    with pytest.raises(TypeError):
        run_powershell(fake_guest, b"bytes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        run_powershell(fake_guest, "a\x00b")


def test_script_text_is_never_logged(fake_guest: FakeGuest, host_tmp: Path,
                                     caplog: pytest.LogCaptureFixture) -> None:
    GuestPowerShell(fake_guest, lambda body: (0, "fine"))
    caplog.set_level(logging.DEBUG)
    run_powershell(fake_guest, "Set-Secret 'SENSITIVE-MARKER-123'")
    run_powershell(fake_guest, "Set-Secret 'SENSITIVE-MARKER-123'\n" + "#" * 9000)
    assert "SENSITIVE-MARKER-123" not in caplog.text
    assert encode_command("SENSITIVE-MARKER-123")[:12] not in caplog.text


# ── run_powershell_file ─────────────────────────────────────────────
def test_run_powershell_file_invokes_the_copied_script_with_literal_args(fake_guest: FakeGuest,
                                                                          host_tmp: Path,
                                                                          tmp_path: Path) -> None:
    local = tmp_path / "tool.ps1"
    local.write_bytes(b"param([string]$ParamsFile)\r\nexit 4\r\n")
    seen: dict = {}

    def handler(body: str):
        m = re.search(r"^& '([^']+\.ps1)'(.*)$", body, re.MULTILINE)
        assert m, body
        seen["path"], seen["args"] = m.group(1), m.group(2)
        seen["content"] = fake_guest.read(m.group(1))
        return 4, "ran"

    GuestPowerShell(fake_guest, handler)
    res = run_powershell_file(fake_guest, local, ["-ParamsFile", "C:\\x y\\p.json", "it's", "-Switch"])
    assert res == PsResult(4, "ran")
    assert seen["content"] == local.read_bytes()  # ASCII: copied byte-for-byte
    assert seen["args"] == " -ParamsFile 'C:\\x y\\p.json' 'it''s' -Switch"
    assert seen["path"].lower().startswith("c:\\mcp\\tmp\\")
    assert not fake_guest.file_exists(seen["path"])
    assert list(host_tmp.iterdir()) == []


def test_run_powershell_file_propagates_the_script_exit_code_via_lastexitcode(fake_guest: FakeGuest,
                                                                              host_tmp: Path,
                                                                              tmp_path: Path) -> None:
    local = tmp_path / "t.ps1"
    local.write_text("exit 0\n")
    emu = GuestPowerShell(fake_guest)
    run_powershell_file(fake_guest, local)
    body = emu.runs[0]["body"]
    assert body.splitlines()[0] == "$global:LASTEXITCODE = 0"
    assert body.splitlines()[-1] == "exit $LASTEXITCODE"


def test_run_powershell_file_adds_bom_to_non_ascii_utf8(fake_guest: FakeGuest, host_tmp: Path,
                                                       tmp_path: Path) -> None:
    local = tmp_path / "k.ps1"
    local.write_bytes("Write-Output '한글'\n".encode())
    seen: dict = {}

    def handler(body: str):
        path = re.search(r"^& '([^']+)'", body, re.MULTILINE).group(1)
        seen["content"] = fake_guest.read(path)
        return 0, ""

    GuestPowerShell(fake_guest, handler)
    run_powershell_file(fake_guest, local)
    assert seen["content"] == codecs.BOM_UTF8 + local.read_bytes()
    assert list(host_tmp.iterdir()) == []


def test_run_powershell_file_requires_a_local_file(fake_guest: FakeGuest, tmp_path: Path) -> None:
    with pytest.raises(TransferError):
        run_powershell_file(fake_guest, tmp_path / "missing.ps1")
    with pytest.raises(TransferError):
        run_powershell_file(fake_guest, tmp_path)  # a directory
    local = tmp_path / "ok.ps1"
    local.write_text("exit 0\n")
    with pytest.raises(TypeError):
        run_powershell_file(fake_guest, local, [1])  # type: ignore[list-item]
    assert fake_guest.calls == []
