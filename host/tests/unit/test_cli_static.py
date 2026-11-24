"""``x64dbg-vm-gateway static-scripts``: where the packaged static-tool sync scripts are, or a
copy of them. Driven through ``cli.main([...])`` like the other CLI tests; it needs no
config file and no VM."""

from __future__ import annotations

import json
from pathlib import Path

from tests.unit.test_cli import run
from x64dbg_vm_gateway import static_scripts

STATIC_DIR = Path(__file__).resolve().parents[3] / "static"


def test_static_scripts_is_listed_in_the_help(capsys):
    assert run(["--help"]) == 0
    assert "static-scripts" in capsys.readouterr().out


def test_static_scripts_help_lists_its_options(capsys):
    assert run(["static-scripts", "--help"]) == 0
    out = capsys.readouterr().out
    assert "--dest" in out and "--force" in out


def test_static_scripts_prints_the_installed_location(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("X64DBG_VM_GATEWAY_CONFIG", str(tmp_path / "no-such-config.toml"))  # not needed
    assert run(["static-scripts"]) == 0
    out = capsys.readouterr().out
    root = static_scripts.installed_root()
    assert root is not None and str(root) in out
    for rel in static_scripts.SCRIPT_FILES:
        assert rel in out, rel
    for tool_id in ("ida", "ghidra", "radare2", "cutter"):
        assert tool_id in out
    assert "static-scripts --dest DIR" in out


def test_static_scripts_json(capsys):
    assert run(["--json", "static-scripts"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["root"] == str(static_scripts.installed_root())
    assert data["files"] == list(static_scripts.SCRIPT_FILES)
    assert data["tools"] == {"ida": "ida/x64dbg_sync.py", "ghidra": "ghidra/x64dbg_sync_ghidra.py",
                             "radare2": "radare2/x64dbg_sync_r2.py", "cutter": "radare2/x64dbg_sync_r2.py"}


def test_static_scripts_dest_copies_and_refuses_to_overwrite(tmp_path, capsys):
    dest = tmp_path / "scripts"
    assert run(["static-scripts", "--dest", str(dest)]) == 0
    out = capsys.readouterr().out
    assert f"copied {len(static_scripts.SCRIPT_FILES)} files to {dest}" in out
    for rel in static_scripts.SCRIPT_FILES:
        assert (dest / rel).read_bytes() == (STATIC_DIR / rel).read_bytes()

    (dest / "ida" / "x64dbg_sync.py").write_text("edited\n", encoding="utf-8")
    assert run(["static-scripts", "--dest", str(dest)]) == 1
    err = capsys.readouterr().err
    assert "already exist" in err and "--force" in err
    assert (dest / "ida" / "x64dbg_sync.py").read_text(encoding="utf-8") == "edited\n"

    assert run(["static-scripts", "--dest", str(dest), "--force"]) == 0
    ida = Path("ida") / "x64dbg_sync.py"
    assert (dest / ida).read_bytes() == (STATIC_DIR / ida).read_bytes()


def test_static_scripts_dest_json(tmp_path, capsys):
    dest = tmp_path / "s"
    assert run(["--json", "static-scripts", "--dest", str(dest)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {"ok": True, "dest": str(dest), "copied": list(static_scripts.SCRIPT_FILES)}


def test_force_without_dest_is_a_usage_error(capsys):
    assert run(["static-scripts", "--force"]) == 2
    assert "--dest" in capsys.readouterr().err
