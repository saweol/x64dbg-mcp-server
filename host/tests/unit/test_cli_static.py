"""The static-analysis side of the command line, driven through ``cli.main([...])`` like the
other CLI tests (no VM, no gateway is built):

- ``static-scripts``: where the packaged static-tool sync scripts are, or a copy of them
  (needs no config file);
- ``mcp-config``: the MCP client registration commands for the gateway and every configured
  static tool (``setup`` prints the same block)."""

from __future__ import annotations

import json
from pathlib import Path

from tests.unit.test_cli import run, write_config
from x64dbg_vm_gateway import config as gw_config
from x64dbg_vm_gateway import static_scripts
from x64dbg_vm_gateway.frontends import cli

STATIC_DIR = Path(__file__).resolve().parents[3] / "static"
ALL_TOOLS = '\n[static]\ntools = ["ida", "ghidra", "radare2", "cutter"]\n'
GHIDRA_ARGV = ["claude", "mcp", "add", "ghidra", "-e", "GHIDRA_INSTALL_DIR=<ghidra-install-dir>",
               "-e", "JAVA_HOME=<jdk25-home>", "--", "pyghidra-mcp", "--transport", "stdio", "--project-path",
               "<project-dir>", "--project-name", "<project-name>", "--wait-for-analysis", "<binary>"]
GHIDRA_FILL_IN = ["<ghidra-install-dir>", "<jdk25-home>", "<project-dir>", "<project-name>", "<binary>"]


def static_config(tmp_path: Path, extra: str = ALL_TOOLS) -> Path:
    path = write_config(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + extra, encoding="utf-8")
    return path


def gateway_argv(path: Path, *tail: str) -> list[str]:
    return ["claude", "mcp", "add", "x64dbg-vm", "-e", f"X64DBG_VM_GATEWAY_CONFIG={path.absolute()}", "--",
            "x64dbg-vm-gateway", "serve", *tail]


def script(rel: str) -> str:
    root = static_scripts.installed_root()
    assert root is not None
    return str(root.joinpath(*rel.split("/")))


# ── mcp-config ──────────────────────────────────────────────────────
def test_mcp_config_is_listed_in_the_help(capsys):
    assert run(["--help"]) == 0
    assert "mcp-config" in capsys.readouterr().out
    assert run(["mcp-config", "--help"]) == 0
    out = capsys.readouterr().out
    assert "--client" in out and "claude" in out and "--json" in out


def test_mcp_config_prints_the_gateway_and_every_configured_tool(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "mcp-config"]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert cli.shell_join(gateway_argv(cfg), windows=False) in lines[1]
    assert "  claude mcp add ida-multi-mcp -- python3 -m ida_multi_mcp" in lines
    assert "  " + cli.shell_join(GHIDRA_ARGV, windows=False) in lines
    assert "  fill in: " + ", ".join(GHIDRA_FILL_IN) in lines
    assert "  install: pip install pyghidra-mcp" in lines
    assert "  claude mcp add radare2 -- r2pm -r r2mcp" in lines
    assert any(line.startswith("  note: ") and "no project-save tool" in line for line in lines)
    assert "claude mcp add cutter" not in out
    assert any(line.startswith("  WARNING: ") and "unsafe" in line for line in lines)
    for rel in ("ida/x64dbg_sync.py", "ghidra/x64dbg_sync_ghidra.py", "radare2/x64dbg_sync_r2.py"):
        assert f"  sync script: {script(rel)}" in lines, rel
    # the order follows [static] tools, after the gateway
    order = [out.index(head) for head in ("x64dbg-vm", "\nida:", "\nghidra:", "\nradare2:", "\ncutter:")]
    assert order == sorted(order)


def test_mcp_config_json(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "--json", "mcp-config"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["client"] == "claude" and data["config"] == str(cfg)
    servers = data["servers"]
    assert [s["id"] for s in servers] == ["gateway", "ida", "ghidra", "radare2", "cutter"]
    gw, ida, ghidra, r2, cutter = servers
    assert gw["name"] == "x64dbg-vm" and gw["argv"] == gateway_argv(cfg) and gw["fill_in"] == []
    assert gw["command"] == cli.shell_join(gateway_argv(cfg))
    assert ida["argv"] == ["claude", "mcp", "add", "ida-multi-mcp", "--", "python3", "-m", "ida_multi_mcp"]
    assert ida["verified"] is True and ida["sync_script"] == script("ida/x64dbg_sync.py")
    assert ghidra["argv"] == GHIDRA_ARGV and ghidra["fill_in"] == GHIDRA_FILL_IN
    assert ghidra["transport"] == "stdio" and ghidra["install"] == "pip install pyghidra-mcp"
    assert any("GhidraMCP" in n for n in ghidra["notes"])
    assert r2["sync_script"] == script("radare2/x64dbg_sync_r2.py") and r2["warning"] is None
    assert cutter["argv"] is None and cutter["command"] is None and "unsafe" in cutter["warning"]
    assert cutter["sync_script"] == script("radare2/x64dbg_sync_r2.py")
    assert "CutterMCP" in cutter["error"]["message"]


def test_mcp_config_uses_the_overrides(tmp_path, capsys):
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ghidra", "radare2", "cutter"]\n'
                                  '[static.servers.ghidra]\n'
                                  'args = ["--transport", "stdio", "--project-path", '
                                  '"/srv/ghidra projects", "--project-name", "lab", "/srv/s.exe"]\n'
                                  'env = { GHIDRA_INSTALL_DIR = "/opt/ghidra", JAVA_HOME = "/opt/jdk-25" }\n'
                                  '[static.servers.radare2]\nurl = "http://127.0.0.1:8089/sse"\n'
                                  'transport = "sse"\nname = "r2"\n'
                                  '[static.servers.cutter]\ncommand = ["/opt/cutter-mcp/bridge"]\n')
    assert run(["--config", str(cfg), "--json", "mcp-config"]) == 0
    _gw, ghidra, r2, cutter = json.loads(capsys.readouterr().out)["servers"]
    assert ghidra["argv"] == ["claude", "mcp", "add", "ghidra", "-e", "GHIDRA_INSTALL_DIR=/opt/ghidra", "-e",
                              "JAVA_HOME=/opt/jdk-25", "--", "pyghidra-mcp", "--transport", "stdio",
                              "--project-path", "/srv/ghidra projects", "--project-name", "lab", "/srv/s.exe"]
    assert ghidra["fill_in"] == [] and ghidra["verified"] is False
    assert r2["argv"] == ["claude", "mcp", "add", "--transport", "sse", "r2", "http://127.0.0.1:8089/sse"]
    assert cutter["argv"] == ["claude", "mcp", "add", "cutter", "--", "/opt/cutter-mcp/bridge"]
    assert "unsafe" in cutter["warning"] and "error" not in cutter  # registered, still warned
    assert run(["--config", str(cfg), "mcp-config"]) == 0
    out = capsys.readouterr().out
    assert "'/srv/ghidra projects'" in out and "fill in" not in out.split("\nradare2:")[0]


def test_mcp_config_quotes_for_windows_shells(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_windows_host", lambda: True)
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ghidra"]\n[static.servers.ghidra]\n'
                                  "command = ['C:\\Program Files\\g\\ghidra-mcp.exe']\n")
    assert run(["--config", str(cfg), "mcp-config"]) == 0
    assert '-- "C:\\Program Files\\g\\ghidra-mcp.exe"' in capsys.readouterr().out


def test_mcp_config_at_the_default_location_needs_no_env(tmp_path, capsys, monkeypatch):
    target = tmp_path / "xdg" / "x64dbg-vm-gateway" / "config.toml"
    target.parent.mkdir(parents=True)
    static_config(tmp_path).rename(target)
    monkeypatch.setattr(gw_config, "default_config_path", lambda **kw: target)
    monkeypatch.delenv(gw_config.ENV_CONFIG_PATH, raising=False)
    assert run(["--profile", "win10", "mcp-config"]) == 0
    out = capsys.readouterr().out
    assert "  claude mcp add x64dbg-vm -- x64dbg-vm-gateway serve --profile win10" in out.splitlines()


def test_mcp_config_without_a_config_file_says_how_to_create_one(tmp_path, capsys):
    assert run(["--config", str(tmp_path / "missing.toml"), "mcp-config"]) == 1
    err = capsys.readouterr().err
    assert "config file not found" in err and "init" in err


def test_mcp_config_never_prints_the_guest_password(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("GW_TEST_GUEST_PW", "guest-pass-s3cr3t")
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "mcp-config"]) == 0
    out = capsys.readouterr().out
    assert "guest-pass-s3cr3t" not in out and "GW_TEST_GUEST_PW" in out  # names the variable only


# ── static-scripts ──────────────────────────────────────────────────


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
