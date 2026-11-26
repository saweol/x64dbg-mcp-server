"""``mcp-config`` beyond the printed ``claude mcp add`` lines (driven through ``cli.main``):

- ``--permissions``: a Claude Code settings.json snippet that allows the observe and
  guest-mutating gateway tools and every mirrored plugin tool by exact name
  (``mcp__<server>__<tool>``) and asks for the host-destructive gateway tools;
- the register line names the gateway executable by its absolute path when it can be resolved;
- ``--client json``: a generic ``mcpServers`` document (Claude Desktop, Cursor, VS Code style);
- ``--apply``: runs the ``claude mcp add`` commands that need nothing filled in, after a y/N
  confirmation on a terminal or with ``--yes``; never with a secret;
- ``--tool ID`` (one server) and ``--set NAME=VALUE`` (fills ``<NAME>`` placeholders, checked
  like the config)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.unit.test_cli import run
from tests.unit.test_cli_static import ALL_TOOLS, GHIDRA_ARGV, gateway_argv, static_config
from x64dbg_vm_gateway import policy
from x64dbg_vm_gateway.frontends import cli
from x64dbg_vm_gateway.frontends.tool_defs import DEPRECATED_ALIASES, GATEWAY_TOOLS, RiskTier

SERVER = "x64dbg-vm"
DESTRUCTIVE = {"vm_snapshot_take", "vm_snapshot_revert", "vm_snapshot_delete", "vm_power", "file_download",
               "analysis_finish"}
GHIDRA_SET = ["--set", "ghidra-install-dir=/opt/ghidra", "--set", "jdk25-home=/opt/jdk-25", "--set",
              "project-dir=/srv/ghidra projects", "--set", "project-name=lab", "--set", "binary=/srv/s.exe"]


@pytest.fixture(autouse=True)
def posix_host(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_windows_host", lambda: False)


def name(tool: str) -> str:
    return f"mcp__{SERVER}__{tool}"


# ── (a) --permissions ───────────────────────────────────────────────
#: plugin tools the review named: never allowed without asking in strict mode
RISKY_PLUGIN_TOOLS = {"ExecuteDebuggerCommand", "WriteMemToAddress", "AllocateMemory", "FreeMemory",
                      "Assemble", "SetRegister", "LoadBinary", "RestartDebug", "StopDebug", "DumpMemory",
                      "DumpModule", "AttachProcess", "SetBreakpoint", "run"}
#: gateway tools strict mode allows besides the observe tier
STRICT_GATEWAY = {"analysis_start", "analysis_collect", "file_upload", "static_export_annotations",
                  "static_import_annotations"}


def catalog_read_only() -> dict[str, bool]:
    """Plugin tool -> read-only in every builtin catalog that lists it."""
    from importlib import resources

    flags: dict[str, bool] = {}
    for version in ("1.9", "1.10"):
        doc = json.loads(resources.files("x64dbg_vm_gateway").joinpath(f"data/tools-v{version}.json")
                         .read_text(encoding="utf-8"))
        for t in doc["tools"]:
            flags[t["name"]] = flags.get(t["name"], True) and bool(t["read_only"])
    return flags


def snippet(tmp_path: Path, capsys: Any, *extra: str, config: Path | None = None) -> tuple[dict, str]:
    cfg = config or static_config(tmp_path)
    assert run(["--config", str(cfg), "mcp-config", "--permissions", *extra]) == 0
    captured = capsys.readouterr()
    return json.loads(captured.out)["permissions"], captured.err  # stdout: the snippet, ready to merge


def test_strict_permissions_are_the_default(tmp_path, capsys):
    perms, err = snippet(tmp_path, capsys)
    allow, ask = perms["allow"], perms["ask"]
    assert len(allow) == len(set(allow)) and len(ask) == len(set(ask)) and not set(allow) & set(ask)
    for tool in GATEWAY_TOOLS:
        allowed = tool.tier is RiskTier.OBSERVE or tool.name in STRICT_GATEWAY
        assert name(tool.name) in (allow if allowed else ask), tool.name
    for gateway_tool in ("debugger_call", "debugger_restart", "debugger_select", *DESTRUCTIVE):
        assert name(gateway_tool) in ask, gateway_tool
    flags = catalog_read_only()
    for tool, read_only in flags.items():
        assert name(tool) in (allow if read_only else ask), tool  # the catalog's read_only flag decides
    for tool in RISKY_PLUGIN_TOOLS:
        assert name(tool) in ask, tool
    for tool in ("GetDebugState", "ReadMemory", "ListModules", "GetCallStack", "GetServerInfo"):
        assert name(tool) in allow, tool
    assert not any(name(alias) in allow + ask for alias in DEPRECATED_ALIASES)  # never listed, never called
    assert all(n.startswith(f"mcp__{SERVER}__") for n in allow + ask)
    assert "settings.json" in err and "strict" in err


def test_lab_permissions_allow_every_guest_changing_tool(tmp_path, capsys):
    perms, err = snippet(tmp_path, capsys, "--permissions-mode", "lab")
    allow, ask = perms["allow"], perms["ask"]
    assert set(ask) == {name(t) for t in DESTRUCTIVE}
    for tool in GATEWAY_TOOLS:
        assert name(tool.name) in (ask if tool.tier is RiskTier.HOST_DESTRUCTIVE else allow), tool.name
    for tool in catalog_read_only():
        assert name(tool) in allow, tool
    assert "disposable" in err  # lab mode is for lab VMs that are reverted anyway


def test_an_endpoint_profile_always_gets_strict_permissions(tmp_path, capsys):
    cfg = tmp_path / "endpoint.toml"
    cfg.write_text(f"""
[gateway]
jobs_root = "{(tmp_path / 'jobs').as_posix()}"
default_profile = "remote"

[profiles.remote]
mode = "endpoint"

[profiles.remote.backends.x64]
url = "http://127.0.0.1:9094/"
token_env = "GW_TEST_X64_TOKEN"
""", encoding="utf-8")
    perms, err = snippet(tmp_path, capsys, "--permissions-mode", "lab", config=cfg)
    assert name("ExecuteDebuggerCommand") in perms["ask"] and name("debugger_call") in perms["ask"]
    assert "endpoint" in err and "strict" in err
    lab = ["--permissions", "--permissions-mode", "lab"]
    assert run(["--config", str(cfg), "--json", "mcp-config", *lab]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "strict" and any("endpoint" in w for w in data["warnings"])


def test_permissions_tiers_come_from_the_policy_tables():
    tiers = policy.GATEWAY_TOOL_TIERS
    assert {t for t, tier in tiers.items() if tier is RiskTier.HOST_DESTRUCTIVE} == DESTRUCTIVE
    perms = cli.permissions_snippet(SERVER, mode="lab")["permissions"]
    assert set(perms["ask"]) == {name(t) for t in DESTRUCTIVE}
    strict = cli.permissions_snippet(SERVER)["permissions"]
    assert {name(t) for t in DESTRUCTIVE} <= set(strict["ask"])


def test_permissions_json(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "--json", "mcp-config", "--permissions"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["server"] == SERVER and data["mode"] == "strict"
    assert name("session_status") in data["settings"]["permissions"]["allow"]
    assert data["notes"] and data["warnings"] == []


def test_permissions_mode_needs_permissions(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "mcp-config", "--permissions-mode", "lab"]) == 2


@pytest.mark.parametrize("server,expected", [
    ("x64dbg-vm", "mcp__x64dbg-vm__run"),
    ("lab_2", "mcp__lab_2__run"),
    ("claude.ai Docs", "mcp__claude_ai_Docs__run"),  # Claude Code turns other characters into _
])
def test_claude_tool_names(server, expected):
    assert cli.claude_tool_name(server, "run") == expected


def test_permissions_cannot_be_combined_with_apply_or_another_client(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "mcp-config", "--permissions", "--apply", "--yes"]) == 2
    assert run(["--config", str(cfg), "mcp-config", "--permissions", "--client", "json"]) == 2


# ── (b) the absolute path of the gateway executable ─────────────────
def test_resolve_from_argv0_then_path():
    def which(_name: str) -> str | None:
        return "/home/u/.local/bin/x64dbg-vm-gateway"

    assert cli.resolve_gateway_program(argv0="/opt/gw/bin/x64dbg-vm-gateway", which=which,
                                       is_file=lambda p: True) == ("/opt/gw/bin/x64dbg-vm-gateway", "argv0")
    assert cli.resolve_gateway_program(argv0="/usr/bin/pytest", which=which, is_file=lambda p: True) == \
        ("/home/u/.local/bin/x64dbg-vm-gateway", "PATH")
    assert cli.resolve_gateway_program(argv0="", which=lambda n: None, is_file=lambda p: False) == \
        (cli.PROG, None)
    # a console script on Windows: argv[0] may name the launcher with or without .exe
    assert cli.resolve_gateway_program(argv0="C:\\gw\\Scripts\\x64dbg-vm-gateway.exe", which=lambda n: None,
                                       is_file=lambda p: True)[1] == "argv0"


def test_resolve_keeps_a_relative_argv0_absolute(tmp_path, monkeypatch):
    exe = tmp_path / "bin" / "x64dbg-vm-gateway"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    program, how = cli.resolve_gateway_program(argv0="bin/x64dbg-vm-gateway", which=lambda n: None)
    assert how == "argv0" and Path(program).is_absolute() and Path(program) == exe


def test_register_line_uses_the_resolved_program(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "gateway_program", lambda: ("/opt/gw/bin/x64dbg-vm-gateway", "PATH"))
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "--json", "mcp-config"]) == 0
    gw = json.loads(capsys.readouterr().out)["servers"][0]
    argv = gateway_argv(cfg)
    argv[argv.index("x64dbg-vm-gateway")] = "/opt/gw/bin/x64dbg-vm-gateway"
    assert gw["argv"] == argv and gw["program"] == "/opt/gw/bin/x64dbg-vm-gateway"
    assert any("/opt/gw/bin/x64dbg-vm-gateway" in n and "absolute path" in n for n in gw["notes"])


def test_register_line_notes_an_unresolved_program(tmp_path, capsys):
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "--json", "mcp-config"]) == 0
    gw = json.loads(capsys.readouterr().out)["servers"][0]
    assert gw["argv"] == gateway_argv(cfg) and gw["program"] == "x64dbg-vm-gateway"
    assert any("PATH" in n for n in gw["notes"])


def test_register_line_quotes_a_windows_path_with_spaces(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_windows_host", lambda: True)
    exe = "C:\\Program Files\\gw\\Scripts\\x64dbg-vm-gateway.exe"
    monkeypatch.setattr(cli, "gateway_program", lambda: (exe, "PATH"))
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "mcp-config"]) == 0
    out = capsys.readouterr().out
    assert f"'--' '{exe}' serve" in out  # one PowerShell argument


# ── (c) --client json ───────────────────────────────────────────────
def test_client_json_document(tmp_path, capsys):
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida", "ghidra", "radare2", "cutter"]\n'
                                  '[static.servers.radare2]\nurl = "http://127.0.0.1:8089/sse"\n'
                                  'transport = "sse"\nname = "r2"\n')
    assert run(["--config", str(cfg), "mcp-config", "--client", "json"]) == 0
    captured = capsys.readouterr()
    servers = json.loads(captured.out)["mcpServers"]  # stdout: the document only
    assert set(servers) == {SERVER, "ida-multi-mcp", "ghidra", "r2"}
    assert servers[SERVER] == {"command": "x64dbg-vm-gateway", "args": ["serve"],
                               "env": {"X64DBG_VM_GATEWAY_CONFIG": str(cfg.absolute())}}
    assert servers["ida-multi-mcp"] == {"command": "python3", "args": ["-m", "ida_multi_mcp"]}
    assert servers["ghidra"]["command"] == "pyghidra-mcp"
    assert servers["ghidra"]["args"] == GHIDRA_ARGV[GHIDRA_ARGV.index("pyghidra-mcp") + 1:]
    assert servers["ghidra"]["env"] == {"GHIDRA_INSTALL_DIR": "<ghidra-install-dir>",
                                        "JAVA_HOME": "<jdk25-home>"}
    assert servers["r2"] == {"type": "sse", "url": "http://127.0.0.1:8089/sse"}
    err = captured.err
    assert "ghidra" in err and "<binary>" in err  # what is left to fill in
    assert "cutter" in err  # skipped: no MCP server by default


def test_client_json_with_json_output(tmp_path, capsys):
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "--json", "mcp-config", "--client", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["client"] == "json" and set(data["mcpServers"]) == {SERVER, "ida-multi-mcp"}
    assert [s["id"] for s in data["servers"]] == ["gateway", "ida"]


def test_client_json_is_the_same_on_windows(tmp_path, capsys, monkeypatch):
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "mcp-config", "--client", "json"]) == 0
    posix = capsys.readouterr().out
    monkeypatch.setattr(cli, "_windows_host", lambda: True)
    assert run(["--config", str(cfg), "mcp-config", "--client", "json"]) == 0
    assert capsys.readouterr().out == posix  # JSON has no shell quoting


# ── (e) --tool and --set ────────────────────────────────────────────
def test_tool_limits_the_output(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "--json", "mcp-config", "--tool", "radare2"]) == 0
    assert [s["id"] for s in json.loads(capsys.readouterr().out)["servers"]] == ["radare2"]
    assert run(["--config", str(cfg), "--json", "mcp-config", "--tool", "gateway"]) == 0
    assert [s["id"] for s in json.loads(capsys.readouterr().out)["servers"]] == ["gateway"]
    assert run(["--config", str(cfg), "mcp-config", "--tool", "radare2"]) == 0
    out = capsys.readouterr().out
    assert "claude mcp add radare2" in out and "x64dbg-vm" not in out


def test_tool_not_in_static_tools_is_printed_with_a_note(tmp_path, capsys):
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "--json", "mcp-config", "--tool", "ghidra"]) == 0
    (entry,) = json.loads(capsys.readouterr().out)["servers"]
    assert entry["id"] == "ghidra" and any("[static] tools" in n for n in entry["notes"])


def test_unknown_tool_is_a_usage_error(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "mcp-config", "--tool", "binja"]) == 2
    assert "ghidra" in capsys.readouterr().err  # lists the valid ids


def test_set_fills_placeholders(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "--json", "mcp-config", "--tool", "ghidra", *GHIDRA_SET]) == 0
    (entry,) = json.loads(capsys.readouterr().out)["servers"]
    assert entry["fill_in"] == []
    assert entry["argv"] == ["claude", "mcp", "add", "ghidra", "-e", "GHIDRA_INSTALL_DIR=/opt/ghidra", "-e",
                             "JAVA_HOME=/opt/jdk-25", "--", "pyghidra-mcp", "--transport", "stdio",
                             "--project-path", "/srv/ghidra projects", "--project-name", "lab",
                             "--wait-for-analysis", "/srv/s.exe"]
    assert entry["command"] == cli.shell_join(entry["argv"])


def test_set_fills_some_and_lists_the_rest(tmp_path, capsys):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "--json", "mcp-config", "--set", "binary=/srv/s.exe"]) == 0
    ghidra = next(s for s in json.loads(capsys.readouterr().out)["servers"] if s["id"] == "ghidra")
    assert "<binary>" not in ghidra["fill_in"] and "<project-dir>" in ghidra["fill_in"]
    assert "/srv/s.exe" in ghidra["argv"]


@pytest.mark.parametrize("setting,why", [
    ("binary", "NAME=VALUE"),
    ("=x", "NAME=VALUE"),
    ("nope=x", "no <nope> placeholder"),
    ("binary=", "empty"),
    ("binary=a\nb", "control"),
    ("binary=a\x1b[2Jb", "control"),
    ("binary=--api-key=abc", "secret"),
    ("binary=https://user:pw@host/x", "secret"),
    ("project-name=Bearer abc", "secret"),
])
def test_set_is_checked_like_the_config(tmp_path, capsys, setting, why):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "mcp-config", "--set", setting]) == 2
    err = capsys.readouterr().err
    assert why in err
    assert "abc" not in err and "pw@" not in err  # a refused value is never echoed


# ── (d) --apply ─────────────────────────────────────────────────────
class Runner:
    def __init__(self, returncodes: dict[str, int] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.returncodes = returncodes or {}

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        code = self.returncodes.get(argv[3] if len(argv) > 3 and argv[3] != "--transport" else argv[5], 0)
        out = f"Added stdio MCP server {argv[3]}" if code == 0 else ""
        return subprocess.CompletedProcess(argv, code, stdout=out, stderr="already exists" if code else "")


@pytest.fixture
def runner(monkeypatch) -> Runner:
    r = Runner()
    monkeypatch.setattr(cli, "_run_command", r)
    monkeypatch.setattr(cli, "_find_claude", lambda: "/usr/local/bin/claude")
    return r


def test_apply_runs_the_complete_registrations(tmp_path, capsys, runner, monkeypatch):
    monkeypatch.setenv("GW_TEST_GUEST_PW", "guest-pass-s3cr3t")
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "mcp-config", "--apply", "--yes"]) == 0
    captured = capsys.readouterr()
    ran = [argv[3] for argv in runner.calls]
    assert ran == ["x64dbg-vm", "ida-multi-mcp", "radare2"]  # ghidra has placeholders, cutter no recipe
    assert runner.calls[0][0] == "/usr/local/bin/claude"
    assert runner.calls[0][1:] == gateway_argv(cfg)[1:]
    assert all("guest-pass-s3cr3t" not in arg for argv in runner.calls for arg in argv)
    out = captured.out
    assert "ran: " in out and "skipped ghidra" in out and "<binary>" in out and "skipped cutter" in out


def test_apply_with_set_registers_ghidra_too(tmp_path, capsys, runner):
    cfg = static_config(tmp_path)
    assert run(["--config", str(cfg), "--json", "mcp-config", "--tool", "ghidra", "--apply", "--yes",
                *GHIDRA_SET]) == 0
    data = json.loads(capsys.readouterr().out)
    (call,) = runner.calls
    assert call[1:5] == ["mcp", "add", "ghidra", "-e"] and "/srv/s.exe" in call
    assert data["applied"][0]["name"] == "ghidra" and data["applied"][0]["ok"] is True
    assert data["skipped"] == []


def test_apply_reports_a_failed_command(tmp_path, capsys, monkeypatch):
    r = Runner({"ida-multi-mcp": 1})
    monkeypatch.setattr(cli, "_run_command", r)
    monkeypatch.setattr(cli, "_find_claude", lambda: "/usr/local/bin/claude")
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "--json", "mcp-config", "--apply", "--yes"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert [(a["name"], a["ok"]) for a in data["applied"]] == [("x64dbg-vm", True), ("ida-multi-mcp", False)]
    assert "already exists" in data["applied"][1]["output"]


def test_apply_needs_a_confirmation(tmp_path, capsys, runner, monkeypatch):
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)
    assert run(["--config", str(cfg), "mcp-config", "--apply"]) == 2  # no terminal, no --yes
    assert "--yes" in capsys.readouterr().err and runner.calls == []
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    answers = iter(["n"])
    monkeypatch.setattr("builtins.input", lambda: next(answers))
    assert run(["--config", str(cfg), "mcp-config", "--apply"]) == 1
    captured = capsys.readouterr()
    assert "[y/N]" in captured.err and "nothing was registered" in captured.err and runner.calls == []
    assert "claude mcp add x64dbg-vm" in captured.err  # the prompt shows what would run
    answers = iter(["y"])
    assert run(["--config", str(cfg), "mcp-config", "--apply"]) == 0
    assert len(runner.calls) == 2


def test_apply_without_claude_on_path(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_find_claude", lambda: None)
    calls: list[Any] = []
    monkeypatch.setattr(cli, "_run_command", calls.append)
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "mcp-config", "--apply", "--yes"]) == 1
    err = capsys.readouterr().err
    assert "claude" in err and "PATH" in err and calls == []


def test_apply_is_for_claude_only(tmp_path, capsys, runner):
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "mcp-config", "--client", "json", "--apply", "--yes"]) == 2
    assert runner.calls == []


def test_apply_skips_arguments_a_batch_launcher_would_misread(tmp_path, capsys, runner, monkeypatch):
    """claude.cmd (npm) runs through cmd.exe, which expands % and splits at & | < > ^ even inside
    quotes: such arguments are never handed to it."""
    monkeypatch.setattr(cli, "_windows_host", lambda: True)
    monkeypatch.setattr(cli, "_find_claude", lambda: "C:\\npm\\claude.cmd")
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida", "ghidra"]\n')
    setting = [*GHIDRA_SET[:-2], "--set", "binary=C:\\s\\a&b.exe"]
    assert run(["--config", str(cfg), "--json", "mcp-config", "--apply", "--yes", *setting]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [argv[3] for argv in runner.calls] == ["x64dbg-vm", "ida-multi-mcp"]
    (skip,) = data["skipped"]
    assert skip["name"] == "ghidra" and "cmd.exe" in skip["reason"]


def test_apply_hands_such_arguments_to_a_native_claude_exe(tmp_path, capsys, runner, monkeypatch):
    """A real executable gets its arguments through CreateProcess (list2cmdline), not cmd.exe."""
    monkeypatch.setattr(cli, "_windows_host", lambda: True)
    monkeypatch.setattr(cli, "_find_claude", lambda: "C:\\Users\\u\\.local\\bin\\claude.exe")
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ghidra"]\n')
    setting = [*GHIDRA_SET[:-2], "--set", "binary=C:\\s\\a&b.exe"]
    assert run(["--config", str(cfg), "--json", "mcp-config", "--apply", "--yes", *setting]) == 0
    assert [argv[3] for argv in runner.calls] == ["x64dbg-vm", "ghidra"]
    assert runner.calls[1][-1] == "C:\\s\\a&b.exe"


def test_apply_refuses_an_argument_that_carries_a_secret(tmp_path, capsys, runner, monkeypatch):
    """Defence in depth: the config loader refuses secrets already; a registration that still holds
    one (here: patched in) is skipped, never run."""
    real = cli.mcp_config_entries

    def entries(*args: Any, **kw: Any) -> list[dict[str, Any]]:
        out = real(*args, **kw)
        out[1]["launch"]["args"] = [*out[1]["launch"]["args"], "--token=abc123"]
        return out

    monkeypatch.setattr(cli, "mcp_config_entries", entries)
    cfg = static_config(tmp_path, '\n[static]\ntools = ["ida"]\n')
    assert run(["--config", str(cfg), "--json", "mcp-config", "--apply", "--yes"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [argv[3] for argv in runner.calls] == ["x64dbg-vm"]
    (skip,) = data["skipped"]
    assert skip["name"] == "ida-multi-mcp" and "secret" in skip["reason"] and "abc123" not in skip["reason"]
    assert all("abc123" not in arg for argv in runner.calls for arg in argv)


def test_help_lists_the_new_options(capsys):
    assert run(["mcp-config", "--help"]) == 0
    out = capsys.readouterr().out
    for option in ("--permissions", "--apply", "--yes", "--tool", "--set", "json"):
        assert option in out, option


def test_all_tools_config_is_still_valid():
    assert "cutter" in ALL_TOOLS
