"""Registry of the static-analysis tools used next to the gateway (IDA, Ghidra, radare2, Cutter).

The gateway does not proxy static analysis. Each tool's own MCP server is registered in
the MCP client NEXT TO the gateway (for example ``claude mcp add ghidra -- pyghidra-mcp``),
and the gateway only offers the tool-neutral side: address rebasing between x64dbg runtime
addresses and ``static image base + RVA`` (``static_rebase``) and the module + RVA
annotation document ``x64dbg-ida-sync/1`` (``static_export_annotations`` /
``static_import_annotations``, see ``ida_sync`` and ``ida/README.md``).

This module is DATA ONLY: one :class:`StaticTool` per supported tool with

- ``executables``: program names ``gateway_doctor`` looks for on PATH (any one is enough);
- ``sync_script``: repository path of the tool's script that imports / exports
  ``x64dbg-ida-sync/1`` documents inside the tool;
- ``mcp``: the :class:`McpRecipe` for registering the tool's MCP server.

``McpRecipe.verified`` is True only for recipes checked against a real installation;
the others are taken from the projects' documentation and may need correcting (edit the
data here, nothing else depends on the values). Values never carry host-specific paths:
a user-specific location belongs in the config, ``[static.servers.<id>]``
(``config.StaticServerConfig``), which :func:`effective_recipe` applies.

Thread-safety: everything is immutable after import.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import TYPE_CHECKING

from .errors import ConfigError

if TYPE_CHECKING:
    from .config import StaticConfig

__all__ = ["TOOLS", "TOOL_IDS", "TRANSPORTS", "McpRecipe", "StaticTool", "effective_recipe", "get_tool",
           "server_name"]

#: Supported tool ids, in documentation order (``config.STATIC_TOOL_IDS`` re-exports it; this module
#: imports ``config`` only for type checking, so the loader can import it without a cycle).
TOOL_IDS: tuple[str, ...] = ("ida", "ghidra", "radare2", "cutter")
#: MCP transports: "stdio" runs ``command``; "http" (streamable HTTP) and "sse" connect to ``url``.
TRANSPORTS: tuple[str, ...] = ("stdio", "http", "sse")


@dataclass(frozen=True)
class McpRecipe:
    """How to register a static tool's MCP server in the MCP client."""

    name: str  # MCP server name to register (the client prefixes the server's tools with it)
    project: str  # MCP server project
    homepage: str  # project page ("" when not recorded)
    transport: str  # one of TRANSPORTS
    command: tuple[str, ...]  # stdio: argv to start the server; () when there is no generic one
    url: str | None  # http / sse: endpoint
    install: str  # how to install the server ("" when the homepage is the only reference)
    notes: str  # prerequisites and caveats for the user
    verified: bool  # recipe checked against a real installation


@dataclass(frozen=True)
class StaticTool:
    id: str  # one of TOOL_IDS
    display: str  # human-readable name
    executables: tuple[str, ...]  # program names on PATH that show the tool is installed
    sync_script: str  # repository path of the in-tool x64dbg-ida-sync/1 import / export script
    mcp: McpRecipe


_TOOLS = (
    StaticTool(
        id="ida",
        display="IDA Pro",
        executables=("ida", "ida64", "idat", "idat64"),
        sync_script="static/ida/x64dbg_sync.py",
        mcp=McpRecipe(
            name="ida-multi-mcp",
            project="ida-multi-mcp",
            homepage="",
            transport="stdio",
            command=("python3", "-m", "ida_multi_mcp"),
            url=None,
            install="",
            notes="Routes calls to the running IDA instances (one per IDB); open the sample in IDA first. "
                  "Image base: idaapi.get_imagebase().",
            verified=True,
        ),
    ),
    StaticTool(
        id="ghidra",
        display="Ghidra",
        executables=("ghidraRun", "analyzeHeadless", "pyghidra-mcp"),
        sync_script="static/ghidra/x64dbg_sync_ghidra.py",
        mcp=McpRecipe(
            name="ghidra",
            project="pyghidra-mcp (headless Ghidra)",
            homepage="https://github.com/clearbluejar/pyghidra-mcp",
            transport="stdio",
            command=("pyghidra-mcp",),
            url=None,
            install="pip install pyghidra-mcp",
            notes="Needs GHIDRA_INSTALL_DIR pointing at the Ghidra installation. Alternative: the GUI "
                  "server LaurieWired/GhidraMCP (a Ghidra plugin plus a bridge; register it with a "
                  "[static.servers.ghidra] override). Image base: currentProgram.getImageBase().",
            verified=False,
        ),
    ),
    StaticTool(
        id="radare2",
        display="radare2",
        executables=("r2", "radare2"),
        sync_script="static/radare2/x64dbg_sync_r2.py",
        mcp=McpRecipe(
            name="radare2",
            project="radare2-mcp (r2mcp)",
            homepage="https://github.com/radareorg/radare2-mcp",
            transport="stdio",
            command=("r2pm", "-r", "r2mcp"),
            url=None,
            install="r2pm -ci r2mcp",
            notes="Installed through radare2's package manager r2pm. Image base: the binary's baddr "
                  "(iI).",
            verified=False,
        ),
    ),
    StaticTool(
        id="cutter",
        display="Cutter",
        executables=("cutter", "Cutter", "rizin"),
        sync_script="static/radare2/x64dbg_sync_r2.py",
        mcp=McpRecipe(
            name="cutter",
            project="CutterMCP",
            homepage="https://github.com/ap425q/CutterMCP",
            transport="stdio",
            command=(),
            url=None,
            install="",
            notes="A Cutter plugin plus an MCP bridge script whose location is user specific: set "
                  "[static.servers.cutter] command = [...] (or url) to register it. Cutter is built on "
                  "rizin, so the radare2 sync script applies. Image base: the binary's baddr (iI).",
            verified=False,
        ),
    ),
)

TOOLS: Mapping[str, StaticTool] = MappingProxyType({t.id: t for t in _TOOLS})


def _unknown(tool_id: object) -> ConfigError:
    shown = repr(tool_id)[:40]
    return ConfigError(f"unknown static tool {shown}", stage="static",
                       hint=f"static tools are: {', '.join(TOOL_IDS)}", details={"tool": shown})


def get_tool(tool_id: str) -> StaticTool:
    """The registry entry of ``tool_id``; ConfigError (with the valid ids as hint) otherwise."""
    tool = TOOLS.get(tool_id) if isinstance(tool_id, str) else None
    if tool is None:
        raise _unknown(tool_id)
    return tool


def server_name(tool_id: str, static_config: StaticConfig | None = None) -> str:
    """MCP server name the tool is registered under (override, else the registry's).

    Unlike :func:`effective_recipe` this never needs a command, so it also answers for a
    tool whose recipe is incomplete (Cutter without an override)."""
    tool = get_tool(tool_id)
    override = static_config.servers.get(tool_id) if static_config is not None else None
    return override.name if override is not None and override.name else tool.mcp.name


def effective_recipe(tool_id: str, static_config: StaticConfig | None = None) -> McpRecipe:
    """The registry recipe of ``tool_id`` with ``[static.servers.<id>]`` applied.

    An override's ``command`` replaces the command (url None, transport "stdio" unless
    given), its ``url`` replaces both (command (), transport "http" unless given), its
    ``name`` the server name; the documentation fields stay. Raises ConfigError when the
    result can not be registered: neither a command nor a url (Cutter without an override,
    whose bridge location is user specific).
    """
    tool = get_tool(tool_id)
    recipe = tool.mcp
    override = static_config.servers.get(tool_id) if static_config is not None else None
    if override is not None:
        if override.command:
            recipe = replace(recipe, command=tuple(override.command), url=None,
                             transport=override.transport or "stdio")
        elif override.url:
            recipe = replace(recipe, command=(), url=override.url, transport=override.transport or "http")
        if override.name:
            recipe = replace(recipe, name=override.name)
    if not recipe.command and not recipe.url:
        key = f"static.servers.{tool.id}"
        raise ConfigError(
            f"{tool.display}: the {recipe.project} MCP server has no default command (its location is "
            "user specific), so it cannot be registered",
            stage="static",
            hint=f"add [{key}] to the gateway config with command = [\"<program>\", \"<args>\"...] (stdio) "
                 f"or url = \"http://<host>:<port>/<path>\" (transport \"http\" or \"sse\")"
                 + (f"; see {recipe.homepage}" if recipe.homepage else ""),
            details={"key": key, "tool": tool.id},
        )
    return recipe
