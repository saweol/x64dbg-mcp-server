"""Registry of the static-analysis tools used next to the gateway (IDA, Ghidra, radare2, Cutter).

The gateway does not proxy static analysis. Each tool's own MCP server is registered in
the MCP client NEXT TO the gateway (``x64dbg-vm-gateway mcp-config`` prints the
``claude mcp add`` commands), and the gateway only offers the tool-neutral side: address
rebasing between x64dbg runtime addresses and ``static image base + RVA``
(``static_rebase``) and the module + RVA annotation document ``x64dbg-ida-sync/1``
(``static_export_annotations`` / ``static_import_annotations``, see ``ida_sync`` and
``static/ida/README.md``).

This module is DATA ONLY: one :class:`StaticTool` per supported tool with

- ``executables``: names of the tool's own programs that ``gateway_doctor`` looks for on
  PATH (any one is enough; never the MCP server's program);
- ``sync_script``: repository path of the tool's script that imports / exports
  ``x64dbg-ida-sync/1`` documents inside the tool (the wheel carries a copy, see
  ``static_scripts``);
- ``mcp``: the :class:`McpRecipe` for registering the tool's MCP server.

``McpRecipe.verified`` is True only for recipes checked against a real installation
(IDA: ida-multi-mcp; Ghidra 12.2 with JDK 25: pyghidra-mcp 0.3.0; radare2 6.2.6: r2mcp
1.9.0). Values never carry host-specific paths: the user-specific parts of a recipe are
placeholders written ``<...>`` (:func:`placeholders`), and the user's values belong in the
config, ``[static.servers.<id>]`` (``config.StaticServerConfig``), which
:func:`effective_recipe` applies.

Thread-safety: everything is immutable after import.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlsplit

from .errors import ConfigError

if TYPE_CHECKING:
    from .config import StaticConfig

__all__ = ["PLACEHOLDER_RE", "TOOLS", "TOOL_IDS", "TRANSPORTS", "McpRecipe", "StaticTool", "effective_recipe",
           "get_tool", "looks_like_secret_name", "placeholders", "secret_in_argument", "server_name"]

#: Supported tool ids, in documentation order (``config.STATIC_TOOL_IDS`` re-exports it; this module
#: imports ``config`` only for type checking, so the loader can import it without a cycle).
TOOL_IDS: tuple[str, ...] = ("ida", "ghidra", "radare2", "cutter")
#: MCP transports: "stdio" runs ``command``; "http" (streamable HTTP) and "sse" connect to ``url``.
TRANSPORTS: tuple[str, ...] = ("stdio", "http", "sse")
#: a user-specific part of a recipe, e.g. ``<project-dir>``
PLACEHOLDER_RE = re.compile(r"<[^<>\s]+>")
#: name segments that suggest a secret (``looks_like_secret_name``; the config refuses them)
_SECRET_SEGMENTS = frozenset({
    "token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "pwd", "pass", "passphrase",
    "auth", "authorization", "bearer", "credential", "credentials", "cookie", "cookies", "key", "keys",
    "apikey", "apikeys", "privatekey"})
#: a last segment that names where a secret is kept rather than the secret (TOKEN_FILE, KEY_PATH)
_SECRET_LOCATIONS = frozenset({"file", "path", "env"})
#: name segments: runs of capitals, capitalised or lower-case words, digits (apiKey -> api, Key)
_SEGMENT_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_URL_IN_TEXT_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
_HEADER_RE = re.compile(r"\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*\S")  # Authorization: ..., token:abc
_ASSIGNED_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")  # NAME in NAME=VALUE


@dataclass(frozen=True)
class McpRecipe:
    """How to register a static tool's MCP server in the MCP client."""

    name: str  # MCP server name to register (the client prefixes the server's tools with it)
    project: str  # MCP server project
    homepage: str  # project page ("" when not recorded)
    transport: str  # one of TRANSPORTS
    command: tuple[str, ...]  # stdio: argv to start the server (may hold placeholders); () when none
    url: str | None  # http / sse: endpoint
    install: str  # how to install the server ("" when the homepage is the only reference)
    notes: tuple[str, ...]  # prerequisites and caveats, one line each
    verified: bool  # recipe checked against a real installation
    env: tuple[tuple[str, str], ...] = ()  # stdio: (NAME, value) the server needs; values may be placeholders
    warning: str = ""  # safety warning to show before everything else ("" when there is none)


@dataclass(frozen=True)
class StaticTool:
    id: str  # one of TOOL_IDS
    display: str  # human-readable name
    executables: tuple[str, ...]  # the tool's own programs on PATH that show it is installed
    sync_script: str  # repository path of the in-tool x64dbg-ida-sync/1 import / export script
    mcp: McpRecipe


_CUTTER_WARNING = (
    "CutterMCP 2.0 is unsafe as shipped: its Cutter plugin listens on all interfaces (port 8000) "
    "without authentication and pastes request parameters unescaped into cutter.cmd (rizin commands, "
    "including ! shell commands), so it is not registered by default. Use the sync script inside Cutter "
    "instead, or radare2's r2mcp (static tool radare2) on the same binary. If you still use CutterMCP, "
    "first patch its plugin to bind 127.0.0.1, then set [static.servers.cutter] command (or url).")

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
            notes=(
                "Routes calls to the running IDA instances (one per IDB): open the sample in IDA first.",
                "Tools: rename, set_comments, decompile; idb_save writes the IDB.",
                "Image base: idaapi.get_imagebase().",
            ),
            verified=True,
        ),
    ),
    StaticTool(
        id="ghidra",
        display="Ghidra",
        executables=("ghidraRun", "analyzeHeadless", "pyghidraRun"),
        sync_script="static/ghidra/x64dbg_sync_ghidra.py",
        mcp=McpRecipe(
            name="ghidra",
            project="pyghidra-mcp (headless Ghidra)",
            homepage="https://github.com/clearbluejar/pyghidra-mcp",
            transport="stdio",
            command=("pyghidra-mcp", "--transport", "stdio", "--project-path", "<project-dir>",
                     "--project-name", "<project-name>", "--wait-for-analysis", "<binary>"),
            env=(("GHIDRA_INSTALL_DIR", "<ghidra-install-dir>"), ("JAVA_HOME", "<jdk25-home>")),
            url=None,
            install="pip install pyghidra-mcp",
            notes=(
                "Ghidra 12.2 needs JDK 25: JAVA_HOME names the JDK, GHIDRA_INSTALL_DIR the Ghidra "
                "installation.",
                "With --wait-for-analysis the first initialize answers only after Ghidra's analysis: raise "
                "the client's start-up timeout (Claude Code: MCP_TIMEOUT) or drop the option.",
                "Tools: rename_function(binary_name, name_or_address, new_name) (functions only), "
                "set_comment(binary_name, target, comment, comment_type eol|pre|post|plate|repeatable|"
                "decompiler), decompile_function(binary_name, name_or_address), save() writes the project; "
                "binary_name comes from list_project_binaries.",
                "Alternative: LaurieWired GhidraMCP 2.0 headless (ghidra_mcp-2.0.0[headless] wheel and "
                "GhidraMCP.jar from the release zip): [static.servers.ghidra] command = [\"ghidra-mcp\", "
                "\"--headless\", \"--binary\", \"<binary>\", \"--project\", \"<project-dir>\", "
                "\"--extension-jar\", \"<GhidraMCP.jar>\"] with the same env; tools "
                "rename_function_by_address, rename_data, set_disassembly_comment (EOL), "
                "set_decompiler_comment (PRE), decompile_function_by_address; its GUI mode was not verified.",
                "Sync script: run it with pyghidraRun -H (plain analyzeHeadless cannot run Python scripts) "
                "or from the Script Manager of a Ghidra started with pyghidraRun. Image base: "
                "currentProgram.getImageBase().",
            ),
            verified=True,
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
            notes=(
                "Needs r2pm and radare2 on PATH (verified with radare2 6.2.6 and r2mcp 1.9.0).",
                "Tools: open_file, analyze, rename_function(address, name) (after analyze), rename_flag, "
                "set_comment(address, message), decompile_function.",
                "r2mcp has no project-save tool: renames and comments made through it are lost when it "
                "exits; use the sync script with --project for anything that must persist.",
                "Image base: the binary's baddr (iI).",
            ),
            verified=True,
        ),
    ),
    StaticTool(
        id="cutter",
        display="Cutter",
        executables=("cutter", "Cutter"),
        sync_script="static/radare2/x64dbg_sync_r2.py",
        mcp=McpRecipe(
            name="cutter",
            project="CutterMCP",
            homepage="https://github.com/ap425q/CutterMCP",
            transport="stdio",
            command=(),
            url=None,
            install="",
            notes=(
                "CutterMCP 2.0's set_decompiler_comment is broken: the 404 comes back as text with isError "
                "false.",
                "The sync script runs in Cutter's Python console (cutter.cmd; checked on Cutter 2.5.0 and "
                "2.4.1); the Cutter 2.5.0 Qt6 AppImage cannot load Python plugins (rizinorg/cutter#3659).",
                "Cutter is built on rizin, so the radare2 sync script applies. Image base: the binary's "
                "baddr (iI).",
            ),
            verified=False,
            warning=_CUTTER_WARNING,
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


def looks_like_secret_name(name: str) -> bool:
    """A variable, option or header name that suggests a secret: one of its segments (split at
    ``_``, ``-``, ``.`` and other separators and where the case changes) is TOKEN, SECRET, PASSWORD,
    PASSWD, PWD, PASS, PASSPHRASE, AUTH, AUTHORIZATION, BEARER, CREDENTIAL(S), COOKIE, KEY or APIKEY
    (API_KEY, GH_TOKEN, DB_PASS, AUTH_HEADER, apiKey), unless the last segment is FILE, PATH or ENV
    (TOKEN_FILE names where the secret is). A word that only contains one is no secret: KEYBOARD,
    COMPASS, BYPASS."""
    segments = [seg.lower() for seg in _SEGMENT_RE.findall(name)]
    if not segments or segments[-1] in _SECRET_LOCATIONS:
        return False
    return any(seg in _SECRET_SEGMENTS for seg in segments)


def secret_in_argument(arg: str) -> str | None:
    """Why the command-line argument or environment value ``arg`` seems to carry a secret, or None.

    Looks at a URL with a user name or password (``user:pass@``) or with a query parameter
    named like a secret; ``Name: value`` (an HTTP header) and ``NAME=VALUE`` pairs and options
    (``--token``, ``--api-key=...``, also inside a value such as ``JAVA_TOOL_OPTIONS``) whose name
    suggests a secret (:func:`looks_like_secret_name`); and ``Bearer <token>``. Positional words
    are not judged (``pass``, ``/opt/token-mcp/run``). The reason never quotes ``arg``."""
    for url in _URL_IN_TEXT_RE.findall(arg):
        why = _secret_in_url(url)
        if why:
            return why
    header = _HEADER_RE.match(arg)
    if header and looks_like_secret_name(header.group(1)):
        return "a 'Name: value' pair (an HTTP header) whose name suggests a secret"
    words = arg.split()
    for i, word in enumerate(words):
        if word.startswith("-"):
            if looks_like_secret_name(re.split(r"[=:]", word.lstrip("-"), maxsplit=1)[0]):
                return "an option whose name suggests a secret"
        elif "=" in word:
            name = word.split("=", 1)[0]
            if _ASSIGNED_NAME_RE.fullmatch(name) and looks_like_secret_name(name):
                return "a NAME=VALUE pair whose name suggests a secret"
        elif word.lower() == "bearer" and i + 1 < len(words):
            return "a bearer token"
    return None


def _secret_in_url(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if "@" in parts.netloc:
        return "a URL with a user name or password (user:password@host)"
    if any(looks_like_secret_name(name) for name, _value in parse_qsl(parts.query, keep_blank_values=True)):
        return "a URL query parameter whose name suggests a secret"
    return None


def placeholders(recipe: McpRecipe) -> tuple[str, ...]:
    """The ``<...>`` placeholders left in ``recipe`` (env values, then the command), each once."""
    found: dict[str, None] = {}
    for text in (*(value for _name, value in recipe.env), *recipe.command):
        for match in PLACEHOLDER_RE.findall(text):
            found.setdefault(match)
    return tuple(found)


def server_name(tool_id: str, static_config: StaticConfig | None = None) -> str:
    """MCP server name the tool is registered under (override, else the registry's).

    Unlike :func:`effective_recipe` this never needs a command, so it also answers for a
    tool whose recipe is incomplete (Cutter without an override)."""
    tool = get_tool(tool_id)
    override = static_config.servers.get(tool_id) if static_config is not None else None
    return override.name if override is not None and override.name else tool.mcp.name


def effective_recipe(tool_id: str, static_config: StaticConfig | None = None) -> McpRecipe:
    """The registry recipe of ``tool_id`` with ``[static.servers.<id>]`` applied.

    An override's ``command`` replaces the server: its command and its env (only the
    override's ``env``; url None, transport "stdio" unless given). ``args`` replaces the
    arguments after the registry's program. ``url`` replaces both (command (), no env,
    transport "http" unless given). Without ``command`` / ``url`` the override's ``env``
    fills in and extends the registry's env by name. ``name`` replaces the server name; the
    documentation fields stay, except ``verified``, which is False once ``command``, ``args``
    or ``url`` replaced the checked recipe. Raises ConfigError when the result can not be registered:
    neither a command nor a url (Cutter without an override; see its warning).
    """
    tool = get_tool(tool_id)
    recipe = tool.mcp
    override = static_config.servers.get(tool_id) if static_config is not None else None
    if override is not None:
        env = dict(override.env)
        if override.command:
            recipe = replace(recipe, command=tuple(override.command), url=None, env=tuple(env.items()),
                             transport=override.transport or "stdio", verified=False)
        elif override.url:
            recipe = replace(recipe, command=(), url=override.url, env=(),
                             transport=override.transport or "http", verified=False)
        else:
            if override.args is not None and recipe.command:
                recipe = replace(recipe, command=(recipe.command[0], *override.args), verified=False)
            recipe = replace(recipe, env=tuple({**dict(recipe.env), **env}.items()))
        if override.name:
            recipe = replace(recipe, name=override.name)
    if not recipe.command and not recipe.url:
        key = f"static.servers.{tool.id}"
        raise ConfigError(
            f"{tool.display}: no MCP server is registered by default ({recipe.project} 2.0 is unsafe as "
            "shipped: it listens on all interfaces without authentication and runs rizin commands built "
            "from request parameters)",
            stage="static",
            hint="use the sync script inside Cutter, or radare2's r2mcp (static tool radare2) on the same "
                 f"binary; to register a CutterMCP patched to bind 127.0.0.1, add [{key}] with "
                 "command = [\"<program>\", \"<args>\"...] (stdio) or "
                 "url = \"http://127.0.0.1:<port>/<path>\" (transport \"http\" or \"sse\")"
                 + (f"; see {recipe.homepage}" if recipe.homepage else ""),
            details={"key": key, "tool": tool.id},
        )
    return recipe
