"""``gateway.env_file``: the KEY=VALUE file the ``*_env`` settings are resolved in.

Kept free of the runtime wiring so every front-end (the CLI's provision, the MCP
server) resolves credentials the same way.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import platform as gw_platform
from .config import GatewayConfig
from .errors import ConfigError

_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _env_error(path: Path, problem: str, hint: str | None = None, **details: Any) -> ConfigError:
    return ConfigError(
        f"env file {path}: {problem}", stage="config", hint=hint, details={"path": str(path), **details}
    )


def read_env_file(path: str | os.PathLike[str], *, system: str | None = None) -> dict[str, str]:
    """Parse a ``KEY=VALUE`` file. No shell expansion; values are never echoed in errors.

    Blank lines and ``#`` comments are ignored, an optional ``export `` prefix is
    accepted and one pair of matching surrounding quotes is stripped. On POSIX
    hosts the file must not be readable or writable by group/other.
    """
    p = Path(path).expanduser()
    try:
        st = p.stat()
    except FileNotFoundError:
        raise _env_error(p, "not found", hint="fix gateway.env_file or create the file") from None
    except OSError as e:
        raise _env_error(p, f"cannot read it ({e.strerror or type(e).__name__})") from None
    if not stat.S_ISREG(st.st_mode):
        raise _env_error(p, "not a regular file")
    if gw_platform.host_system(system) != "Windows" and st.st_mode & 0o066:
        raise _env_error(
            p, f"group/other may access it (mode {stat.S_IMODE(st.st_mode):04o})", hint=f"chmod 600 {p}"
        )
    try:
        text = p.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise _env_error(p, "not valid UTF-8") from None
    except OSError as e:
        raise _env_error(p, f"cannot read it ({e.strerror or type(e).__name__})") from None
    out: dict[str, str] = {}
    for lineno, raw in enumerate(text.lstrip("﻿").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not _ENV_NAME_RE.fullmatch(key):
            raise _env_error(
                p, f"line {lineno}: expected KEY=VALUE with KEY like [A-Za-z_][A-Za-z0-9_]*", line=lineno
            )
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out[key] = value
    return out


def resolve_environ(
    config: GatewayConfig, environ: Mapping[str, str] | None = None, *, system: str | None = None
) -> dict[str, str]:
    """The mapping ``*_env`` names are resolved in: ``environ`` (default ``os.environ``)
    over the values of ``config.env_file`` (the real environment wins, except a variable
    set to the empty string, which counts as unset). A relative
    env file path is relative to the config file's directory."""
    base = dict(os.environ if environ is None else environ)
    if not config.env_file:
        return base
    path = Path(config.env_file).expanduser()
    if not path.is_absolute() and config.config_path:
        path = Path(config.config_path).expanduser().parent / path
    # An empty variable in the real environment counts as unset (resolve_secret treats it so),
    # so it must not hide the env file's value.
    return {**read_env_file(path, system=system), **{k: v for k, v in base.items() if v != ""}}
