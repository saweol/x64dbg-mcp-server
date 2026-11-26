"""Unit-test defaults shared by every module here."""

from __future__ import annotations

import pytest

from x64dbg_vm_gateway.frontends import cli


@pytest.fixture(autouse=True)
def bare_gateway_program(monkeypatch: pytest.MonkeyPatch) -> None:
    """``mcp-config`` / ``setup`` name the gateway executable by its absolute path when they can
    resolve it (``cli.gateway_program``); under pytest that would be this checkout's virtualenv. The
    tests pin the bare name; the tests of the resolution itself call ``cli.resolve_gateway_program``
    or patch ``gateway_program`` again."""
    monkeypatch.setattr(cli, "gateway_program", lambda: (cli.PROG, None))
