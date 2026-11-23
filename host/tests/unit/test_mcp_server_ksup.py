"""The MCP front-ends warm the gateway up before they serve (E5).

Claude Code does not reliably honour ``notifications/tools/list_changed``: the first
``tools/list`` must already carry the tools of the live plugin build, so stdio and
HTTP serving ask the app to learn the backends' plugin versions first (bounded).
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any

import anyio
import pytest
from mcp import Client

from tests.fakes.fake_app import FakeApp
from tests.fakes.fake_runtime import make_lab
from x64dbg_vm_gateway.config import HttpServerConfig
from x64dbg_vm_gateway.frontends import http_server, mcp_server

V110_TOOLS = {"GetServerInfo", "SetArtifactDir", "ProbeFile"}
ENV = {"GW_ADMIN": "a" * 24 + "-admin-token"}


class WarmApp(FakeApp):
    def __init__(self, *, fail: BaseException | None = None) -> None:
        super().__init__()
        self.order: list[str] = []
        self.warm_fail = fail
        self.warm_kwargs: list[dict[str, Any]] = []

    def warm_up(self, timeout_s: float | None = None) -> dict[str, Any]:
        self.order.append("warm_up")
        self.warm_kwargs.append({"timeout_s": timeout_s})
        if self.warm_fail is not None:
            raise self.warm_fail
        return {"profile": "lab", "backends": {}}

    def instructions(self) -> str:
        self.order.append("instructions")
        return super().instructions()


@contextlib.asynccontextmanager
async def closed_stdio() -> AsyncIterator[Any]:
    """stdio streams whose client hangs up at once (the server returns)."""
    to_server_send, to_server_recv = anyio.create_memory_object_stream[Any](1)
    from_server_send, _from_server_recv = anyio.create_memory_object_stream[Any](1)
    await to_server_send.aclose()
    yield to_server_recv, from_server_send


def test_run_stdio_warms_the_app_up_before_building_the_server(monkeypatch):
    app = WarmApp()
    monkeypatch.setattr(mcp_server, "stdio_server", closed_stdio)
    mcp_server.run_stdio(app)
    assert app.order[:2] == ["warm_up", "instructions"]
    # The front-end leaves the budget to the app (app.WARM_UP_TIMEOUT_S, its only definition).
    assert app.warm_kwargs == [{"timeout_s": None}]


def test_a_failing_warm_up_never_stops_serving(monkeypatch):
    app = WarmApp(fail=RuntimeError("boom"))
    monkeypatch.setattr(mcp_server, "stdio_server", closed_stdio)
    mcp_server.run_stdio(app)
    assert app.order[:2] == ["warm_up", "instructions"]


class NoWarmUpApp(FakeApp):
    """An app built against the contract before ``warm_up`` existed (``None`` hides the
    inherited method from both ``isinstance`` flavours: hasattr on 3.11, getattr_static
    on 3.12+)."""

    warm_up = None  # type: ignore[assignment]


def test_an_app_without_warm_up_is_served_as_before(monkeypatch):
    app = NoWarmUpApp()
    monkeypatch.setattr(mcp_server, "stdio_server", closed_stdio)
    mcp_server.run_stdio(app)  # no AttributeError


def test_warm_up_contract_is_checked_against_the_gateway(tmp_path):
    """Review: a renamed ``Gateway.warm_up`` must fail a test, not silently skip the warm-up.

    The contract is the front-end's ``WarmUpApp`` protocol (``app_api.GatewayApp`` is not
    this feature's to change), and the start-up budget is defined once, in ``app``: the
    front-end calls ``warm_up()`` without a budget of its own.
    """
    import inspect

    from x64dbg_vm_gateway import app as app_mod
    from x64dbg_vm_gateway import app_api

    lab = make_lab(tmp_path)
    try:
        assert isinstance(lab.gateway(), mcp_server.WarmUpApp)
    finally:
        lab.close()
    assert isinstance(FakeApp(), mcp_server.WarmUpApp)
    assert not isinstance(NoWarmUpApp(), mcp_server.WarmUpApp)
    default = inspect.signature(app_mod.Gateway.warm_up).parameters["timeout_s"].default
    assert default is app_mod.WARM_UP_TIMEOUT_S
    assert "WARM_UP_TIMEOUT_S" not in vars(mcp_server)
    assert "WARM_UP_TIMEOUT_S" not in vars(app_api)
    assert "warm_up" not in vars(app_api.GatewayApp)


def test_an_app_without_warm_up_is_logged_and_served(monkeypatch, caplog):
    app = NoWarmUpApp()
    monkeypatch.setattr(mcp_server, "stdio_server", closed_stdio)
    with caplog.at_level("WARNING", logger=mcp_server.__name__):
        mcp_server.run_stdio(app)
    assert any("warm_up" in r.getMessage() for r in caplog.records)


def test_serve_http_warms_the_app_up_before_serving(tmp_path, monkeypatch):
    app = WarmApp()
    ran: list[str] = []

    class FakeServer:
        def __init__(self, config: Any) -> None:
            pass

        def run(self) -> None:
            ran.append("run")
            app.order.append("uvicorn.run")

    monkeypatch.setattr(http_server.uvicorn, "Server", FakeServer)
    monkeypatch.setattr(http_server.uvicorn, "Config", lambda asgi, **kw: None)
    http_server.serve_http(app, HttpServerConfig(enabled=True, token_envs={"admin": "GW_ADMIN"}),
                           environ=ENV, jobs_root=tmp_path)
    assert ran == ["run"]
    assert app.order.index("warm_up") < app.order.index("instructions") < app.order.index("uvicorn.run")


def test_serve_http_refuses_a_bad_config_before_touching_the_vm(tmp_path):
    from x64dbg_vm_gateway.errors import ConfigError

    app = WarmApp()
    with pytest.raises(ConfigError):
        http_server.serve_http(app, HttpServerConfig(enabled=True, token_envs={"admin": "GW_UNSET"}),
                               environ={}, jobs_root=tmp_path)
    assert "warm_up" not in app.order


def test_tools_list_of_a_warmed_up_gateway_has_the_live_v110_tools(tmp_path):
    lab = make_lab(tmp_path, plugin_version="1.10")
    try:
        gw = lab.gateway()
        mcp_server.warm_up(gw)
        server = mcp_server.build_server(gw)

        async def main() -> Any:
            with anyio.fail_after(20):
                async with Client(server, mode="legacy", cache=None) as client:
                    return await client.list_tools()

        listed = {t.name for t in anyio.run(main).tools}
        assert V110_TOOLS <= listed
    finally:
        lab.close()
