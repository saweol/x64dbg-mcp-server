"""Scriptable VmrunRunner fake: records every call, returns queued results."""

from __future__ import annotations

from collections.abc import Callable

from x64dbg_vm_gateway.contracts import VmrunResult


class FakeVmrunRunner:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self._responses: dict[str, list[VmrunResult | Exception]] = {}
        self.handler: Callable[[str, tuple[str, ...], bool], VmrunResult | None] | None = None

    def queue(self, command: str, result: VmrunResult | Exception | str) -> None:
        if isinstance(result, str):
            result = VmrunResult(0, result, "")
        self._responses.setdefault(command, []).append(result)

    def run(self, command: str, *params: str, guest: bool = False,
            timeout_s: float = 120.0, vmx: bool = True) -> VmrunResult:
        self.calls.append({"command": command, "params": params, "guest": guest,
                           "timeout_s": timeout_s, "vmx": vmx})
        q = self._responses.get(command)
        if q:
            r = q.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        if self.handler:
            r = self.handler(command, params, guest)
            if r is not None:
                return r
        return VmrunResult(0, "", "")

    def commands(self) -> list[str]:
        return [c["command"] for c in self.calls]
