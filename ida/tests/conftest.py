"""Test support for ida/x64dbg_sync.py without IDA.

Run from host/:  uv run pytest ../ida/tests -q

``ida/`` is put on ``sys.path`` so ``import x64dbg_sync`` works. The
``fake_ida`` fixture installs stub ``idaapi`` / ``ida_*`` / ``idautils``
modules into ``sys.modules`` (undone after each test) that record what the
script does to the "database".
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

IDA_DIR = Path(__file__).resolve().parent.parent
if str(IDA_DIR) not in sys.path:
    sys.path.insert(0, str(IDA_DIR))

SEG_NORM = 0
SEG_XTRN = 1


@dataclass
class FakeSegment:
    start_ea: int
    end_ea: int
    type: int = SEG_NORM


@dataclass
class FakeFunc:
    start_ea: int
    end_ea: int
    cmt: str | None = None
    rcmt: str | None = None


@dataclass
class FakeIdaState:
    imagebase: int = 0x140000000
    root_filename: str = "sample.exe"
    segments: list[FakeSegment] = field(default_factory=list)
    names: dict[int, str] = field(default_factory=dict)
    comments: dict[tuple[int, bool], str] = field(default_factory=dict)
    heads: list[int] = field(default_factory=list)
    funcs: list[FakeFunc] = field(default_factory=list)
    fail_set_name: set[int] = field(default_factory=set)
    set_name_calls: list[tuple[int, str, int]] = field(default_factory=list)
    ask_file_result: str | None = None
    ask_str_result: str | None = None
    ask_buttons_result: int = -1
    infos: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    registered: dict[str, Any] = field(default_factory=dict)
    unregistered: list[str] = field(default_factory=list)
    attached: list[tuple[str, str, int]] = field(default_factory=list)

    def seg_at(self, ea: int) -> FakeSegment | None:
        for s in self.segments:
            if s.start_ea <= ea < s.end_ea:
                return s
        return None


def _build_modules(st: FakeIdaState) -> dict[str, types.ModuleType]:
    idaapi = types.ModuleType("idaapi")
    idaapi.PLUGIN_KEEP = 2
    idaapi.PLUGIN_SKIP = 0

    class plugin_t:  # noqa: N801 - mirrors the IDA class name
        pass

    idaapi.plugin_t = plugin_t
    idaapi.get_imagebase = lambda: st.imagebase

    ida_name = types.ModuleType("ida_name")
    ida_name.SN_NOCHECK = 0x01
    ida_name.SN_NOWARN = 0x100
    ida_name.SN_FORCE = 0x800
    ida_name.SN_NODUMMY = 0x1000

    def set_name(ea: int, name: str, flags: int = 0) -> bool:
        st.set_name_calls.append((ea, name, flags))
        if ea in st.fail_set_name:
            return False
        st.names[ea] = name
        return True

    ida_name.set_name = set_name
    ida_name.get_name = lambda ea: st.names.get(ea, "")

    ida_bytes = types.ModuleType("ida_bytes")

    def set_cmt(ea: int, cmt: str, rpt: bool) -> bool:
        st.comments[(ea, bool(rpt))] = cmt
        return True

    ida_bytes.set_cmt = set_cmt
    ida_bytes.get_cmt = lambda ea, rpt: st.comments.get((ea, bool(rpt)))
    ida_bytes.is_mapped = lambda ea: st.seg_at(ea) is not None

    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_root_filename = lambda: st.root_filename

    ida_segment = types.ModuleType("ida_segment")
    ida_segment.SEG_NORM = SEG_NORM
    ida_segment.SEG_XTRN = SEG_XTRN
    ida_segment.getseg = st.seg_at

    ida_funcs = types.ModuleType("ida_funcs")

    def get_func(ea: int) -> FakeFunc | None:
        for f in st.funcs:
            if f.start_ea <= ea < f.end_ea:
                return f
        return None

    ida_funcs.get_func = get_func
    ida_funcs.get_func_cmt = lambda f, rpt: f.rcmt if rpt else f.cmt

    idautils = types.ModuleType("idautils")
    idautils.Names = lambda: iter(sorted(st.names.items()))
    idautils.Segments = lambda: iter([s.start_ea for s in st.segments])
    idautils.Heads = lambda start=None, end=None: iter(
        [h for h in sorted(st.heads) if (start is None or h >= start) and (end is None or h < end)]
    )
    idautils.Functions = lambda start=None, end=None: iter([f.start_ea for f in st.funcs])

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.SETMENU_APP = 1
    ida_kernwin.AST_ENABLE_ALWAYS = 0

    class action_handler_t:  # noqa: N801
        def __init__(self) -> None:
            pass

    class action_desc_t:  # noqa: N801
        def __init__(
            self,
            name: str,
            label: str,
            handler: Any,
            shortcut: Any = None,
            tooltip: str | None = None,
            icon: int = -1,
        ) -> None:
            self.name = name
            self.label = label
            self.handler = handler
            self.tooltip = tooltip

    def register_action(desc: action_desc_t) -> bool:
        if desc.name in st.registered:
            return False
        st.registered[desc.name] = desc
        return True

    def unregister_action(name: str) -> bool:
        st.unregistered.append(name)
        return st.registered.pop(name, None) is not None

    ida_kernwin.action_handler_t = action_handler_t
    ida_kernwin.action_desc_t = action_desc_t
    ida_kernwin.register_action = register_action
    ida_kernwin.unregister_action = unregister_action
    ida_kernwin.attach_action_to_menu = lambda path, name, flags: (
        st.attached.append((path, name, flags)) or True
    )
    ida_kernwin.ask_file = lambda for_saving, defval, prompt: st.ask_file_result
    ida_kernwin.ask_str = lambda defval, hist, prompt: st.ask_str_result
    ida_kernwin.ask_buttons = lambda yes, no, cancel, deflt, prompt: st.ask_buttons_result
    ida_kernwin.info = st.infos.append
    ida_kernwin.warning = st.warnings.append
    ida_kernwin.msg = lambda text: None

    return {
        "idaapi": idaapi,
        "ida_name": ida_name,
        "ida_bytes": ida_bytes,
        "ida_nalt": ida_nalt,
        "ida_segment": ida_segment,
        "ida_funcs": ida_funcs,
        "idautils": idautils,
        "ida_kernwin": ida_kernwin,
    }


@pytest.fixture
def fake_ida(monkeypatch: pytest.MonkeyPatch) -> FakeIdaState:
    st = FakeIdaState(
        segments=[FakeSegment(0x140001000, 0x140008000), FakeSegment(0x140008000, 0x140009000, SEG_XTRN)]
    )
    for name, mod in _build_modules(st).items():
        monkeypatch.setitem(sys.modules, name, mod)
    return st
