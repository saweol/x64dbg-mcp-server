"""E1: VmrunProvider.vm_process_ids() / instance_report() (duplicate VM instance detection)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes.fake_vm import FakeClock
from tests.fakes.fake_vmrun import FakeVmrunRunner
from x64dbg_vm_gateway.contracts import PowerState
from x64dbg_vm_gateway.errors import GatewayError, VmrunError
from x64dbg_vm_gateway.vmrun import NullProvider, VmrunProvider


def _provider(tmp_path: Path, pids: list[int] | Exception) -> tuple[VmrunProvider, FakeVmrunRunner, Path,
                                                                     list[str]]:
    vmdir = tmp_path / "vm"
    vmdir.mkdir(exist_ok=True)
    vmx = vmdir / "x.vmx"
    vmx.write_text("")
    asked: list[str] = []

    def finder(path: str) -> list[int]:
        asked.append(path)
        if isinstance(pids, Exception):
            raise pids
        return list(pids)

    r = FakeVmrunRunner()
    return VmrunProvider(r, str(vmx), clock=FakeClock(), process_finder=finder), r, vmx, asked


def _listed(r: FakeVmrunRunner, vmx: Path, yes: bool) -> None:
    r.queue("list", f"Total running VMs: {2 if yes else 1}\n/other/y.vmx\n" + (f"{vmx}\n" if yes else ""))


def test_vm_process_ids_uses_the_finder_with_this_vmx(tmp_path: Path) -> None:
    prov, r, vmx, asked = _provider(tmp_path, [4242, 1717, 4242])
    assert prov.vm_process_ids() == [1717, 4242]
    assert asked == [str(vmx)]
    assert r.calls == []  # no vmrun involved


def test_default_finder_is_the_platform_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from x64dbg_vm_gateway import platform as plat
    from x64dbg_vm_gateway import vmrun as vmrun_mod

    seen: list[str] = []
    monkeypatch.setattr(plat, "find_vmx_processes", lambda p, **kw: seen.append(p) or [7])
    monkeypatch.setattr(vmrun_mod, "find_vmx_processes", lambda p, **kw: seen.append(p) or [7], raising=False)
    prov = VmrunProvider(FakeVmrunRunner(), str(tmp_path / "a.vmx"), clock=FakeClock())
    assert prov.vm_process_ids() == [7]
    assert seen == [str(tmp_path / "a.vmx")]


def test_report_listed_with_one_process_is_clean(tmp_path: Path) -> None:
    prov, r, vmx, _ = _provider(tmp_path, [4242])
    _listed(r, vmx, True)
    assert prov.instance_report() == {"listed": True, "pids": [4242], "orphans": []}


def test_report_not_listed_and_no_process_is_clean(tmp_path: Path) -> None:
    prov, r, vmx, _ = _provider(tmp_path, [])
    _listed(r, vmx, False)
    assert prov.instance_report() == {"listed": False, "pids": [], "orphans": []}


def test_report_orphan_when_not_listed_but_running(tmp_path: Path) -> None:
    # E1: after revertToSnapshot the VM vanished from `vmrun list`, yet an old
    # vmware-vmx still ran the same .vmx; `vmrun start` would create a twin.
    prov, r, vmx, _ = _provider(tmp_path, [1717])
    _listed(r, vmx, False)
    assert prov.instance_report() == {"listed": False, "pids": [1717], "orphans": [1717]}


def test_report_duplicate_instances_are_all_orphans(tmp_path: Path) -> None:
    prov, r, vmx, _ = _provider(tmp_path, [4242, 1717])
    _listed(r, vmx, True)
    assert prov.instance_report() == {"listed": True, "pids": [1717, 4242], "orphans": [1717, 4242]}


def test_report_propagates_a_failed_scan(tmp_path: Path) -> None:
    prov, r, vmx, _ = _provider(tmp_path, GatewayError("cannot read /proc", stage="platform"))
    _listed(r, vmx, False)
    with pytest.raises(GatewayError):
        prov.instance_report()


def test_report_propagates_vmrun_list_errors(tmp_path: Path) -> None:
    prov, r, _, _ = _provider(tmp_path, [])
    r.queue("list", VmrunError("vmrun list failed"))
    with pytest.raises(VmrunError):
        prov.instance_report()


def test_power_state_semantics_unchanged_by_orphans(tmp_path: Path) -> None:
    # power_state still answers from `vmrun list` (+ suspend files) only.
    prov, r, vmx, asked = _provider(tmp_path, [1717])
    _listed(r, vmx, False)
    assert prov.power_state() is PowerState.OFF
    assert asked == []


def test_start_docstring_warns_about_running_instances() -> None:
    doc = " ".join((VmrunProvider.start.__doc__ or "").split())
    assert "instance_report" in doc and "pids" in doc
    rdoc = " ".join((VmrunProvider.instance_report.__doc__ or "").split())
    assert "must not call start()" in rdoc


def test_null_provider_reports_no_instance() -> None:
    n = NullProvider()
    assert n.vm_process_ids() == []
    assert n.instance_report() == {"listed": False, "pids": [], "orphans": []}
