"""vm_inventory: the .vmx files ``setup`` offers (``vmrun list`` and the VMware inventory)."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath

from tests.fakes.fake_vmrun import FakeVmrunRunner
from x64dbg_vm_gateway import vm_inventory
from x64dbg_vm_gateway.contracts import VmrunResult
from x64dbg_vm_gateway.errors import VmrunError

INVENTORY = """\
.encoding = "UTF-8"
vmlist1.config = "/vms/win10/win10.vmx"
vmlist1.DisplayName = "Windows 10 x64"
vmlist1.ParentID = "0"
vmlist2.config = "folder0"
vmlist2.Type = "2"
vmlist2.DisplayName = "My Folder"
vmlist3.config = "/vms/old/old.VMX"
vmlist3.DisplayName = "old lab"
vmlist10.config = "/vms/ten/ten.vmx"
index0.field0.name = "guest"
"""


def test_parse_inventory_keeps_vmx_entries_in_order():
    assert vm_inventory.parse_inventory(INVENTORY) == [
        ("/vms/win10/win10.vmx", "Windows 10 x64"),
        ("/vms/old/old.VMX", "old lab"),
        ("/vms/ten/ten.vmx", None),
    ]


def test_parse_inventory_of_garbage_is_empty():
    assert vm_inventory.parse_inventory("not an inventory\n\x00\n= =\n") == []


def test_inventory_files_per_host_os():
    linux = vm_inventory.inventory_files(system="Linux", environ={"HOME": "/home/u"})
    assert [PurePosixPath(p) for p in linux] == [PurePosixPath("/home/u/.vmware/inventory.vmls")]
    mac = vm_inventory.inventory_files(system="Darwin", environ={"HOME": "/Users/u"})
    assert [PurePosixPath(p) for p in mac] == [
        PurePosixPath("/Users/u/Library/Application Support/VMware Fusion/vmInventory")]
    appdata = "C:\\Users\\u\\AppData\\Roaming"
    win = vm_inventory.inventory_files(system="Windows", environ={"APPDATA": appdata})
    assert [PureWindowsPath(str(p)) for p in win] == [
        PureWindowsPath("C:\\Users\\u\\AppData\\Roaming\\VMware\\inventory.vmls")]
    assert vm_inventory.inventory_files(system="Windows", environ={}) == []


def test_parse_vmrun_list():
    text = "Total running VMs: 2\n/vms/a/a.vmx\r\n\nD:\\VMs\\b\\b.vmx\n"
    assert vm_inventory.parse_vmrun_list(text) == ["/vms/a/a.vmx", "D:\\VMs\\b\\b.vmx"]


def test_running_vms_asks_vmrun_list_without_a_vmx():
    runner = FakeVmrunRunner()
    runner.queue("list", "Total running VMs: 1\n/vms/a/a.vmx\n")
    assert vm_inventory.running_vms(runner) == ["/vms/a/a.vmx"]
    (call,) = runner.calls
    assert call["command"] == "list" and call["vmx"] is False and call["guest"] is False


def test_running_vms_is_best_effort():
    runner = FakeVmrunRunner()
    runner.queue("list", VmrunError("vmrun failed"))
    assert vm_inventory.running_vms(runner) == []
    runner.queue("list", VmrunResult(0, "Total running VMs: 0\n", ""))
    assert vm_inventory.running_vms(runner) == []


def test_candidates_running_first_then_existing_inventory_entries(tmp_path):
    a, b, c = (tmp_path / n / f"{n}.vmx" for n in ("a", "b", "c"))
    for p in (a, b):
        p.parent.mkdir()
        p.write_text("", encoding="utf-8")
    found = vm_inventory.candidates(
        running=[str(b)],
        inventory=[(str(a), "VM a"), (str(b), "VM b"), (str(c), "gone"), (str(a), "duplicate")])
    assert [(Path(x.vmx), x.name, x.running) for x in found] == [(b, "VM b", True), (a, "VM a", False)]


def test_find_vms_reads_the_inventory_and_vmrun(tmp_path):
    vmx = tmp_path / "win10" / "win10.vmx"
    vmx.parent.mkdir()
    vmx.write_text("", encoding="utf-8")
    inv = tmp_path / "inventory.vmls"
    inv.write_text(f'vmlist1.config = "{vmx.as_posix()}"\nvmlist1.DisplayName = "lab"\n', encoding="utf-8")
    runner = FakeVmrunRunner()
    runner.queue("list", "Total running VMs: 0\n")
    found = vm_inventory.find_vms(runner, files=[inv, tmp_path / "missing.vmls"])
    assert [(Path(x.vmx), x.name, x.running) for x in found] == [(vmx, "lab", False)]
    assert vm_inventory.find_vms(None, files=[]) == []


def test_parse_inventory_skips_an_absurd_entry_index():
    """Review finding: int() of a 5000-digit index raised ValueError and stopped setup."""
    text = "vmlist" + "9" * 5000 + '.config = "/v/x.vmx"\nvmlist1.config = "/v/a.vmx"\n'
    assert vm_inventory.parse_inventory(text) == [("/v/a.vmx", None)]


def test_an_oversized_inventory_file_is_skipped(tmp_path, monkeypatch):
    vmx = tmp_path / "a.vmx"
    vmx.write_text("", encoding="utf-8")
    inv = tmp_path / "inventory.vmls"
    inv.write_text(f'vmlist1.config = "{vmx.as_posix()}"\n' + "#" * 200, encoding="utf-8")
    monkeypatch.setattr(vm_inventory, "MAX_INVENTORY_BYTES", 100)
    assert vm_inventory.find_vms(None, files=[inv]) == []
    monkeypatch.setattr(vm_inventory, "MAX_INVENTORY_BYTES", 10_000)
    assert [Path(c.vmx) for c in vm_inventory.find_vms(None, files=[inv])] == [vmx]


def test_parse_vmrun_list_takes_only_vmx_lines():
    text = ("Total running VMs: 1\nWarning: the libaio package is outdated\n/vms/a/a.VMX\n"
            "Error: something\n")
    assert vm_inventory.parse_vmrun_list(text) == ["/vms/a/a.VMX"]
