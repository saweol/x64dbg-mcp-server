import json
from importlib import resources

from x64dbg_vm_gateway import contracts, errors
from x64dbg_vm_gateway.contracts import GuestProcess, Secret


def test_secret_never_leaks_in_str_repr_format():
    s = Secret("hunter2")
    assert "hunter2" not in str(s) and "hunter2" not in repr(s) and "hunter2" not in f"{s}"
    assert s.reveal() == "hunter2"


def test_error_codes_are_unique():
    codes = [c.code for c in vars(errors).values()
             if isinstance(c, type) and issubclass(c, errors.GatewayError)]
    assert len(codes) == len(set(codes))


def test_error_to_dict_schema():
    e = errors.BackendRestarted("x", stage="call", hint="h", next_tool="session_status")
    assert set(e.to_dict()) == {"code", "message", "stage", "retryable", "hint", "next_tool", "details"}


def test_guest_process_image_name():
    assert GuestProcess(1, "u", '"C:\\x64dbg\\release\\x64\\x64dbg.exe" a b').image_name == "x64dbg.exe"
    assert GuestProcess(1, "u", "C:\\Windows\\notepad.exe").image_name == "notepad.exe"


def test_builtin_tool_catalog_shape():
    data = json.loads(resources.files("x64dbg_vm_gateway").joinpath("data/tools-v1.9.json").read_text())
    tools = data["tools"]
    assert len(tools) == 80 and sum(t["read_only"] for t in tools) == 36
    assert all(t["inputSchema"]["type"] == "object" for t in tools)


def test_fakes_satisfy_protocols(fake_guest, fake_vm):
    assert isinstance(fake_guest, contracts.GuestChannel)
    assert isinstance(fake_vm, contracts.VmProvider)


def test_fake_vmrun_runner_satisfies_protocol():
    from tests.fakes.fake_vmrun import FakeVmrunRunner

    r = FakeVmrunRunner()
    assert isinstance(r, contracts.VmrunRunner)
    r.queue("list", "Total running VMs: 0")
    assert r.run("list", vmx=False).stdout == "Total running VMs: 0"
