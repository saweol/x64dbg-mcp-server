"""Tests for the platform layer (plan 5.2 vmrun discovery, 6.3 host OS handling).

Every function is injectable, so Windows and macOS behaviour is exercised on Linux.
"""

from __future__ import annotations

import codecs
import os
import stat
import sys

import pytest

from x64dbg_vm_gateway import platform as plat
from x64dbg_vm_gateway.errors import ConfigError, VmrunNotFound

WIN_DEFAULT = "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe"
WIN_REG_KEY = "SOFTWARE\\WOW6432Node\\VMware, Inc.\\VMware Workstation"
MAC_DEFAULT = "/Applications/VMware Fusion.app/Contents/Library/vmrun"


def exists_in(*paths: str):
    allowed = set(paths)
    return lambda p: str(p) in allowed


def no_which(_name, path=None):
    return None


# ── find_vmrun ──────────────────────────────────────────────────────
def test_configured_path_wins_when_it_exists():
    got = plat.find_vmrun("/opt/vmware/bin/vmrun", system="Linux", env={},
                          which=lambda *_a, **_k: "/usr/bin/vmrun",
                          exists=exists_in("/opt/vmware/bin/vmrun", "/usr/bin/vmrun"))
    assert got == "/opt/vmware/bin/vmrun"


def test_configured_path_must_exist_no_fallback():
    with pytest.raises(VmrunNotFound) as ei:
        plat.find_vmrun("/opt/missing/vmrun", system="Linux", env={},
                        which=lambda *_a, **_k: "/usr/bin/vmrun", exists=exists_in("/usr/bin/vmrun"))
    assert ei.value.details["tried"] == ["/opt/missing/vmrun"]
    assert "/opt/missing/vmrun" in ei.value.message


def test_configured_path_expands_user():
    home = os.path.expanduser("~")
    got = plat.find_vmrun("~/bin/vmrun", system="Linux", env={}, which=no_which,
                          exists=exists_in(os.path.join(home, "bin", "vmrun")))
    assert got == os.path.join(home, "bin", "vmrun")


@pytest.mark.parametrize("configured", ["auto", "", "AUTO", None])
def test_auto_values(configured):
    got = plat.find_vmrun(configured, system="Linux", env={}, which=no_which,
                          exists=exists_in("/usr/bin/vmrun"))
    assert got == "/usr/bin/vmrun"


def test_linux_prefers_path_lookup():
    seen = {}

    def which(name, path=None):
        seen["args"] = (name, path)
        return "/usr/local/bin/vmrun"

    got = plat.find_vmrun("auto", system="Linux", env={"PATH": "/usr/local/bin:/usr/bin"}, which=which,
                          exists=exists_in("/usr/local/bin/vmrun", "/usr/bin/vmrun"))
    assert got == "/usr/local/bin/vmrun"
    assert seen["args"] == ("vmrun", "/usr/local/bin:/usr/bin")


def test_linux_falls_back_to_usr_bin():
    assert plat.find_vmrun(system="Linux", env={}, which=no_which,
                           exists=exists_in("/usr/bin/vmrun")) == "/usr/bin/vmrun"


def test_linux_not_found_lists_locations_tried():
    with pytest.raises(VmrunNotFound) as ei:
        plat.find_vmrun(system="Linux", env={}, which=no_which, exists=exists_in())
    tried = ei.value.details["tried"]
    assert tried[0].startswith("PATH") and "/usr/bin/vmrun" in tried
    assert "/usr/bin/vmrun" in ei.value.message
    assert ei.value.hint and "vmrun" in ei.value.hint


def test_windows_registry_install_path():
    calls = []

    def reg(key, value):
        calls.append((key, value))
        return "D:\\VMware\\Workstation\\" if key == WIN_REG_KEY and value == "InstallPath" else None

    got = plat.find_vmrun(system="Windows", env={}, which=no_which, registry_reader=reg,
                          exists=exists_in("D:\\VMware\\Workstation\\vmrun.exe", WIN_DEFAULT))
    assert got == "D:\\VMware\\Workstation\\vmrun.exe"
    assert calls[0] == (WIN_REG_KEY, "InstallPath")


def test_windows_default_path_when_registry_empty():
    got = plat.find_vmrun(system="Windows", env={}, which=no_which, registry_reader=lambda k, v: None,
                          exists=exists_in(WIN_DEFAULT))
    assert got == WIN_DEFAULT


def test_windows_registry_reader_failure_is_tolerated():
    def boom(_k, _v):
        raise OSError("access denied")

    got = plat.find_vmrun(system="Windows", env={}, which=no_which, registry_reader=boom,
                          exists=exists_in(WIN_DEFAULT))
    assert got == WIN_DEFAULT


def test_windows_registry_path_missing_on_disk_falls_through():
    got = plat.find_vmrun(system="Windows", env={}, which=no_which,
                          registry_reader=lambda k, v: "E:\\gone",
                          exists=exists_in(WIN_DEFAULT))
    assert got == WIN_DEFAULT


def test_windows_not_found_lists_registry_and_default():
    with pytest.raises(VmrunNotFound) as ei:
        plat.find_vmrun(system="Windows", env={}, which=no_which,
                        registry_reader=lambda k, v: "E:\\gone", exists=exists_in())
    tried = ei.value.details["tried"]
    assert "E:\\gone\\vmrun.exe" in tried
    assert WIN_DEFAULT in tried
    assert tried.index("E:\\gone\\vmrun.exe") < tried.index(WIN_DEFAULT)


def test_windows_default_registry_reader_unavailable_off_windows():
    # without an injected reader on a non-Windows interpreter, the registry step is skipped quietly
    with pytest.raises(VmrunNotFound):
        plat.find_vmrun(system="Windows", env={}, which=no_which, exists=exists_in())


def test_macos_fusion_bundle_path():
    got = plat.find_vmrun(system="Darwin", env={}, which=no_which, exists=exists_in(MAC_DEFAULT))
    assert got == MAC_DEFAULT


def test_macos_not_found():
    with pytest.raises(VmrunNotFound) as ei:
        plat.find_vmrun(system="Darwin", env={}, which=no_which, exists=exists_in())
    assert MAC_DEFAULT in ei.value.details["tried"]


# ── vmrun_type ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("configured", "system", "expected"),
    [
        ("auto", "Darwin", "fusion"),
        ("auto", "Linux", "ws"),
        ("auto", "Windows", "ws"),
        ("ws", "Darwin", "ws"),
        ("fusion", "Linux", "fusion"),
    ],
)
def test_vmrun_type(configured, system, expected):
    assert plat.vmrun_type(configured, system) == expected


def test_vmrun_type_invalid():
    with pytest.raises(ConfigError):
        plat.vmrun_type("player", "Linux")


# ── decode_output ───────────────────────────────────────────────────
def test_decode_utf8_on_posix_with_replacement():
    assert plat.decode_output("한글 ok".encode(), "Linux") == "한글 ok"
    assert plat.decode_output(b"bad \xff byte", "Darwin") == "bad \ufffd byte"


def test_decode_windows_falls_back_to_cp437_without_oem_or_mbcs():
    def lookup(name):
        if name in ("oem", "mbcs"):
            raise LookupError(name)
        return codecs.lookup(name)

    assert plat.decode_output(b"caf\x82", "Windows", lookup=lookup) == "café"


def test_decode_windows_prefers_oem_codec():
    def lookup(name):
        if name == "oem":
            return codecs.lookup("cp949")  # e.g. a Korean console code page
        return codecs.lookup(name)

    assert plat.decode_output("한글".encode("cp949"), "Windows", lookup=lookup) == "한글"


def test_decode_windows_uses_mbcs_when_oem_missing():
    used = []

    def lookup(name):
        used.append(name)
        if name == "oem":
            raise LookupError(name)
        if name == "mbcs":
            return codecs.lookup("cp1252")
        return codecs.lookup(name)

    assert plat.decode_output(b"\x80", "Windows", lookup=lookup) == "\u20ac"
    assert used[:2] == ["oem", "mbcs"]


def test_decode_never_raises():
    assert isinstance(plat.decode_output(bytes(range(256)), "Windows"), str)
    assert isinstance(plat.decode_output(bytes(range(256)), "Linux"), str)


# ── subprocess_kwargs ───────────────────────────────────────────────
def test_subprocess_kwargs_windows_hides_console():
    assert plat.subprocess_kwargs("Windows") == {"creationflags": 0x08000000}


@pytest.mark.parametrize("system", ["Linux", "Darwin"])
def test_subprocess_kwargs_posix_empty(system):
    assert plat.subprocess_kwargs(system) == {}


# ── secure_dir / secure_file ────────────────────────────────────────
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_secure_dir_and_file_posix(tmp_path):
    d = tmp_path / "d"
    d.mkdir(mode=0o777)
    f = d / "f"
    f.write_bytes(b"x")
    os.chmod(f, 0o755)  # noqa: S103 - deliberately loose so the test can see it tightened
    assert plat.secure_dir(d) is True
    assert plat.secure_file(f) is True
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_secure_noop_on_windows(tmp_path):
    calls = []
    assert plat.secure_dir(tmp_path, system="Windows", chmod=lambda *a: calls.append(a)) is False
    assert plat.secure_file(tmp_path / "x", system="Windows", chmod=lambda *a: calls.append(a)) is False
    assert calls == []


def test_secure_uses_injected_chmod_on_posix(tmp_path):
    calls = []
    assert plat.secure_dir(tmp_path, system="Darwin", chmod=lambda p, m: calls.append((str(p), m))) is True
    assert calls == [(str(tmp_path), 0o700)]
