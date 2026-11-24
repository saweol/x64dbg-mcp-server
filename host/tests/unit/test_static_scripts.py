"""The static-tool sync scripts under ``static/`` (Ghidra, radare2 / rizin / Cutter, the
shared core and the IDA script in ``static/ida``) and their copies inside the package
(``data/static``, ``static_scripts``).

``static/tests`` sits outside this project's ``testpaths`` (the scripts run inside the
tools, not in the gateway), so the default ``uv run pytest`` runs it here in a
subprocess, like ``test_ida_sync.py`` does for ``static/ida/tests``."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from x64dbg_vm_gateway import static_scripts, static_tools
from x64dbg_vm_gateway.errors import InvalidArgument

HOST_DIR = Path(__file__).resolve().parents[2]
REPO = HOST_DIR.parent
STATIC_DIR = REPO / "static"
PACKAGED_DIR = HOST_DIR / "src" / "x64dbg_vm_gateway" / "data" / "static"


def _run_suite(path: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(path), "-q", "-p", "no:cacheprovider"],
        cwd=HOST_DIR, capture_output=True, text=True, timeout=50, env=env, check=False,
    )


def test_static_script_suite_passes() -> None:
    out = _run_suite(STATIC_DIR / "tests")
    assert out.returncode == 0, out.stdout[-4000:] + out.stderr[-2000:]
    assert " passed" in out.stdout and "failed" not in out.stdout


def test_the_ida_script_lives_with_the_other_static_scripts() -> None:
    assert (STATIC_DIR / "ida" / "x64dbg_sync.py").is_file()
    assert (STATIC_DIR / "ida" / "tests").is_dir()
    assert not (REPO / "ida").exists(), "the IDA script moved to static/ida"


# ── packaged copies (data/static) ───────────────────────────────────
def _repo_scripts() -> set[str]:
    return {p.relative_to(STATIC_DIR).as_posix() for p in STATIC_DIR.glob("*/*.py")
            if p.parent.name != "tests"}


def test_the_package_lists_every_repository_script() -> None:
    assert set(static_scripts.SCRIPT_FILES) == _repo_scripts() == {
        "common/x64dbg_sync_core.py", "ida/x64dbg_sync.py", "ghidra/x64dbg_sync_ghidra.py",
        "radare2/x64dbg_sync_r2.py"}


def test_packaged_scripts_are_byte_identical_to_the_repository_scripts() -> None:
    packaged = {p.relative_to(PACKAGED_DIR).as_posix() for p in PACKAGED_DIR.rglob("*") if p.is_file()
                and "__pycache__" not in p.parts}
    assert packaged == set(static_scripts.SCRIPT_FILES), "copy static/<tool>/*.py into data/static"
    for rel in static_scripts.SCRIPT_FILES:
        assert (PACKAGED_DIR / rel).read_bytes() == (STATIC_DIR / rel).read_bytes(), (
            f"data/static/{rel} differs from static/{rel}: copy it again")
        assert static_scripts.scripts_root().joinpath(rel).read_bytes() == (STATIC_DIR / rel).read_bytes()


def test_every_tool_names_a_packaged_sync_script() -> None:
    for tool in static_tools.TOOLS.values():
        rel = static_scripts.relative_path(tool.sync_script)
        assert rel in static_scripts.SCRIPT_FILES, tool.id
        assert static_scripts.packaged(tool.id).is_file()
    rel = static_scripts.relative_path("static/ghidra/x64dbg_sync_ghidra.py")
    assert rel == "ghidra/x64dbg_sync_ghidra.py"
    with pytest.raises(ValueError):
        static_scripts.relative_path("ida/x64dbg_sync.py")


def test_a_packaged_script_finds_the_core_in_the_package_layout(monkeypatch) -> None:
    monkeypatch.setattr(sys, "dont_write_bytecode", True)  # no __pycache__ inside the package source
    script = PACKAGED_DIR / "ghidra" / "x64dbg_sync_ghidra.py"
    spec = importlib.util.spec_from_file_location("packaged_ghidra_under_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert Path(module.core.__file__).resolve() == (PACKAGED_DIR / "common" / "x64dbg_sync_core.py").resolve()


def test_installed_path_is_a_real_directory_for_a_normal_installation() -> None:
    root = static_scripts.installed_root()
    assert root is not None and root.is_dir() and (root / "ida" / "x64dbg_sync.py").is_file()


# ── copy_to ─────────────────────────────────────────────────────────
def test_copy_to_writes_the_layout_into_a_new_directory(tmp_path) -> None:
    dest = tmp_path / "out" / "scripts"
    copied = static_scripts.copy_to(dest)
    assert copied == list(static_scripts.SCRIPT_FILES)
    for rel in static_scripts.SCRIPT_FILES:
        assert (dest / rel).read_bytes() == (STATIC_DIR / rel).read_bytes()


def test_copy_to_refuses_to_overwrite_and_writes_nothing(tmp_path) -> None:
    dest = tmp_path / "scripts"
    (dest / "radare2").mkdir(parents=True)
    (dest / "radare2" / "x64dbg_sync_r2.py").write_text("mine\n", encoding="utf-8")
    with pytest.raises(InvalidArgument) as ei:
        static_scripts.copy_to(dest)
    assert "radare2/x64dbg_sync_r2.py" in ei.value.message and "--force" in (ei.value.hint or "")
    assert (dest / "radare2" / "x64dbg_sync_r2.py").read_text(encoding="utf-8") == "mine\n"
    assert not (dest / "ida").exists() and not (dest / "common").exists()


def test_copy_to_with_force_replaces_the_files(tmp_path) -> None:
    dest = tmp_path / "scripts"
    static_scripts.copy_to(dest)
    (dest / "ida" / "x64dbg_sync.py").write_text("old\n", encoding="utf-8")
    static_scripts.copy_to(dest, force=True)
    ida = Path("ida") / "x64dbg_sync.py"
    assert (dest / ida).read_bytes() == (STATIC_DIR / ida).read_bytes()
    assert sorted(p.name for p in (dest / "ida").iterdir()) == ["x64dbg_sync.py"]  # no temp files left


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_copy_to_with_force_replaces_a_symlink_instead_of_writing_through_it(tmp_path) -> None:
    dest = tmp_path / "scripts"
    (dest / "ida").mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n", encoding="utf-8")
    (dest / "ida" / "x64dbg_sync.py").symlink_to(victim)
    with pytest.raises(InvalidArgument):
        static_scripts.copy_to(dest)  # a symlink counts as an existing file
    static_scripts.copy_to(dest, force=True)
    assert victim.read_text(encoding="utf-8") == "keep\n"
    assert not (dest / "ida" / "x64dbg_sync.py").is_symlink()


def test_copy_to_refuses_a_file_as_destination(tmp_path) -> None:
    target = tmp_path / "file"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(InvalidArgument):
        static_scripts.copy_to(target)
