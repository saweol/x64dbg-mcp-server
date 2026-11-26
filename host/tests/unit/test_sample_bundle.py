"""The demo samples bundled in the package (``data/samples/``, put there by
scripts/build-release.sh from tests/vm/samples/hello.zig)."""

from __future__ import annotations

import os
import stat
import zipfile
from importlib import resources
from pathlib import Path

import pytest

from x64dbg_vm_gateway import sample_bundle

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "vm" / "samples"


def make_samples(root: Path, archs: tuple[str, ...] = ("x64", "x32")) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for arch in archs:
        (root / sample_bundle.SAMPLE_FILES[arch]).write_bytes(b"MZ sample " + arch.encode())
    return root


def test_the_file_names_are_the_ones_build_sh_writes():
    build = (SAMPLES_DIR / "build.sh").read_text(encoding="utf-8")
    assert '--name "e2e_sample_$t"' in build and "for t in x86_64 x86" in build
    assert sample_bundle.SAMPLE_FILES == {"x64": "e2e_sample_x86_64.exe", "x32": "e2e_sample_x86.exe"}


def test_the_sample_source_calls_kernel32_sleep():
    """The demo breaks on kernel32.Sleep: the bundled program must call it."""
    source = (SAMPLES_DIR / "hello.zig").read_text(encoding="utf-8")
    assert 'extern "kernel32" fn Sleep(' in source and "Sleep(500)" in source


def test_default_root_is_the_package_data_directory():
    expected = resources.files("x64dbg_vm_gateway").joinpath("data").joinpath("samples")
    assert str(sample_bundle.bundle_root()) == str(expected)


def test_missing_and_found(tmp_path):
    assert sample_bundle.missing_files(tmp_path / "none") == list(sample_bundle.SAMPLE_FILES.values())
    root = make_samples(tmp_path / "s", archs=("x64",))
    assert sample_bundle.missing_files(root) == ["e2e_sample_x86.exe"]
    assert sample_bundle.find_sample("x64", root) is not None
    assert sample_bundle.find_sample("x32", root) is None
    with pytest.raises(ValueError):
        sample_bundle.find_sample("arm64", root)


def test_copy_sample_is_private_and_never_overwrites(tmp_path):
    root = make_samples(tmp_path / "s")
    dest = tmp_path / "d"
    dest.mkdir()
    copy = sample_bundle.copy_sample("x32", dest, root)
    assert copy == dest / "e2e_sample_x86.exe" and copy.read_bytes() == b"MZ sample x32"
    if os.name == "posix":
        assert stat.S_IMODE(copy.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        sample_bundle.copy_sample("x32", dest, root)
    with pytest.raises(FileNotFoundError):
        sample_bundle.copy_sample("x64", dest, tmp_path / "empty")


def test_samples_inside_a_zip_archive(tmp_path):
    archive = tmp_path / "pkg.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("data/samples/e2e_sample_x86_64.exe", b"MZ zipped")
    root = zipfile.Path(archive, "data/samples/")
    dest = tmp_path / "d"
    dest.mkdir()
    assert sample_bundle.copy_sample("x64", dest, root).read_bytes() == b"MZ zipped"


def test_the_build_hint_says_how_to_build_them():
    hint = sample_bundle.BUILD_HINT
    assert "build.sh" in hint and "build-release.sh" in hint and "Zig" in hint
