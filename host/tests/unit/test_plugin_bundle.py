"""The plugin build bundled in the package (``data/plugin/<arch>/``, put there by
scripts/build-release.sh): found through importlib.resources, laid out for
``provision.install_plugin`` in a temporary directory."""

from __future__ import annotations

import zipfile
from importlib import resources
from pathlib import Path

import pytest

from x64dbg_vm_gateway import plugin_bundle
from x64dbg_vm_gateway.provision import ARCH_SPECS


def make_bundle(root: Path, *, archs: tuple[str, ...] = ("x64", "x32"),
                version: str | None = "1.10.0") -> Path:
    for arch in archs:
        folder = root / arch
        folder.mkdir(parents=True, exist_ok=True)
        (folder / plugin_bundle.PLUGIN_FILES[arch]).write_bytes(b"MZ-" + arch.encode())
    if version is not None:
        root.mkdir(parents=True, exist_ok=True)
        (root / plugin_bundle.VERSION_FILE).write_text(version + "\n", encoding="utf-8")
    return root


def test_plugin_file_names_match_what_install_plugin_expects():
    assert set(plugin_bundle.PLUGIN_FILES) == set(ARCH_SPECS)
    for arch, spec in ARCH_SPECS.items():
        assert plugin_bundle.PLUGIN_FILES[arch] == spec.plugin


def test_default_root_is_the_package_data_directory():
    expected = resources.files("x64dbg_vm_gateway").joinpath("data").joinpath("plugin")
    assert str(plugin_bundle.bundle_root()) == str(expected)


def test_no_bundle_when_the_directory_is_missing(tmp_path):
    assert plugin_bundle.find_bundle(tmp_path / "nope") is None


def test_a_partial_bundle_is_no_bundle(tmp_path):
    root = make_bundle(tmp_path / "b", archs=("x64",))
    assert plugin_bundle.find_bundle(root) is None
    assert plugin_bundle.missing_files(root) == ["x32/x64dbg-MCP-Server.dp32"]


def test_bundle_with_version(tmp_path):
    bundle = plugin_bundle.find_bundle(make_bundle(tmp_path / "b"))
    assert bundle is not None and bundle.version == "1.10.0"
    assert bundle.describe() == {"source": "bundled", "version": "1.10.0"}


def test_bundle_without_version_file(tmp_path):
    bundle = plugin_bundle.find_bundle(make_bundle(tmp_path / "b", version=None))
    assert bundle is not None and bundle.version is None


def test_a_bogus_version_file_is_ignored(tmp_path):
    root = make_bundle(tmp_path / "b")
    (root / plugin_bundle.VERSION_FILE).write_text("1.10.0\x1b[2J and more\n" * 50, encoding="utf-8")
    bundle = plugin_bundle.find_bundle(root)
    assert bundle is not None and bundle.version is None


def test_find_bundle_uses_the_default_root(tmp_path, monkeypatch):
    root = make_bundle(tmp_path / "b")
    monkeypatch.setattr(plugin_bundle, "bundle_root", lambda: root)
    bundle = plugin_bundle.find_bundle()
    assert bundle is not None and bundle.version == "1.10.0"


def test_materialize_lays_the_build_out_like_zig_build_prefix(tmp_path):
    bundle = plugin_bundle.find_bundle(make_bundle(tmp_path / "b"))
    assert bundle is not None
    with plugin_bundle.materialize(bundle) as dist:
        assert (dist / "x64" / "plugins" / "x64dbg-MCP-Server.dp64").read_bytes() == b"MZ-x64"
        assert (dist / "x32" / "plugins" / "x64dbg-MCP-Server.dp32").read_bytes() == b"MZ-x32"
        kept = dist
    assert not kept.exists()  # a temporary copy: removed afterwards


def test_materialize_removes_the_copy_on_error(tmp_path):
    bundle = plugin_bundle.find_bundle(make_bundle(tmp_path / "b"))
    assert bundle is not None
    seen: list[Path] = []
    with pytest.raises(RuntimeError), plugin_bundle.materialize(bundle) as dist:
        seen.append(dist)
        raise RuntimeError("boom")
    assert seen and not seen[0].exists()


def test_bundle_inside_a_zip_archive(tmp_path):
    """importlib.resources may hand out zip entries (zipapp, zipped site-packages)."""
    archive = tmp_path / "pkg.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("data/plugin/x64/x64dbg-MCP-Server.dp64", b"MZ-zip64")
        zf.writestr("data/plugin/x32/x64dbg-MCP-Server.dp32", b"MZ-zip32")
        zf.writestr("data/plugin/VERSION", "1.10.0\n")
    root = zipfile.Path(archive, "data/plugin/")
    bundle = plugin_bundle.find_bundle(root)
    assert bundle is not None and bundle.version == "1.10.0"
    with plugin_bundle.materialize(bundle) as dist:
        assert (dist / "x64" / "plugins" / "x64dbg-MCP-Server.dp64").read_bytes() == b"MZ-zip64"
