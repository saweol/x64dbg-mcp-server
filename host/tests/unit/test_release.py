"""Release packaging: the wheel and the sdist carry the bundled plugin build when it is
present (hatch ``artifacts``: the binaries are gitignored), the build still works
without it, scripts/build-release.sh produces the release folder, and the release
workflow runs only for version tags with pinned actions.

The build tests run the real ``uv build`` (hatchling) on a copy of the project
inside a fake repository (``.git`` + the real root ``.gitignore``), so hatchling's
VCS exclusion is the one a checkout sees. The build-release.sh test replaces Zig
with a stub (``ZIG``) that writes fake plugin files."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

HOST = Path(__file__).resolve().parents[2]
REPO = HOST.parent
PACKAGE = "x64dbg_vm_gateway"
SCRIPT = REPO / "scripts" / "build-release.sh"
WORKFLOW = REPO / ".github" / "workflows" / "release.yml"
PLUGIN_ENTRIES = {"x64/plugins/x64dbg-MCP-Server.dp64", "x32/plugins/x64dbg-MCP-Server.dp32"}
BUNDLE_FILES = ("data/plugin/x64/x64dbg-MCP-Server.dp64", "data/plugin/x32/x64dbg-MCP-Server.dp32")
DATA_FILES = ("data/guest/provision.ps1", "data/tools-v1.10.json")
UV = shutil.which("uv")
BASH = shutil.which("bash")
needs_uv = pytest.mark.skipif(UV is None, reason="uv is not on PATH")
needs_bash = pytest.mark.skipif(BASH is None or sys.platform == "win32",
                                reason="build-release.sh needs bash on a POSIX host")


def _pyproject() -> dict:
    return tomllib.loads((HOST / "pyproject.toml").read_text(encoding="utf-8"))


def _plugin_version() -> str:
    match = re.search(r'^\s*\.version\s*=\s*"([^"]+)"', (REPO / "build.zig.zon").read_text(encoding="utf-8"),
                      re.MULTILINE)
    assert match
    return match.group(1)


def _copy_project(dst: Path, *, with_script: bool = False) -> Path:
    """A fake repository holding the host project (and optionally the release script); returns it."""
    (dst / ".git").mkdir(parents=True)
    shutil.copyfile(REPO / ".gitignore", dst / ".gitignore")
    host = dst / "host"
    host.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copyfile(HOST / name, host / name)
    shutil.copytree(HOST / "src", host / "src",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.dp32", "*.dp64", "VERSION"))
    if with_script:
        (dst / "scripts").mkdir()
        shutil.copy2(SCRIPT, dst / "scripts" / SCRIPT.name)
        shutil.copyfile(REPO / "build.zig.zon", dst / "build.zig.zon")
    return dst


def _add_bundle(host: Path) -> None:
    data = host / "src" / PACKAGE / "data" / "plugin"
    for rel in BUNDLE_FILES:
        target = host / "src" / PACKAGE / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"MZ fake " + rel.encode())
    (data / "VERSION").write_text("1.2.3\n", encoding="utf-8")


def _uv_build(host: Path, out: Path, *args: str) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT")}
    res = subprocess.run([UV, "build", "--quiet", "--out-dir", str(out), *args], cwd=host, env=env,
                         capture_output=True, text=True, timeout=300)
    assert res.returncode == 0, res.stderr


def _wheel_names(out: Path) -> set[str]:
    (wheel,) = out.glob("*.whl")
    with zipfile.ZipFile(wheel) as zf:
        return set(zf.namelist())


# ── hatch configuration ─────────────────────────────────────────────
def test_the_bundled_plugin_is_declared_as_build_artifacts():
    artifacts = _pyproject()["tool"]["hatch"]["build"]["artifacts"]
    assert any("data/plugin" in pattern for pattern in artifacts), artifacts


def test_gitignore_keeps_release_output_and_the_bundled_binaries_out_of_git():
    lines = {line.strip() for line in (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()}
    assert "release/" in lines or "/release/" in lines
    assert "host/src/x64dbg_vm_gateway/data/plugin/" in lines


@needs_uv
def test_wheel_and_sdist_carry_the_bundled_plugin(tmp_path):
    repo = _copy_project(tmp_path / "repo")
    _add_bundle(repo / "host")
    out = tmp_path / "out"
    _uv_build(repo / "host", out)  # like build-release.sh: the sdist, then the wheel built from it
    names = _wheel_names(out)
    for rel in (*BUNDLE_FILES, "data/plugin/VERSION", *DATA_FILES):
        assert f"{PACKAGE}/{rel}" in names, rel
    (sdist,) = out.glob("*.tar.gz")
    with tarfile.open(sdist) as tf:
        members = {m.name.split("/", 1)[1] for m in tf.getmembers() if "/" in m.name}
    for rel in BUNDLE_FILES:
        assert f"src/{PACKAGE}/{rel}" in members, rel


@needs_uv
def test_the_build_works_without_a_bundled_plugin(tmp_path):
    repo = _copy_project(tmp_path / "repo")
    out = tmp_path / "out"
    _uv_build(repo / "host", out, "--wheel")
    names = _wheel_names(out)
    assert not any("/data/plugin/" in n for n in names)
    for rel in DATA_FILES:
        assert f"{PACKAGE}/{rel}" in names, rel


@needs_uv
def test_control_without_artifacts_the_gitignore_drops_the_binaries(tmp_path):
    """Negative control: the copied .gitignore really excludes *.dp64 / *.dp32, so the
    artifacts setting is what puts them into the wheel."""
    repo = _copy_project(tmp_path / "repo")
    _add_bundle(repo / "host")
    pyproject = repo / "host" / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    stripped = re.sub(r"(?ms)^\[tool\.hatch\.build\]\n.*?(?=^\[)", "", text)
    assert stripped != text
    pyproject.write_text(stripped, encoding="utf-8")
    out = tmp_path / "out"
    _uv_build(repo / "host", out, "--wheel")
    names = _wheel_names(out)
    assert not any(n.endswith((".dp64", ".dp32")) for n in names)


# ── scripts/build-release.sh ────────────────────────────────────────
FAKE_ZIG = """#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "version" ]; then echo 0.14.0; exit 0; fi
echo "$*" >> "$FAKE_ZIG_LOG"
prefix=""
while [ $# -gt 0 ]; do
  case "$1" in --prefix) prefix="$2"; shift 2;; *) shift;; esac
done
mkdir -p "$prefix/x64/plugins" "$prefix/x32/plugins"
printf 'MZ fake x64 %s' "$FAKE_ZIG_TAG" > "$prefix/x64/plugins/x64dbg-MCP-Server.dp64"
printf 'MZ fake x32 %s' "$FAKE_ZIG_TAG" > "$prefix/x32/plugins/x64dbg-MCP-Server.dp32"
"""


def test_build_release_script_is_strict_bash():
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    if sys.platform != "win32":
        assert os.access(SCRIPT, os.X_OK)


def _run_script(repo: Path, cwd: Path, tmp: Path, *, tag: str = "1", zig: str | None = None
                ) -> subprocess.CompletedProcess[str]:
    fake = tmp / "bin" / "zig"
    if not fake.exists():
        fake.parent.mkdir(parents=True)
        fake.write_text(FAKE_ZIG, encoding="utf-8")
        fake.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT")}
    env.update(ZIG=zig or str(fake), FAKE_ZIG_LOG=str(tmp / "zig.log"), FAKE_ZIG_TAG=tag)
    return subprocess.run([BASH, str(repo / "scripts" / "build-release.sh")], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=600)


@needs_uv
@needs_bash
def test_build_release_writes_the_release_folder(tmp_path):
    repo = _copy_project(tmp_path / "repo", with_script=True)
    version = _plugin_version()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    res = _run_script(repo, elsewhere, tmp_path)  # works from any working directory
    assert res.returncode == 0, res.stdout + res.stderr
    assert "build -Doptimize=ReleaseSafe --prefix" in (tmp_path / "zig.log").read_text(encoding="utf-8")

    release = repo / "release"
    wheel_name = f"{PACKAGE}-0.1.0-py3-none-any.whl"
    plugin_zip = f"x64dbg-mcp-plugin-{version}.zip"
    assert sorted(p.name for p in release.iterdir()) == sorted(
        [wheel_name, f"{PACKAGE}-0.1.0.tar.gz", plugin_zip, "SHA256SUMS"])

    with zipfile.ZipFile(release / plugin_zip) as zf:
        assert set(zf.namelist()) == PLUGIN_ENTRIES
        assert zf.read("x64/plugins/x64dbg-MCP-Server.dp64") == b"MZ fake x64 1"
    with zipfile.ZipFile(release / wheel_name) as zf:
        assert zf.read(f"{PACKAGE}/data/plugin/x32/x64dbg-MCP-Server.dp32") == b"MZ fake x32 1"
        assert zf.read(f"{PACKAGE}/data/plugin/VERSION").decode().strip() == version
        for rel in DATA_FILES:
            assert f"{PACKAGE}/{rel}" in zf.namelist()

    sums = (release / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    listed = {}
    for line in sums:
        digest, name = line.split("  ", 1)
        listed[name] = digest
    assert set(listed) == {wheel_name, f"{PACKAGE}-0.1.0.tar.gz", plugin_zip}
    for name, digest in listed.items():
        assert hashlib.sha256((release / name).read_bytes()).hexdigest() == digest

    # idempotent: a second run replaces everything (stale files go, the new build is bundled)
    (release / "stale.txt").write_text("old", encoding="utf-8")
    res = _run_script(repo, repo, tmp_path, tag="2")
    assert res.returncode == 0, res.stdout + res.stderr
    assert sorted(p.name for p in release.iterdir()) == sorted([*listed, "SHA256SUMS"])
    with zipfile.ZipFile(release / wheel_name) as zf:
        assert zf.read(f"{PACKAGE}/data/plugin/x64/x64dbg-MCP-Server.dp64") == b"MZ fake x64 2"


@needs_bash
def test_build_release_fails_clearly_without_zig(tmp_path):
    repo = _copy_project(tmp_path / "repo", with_script=True)
    res = _run_script(repo, repo, tmp_path, zig=str(tmp_path / "no-such-zig"))
    assert res.returncode != 0
    assert "zig" in (res.stdout + res.stderr).lower()
    assert not (repo / "release").exists()


# ── .github/workflows/release.yml ───────────────────────────────────
@pytest.fixture(scope="module")
def workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _on_block(text: str) -> str:
    match = re.search(r"(?ms)^on:\n(.*?)(?=^\S)", text)
    assert match, "no top-level on: block"
    return match.group(1)


def test_release_workflow_runs_only_for_version_tags(workflow):
    on = _on_block(workflow)
    assert re.search(r"(?m)^  push:\n    tags:\n      - [\"']?v\*[\"']?\s*$", on), on
    for other in ("branches", "pull_request", "workflow_dispatch", "schedule"):
        assert other not in on


def test_release_workflow_pins_its_actions(workflow):
    uses = re.findall(r"uses:\s*(\S+)(.*)", workflow)
    assert uses
    for ref, comment in uses:
        name, _, version = ref.partition("@")
        assert re.fullmatch(r"[0-9a-f]{40}", version), f"{name} is not pinned to a commit: {ref}"
        assert re.search(r"#\s*v\d+\.\d+\.\d+", comment), f"{name}: say which release the commit is"
    names = {ref.partition("@")[0] for ref, _ in uses}
    expected = {"actions/checkout", "mlugg/setup-zig", "astral-sh/setup-uv", "softprops/action-gh-release"}
    assert expected <= names


def test_release_workflow_builds_and_uploads_the_release_folder(workflow):
    assert "runs-on: ubuntu-latest" in workflow
    assert re.search(r"version:\s*[\"']?0\.14\.0", workflow)
    assert "scripts/build-release.sh" in workflow
    assert re.search(r"files:\s*[\"']?release/\*", workflow)
    assert re.search(r"(?m)^\s*contents:\s*write\s*$", workflow)
