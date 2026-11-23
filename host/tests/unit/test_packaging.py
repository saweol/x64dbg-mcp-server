"""Packaging and CI: the declared dependencies cover what the package imports, uv.lock
matches pyproject.toml, and the CI workflow runs the host suite on all three host OSes."""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

HOST = Path(__file__).resolve().parents[2]
REPO = HOST.parent
SRC = HOST / "src" / "x64dbg_vm_gateway"
CI = REPO / ".github" / "workflows" / "ci.yml"

#: import name -> distribution name, for third-party modules the package imports directly
DISTRIBUTION_OF = {"mcp": "mcp", "anyio": "anyio", "starlette": "starlette", "uvicorn": "uvicorn",
                   "jsonschema": "jsonschema"}
#: imported only behind a feature test (``aeszip`` extra)
OPTIONAL_IMPORTS = {"pyzipper"}


def _pyproject() -> dict:
    return tomllib.loads((HOST / "pyproject.toml").read_text(encoding="utf-8"))


def _requirements() -> dict[str, Requirement]:
    reqs = [Requirement(r) for r in _pyproject()["project"]["dependencies"]]
    return {canonicalize_name(r.name): r for r in reqs}


def _lock() -> dict:
    return tomllib.loads((HOST / "uv.lock").read_text(encoding="utf-8"))


def _locked_versions() -> dict[str, str]:
    return {canonicalize_name(p["name"]): p["version"] for p in _lock()["package"] if "version" in p}


def _third_party_imports() -> set[str]:
    names: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    return {n for n in names if n not in stdlib and n != "x64dbg_vm_gateway"}


def test_every_direct_import_is_a_declared_dependency():
    imported = _third_party_imports() - OPTIONAL_IMPORTS
    unknown = imported - set(DISTRIBUTION_OF)
    assert not unknown, f"map these imports to their distributions: {sorted(unknown)}"
    declared = set(_requirements())
    missing = {DISTRIBUTION_OF[m] for m in imported} - declared
    assert not missing, f"imported but not declared in [project].dependencies: {sorted(missing)}"


def test_mcp_is_pinned_to_the_2x_series():
    req = _requirements()["mcp"]
    assert req.specifier.contains("2.3.0") and not req.specifier.contains("2.2.9")
    assert not req.specifier.contains("3.0.0")


@pytest.mark.parametrize("name", sorted(set(DISTRIBUTION_OF.values())))
def test_direct_dependencies_have_a_lower_bound_the_lock_satisfies(name):
    req = _requirements()[name]
    assert any(s.operator in (">=", "~=", "==") for s in req.specifier), f"{name} needs a lower bound"
    locked = _locked_versions()[name]
    assert req.specifier.contains(Version(locked)), f"{name} {req.specifier} excludes locked {locked}"


def test_uv_lock_was_regenerated_for_the_declared_dependencies():
    (root,) = [p for p in _lock()["package"] if p["name"] == "x64dbg-vm-gateway"]
    requires = root["metadata"]["requires-dist"]
    locked = {(canonicalize_name(d["name"]), d.get("specifier", "")) for d in requires if "marker" not in d}
    declared = {(n, str(r.specifier)) for n, r in _requirements().items()}
    assert {(n, frozenset(s.split(","))) for n, s in locked} == \
        {(n, frozenset(s.split(","))) for n, s in declared}


# ── CI ──────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def ci_text() -> str:
    return CI.read_text(encoding="utf-8")


def test_ci_keeps_the_zig_jobs(ci_text):
    assert "zig build test" in ci_text
    assert "zig build -Doptimize=ReleaseSafe" in ci_text


def test_ci_runs_the_host_suite_on_three_host_oses(ci_text):
    host_job = ci_text[ci_text.index("\n  host:"):]
    for os_name in ("ubuntu-latest", "windows-latest", "macos-latest"):
        assert os_name in host_job
    assert "astral-sh/setup-uv" in host_job
    assert '"3.12"' in host_job or "'3.12'" in host_job or "3.12" in host_job
    assert "working-directory: host" in host_job
    for command in ("uv sync", "uv run pytest -q", "uv run ruff check src tests"):
        assert command in host_job, command
