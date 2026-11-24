"""The static-tool sync scripts under ``static/`` (Ghidra, radare2 / rizin / Cutter, the
shared core and the IDA script in ``static/ida``).

``static/tests`` sits outside this project's ``testpaths`` (the scripts run inside the
tools, not in the gateway), so the default ``uv run pytest`` runs it here in a
subprocess, like ``test_ida_sync.py`` does for ``static/ida/tests``."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HOST_DIR = Path(__file__).resolve().parents[2]
REPO = HOST_DIR.parent
STATIC_DIR = REPO / "static"


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
