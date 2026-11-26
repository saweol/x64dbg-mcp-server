"""``x64dbg-vm-gateway demo``: an installation self-test on the configured VM.

For each architecture (x64 and/or x32) the demo analyses the bundled benign sample
(``sample_bundle``: the E2E program built from tests/vm/samples/hello.zig) through the same
gateway calls an MCP client makes::

    analysis_start -> SetBreakpoint kernel32.Sleep -> run (until paused in kernel32, at most
    MAX_RUNS times; GetDebugState after each) -> GetCallStack -> analysis_collect
    -> analysis_finish(revert=true)

and reports every step with its duration, then PASS or FAIL with hints. A failing step after
the start cleans up the demo's own job (collect, discard if the collection stays partial, then
finish with revert), so the profile is free and the VM clean afterwards; another job is never
touched.

Where the sample comes from: ``staged_samples`` copies it into a fresh private directory below
``demo_root()`` (the per-user cache), and the CLI builds the demo's gateway with
``upload_roots`` = that directory only, for this process. The config file, and with it the
upload roots of every MCP client's gateway, is never changed.

Refusals (before the VM is touched): another gateway process serving the jobs root (the CLI's
jobs-root claim raises LOCK_TIMEOUT), a live or unreadable job of the profile (``check_idle``),
an endpoint profile, an architecture without a backend, missing bundled samples.

Long operations may answer ``{"state": "in_progress"}``: ``DemoRun.wait`` polls
``session_status()["operation"]`` until it is done (or failed, ``OperationFailed``).

Thread-safety: one DemoRun per thread; it calls a thread-safe GatewayApp.
"""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from .. import sample_bundle
from ..catalog import default_cache_dir
from ..config import ProfileConfig
from ..errors import ConfigError, GatewayError, StateViolation
from ..jobs import DISCARD_ACTOR
from ..platform import secure_dir
from ..proxy import sanitize_untrusted_text

log = logging.getLogger(__name__)

__all__ = ["ARCH_CHOICES", "DEMO_API", "MAX_RUNS", "DemoRun", "OperationFailed", "check_idle", "demo_archs",
           "demo_root", "format_result", "format_step", "staged_samples"]

DEMO_API = "kernel32.Sleep"  # hello.zig calls it five times, 500 ms each
MAX_RUNS = 4
RUN_TIMEOUT_MS = 60_000
POLL_S = 2.0
OP_TIMEOUT_S = 1800.0
ARCH_CHOICES = ("x64", "x32", "both")
TERMINAL = ("DONE", "FAILED")
_MODULE_RE = re.compile(r"^\s*currentModule:\s*(\S+)", re.MULTILINE)
_ADDRESS_RE = re.compile(r"^\s*currentAddress:\s*(0x[0-9A-Fa-f]+)", re.MULTILINE)
_STATUS_RE = re.compile(r"^\s*status:\s*(\w+)", re.MULTILINE)
_NOT_DEBUGGING_RE = re.compile(r"^\s*isDebugging:\s*false", re.MULTILINE | re.IGNORECASE)

#: what to check when a step fails (shown with the error's own hint)
STEP_HINTS = {
    "analysis_start": ("run `x64dbg-vm-gateway doctor`: it checks vmrun, the clean snapshot, VMware Tools, "
                       "the guest credentials and the debugger backends"),
    "SetBreakpoint": (f"the debugger did not accept a breakpoint on {DEMO_API}: check the plugin with "
                      "`x64dbg-vm-gateway status` (backend health, plugin version)"),
    "run": (f"the sample should stop in {DEMO_API} within {MAX_RUNS} runs: look at the guest screen "
            "(vm_screenshot) and at x64dbg's event settings (it may stop on other events first)"),
    "GetCallStack": ("the debugger did not return a call stack: check the plugin with "
                     "`x64dbg-vm-gateway status`"),
    "analysis_collect": ("the collection failed: see the errors above; `x64dbg-vm-gateway doctor` checks the "
                         "guest job directory and the host jobs root"),
    "analysis_finish": ("the revert failed: check the clean snapshot (`x64dbg-vm-gateway doctor`) and revert "
                        "the VM yourself if it still holds the sample"),
}


class OperationFailed(GatewayError):
    """A long operation that answered in_progress ended with an error (its error dict)."""

    def __init__(self, error: Mapping[str, Any] | None, op: str) -> None:
        err = dict(error or {})
        super().__init__(str(err.get("message") or f"{op} failed"), stage=op, hint=err.get("hint"),
                         next_tool=err.get("next_tool"), details=dict(err.get("details") or {}))
        self.code = str(err.get("code") or "OPERATION_FAILED")


def demo_root() -> Path:
    """Per-user work directory of the demo (below the gateway's cache directory)."""
    return default_cache_dir() / "demo"


def demo_archs(profile: ProfileConfig, requested: str | None) -> list[str]:
    """The architectures to test: ``requested`` (x64, x32, both), default every architecture the
    profile has a backend for. ConfigError when one of them has no backend."""
    have = [a for a in ("x64", "x32") if any(b.arch == a for b in profile.backends)]
    if requested is None:
        if not have:
            raise ConfigError(f"profile {profile.name} has no x64 or x32 backend", stage="demo")
        return have
    wanted = ["x64", "x32"] if requested == "both" else [requested]
    for arch in wanted:
        if arch not in have:
            raise ConfigError(f"profile {profile.name} has no {arch} backend, so the {arch} demo cannot run",
                              stage="demo", hint=f"use --arch {' or --arch '.join(have) or 'x64'}, or add an "
                                                 f"{arch} backend to profiles.{profile.name}.backends")
    return wanted


def check_idle(app: Any, profile: str | None) -> None:
    """Refuse while the profile has a live job (the demo reverts the VM) or an unreadable job dir."""
    listing = app.list_jobs(profile)
    name = listing.get("profile") if isinstance(listing, Mapping) else None
    for job in (listing.get("jobs") or []) if isinstance(listing, Mapping) else []:
        if job.get("state") not in TERMINAL:
            job_id, state = job.get("job_id"), job.get("state")
            raise StateViolation(
                f"profile {job.get('profile') or name} has job {job_id} in state {state}; the demo reverts "
                "the VM and would destroy its results",
                stage="demo", details={"job_id": job_id, "state": state},
                hint="finish it through the MCP tools (analysis_collect, analysis_finish), or discard it "
                     f"with `x64dbg-vm-gateway discard {job_id}` if its results do not matter")
    corrupt = listing.get("corrupt") if isinstance(listing, Mapping) else None
    if corrupt:
        first = corrupt[0] if isinstance(corrupt[0], Mapping) else {}
        raise StateViolation(
            f"the jobs root has an unreadable job directory ({first.get('job_id') or '?'}); it blocks new "
            "jobs until it is resolved", stage="demo",
            hint="see `x64dbg-vm-gateway jobs list`; restore its state.json or move the directory away")


@contextlib.contextmanager
def staged_samples(archs: Sequence[str], root: Path | None = None) -> Iterator[tuple[Path, dict[str, Path]]]:
    """A fresh private directory below ``root`` (default ``demo_root()``) holding a copy of the
    bundled sample of each architecture; removed on exit. ConfigError when the bundle lacks one."""
    missing = [sample_bundle.SAMPLE_FILES[a] for a in archs if sample_bundle.find_sample(a) is None]
    if missing:
        raise ConfigError(f"the bundled demo sample(s) {', '.join(missing)} are missing", stage="demo",
                          hint=sample_bundle.BUILD_HINT)
    base = root if root is not None else demo_root()
    base.mkdir(parents=True, exist_ok=True)
    secure_dir(base)
    folder = Path(tempfile.mkdtemp(prefix="run-", dir=base))  # 0700
    try:
        yield folder, {arch: sample_bundle.copy_sample(arch, folder) for arch in archs}
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _texts(res: Any) -> str:
    texts = res.get("texts") if isinstance(res, Mapping) else None
    return "\n".join(t for t in texts if isinstance(t, str)) if isinstance(texts, list) else ""


def _lines(text: str) -> list[str]:
    """The tool's own lines: without the untrusted wrapper and the gateway / state lines."""
    out = []
    for line in sanitize_untrusted_text(text).splitlines():
        line = re.sub(r"</?untrusted_guest_output>", "", line).strip()
        if line and not line.startswith(("[gateway]", "[state]")):
            out.append(line)
    return out


def _short(text: Any, limit: int = 200) -> str:
    """Guest text for one line of output: no control characters, the untrusted wrapper dropped."""
    clean = sanitize_untrusted_text(str(text), max_len=4 * limit)
    clean = re.sub(r"</?untrusted_guest_output>|\[gateway\][^\n]*|\[state\][^\n]*", " ", clean)
    clean = " ".join(clean.split())
    return clean if len(clean) <= limit else clean[: limit - 3] + "..."


class _StepFailed(Exception):
    def __init__(self, detail: str, error: dict[str, Any] | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.error = error


class DemoRun:
    """Runs the demo for one architecture against ``app`` (a GatewayApp with ``get_job`` and
    ``discard_job``). ``on_step(step)`` is called after each step (the CLI prints it)."""

    def __init__(self, app: Any, *, on_step: Callable[[dict[str, Any]], None] | None = None,
                 poll_s: float | None = None, op_timeout_s: float = OP_TIMEOUT_S,
                 sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self.app = app
        self.on_step = on_step
        self.poll_s = POLL_S if poll_s is None else poll_s
        self.op_timeout_s = op_timeout_s
        self.sleep = sleep
        self.monotonic = monotonic

    # ── long operations ─────────────────────────────────────────────
    def wait(self, result: Any, op: str) -> Any:
        """The final outcome of a long operation that may have answered in_progress."""
        if not (isinstance(result, Mapping) and result.get("state") == "in_progress"):
            return result
        op_id = result.get("op_id")
        deadline = self.monotonic() + self.op_timeout_s
        while self.monotonic() < deadline:
            self.sleep(self.poll_s)
            status = self.app.session_status()
            cur = status.get("operation") if isinstance(status, Mapping) else None
            if not isinstance(cur, Mapping) or cur.get("op_id") != op_id or cur.get("state") == "running":
                continue
            if cur.get("state") == "done":
                return cur.get("result")
            raise OperationFailed(cur.get("error"), op)
        raise OperationFailed({"code": "TIMEOUT", "message": f"{op} still in progress after "
                                                            f"{self.op_timeout_s:g} s",
                               "hint": "poll session_status (x64dbg-vm-gateway status) for its outcome"}, op)

    # ── steps ───────────────────────────────────────────────────────
    def _step(self, steps: list[dict[str, Any]], name: str, fn: Callable[[], str], *,
              cleanup: bool = False) -> bool:
        started = self.monotonic()
        entry: dict[str, Any] = {"step": name, "ok": True, "seconds": 0.0, "detail": ""}
        if cleanup:
            entry["cleanup"] = True
        try:
            entry["detail"] = fn()
        except _StepFailed as e:
            entry.update(ok=False, detail=e.detail)
            if e.error:
                entry["error"] = e.error
        except GatewayError as e:
            entry.update(ok=False, detail=f"{e.code}: {_short(e.message, 300)}", error=e.to_dict())
        except Exception as e:  # noqa: BLE001 - a bug must not skip the cleanup of the demo's job
            entry.update(ok=False, detail=f"unexpected {type(e).__name__} (run with --verbose for details)")
            log.debug("demo step %s failed", name, exc_info=True)
        entry["seconds"] = round(self.monotonic() - started, 3)
        steps.append(entry)
        if self.on_step is not None:
            self.on_step(entry)
        return bool(entry["ok"])

    def _call(self, tool: str, args: Mapping[str, Any] | None = None) -> str:
        res = self.app.call_mirrored(tool, dict(args or {}))
        text = _texts(res)
        if not isinstance(res, Mapping) or res.get("is_error"):
            raise _StepFailed(f"{tool} reported an error: {_short(text) or 'no text'}")
        return text

    def run(self, arch: str, sample: Path) -> dict[str, Any]:
        """The demo for ``arch`` with the staged ``sample``: ``{"arch", "ok", "sample", "job_id",
        "seconds", "failed_step", "steps", "hints"}``."""
        started = self.monotonic()
        steps: list[dict[str, Any]] = []
        state: dict[str, Any] = {"job_id": None, "sha256": None, "collected": False, "finished": False}

        def start() -> str:
            res = self.wait(self.app.analysis_start(str(sample), arch=arch), "analysis_start")
            res = res if isinstance(res, Mapping) else {}
            state["job_id"] = res.get("job_id")
            info = res.get("sample")
            state["sha256"] = info.get("sha256") if isinstance(info, Mapping) else None
            if res.get("state") != "ANALYZING" or not res.get("loaded"):
                raise _StepFailed(f"job {res.get('job_id')} is {res.get('state')}, "
                                  f"loaded={res.get('loaded')}")
            if not res.get("paused"):
                raise _StepFailed(f"job {res.get('job_id')}: the sample was loaded but the debugger did not "
                                  "report a pause (see its warnings)")
            return (f"job {res.get('job_id')}: backend {res.get('backend_id')} epoch {res.get('epoch')}, "
                    "paused at the system breakpoint")

        def breakpoint_() -> str:
            self._call("SetBreakpoint", {"target": DEMO_API})
            return DEMO_API

        def run_once(i: int) -> str:
            self._call("run", {"timeoutMs": RUN_TIMEOUT_MS})
            text = self._call("GetDebugState")
            if _NOT_DEBUGGING_RE.search(text):
                raise _StepFailed(f"the sample exited before it stopped in {DEMO_API}")
            module = _MODULE_RE.search(text)
            address = _ADDRESS_RE.search(text)
            status = _STATUS_RE.search(text)
            where = _short(module.group(1), 80) if module else "an unknown module"
            at = f" at {address.group(1)}" if address else ""
            detail = f"{(status.group(1) if status else 'stopped').lower()} in {where}{at}"
            state["in_kernel32"] = bool(module and module.group(1).lower().startswith("kernel32"))
            if not state["in_kernel32"] and i == MAX_RUNS:
                raise _StepFailed(f"{detail}; not in {DEMO_API} after {MAX_RUNS} runs")
            return detail

        def callstack() -> str:
            lines = _lines(self._call("GetCallStack"))
            if not lines:
                raise _StepFailed("GetCallStack returned no frames")
            return f"{len(lines)} line(s), first: {_short(lines[0], 100)}"

        def collect() -> str:
            res = self.wait(self.app.analysis_collect(state["job_id"]), "analysis_collect")
            res = res if isinstance(res, Mapping) else {}
            if res.get("state") != "COLLECTED" or res.get("partial"):
                errors = "; ".join(_short(e.get("message") or e.get("error") or "?", 120)
                                   for e in (res.get("errors") or []) if isinstance(e, Mapping))
                errors = errors or "see analysis_collect's errors"
                raise _StepFailed(f"collection is {res.get('state')} (partial): {errors}")
            state["collected"] = True
            return f"{res.get('file_count', 0)} file(s) collected, manifest {res.get('manifest_path')}"

        def finish() -> str:
            res = self.wait(self.app.analysis_finish(state["job_id"], revert=True), "analysis_finish")
            res = res if isinstance(res, Mapping) else {}
            if res.get("state") != "DONE" or not res.get("reverted"):
                raise _StepFailed(f"job is {res.get('state')}, reverted={res.get('reverted')}")
            state["finished"] = True
            return "job DONE, VM reverted to the clean snapshot"

        failed: str | None = None
        if not self._step(steps, "analysis_start", start):
            failed = "analysis_start"
            details = (steps[-1].get("error") or {}).get("details") or {}
            state["job_id"] = state["job_id"] or details.get("job_id")  # the gateway names the failed job
        elif not self._step(steps, "SetBreakpoint", breakpoint_):
            failed = "SetBreakpoint"
        else:
            for i in range(1, MAX_RUNS + 1):
                state["in_kernel32"] = False
                if not self._step(steps, f"run {i}/{MAX_RUNS}", lambda i=i: run_once(i)):
                    failed = "run"
                    break
                if state["in_kernel32"]:
                    break
            if failed is None and not self._step(steps, "GetCallStack", callstack):
                failed = "GetCallStack"
            if failed is None and not self._step(steps, "analysis_collect", collect):
                failed = "analysis_collect"
            if failed is None and not self._step(steps, "analysis_finish", finish):
                failed = "analysis_finish"
        if failed is not None and state["job_id"] and not state["finished"]:
            self._cleanup(steps, state)
        hints = self._hints(steps, failed)
        return {
            "arch": arch, "ok": failed is None,
            "sample": {"name": sample.name, "size": sample.stat().st_size if sample.exists() else None,
                       "sha256": state["sha256"]},
            "job_id": state["job_id"], "seconds": round(self.monotonic() - started, 3),
            "failed_step": failed, "steps": steps, "hints": hints,
        }

    def _cleanup(self, steps: list[dict[str, Any]], state: dict[str, Any]) -> None:
        """Leave the profile free and the VM clean: collect, discard the demo's own job if the
        collection stays partial, finish with revert. Only the job this run created."""
        job_id = state["job_id"]

        def job_state() -> str | None:
            try:
                view = self.app.get_job(job_id)
            except GatewayError:
                return None
            return view.get("state") if isinstance(view, Mapping) else None

        current = job_state()
        if current in TERMINAL or current is None:
            return  # a failed start: the job is FAILED; the next analysis_start reverts the VM
        if current in ("ANALYZING", "COLLECTED_PARTIAL", "COLLECTING"):
            def collect() -> str:
                res = self.wait(self.app.analysis_collect(job_id), "analysis_collect")
                return f"job {job_id} is {res.get('state') if isinstance(res, Mapping) else '?'}"

            self._step(steps, "cleanup: analysis_collect", collect, cleanup=True)
            current = job_state()
        if current not in ("COLLECTED", "DISCARDED"):
            def discard() -> str:
                self.app.discard_job(job_id, actor=DISCARD_ACTOR)
                return (f"job {job_id} (the bundled benign sample only) discarded: its collection did not "
                        "complete")

            self._step(steps, "cleanup: discard", discard, cleanup=True)

        def finish() -> str:
            res = self.wait(self.app.analysis_finish(job_id, revert=True), "analysis_finish")
            reverted = res.get("reverted") if isinstance(res, Mapping) else None
            return f"job {job_id} finished, VM reverted: {reverted}"

        self._step(steps, "cleanup: analysis_finish", finish, cleanup=True)

    @staticmethod
    def _hints(steps: Sequence[Mapping[str, Any]], failed: str | None) -> list[str]:
        hints: list[str] = []
        for step in steps:
            err = step.get("error")
            if not step.get("ok") and isinstance(err, Mapping) and err.get("hint"):
                hints.append(f"{step['step']}: {_short(err['hint'], 300)}")
        if failed is not None:
            hints.append(STEP_HINTS[failed])
        if any(s.get("cleanup") and not s.get("ok") for s in steps):
            hints.append("the cleanup failed: run `x64dbg-vm-gateway jobs list`; finish or discard the demo "
                         "job before the next analysis")
        return hints


# ── output ──────────────────────────────────────────────────────────
def format_step(step: Mapping[str, Any]) -> str:
    tag = " ok " if step["ok"] else "FAIL"
    return f"  [{tag}] {step['seconds']:7.1f} s  {step['step']:<26} {step.get('detail') or ''}".rstrip()


def format_arch(result: Mapping[str, Any]) -> str:
    if result["ok"]:
        return f"demo {result['arch']}: PASS in {result['seconds']:.1f} s (job {result['job_id']})"
    return f"demo {result['arch']}: FAIL at {result['failed_step']} after {result['seconds']:.1f} s"


def format_result(doc: Mapping[str, Any], *, streamed: bool = False) -> str:
    """The demo's human output; ``streamed``: the step lines were printed already."""
    lines: list[str] = []
    for res in doc["results"]:
        if not streamed:
            lines.append(f"demo {res['arch']}: {res['sample']['name']} on profile {doc['profile']}")
            lines.extend(format_step(s) for s in res["steps"])
            lines.append(format_arch(res))
    archs = ", ".join(r["arch"] for r in doc["results"])
    failed = [r for r in doc["results"] if not r["ok"]]
    if not failed:
        lines.append(f"demo: PASS ({archs})")
        return "\n".join(lines)
    where = ", ".join(f"{r['arch']} at {r['failed_step']}" for r in failed)
    lines.append(f"demo: FAIL ({where})")
    hints = [h for r in failed for h in r["hints"]]
    if hints:
        lines.append("hints:")
        lines.extend(f"  - {h}" for h in hints)
    return "\n".join(lines)
