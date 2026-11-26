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
import hashlib
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
_HEX_RE = re.compile(r"\b0x([0-9A-Fa-f]+)\b")
#: x64dbg expression for the address the demo breakpoint stops at (EvalExpression)
SLEEP_EXPRESSION = "kernel32:Sleep"
#: GetDebugState status words of a stopped debuggee ("LOCKED": plugin builds before the fix)
_STOPPED = ("PAUSED", "LOCKED")
#: job states the cleanup collects (and discards when the collection stays incomplete)
_COLLECTABLE = ("ANALYZING", "COLLECTED_PARTIAL")
#: job states analysis_finish(revert=true) accepts
_FINISHABLE = ("COLLECTED", "DISCARDED", "REVERTING")
PROG = "x64dbg-vm-gateway"

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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _leftover_advice(job_id: str, state: str | None) -> tuple[str | None, str]:
    """(CLI command, what to do) for a demo job that is still live."""
    if state in ("COLLECTED", "DISCARDED", "REVERTING"):
        return None, ("finish it with analysis_finish(revert=true) through the MCP tools, which reverts "
                      "the VM to the clean snapshot")
    command = f"{PROG} discard {job_id}"
    return command, ("finish it through the MCP tools (analysis_collect, then analysis_finish), or run "
                     f"`{command}` and then analysis_finish(revert=true) through the MCP tools; it holds "
                     "only the bundled benign sample")


class DemoRun:
    """Runs the demo for one architecture against ``app`` (a GatewayApp with ``get_job`` and
    ``discard_job``). ``on_step(step)`` is called after each step (the CLI prints it).

    Own job: the demo cleans up only a job this run created. That is the job of a successful
    ``analysis_start`` answer, or a job found after a failed start (timeout, interrupt) through
    ``session_status().operation`` or ``list_jobs`` that holds this run's sample (sha256 and
    original name), belongs to ``profile`` and did not exist before the run started. A job an
    error names (``details.job_id`` of a refused start is the job that was already there) is never
    adopted."""

    def __init__(self, app: Any, *, profile: str | None = None,
                 on_step: Callable[[dict[str, Any]], None] | None = None,
                 poll_s: float | None = None, op_timeout_s: float = OP_TIMEOUT_S,
                 sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self.app = app
        self.profile = profile
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
            cur = self._operation()
            if not isinstance(cur, Mapping) or cur.get("op_id") != op_id or cur.get("state") == "running":
                continue
            if cur.get("state") == "done":
                return cur.get("result")
            raise OperationFailed(cur.get("error"), op)
        raise OperationFailed({"code": "TIMEOUT", "message": f"{op} still in progress after "
                                                            f"{self.op_timeout_s:g} s",
                               "hint": "poll session_status (x64dbg-vm-gateway status) for its outcome"}, op)

    def _operation(self) -> Mapping[str, Any] | None:
        status = self.app.session_status(self.profile)
        cur = status.get("operation") if isinstance(status, Mapping) else None
        return cur if isinstance(cur, Mapping) else None

    def _operation_running(self) -> str | None:
        """The name of a gateway operation that still runs, or None (also when it cannot be told)."""
        try:
            cur = self._operation()
        except GatewayError:
            return None
        return str(cur.get("op")) if cur is not None and cur.get("state") == "running" else None

    # ── own job ─────────────────────────────────────────────────────
    def _job_ids(self) -> set[str] | None:
        """The ids of the profile's jobs now (None when the store cannot be listed)."""
        try:
            listing = self.app.list_jobs(self.profile)
        except GatewayError:
            return None
        jobs = listing.get("jobs") if isinstance(listing, Mapping) else None
        if not isinstance(jobs, list):
            return None
        return {str(j.get("job_id")) for j in jobs if isinstance(j, Mapping)}

    def _is_own(self, view: Any, ident: Mapping[str, Any]) -> bool:
        if not isinstance(view, Mapping) or ident["before"] is None:
            return False
        sample = view.get("sample") if isinstance(view.get("sample"), Mapping) else {}
        return (str(view.get("job_id")) not in ident["before"]
                and (self.profile is None or view.get("profile") == self.profile)
                and sample.get("sha256") == ident["sha256"] and sample.get("original_name") == ident["name"])

    def _find_own(self, ident: Mapping[str, Any]) -> tuple[str | None, bool]:
        """(the job this run created, True if several candidates match). Every candidate is read
        back with get_job and must pass the identity check."""
        candidates: list[str] = []
        try:
            cur = self._operation()
        except GatewayError:
            cur = None
        if cur is not None and cur.get("op") == "analysis_start" and cur.get("job_id"):
            candidates.append(str(cur["job_id"]))
        try:
            listing = self.app.list_jobs(self.profile)
        except GatewayError:
            listing = None
        for view in (listing.get("jobs") or []) if isinstance(listing, Mapping) else []:
            if self._is_own(view, ident) and str(view.get("job_id")) not in candidates:
                candidates.append(str(view.get("job_id")))
        own: list[str] = []
        for job_id in candidates:
            try:
                view = self.app.get_job(job_id)
            except GatewayError:
                continue
            if self._is_own(view, ident):
                own.append(job_id)
        if len(own) > 1:
            return None, True
        return (own[0] if own else None), False

    def _job_state(self, job_id: str) -> str | None:
        try:
            view = self.app.get_job(job_id)
        except GatewayError:
            return None
        return str(view.get("state")) if isinstance(view, Mapping) and view.get("state") else None

    # ── steps ───────────────────────────────────────────────────────
    def _record(self, steps: list[dict[str, Any]], entry: dict[str, Any]) -> None:
        steps.append(entry)
        if self.on_step is not None:
            self.on_step(entry)

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
        self._record(steps, entry)
        return bool(entry["ok"])

    def _note(self, steps: list[dict[str, Any]], name: str, detail: str, *, ok: bool = False,
              cleanup: bool = True) -> None:
        entry: dict[str, Any] = {"step": name, "ok": ok, "seconds": 0.0, "detail": detail}
        if cleanup:
            entry["cleanup"] = True
        self._record(steps, entry)

    def _call(self, tool: str, args: Mapping[str, Any] | None = None) -> str:
        res = self.app.call_mirrored(tool, dict(args or {}))
        text = _texts(res)
        if not isinstance(res, Mapping) or res.get("is_error"):
            raise _StepFailed(f"{tool} reported an error: {_short(text) or 'no text'}")
        return text

    def _sequence(self, steps: list[dict[str, Any]], state: dict[str, Any], ident: Mapping[str, Any],
                  arch: str, sample: Path) -> str | None:
        """The demo steps; the name of the failed step, or None."""

        def start() -> str:
            res = self.wait(self.app.analysis_start(str(sample), profile=self.profile, arch=arch),
                            "analysis_start")
            res = res if isinstance(res, Mapping) else {}
            info = res.get("sample") if isinstance(res.get("sample"), Mapping) else {}
            job_id = res.get("job_id")
            if job_id and info.get("sha256") == ident["sha256"] and (
                    ident["before"] is None or str(job_id) not in ident["before"]):
                state["job_id"] = str(job_id)  # the job this start created
            elif job_id:
                raise _StepFailed(f"analysis_start answered with job {job_id}, which does not hold this "
                                  "demo's sample: it is left alone")
            if res.get("state") != "ANALYZING" or not res.get("loaded"):
                raise _StepFailed(f"job {job_id} is {res.get('state')}, loaded={res.get('loaded')}")
            if not res.get("paused"):
                raise _StepFailed(f"job {job_id}: the sample was loaded but the debugger did not report a "
                                  "pause (see its warnings)")
            return (f"job {job_id}: backend {res.get('backend_id')} epoch {res.get('epoch')}, paused at the "
                    "system breakpoint")

        def breakpoint_() -> str:
            self._call("SetBreakpoint", {"target": DEMO_API})
            try:  # where the stop must be: "0x{X} ({d})"; unknown when it cannot be evaluated
                lines = _lines(self._call("EvalExpression", {"expression": SLEEP_EXPRESSION}))
                found = _HEX_RE.search(lines[0]) if lines else None
                value = int(found.group(1), 16) if found else 0
            except (_StepFailed, GatewayError):
                value = 0
            state["sleep_address"] = value or None
            return f"{DEMO_API} at 0x{value:X}" if value else f"{DEMO_API} (address not resolved)"

        def run_once(i: int) -> str:
            self._call("run", {"timeoutMs": RUN_TIMEOUT_MS})
            text = self._call("GetDebugState")
            if _NOT_DEBUGGING_RE.search(text):
                raise _StepFailed(f"the sample exited before it stopped in {DEMO_API}")
            status = _STATUS_RE.search(text)
            word = status.group(1).upper() if status else "UNKNOWN"
            if word not in _STOPPED:
                raise _StepFailed(f"the debuggee is {word.lower()} after run(timeoutMs={RUN_TIMEOUT_MS}): "
                                  "it did not stop in time (not running it again)")
            module = _MODULE_RE.search(text)
            address = _ADDRESS_RE.search(text)
            where = _short(module.group(1), 80) if module else "an unknown module"
            at = int(address.group(1), 16) if address else None
            detail = f"{word.lower()} in {where}" + (f" at 0x{at:X}" if at is not None else "")
            in_kernel32 = bool(module and module.group(1).lower().startswith("kernel32"))
            expected = state.get("sleep_address")
            if in_kernel32 and expected is not None and at != expected:
                detail += f" (not kernel32.Sleep at 0x{expected:X})"
                in_kernel32 = False
            state["in_sleep"] = in_kernel32
            if not in_kernel32 and i == MAX_RUNS:
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
            return f"{res.get('file_count', 0)} file(s) collected, manifest {res.get('manifest_path')}"

        def finish() -> str:
            res = self.wait(self.app.analysis_finish(state["job_id"], revert=True), "analysis_finish")
            res = res if isinstance(res, Mapping) else {}
            if res.get("state") != "DONE" or not res.get("reverted"):
                raise _StepFailed(f"job is {res.get('state')}, reverted={res.get('reverted')}")
            state["finished"] = True
            return "job DONE, VM reverted to the clean snapshot"

        if not self._step(steps, "analysis_start", start):
            return "analysis_start"
        if not self._step(steps, "SetBreakpoint", breakpoint_):
            return "SetBreakpoint"
        for i in range(1, MAX_RUNS + 1):
            state["in_sleep"] = False
            if not self._step(steps, f"run {i}/{MAX_RUNS}", lambda i=i: run_once(i)):
                return "run"
            if state["in_sleep"]:
                break
        tail = (("GetCallStack", callstack), ("analysis_collect", collect), ("analysis_finish", finish))
        for name, fn in tail:
            if not self._step(steps, name, fn):
                return name
        return None

    def run(self, arch: str, sample: Path) -> dict[str, Any]:
        """The demo for ``arch`` with the staged ``sample``: ``{"arch", "ok", "sample", "job_id",
        "seconds", "failed_step", "steps", "hints", "leftover", "interrupted"}``. ``leftover`` (else
        None) names the demo job that is still live and what to do with it."""
        started = self.monotonic()
        steps: list[dict[str, Any]] = []
        ident = {"sha256": _sha256(sample), "name": sample.name, "before": self._job_ids()}
        state: dict[str, Any] = {"job_id": None, "finished": False, "sleep_address": None}
        interrupted: BaseException | None = None
        try:
            failed = self._sequence(steps, state, ident, arch, sample)
        except (KeyboardInterrupt, SystemExit) as e:
            interrupted, failed = e, "interrupted"
            self._note(steps, "interrupted", f"{type(e).__name__}: the demo was stopped", cleanup=False)
        leftover: dict[str, Any] | None = None
        if failed is not None and not state["finished"]:
            ambiguous = False
            try:
                if state["job_id"] is None:
                    state["job_id"], ambiguous = self._find_own(ident)
                if state["job_id"] is not None:
                    self._cleanup(steps, state["job_id"])
            except (KeyboardInterrupt, SystemExit) as e:
                interrupted = interrupted or e
                self._note(steps, "cleanup: interrupted", f"{type(e).__name__}: the cleanup was stopped")
            leftover = self._leftover(state["job_id"], ambiguous)
        return {
            "arch": arch, "ok": failed is None,
            "sample": {"name": sample.name, "size": sample.stat().st_size if sample.exists() else None,
                       "sha256": ident["sha256"]},
            "job_id": state["job_id"], "seconds": round(self.monotonic() - started, 3),
            "failed_step": failed, "steps": steps, "hints": self._hints(steps, failed, leftover),
            "leftover": leftover, "interrupted": interrupted is not None,
        }

    def _leftover(self, job_id: str | None, ambiguous: bool) -> dict[str, Any] | None:
        if job_id is None:
            if not ambiguous:
                return None
            return {"job_id": None, "state": None, "command": None,
                    "advice": f"more than one job holds this demo's sample: check `{PROG} jobs list`; the "
                              "demo touched none of them"}
        current = self._job_state(job_id)
        if current in TERMINAL:
            return None
        command, advice = _leftover_advice(job_id, current)
        running = self._operation_running()
        if running:
            advice = (f"the gateway operation {running} was still running for it when the demo stopped "
                      f"(it ends with this process); check `{PROG} status`, then {advice}")
        if current is None:
            advice = f"its state could not be read; check `{PROG} jobs show {job_id}`, then {advice}"
        return {"job_id": job_id, "state": current, "command": command, "advice": advice}

    def _cleanup(self, steps: list[dict[str, Any]], job_id: str) -> None:
        """Leave the profile free and the VM clean: collect, discard (only from ANALYZING or
        COLLECTED_PARTIAL, when the collection did not complete), finish with revert. Only for the
        job this run created; nothing while a gateway operation still runs."""
        running = self._operation_running()
        if running:
            self._note(steps, "cleanup: skipped",
                       f"the gateway operation {running} still runs for job {job_id}")
            return
        current = self._job_state(job_id)
        if current is None:
            self._note(steps, "cleanup: job state",
                       f"could not read the state of job {job_id}: not cleaned up")
            return
        if current in TERMINAL:
            return  # a failed start: the job is FAILED and the next analysis_start reverts the VM
        if current in _COLLECTABLE:
            def collect() -> str:
                res = self.wait(self.app.analysis_collect(job_id), "analysis_collect")
                return f"job {job_id} is {res.get('state') if isinstance(res, Mapping) else '?'}"

            self._step(steps, "cleanup: analysis_collect", collect, cleanup=True)
            current = self._job_state(job_id)
        if current in _COLLECTABLE:
            def discard() -> str:
                self.app.discard_job(job_id, actor=DISCARD_ACTOR)
                return (f"job {job_id} (the bundled benign sample only) discarded: its collection did not "
                        "complete")

            self._step(steps, "cleanup: discard", discard, cleanup=True)
            current = self._job_state(job_id)
        if current in _FINISHABLE:
            def finish() -> str:
                res = self.wait(self.app.analysis_finish(job_id, revert=True), "analysis_finish")
                reverted = res.get("reverted") if isinstance(res, Mapping) else None
                return f"job {job_id} finished, VM reverted: {reverted}"

            self._step(steps, "cleanup: analysis_finish", finish, cleanup=True)
        elif current not in TERMINAL:
            self._note(steps, "cleanup: not finished",
                       f"job {job_id} is {current}: the demo does not finish it")

    @staticmethod
    def _hints(steps: Sequence[Mapping[str, Any]], failed: str | None,
               leftover: Mapping[str, Any] | None) -> list[str]:
        hints: list[str] = []
        for step in steps:
            err = step.get("error")
            if not step.get("ok") and isinstance(err, Mapping) and err.get("hint"):
                hints.append(f"{step['step']}: {_short(err['hint'], 300)}")
        if failed is not None and failed in STEP_HINTS:
            hints.append(STEP_HINTS[failed])
        if leftover is not None:
            who = f"job {leftover['job_id']}" if leftover.get("job_id") else "a demo job"
            hints.append(f"{who} is still live: {leftover['advice']}")
        return hints


# ── output ──────────────────────────────────────────────────────────
def format_step(step: Mapping[str, Any]) -> str:
    tag = " ok " if step["ok"] else "FAIL"
    return f"  [{tag}] {step['seconds']:7.1f} s  {step['step']:<26} {step.get('detail') or ''}".rstrip()


def format_leftover(left: Mapping[str, Any]) -> str:
    if left.get("job_id") is None:
        return f"left: {left['advice']}"
    return f"left: job {left['job_id']} ({left.get('state') or 'state unknown'}): {left['advice']}"


def format_arch(result: Mapping[str, Any]) -> str:
    if result["ok"]:
        return f"demo {result['arch']}: PASS in {result['seconds']:.1f} s (job {result['job_id']})"
    how = "INTERRUPTED" if result.get("interrupted") else "FAIL"
    line = f"demo {result['arch']}: {how} at {result['failed_step']} after {result['seconds']:.1f} s"
    if result.get("leftover"):
        line += "\n" + format_leftover(result["leftover"])
    return line


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
    skipped = [a for a in doc.get("archs", []) if a not in {r["arch"] for r in doc["results"]}]
    if not failed and not skipped:
        lines.append(f"demo: PASS ({archs})")
        return "\n".join(lines)
    where = ", ".join(f"{r['arch']} at {r['failed_step']}" for r in failed)
    if skipped:
        where += ("; " if where else "") + f"not run: {', '.join(skipped)}"
    lines.append(f"demo: {'INTERRUPTED' if any(r.get('interrupted') for r in failed) else 'FAIL'} ({where})")
    hints = [h for r in failed for h in r["hints"]]
    if hints:
        lines.append("hints:")
        lines.extend(f"  - {h}" for h in hints)
    return "\n".join(lines)
