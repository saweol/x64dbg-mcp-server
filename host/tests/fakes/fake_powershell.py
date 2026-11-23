"""Emulates the PowerShell one-liners the gateway runs in the guest, on top of FakeGuest.

Supported (exactly the commands transfer.py builds):

- ``(Get-FileHash -Algorithm SHA256 -LiteralPath '<src>').Hash | Out-File -Encoding ascii -FilePath '<dst>'``
- ``Compress-Archive -Path '<dir>\\*' -DestinationPath '<zip>' -Force``
- ``(Get-Item -LiteralPath '<src>' -Force).Length | Out-File -Encoding ascii -FilePath '<dst>'``

Install it as ``FakeGuest.on_run_program`` (or call it from a dispatcher). Hooks:

- ``gate``: a ``threading.Event`` the hash step waits for (tests of in-progress operations);
- ``hash_results``: queued overrides for the hash written by Get-FileHash ("real" = actual hash);
- ``exit_codes``: queued exit codes for the next commands.
"""

from __future__ import annotations

import hashlib
import io
import re
import threading
import zipfile
from pathlib import PureWindowsPath

from tests.fakes.fake_guest import FakeGuest

PS_PREFIX = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]
_HASH_RE = re.compile(r"-LiteralPath '([^']+)'\)\.Hash \| Out-File -Encoding ascii -FilePath '([^']+)'$")
_ZIP_RE = re.compile(r"^Compress-Archive -Path '([^']+)\\\*' -DestinationPath '([^']+)' -Force$")
_SIZE_RE = re.compile(
    r"^\(Get-Item -LiteralPath '([^']+)' -Force\)\.Length \| Out-File -Encoding ascii -FilePath '([^']+)'$")


def is_powershell(exe: str) -> bool:
    return exe.lower().endswith("\\powershell.exe")


class GuestPowerShell:
    def __init__(self, guest: FakeGuest) -> None:
        self.guest = guest
        self.hash_results: list[str | None] = []
        self.exit_codes: list[int] = []
        self.commands: list[str] = []
        self.gate: threading.Event | None = None
        self.gate_timeout_s = 10.0
        self.hashing = threading.Event()  # set when a hash command starts (before the gate)

    def _content(self, guest_path: str) -> bytes | None:
        try:
            return self.guest.read(guest_path)
        except KeyError:
            return None

    def __call__(self, exe: str, args: tuple, **_kw) -> int:
        assert is_powershell(exe), exe
        assert list(args[:5]) == PS_PREFIX and len(args) == 6, args
        cmd = args[5]
        self.commands.append(cmd)
        if m := _SIZE_RE.match(cmd):
            src, dst = m.groups()
            data = self._content(src)
            if data is None:
                return 1
            self.guest.write(dst, f"{len(data)}\r\n".encode("ascii"))
            return 0
        code = self.exit_codes.pop(0) if self.exit_codes else 0
        if m := _HASH_RE.search(cmd):
            self.hashing.set()
            if self.gate is not None:
                assert self.gate.wait(self.gate_timeout_s), "PowerShell gate never opened"
            src, dst = m.groups()
            override = self.hash_results.pop(0) if self.hash_results else "real"
            if override is None:
                return code
            data = self._content(src)
            if data is None:
                return 1
            digest = hashlib.sha256(data).hexdigest().upper() if override == "real" else override
            self.guest.write(dst, (digest + "\r\n").encode("ascii"))
            return code
        if m := _ZIP_RE.match(cmd):
            src_dir, dst = m.groups()
            if code != 0:
                return code
            prefix = str(PureWindowsPath(src_dir)).lower() + "\\"
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for key, data in sorted(self.guest.files.items()):
                    if key.startswith(prefix):
                        zf.writestr(key[len(prefix):].replace("\\", "/"), data)
            self.guest.write(dst, buf.getvalue())
            return code
        raise AssertionError(f"unexpected PowerShell command: {cmd}")
