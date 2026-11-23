"""Windows PowerShell 5.1 cannot serialise ``@($list)`` of a generic List (real-VM finding).

Measured on the spike VM (Windows 10, PowerShell 5.1, Korean locale), with
``$l = New-Object System.Collections.Generic.List[object]`` holding pscustomobjects:

- ``ConvertTo-Json -InputObject @($l)``  -> "인수 형식이 일치하지 않습니다" (Argument types do
  not match), also when empty;
- ``@($l) | ConvertTo-Json``             -> the same error;
- ``ConvertTo-Json -InputObject ($l.ToArray())`` -> works (``[]`` when empty).

``List[string]`` worked with ``-InputObject @($l)`` and as a hashtable property
(``$r.actions = @($l)``, provision.ps1), but every list is held to ``.ToArray()`` here.
The install_plugin backup listing and discover_x64dbg used the failing form.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from x64dbg_vm_gateway import platform, provision, transfer

GENERIC_LIST = re.compile(
    r"\$(\w+)\s*=\s*(?:New-Object\s+System\.Collections\.Generic\.List\[|"
    r"\[System\.Collections\.Generic\.List\[[^\]]*\]\]::new\()",
    re.IGNORECASE,
)
REPO = Path(__file__).resolve().parents[3]
PS1_FILES = [REPO / "guest" / "provision.ps1",
             REPO / "host" / "src" / "x64dbg_vm_gateway" / "data" / "guest" / "provision.ps1"]


def _scripts() -> list[tuple[str, str]]:
    out = []
    for mod in (provision, platform, transfer):
        for name, value in vars(mod).items():
            if isinstance(value, str) and "ConvertTo-Json" in value:
                out.append((f"{mod.__name__}.{name}", value))
    for path in PS1_FILES:
        out.append((str(path.relative_to(REPO)), path.read_text(encoding="utf-8-sig")))
    return out


@pytest.mark.parametrize(("name", "script"), _scripts(), ids=[n for n, _ in _scripts()])
def test_no_generic_list_is_wrapped_in_an_array_for_convertto_json(name, script):
    for var in GENERIC_LIST.findall(script):
        wrapped = r"@\(\s*\$" + re.escape(var) + r"\s*\)"
        for form in (r"ConvertTo-Json\s+(?:-InputObject\s+)?" + wrapped, wrapped + r"\s*\|\s*ConvertTo-Json"):
            bad = re.search(form, script, re.IGNORECASE)
            assert bad is None, f"{name}: use ${var}.ToArray() (PowerShell 5.1 fails on {bad.group(0)!r})"


def test_the_scripts_that_build_lists_are_covered():
    names = {n for n, _ in _scripts()}
    assert {"x64dbg_vm_gateway.provision._BACKUP_HASH_SCRIPT",
            "x64dbg_vm_gateway.provision._DISCOVER_SCRIPT", "guest/provision.ps1"} <= names


def test_the_pattern_catches_both_list_constructions():
    for decl in ("$r = New-Object System.Collections.Generic.List[object]",
                 "$r = [System.Collections.Generic.List[object]]::new()"):
        assert GENERIC_LIST.findall(decl + "\nConvertTo-Json -InputObject @($r)") == ["r"]


@pytest.mark.parametrize("use", ["ConvertTo-Json -InputObject @($r)", "ConvertTo-Json @($r)",
                                 "@($r) | ConvertTo-Json -Compress"])
def test_every_failing_spelling_is_rejected(use):
    script = "$r = New-Object System.Collections.Generic.List[object]\n" + use
    with pytest.raises(AssertionError):
        test_no_generic_list_is_wrapped_in_an_array_for_convertto_json("probe", script)
