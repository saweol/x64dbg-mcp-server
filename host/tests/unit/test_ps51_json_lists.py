"""Windows PowerShell 5.1 cannot serialise ``@($list)`` of a generic List (real-VM finding).

On the spike VM (Windows 10, PowerShell 5.1, Korean locale)
``ConvertTo-Json -InputObject @($rows)`` with ``$rows = New-Object
System.Collections.Generic.List[object]`` failed with "인수 형식이 일치하지 않습니다"
("Argument types do not match"), empty or not, while ``$rows.ToArray()`` worked. The
install_plugin backup listing and discover_x64dbg used the failing form.
"""

from __future__ import annotations

import re

import pytest

from x64dbg_vm_gateway import platform, provision, transfer

GENERIC_LIST = re.compile(r"\$(\w+)\s*=\s*New-Object\s+System\.Collections\.Generic\.List\[", re.IGNORECASE)


def _scripts() -> list[tuple[str, str]]:
    out = []
    for mod in (provision, platform, transfer):
        for name, value in vars(mod).items():
            if isinstance(value, str) and "ConvertTo-Json" in value:
                out.append((f"{mod.__name__}.{name}", value))
    return out


@pytest.mark.parametrize(("name", "script"), _scripts(), ids=[n for n, _ in _scripts()])
def test_no_generic_list_is_wrapped_in_an_array_for_convertto_json(name, script):
    for var in GENERIC_LIST.findall(script):
        bad = re.search(r"ConvertTo-Json\s+-InputObject\s+@\(\s*\$" + re.escape(var) + r"\s*\)", script,
                        re.IGNORECASE)
        assert bad is None, f"{name}: use ${var}.ToArray() (PowerShell 5.1 fails on @(${var}))"


def test_the_scripts_that_build_lists_are_covered():
    names = {n for n, _ in _scripts()}
    assert {"x64dbg_vm_gateway.provision._BACKUP_HASH_SCRIPT",
            "x64dbg_vm_gateway.provision._DISCOVER_SCRIPT"} <= names
