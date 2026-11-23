"""Older plugin builds report a stopped target as "status: LOCKED" (x64dbg holds its run lock
while the debuggee is stopped; measured on the spike VM). The loop rules must tell the AI that
LOCKED means stopped, or it waits for a PAUSED that never comes."""

from __future__ import annotations

from x64dbg_vm_gateway.app import LOOP_RULES


def test_loop_rules_explain_the_locked_status():
    rule = next(line for line in LOOP_RULES.splitlines() if "LOCKED" in line)
    assert "GetDebugState" in rule and "PAUSED" in rule and "stopped" in rule
