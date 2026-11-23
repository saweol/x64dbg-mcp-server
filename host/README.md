# x64dbg-vm-gateway

Host-side MCP gateway for the x64dbg-MCP plugin. Design: `../docs/VM_ORCHESTRATION_PLAN.md`.

```console
uv sync
uv run pytest            # unit tests (no VM)
uv run pytest -m vm      # real-VM tests (needs the spike VM + env vars)
```
