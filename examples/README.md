# Phase 1 Examples

These scripts show the intended local guard patterns for Phase 1:

- `browser_guard_example.py`: sdk-python style pre-action authorization hook using typed step evidence.
- `mcp_tool_guard_example.py`: guard for MCP tool execution.
- `outbound_http_guard_example.py`: guard for outbound HTTP actions.

Run with:

```bash
PYTHONPATH=. python examples/browser_guard_example.py
PYTHONPATH=. python examples/mcp_tool_guard_example.py
PYTHONPATH=. python examples/outbound_http_guard_example.py
```
