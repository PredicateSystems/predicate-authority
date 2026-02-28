# Examples

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

## `predicate-authorityd` operations example (Phase 2)

- `authorityd/policy.json`: sample sidecar policy file.
- `authorityd/daemon_endpoint_check.py`: checks `/health` and `/status` endpoints.

Start daemon:

```bash
predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json \
  --policy-poll-interval-s 2.0 \
  --credential-store-file ./.predicate-authorityd/credentials.json
```

Check endpoints:

```bash
PYTHONPATH=. python examples/authorityd/daemon_endpoint_check.py
```

## Okta compatibility example notes

For Okta OBO/token-exchange compatibility setup and troubleshooting, see:

- `examples/README_Okta.md`

## Entra compatibility example notes

For Entra OBO compatibility setup and troubleshooting, see:

- `examples/README_Entra.md`

## OIDC compatibility example notes

For generic OIDC token-exchange compatibility setup and fallback behavior, see:

- `examples/README_OIDC.md`
