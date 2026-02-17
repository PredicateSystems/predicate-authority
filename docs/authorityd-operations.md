# `predicate-authorityd` Operations Guide

This guide shows how to run the local sidecar daemon, provide a policy file, and verify health/status endpoints.

## 1) Sample `policy.json`

Create `examples/authorityd/policy.json`:

```json
{
  "rules": [
    {
      "name": "allow-orders-http-post",
      "effect": "allow",
      "principals": ["agent:orders-*"],
      "actions": ["http.post"],
      "resources": ["https://api.vendor.com/orders"],
      "required_labels": []
    },
    {
      "name": "deny-admin-delete",
      "effect": "deny",
      "principals": ["agent:*"],
      "actions": ["http.delete"],
      "resources": ["https://api.vendor.com/admin/*"],
      "required_labels": []
    }
  ]
}
```

## 2) Start the daemon

Run from repo root:

```bash
PYTHONPATH=. predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json \
  --policy-poll-interval-s 2.0 \
  --credential-store-file ./.predicate-authorityd/credentials.json
```

### Optional: enable control-plane shipping

To automatically ship proof events and usage records to
`predicate-authority-control-plane`, set:

```bash
export CONTROL_PLANE_URL="http://127.0.0.1:8080"
export CONTROL_PLANE_TENANT_ID="dev-tenant"
export CONTROL_PLANE_PROJECT_ID="dev-project"
export CONTROL_PLANE_AUTH_TOKEN="<bearer-token>"

PYTHONPATH=. predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json \
  --control-plane-enabled \
  --control-plane-fail-open
```

When enabled, daemon bootstrap auto-attaches `ControlPlaneTraceEmitter` so each
authority decision pushes:

- audit events -> `/v1/audit/events:batch`
- usage credits -> `/v1/metering/usage:batch`

Expected startup output:

```text
predicate-authorityd listening on http://127.0.0.1:8787 (mode=local_only)
```

## 3) Endpoint checks

### Health

```bash
curl -s http://127.0.0.1:8787/health | jq
```

Example response:

```json
{
  "status": "ok",
  "mode": "local_only",
  "uptime_s": 12
}
```

### Status

```bash
curl -s http://127.0.0.1:8787/status | jq
```

Example response:

```json
{
  "mode": "local_only",
  "policy_hot_reload_enabled": true,
  "revoked_principal_count": 0,
  "revoked_intent_count": 0,
  "revoked_mandate_count": 0,
  "proof_event_count": 0,
  "daemon_running": true,
  "policy_reload_count": 1,
  "policy_poll_error_count": 0,
  "last_policy_reload_epoch_s": 1700000000.0,
  "last_policy_poll_error": null
}
```

## 4) Verify policy hot-reload

1. Update `examples/authorityd/policy.json`.
2. Wait for at most `--policy-poll-interval-s`.
3. Check `/status` and confirm `policy_reload_count` increases.

## 5) Stop daemon

Press `Ctrl+C` in the daemon terminal.
