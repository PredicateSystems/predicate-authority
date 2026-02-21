# `predicate-authorityd` Operations Guide

This guide shows how to run the local sidecar daemon, provide a policy file, and verify health/status endpoints.

---

## Sidecar Installation

The sidecar (`predicate-authorityd`) is a lightweight Rust binary that handles policy evaluation and mandate signing.

### Option A: Install via pip (recommended for Python users)

```bash
# Install SDK with sidecar extra - downloads binary automatically
pip install predicate-authority[sidecar]

# Or manually trigger download after installing core SDK
pip install predicate-authority
predicate-download-sidecar
```

Binary location after install:
- macOS: `~/Library/Application Support/predicate-authority/bin/predicate-authorityd`
- Linux: `~/.local/share/predicate-authority/bin/predicate-authorityd`
- Windows: `%LOCALAPPDATA%/predicate-authority/bin/predicate-authorityd.exe`

### Option B: Download binary directly

Download pre-built binaries from [GitHub Releases](https://github.com/PredicateSystems/predicate-authority-sidecar/releases):

| Platform | Binary |
|----------|--------|
| macOS ARM64 (Apple Silicon) | `predicate-authorityd-darwin-arm64.tar.gz` |
| macOS x64 (Intel) | `predicate-authorityd-darwin-x64.tar.gz` |
| Linux x64 | `predicate-authorityd-linux-x64.tar.gz` |
| Linux ARM64 | `predicate-authorityd-linux-arm64.tar.gz` |
| Windows x64 | `predicate-authorityd-windows-x64.zip` |

```bash
# Example: macOS ARM64
curl -LO https://github.com/PredicateSystems/predicate-authority-sidecar/releases/latest/download/predicate-authorityd-darwin-arm64.tar.gz
tar -xzf predicate-authorityd-darwin-arm64.tar.gz
chmod +x predicate-authorityd
./predicate-authorityd --version
```

### Option C: Use from Python code

```python
from predicate_authority import run_sidecar, is_sidecar_available, download_sidecar

# Download if needed
if not is_sidecar_available():
    download_sidecar()

# Start as subprocess
process = run_sidecar(port=8787, policy_file="policy.json")

# Graceful shutdown
process.terminate()
process.wait()
```

---

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

### Basic local mode

```bash
./predicate-authorityd run \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file policy.json
```

### With local identity registry

```bash
./predicate-authorityd run \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file policy.json \
  --identity-file ./local-identities.json
```

### Cloud-connected mode (control-plane sync)

Connect to Predicate Authority control-plane for policy sync, revocation push, and audit forwarding:

```bash
export PREDICATE_API_KEY="your-api-key"

./predicate-authorityd run \
  --host 127.0.0.1 \
  --port 8787 \
  --mode cloud_connected \
  --policy-file policy.json \
  --control-plane-url https://api.predicatesystems.dev \
  --tenant-id your-tenant \
  --project-id your-project \
  --predicate-api-key $PREDICATE_API_KEY \
  --sync-enabled
```

### Local IdP mode (development/air-gapped)

For development or air-gapped environments without external IdP:

```bash
export LOCAL_IDP_SIGNING_KEY="replace-with-strong-secret"

./predicate-authorityd run \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file policy.json \
  --identity-mode local-idp \
  --local-idp-issuer "http://localhost/predicate-local-idp" \
  --local-idp-audience "api://predicate-authority"
```

Quick health checks:

```bash
curl -s http://127.0.0.1:8787/health | jq
curl -s http://127.0.0.1:8787/status | jq
```

### Signing key safety note (required until mandate `v2` claims)

Until mandate `v2` introduces explicit `iss`/`aud` claims and asymmetric signing defaults,
each deployment instance must use a unique signing key to reduce cross-instance replay risk.

Recommended startup pattern:

```bash
export PREDICATE_AUTHORITY_SIGNING_KEY="<unique-random-per-instance>"

PYTHONPATH=. predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json \
  --mandate-signing-key-env PREDICATE_AUTHORITY_SIGNING_KEY
```

## 2b) Okta production hardening checklist + staging matrix

Use this section when validating enterprise IdP readiness for Phase 2.

### Checklist

- [ ] Configure dedicated Okta OIDC app integration per environment (staging/prod split).
- [ ] Verify configured `issuer` and `audience` are exact matches to the target environment.
- [ ] Verify required claims/scopes/groups mapping used by authority role/tenant checks.
- [ ] Enforce strict JWT checks (`iss`, `aud`, `exp`, `nbf`, `iat`, required claims, alg allowlist).
- [ ] Validate JWKS retrieval and cache behavior for normal operation.
- [ ] Validate key rotation behavior (`kid` rollover) without service restart.
- [ ] Validate fail-closed behavior for cold-start JWKS failure and stale key scenarios.
- [x] Validate redaction: no token/secret leakage in logs on failures/retries.
- [x] Validate startup diagnostics for missing/invalid auth configuration.
- [ ] Validate revocation path behavior under Okta-backed principals.

### Staging test matrix

| Test ID | Scenario | Expected Result |
| --- | --- | --- |
| OKTA-01 | Valid token (correct issuer/audience/scope) | Request authorized and audit emitted |
| OKTA-02 | Wrong issuer | Denied with issuer mismatch reason |
| OKTA-03 | Wrong audience | Denied with audience mismatch reason |
| OKTA-04 | Missing required scope | Denied fail-closed before action |
| OKTA-05 | Expired token | Denied with expiration reason |
| OKTA-06 | Future `nbf` beyond leeway | Denied with temporal validation reason |
| OKTA-07 | Unsupported signing algorithm | Denied before trust decision |
| OKTA-08 | JWKS rotation (`kid` changes) | Validation recovers without restart |
| OKTA-09 | JWKS outage with warm cache | Existing key path continues until cache boundary |
| OKTA-10 | JWKS outage with cold cache | Startup/auth fails closed with actionable diagnostics |
| OKTA-11 | Tenant outside allow-list | Denied with tenant policy reason |
| OKTA-12 | Principal/intent revocation during run | Subsequent action denied promptly |
| OKTA-13 | Log redaction check | No raw tokens/secrets in logs |

### Emergency JWKS key-rotation runbook (owner + on-call flow)

Owner model:

- Primary owner: Platform Identity On-call.
- Secondary owner: Security On-call (approver for forced key disable).
- Incident commander: Platform lead on duty.

Trigger conditions:

- compromised signing key suspected,
- unexpected `kid` churn causing authorization failures,
- emergency tenant request to invalidate active key material.

Runbook steps:

1. **Declare incident + freeze risky deploys**
   - open incident channel and assign owner/approver,
   - freeze policy/auth-related deploy pipelines until stabilized.
2. **Rotate signing key in Okta**
   - publish new signing key and ensure new `kid` appears in JWKS,
   - stop issuing tokens from compromised/old key.
3. **Force validation against refreshed JWKS**
   - run targeted validation:
     - `python3 -m pytest tests/test_identity_bridge_phase2.py -k "jwks_kid_rollover_refreshes_without_restart"`
   - if runtime impact is active, temporarily reduce cache TTL and trigger sidecar restart waves.
4. **Confirm deny behavior for old/unknown `kid`**
   - run:
     - `python3 -m pytest tests/test_identity_bridge_phase2.py -k "jwks_stale_cache_and_outage_fails_closed_with_diagnostics"`
   - verify fail-closed behavior remains active.
5. **Recovery validation**
   - confirm healthy authorization path with new `kid`,
   - confirm no broad deny regressions in tenant traffic.
6. **Closeout**
   - document timeline, affected tenants, and remediation actions,
   - restore deploy pipeline and publish post-incident notes.

### Signoff evidence commands (deterministic integration tests)

Run these from `AgentIdentity` repo root and attach output to signoff evidence.

1) Network partition fail-closed behavior:

```bash
python3 -m pytest tests/test_daemon_phase2.py -k "network_partition_fail_closed_raises_and_tracks_failure"
```

Checkpoints:

- pass result proves fail-closed error path is enforced when control-plane is partitioned and `fail_open=False`,
- `/status` payload includes incremented control-plane failure counters.

2) Restart recovery with persisted queue:

```bash
python3 -m pytest tests/test_daemon_phase2.py -k "restart_recovers_queue_after_partition"
```

Checkpoints:

- pre-restart flush queue has pending event(s),
- post-restart `POST /ledger/flush-now` reports `sent_count >= 1`,
- post-flush queue is empty (`GET /ledger/flush-queue` returns no items).

3) Redaction and failure-reason validation:

```bash
python3 -m pytest tests/test_identity_bridge_phase2.py -k "reasonful_and_redacted"
```

Checkpoints:

- validation error includes a reason category (e.g. issuer mismatch),
- error text does not include raw token string or sensitive claim values.

4) Okta token exchange/OBO compatibility (tenant capability-gated):

```bash
# If tenant supports token exchange:
export OKTA_OBO_COMPAT_CHECK_ENABLED=1
export OKTA_SUPPORTS_TOKEN_EXCHANGE=true
python3 -m pytest tests/test_okta_obo_compatibility.py -k "live_check_when_enabled"

# If tenant does NOT support token exchange:
export OKTA_OBO_COMPAT_CHECK_ENABLED=1
export OKTA_SUPPORTS_TOKEN_EXCHANGE=false
python3 -m pytest tests/test_okta_obo_compatibility.py -k "live_check_when_enabled"
```

Checkpoints:

- `client_credentials_ok` must pass in both modes,
- when `OKTA_SUPPORTS_TOKEN_EXCHANGE=true`, token exchange must succeed,
- when `OKTA_SUPPORTS_TOKEN_EXCHANGE=false`, token exchange path is explicitly gated as tenant-disabled (no false failure).

### Example demo script: Okta delegation compatibility

Run example from repo root:

```bash
python3 examples/delegation/okta_obo_compat_demo.py \
  --issuer "$OKTA_ISSUER" \
  --client-id "$OKTA_CLIENT_ID" \
  --client-secret "$OKTA_CLIENT_SECRET" \
  --audience "$OKTA_AUDIENCE" \
  --scope "${OKTA_SCOPE:-authority:check}" \
  --supports-token-exchange
```

Notes:

- omit `--supports-token-exchange` for tenants that do not support OBO/token exchange,
- script reports whether delegation path should use IdP token exchange or authority mandate delegation.

### Entra OBO compatibility (capability-gated)

```bash
export ENTRA_OBO_COMPAT_CHECK_ENABLED=1

# Tenant supports OBO and user assertion is available:
export ENTRA_SUPPORTS_OBO=true
export ENTRA_USER_ASSERTION="<user-assertion-jwt>"
python3 -m pytest tests/test_entra_obo_compatibility.py -k "live_check_when_enabled"

# Tenant does NOT support OBO (or app policy not enabled):
export ENTRA_SUPPORTS_OBO=false
python3 -m pytest tests/test_entra_obo_compatibility.py -k "live_check_when_enabled"
```

Run demo script:

```bash
python examples/delegation/entra_obo_compat_demo.py \
  --tenant-id "$ENTRA_TENANT_ID" \
  --client-id "$ENTRA_CLIENT_ID" \
  --client-secret "$ENTRA_CLIENT_SECRET" \
  --scope "$ENTRA_SCOPE"
```

If OBO is supported and you have a user assertion:

```bash
python examples/delegation/entra_obo_compat_demo.py \
  --tenant-id "$ENTRA_TENANT_ID" \
  --client-id "$ENTRA_CLIENT_ID" \
  --client-secret "$ENTRA_CLIENT_SECRET" \
  --scope "$ENTRA_SCOPE" \
  --user-assertion "$ENTRA_USER_ASSERTION" \
  --supports-obo
```

### Generic OIDC token exchange compatibility (capability-gated)

```bash
export OIDC_COMPAT_CHECK_ENABLED=1
export OIDC_ISSUER="https://<oidc-provider>/oauth2/default"
export OIDC_CLIENT_ID="<oidc-client-id>"
export OIDC_CLIENT_SECRET="<oidc-client-secret>"
export OIDC_AUDIENCE="api://predicate-authority"
export OIDC_SCOPE="authority:check"

# Provider does NOT support token exchange:
export OIDC_SUPPORTS_TOKEN_EXCHANGE=false
python3 -m pytest tests/test_oidc_compatibility.py -k "live_check_when_enabled"

# Provider supports token exchange:
export OIDC_SUPPORTS_TOKEN_EXCHANGE=true
export OIDC_SUBJECT_TOKEN="<subject-access-token>"
python3 -m pytest tests/test_oidc_compatibility.py -k "live_check_when_enabled"
```

Run demo script:

```bash
python examples/delegation/oidc_compat_demo.py \
  --issuer "$OIDC_ISSUER" \
  --client-id "$OIDC_CLIENT_ID" \
  --client-secret "$OIDC_CLIENT_SECRET" \
  --audience "$OIDC_AUDIENCE" \
  --scope "${OIDC_SCOPE:-authority:check}"
```

If token exchange is supported and subject token is available:

```bash
python examples/delegation/oidc_compat_demo.py \
  --issuer "$OIDC_ISSUER" \
  --client-id "$OIDC_CLIENT_ID" \
  --client-secret "$OIDC_CLIENT_SECRET" \
  --audience "$OIDC_AUDIENCE" \
  --scope "${OIDC_SCOPE:-authority:check}" \
  --subject-token "$OIDC_SUBJECT_TOKEN" \
  --supports-token-exchange
```

### Secret storage policy (Okta credentials)

- never commit Okta client secrets/API tokens/private keys to repo files,
- store Okta credentials in runtime secret manager and CI secret store only,
- CI enforcement:
  - `scripts/check_no_plaintext_okta_secrets.py` scans for plaintext Okta secrets,
  - auth module security checks run Bandit for `predicate_authority` auth paths.

When enabled, daemon bootstrap auto-attaches `ControlPlaneTraceEmitter` so each
authority decision pushes:

- audit events -> `/v1/audit/events:batch`
- usage credits -> `/v1/metering/usage:batch`

### Optional: use Okta identity mode

Provide Okta OIDC values via env vars:

```bash
export OKTA_ISSUER="https://<org>.okta.com/oauth2/default"
export OKTA_CLIENT_ID="<okta-client-id>"
export OKTA_AUDIENCE="api://predicate-authority"
```

Start daemon in Okta mode:

```bash
PYTHONPATH=. predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode cloud_connected \
  --identity-mode okta \
  --okta-issuer "$OKTA_ISSUER" \
  --okta-client-id "$OKTA_CLIENT_ID" \
  --okta-audience "$OKTA_AUDIENCE" \
  --okta-required-claims "sub,tenant_id" \
  --okta-required-scopes "authority:check" \
  --okta-required-roles "authority-operator" \
  --okta-allowed-tenants "tenant-a" \
  --idp-token-ttl-s 300 \
  --mandate-ttl-s 300 \
  --policy-file examples/authorityd/policy.json
```

Safety gate note:

- in `cloud_connected` mode, `identity-mode local` or `identity-mode local-idp` now requires explicit `--allow-local-fallback`,
- this prevents accidental implicit downgrade to local identity behavior.

TTL alignment note:

- startup enforces `idp-token-ttl-s >= mandate-ttl-s` to avoid mandates outliving identity session controls.

### Emergency rollback route (Okta integration)

If Okta integration causes broad auth failures, use this rollback sequence:

1. disable the affected Okta app integration for the impacted environment,
2. rotate signing keys and invalidate compromised sessions in Okta,
3. switch sidecar traffic to a known-good identity config (or controlled local fallback with explicit `--allow-local-fallback`),
4. verify deny behavior + recovery through signoff evidence commands before restoring normal traffic.

## 3b) Optional local identity registry (ephemeral task identities)

Enable local identity support:

```bash
PYTHONPATH=. predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json \
  --identity-mode local-idp \
  --local-identity-enabled \
  --local-identity-registry-file ./.predicate-authorityd/local-identities.json \
  --local-identity-default-ttl-s 900 \
  --flush-worker-enabled \
  --flush-worker-interval-s 2.0 \
  --flush-worker-max-batch-size 50 \
  --flush-worker-dead-letter-max-attempts 5
```

Issue an ephemeral identity:

```bash
curl -s -X POST http://127.0.0.1:8787/identity/task \
  -H "Content-Type: application/json" \
  -d '{"principal_id":"agent:backend","task_id":"refactor-pr-102","ttl_seconds":120}'
```

Inspect pending local ledger flush queue:

```bash
curl -s http://127.0.0.1:8787/ledger/flush-queue | jq
```

List quarantined dead-letter items only:

```bash
curl -s http://127.0.0.1:8787/ledger/dead-letter | jq
```

Manually trigger an immediate flush cycle:

```bash
curl -s -X POST http://127.0.0.1:8787/ledger/flush-now \
  -H "Content-Type: application/json" \
  -d '{"max_items":50}' | jq
```

Requeue a quarantined item for retry:

```bash
curl -s -X POST http://127.0.0.1:8787/ledger/requeue \
  -H "Content-Type: application/json" \
  -d '{"queue_item_id":"q_abc123"}' | jq
```

Flush worker behavior:

- reuses control-plane client retry policy (`--control-plane-max-retries`, `--control-plane-backoff-initial-s`),
- drains up to `--flush-worker-max-batch-size` queue items per cycle,
- quarantines entries after `--flush-worker-dead-letter-max-attempts` failed sends,
- sleeps `--flush-worker-interval-s` between flush cycles.

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
  "mandate_store_persistence_enabled": false,
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
