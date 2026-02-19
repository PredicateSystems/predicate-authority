# Predicate Authority User Manual

This guide explains how to use `predicate-authority` in real projects with
practical examples. It is written for application developers and platform
operators who want deterministic, pre-execution authorization for AI agents.

---

## What is `predicate-authority`?

`predicate-authority` is an authorization layer for AI agents.

It checks risky actions **before execution** (fail-closed by default), issues
short-lived mandates for allowed actions, and records proof events for audit.

Core use cases:

- protect outbound API calls,
- protect tool invocation (MCP/function calls),
- enforce policy invariants using state and verification evidence,
- centralize revocation and operational controls through a sidecar.

---

## Package overview

- `predicate_contracts`: shared typed contracts and protocols.
- `predicate_authority`: policy engine, guard, sidecar, identity bridge,
  revocation, proof ledger.
- `predicate-authorityd`: optional local sidecar daemon (CLI service).

---

## Install

```bash
pip install predicate-contracts predicate-authority
```

For local development from source:

```bash
cd /path/to/AgentIdentity
pip install -e ./predicate_contracts
pip install -e ./predicate_authority
```

---

## Fastest local validation path (Day 1)

Use this path if you want fast feedback with minimal setup.

You do **not** need:

- Entra ID / enterprise IdP setup,
- two browser agents,
- hosted control plane.

### Step 1: run one local authorize/deny script

- Use in-process `ActionGuard` with a tiny local policy.
- Build one allowed request and one denied request.
- Confirm deny reason is deterministic.

### Step 2: simulate delegation with two Python scripts

- Script A (root) requests a mandate with limited delegation depth.
- Script B (worker) uses the received token and attempts delegated action.
- Validate expected behavior for:
  - valid delegation,
  - over-depth delegation (must fail),
  - revoked root/intent (must fail).

### Step 3: optional sidecar smoke test

- Start `predicate-authorityd` in local mode.
- Call `/status`, `/ledger/flush-now`, and `/ledger/dead-letter`.
- Confirm operations safety endpoints work before enterprise integration.

When this passes, add enterprise IdP (OIDC/Entra) and real web-agent E2E flows.

---

## Mental model

1. Build an `ActionRequest` from current agent context.
2. Call `ActionGuard.authorize(request)` (or sidecar equivalent).
3. If allowed, execute action (with mandate attached if needed).
4. If denied, stop action and handle deny reason.
5. Emit/store proof events for governance.

---

## Quick start (in-process guard)

```python
from predicate_authority import ActionGuard, InMemoryProofLedger, LocalMandateSigner, PolicyEngine
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    PolicyEffect,
    PolicyRule,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
    VerificationSignal,
    VerificationStatus,
)

rules = (
    PolicyRule(
        name="allow-orders-create",
        effect=PolicyEffect.ALLOW,
        principals=("agent:checkout",),
        actions=("http.post",),
        resources=("https://api.vendor.com/orders",),
        required_labels=("on_checkout_page",),
    ),
)

guard = ActionGuard(
    policy_engine=PolicyEngine(rules=rules),
    mandate_signer=LocalMandateSigner(secret_key="replace-with-strong-secret"),
    proof_ledger=InMemoryProofLedger(),
)

request = ActionRequest(
    principal=PrincipalRef(principal_id="agent:checkout", tenant_id="tenant-a"),
    action_spec=ActionSpec(
        action="http.post",
        resource="https://api.vendor.com/orders",
        intent="submit customer order",
    ),
    state_evidence=StateEvidence(source="sdk-python", state_hash="sha256:abc123"),
    verification_evidence=VerificationEvidence(
        signals=(
            VerificationSignal(
                label="on_checkout_page",
                status=VerificationStatus.PASSED,
                required=True,
            ),
        )
    ),
)

decision = guard.authorize(request)
if not decision.allowed:
    raise RuntimeError(f"Denied: {decision.reason.value}")

print("Allowed. mandate_id=", decision.mandate.claims.mandate_id if decision.mandate else None)
```

---

## Policy basics

A policy rule matches:

- principal (`agent:*`, `agent:checkout`, etc.),
- action (`http.post`, `tool.execute`, `browser.click`),
- resource (`https://...`, `mcp://...`, etc.),
- optional required verification labels.

If no allow rule matches, behavior is deny (`NO_MATCHING_POLICY`).

Common deny reasons:

- `NO_MATCHING_POLICY`
- `EXPLICIT_DENY`
- `MISSING_REQUIRED_VERIFICATION`
- `INVALID_MANDATE`

---

## Using the sidecar (`predicate-authorityd`)

Start local sidecar with file policy:

```bash
PYTHONPATH=. predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json
```

Health and status:

```bash
curl -s http://127.0.0.1:8787/health | jq
curl -s http://127.0.0.1:8787/status | jq
```

---

## Identity modes

`predicate-authorityd` supports multiple identity bridge modes:

- `local` (default): local deterministic bridge,
- `local-idp`: local IdP-style signed token mode (offline/dev/air-gapped),
- `oidc`: enterprise OIDC bridge,
- `entra`: Microsoft Entra bridge.

Example (`local-idp`):

```bash
export LOCAL_IDP_SIGNING_KEY="replace-with-strong-secret"
predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json \
  --identity-mode local-idp \
  --local-idp-issuer "http://localhost/predicate-local-idp" \
  --local-idp-audience "api://predicate-authority"
```

---

## Okta delegation compatibility check (capability-gated)

Use this when you want to verify whether your Okta tenant can do IdP token
exchange/OBO for delegation, or if you should use authority mandate delegation
as the fallback path.

### 1) Set environment variables

```bash
cp .env.example .env

export OKTA_ISSUER="https://<org>.okta.com/oauth2/default"
export OKTA_CLIENT_ID="<okta-client-id>"
export OKTA_CLIENT_SECRET="<okta-client-secret>"
export OKTA_AUDIENCE="api://predicate-authority"
export OKTA_SCOPE="authority:check"
```

### 2) Run compatibility test (live check is opt-in)

```bash
# Tenant supports token exchange/OBO
export OKTA_OBO_COMPAT_CHECK_ENABLED=1
export OKTA_SUPPORTS_TOKEN_EXCHANGE=true
python -m pytest tests/test_okta_obo_compatibility.py -k "live_check_when_enabled"

# Tenant does NOT support token exchange/OBO
export OKTA_OBO_COMPAT_CHECK_ENABLED=1
export OKTA_SUPPORTS_TOKEN_EXCHANGE=false
python -m pytest tests/test_okta_obo_compatibility.py -k "live_check_when_enabled"
```

Expected behavior:

- `client_credentials` path succeeds in both modes.
- if `OKTA_SUPPORTS_TOKEN_EXCHANGE=true`, token exchange should succeed.
- if `OKTA_SUPPORTS_TOKEN_EXCHANGE=false`, test is explicitly gated and does not
  fail as a false negative.

### 3) Run demo script in `examples/`

```bash
python examples/delegation/okta_obo_compat_demo.py \
  --issuer "$OKTA_ISSUER" \
  --client-id "$OKTA_CLIENT_ID" \
  --client-secret "$OKTA_CLIENT_SECRET" \
  --audience "$OKTA_AUDIENCE" \
  --scope "${OKTA_SCOPE:-authority:check}" \
  --supports-token-exchange
```

If your tenant does not support token exchange, omit
`--supports-token-exchange`. The script reports which delegation path to use:

- `idp_token_exchange` (when supported), or
- `authority_mandate_delegation` (fallback).

---

## Entra OBO compatibility check (capability-gated)

Use this when validating Entra on-behalf-of delegation support before production rollout.

### 1) Set environment variables

```bash
export ENTRA_TENANT_ID="<entra-tenant-id>"
export ENTRA_CLIENT_ID="<entra-client-id>"
export ENTRA_CLIENT_SECRET="<entra-client-secret>"
export ENTRA_SCOPE="api://predicate-authority/.default"
```

### 2) Run compatibility test

```bash
# OBO not supported/configured:
export ENTRA_OBO_COMPAT_CHECK_ENABLED=1
export ENTRA_SUPPORTS_OBO=false
python -m pytest tests/test_entra_obo_compatibility.py -k "live_check_when_enabled"

# OBO supported and user assertion available:
export ENTRA_OBO_COMPAT_CHECK_ENABLED=1
export ENTRA_SUPPORTS_OBO=true
export ENTRA_USER_ASSERTION="<user-assertion-jwt>"
python -m pytest tests/test_entra_obo_compatibility.py -k "live_check_when_enabled"
```

### 3) Run demo script in `examples/`

```bash
python examples/delegation/entra_obo_compat_demo.py \
  --tenant-id "$ENTRA_TENANT_ID" \
  --client-id "$ENTRA_CLIENT_ID" \
  --client-secret "$ENTRA_CLIENT_SECRET" \
  --scope "$ENTRA_SCOPE"
```

If OBO is supported and assertion is available, add:

```bash
--user-assertion "$ENTRA_USER_ASSERTION" --supports-obo
```

Expected delegation path output:

- `idp_obo_token_exchange` (if OBO succeeds), or
- `authority_mandate_delegation` (fallback).

---

## Generic OIDC token exchange compatibility (capability-gated)

Use this when integrating with a non-Okta, non-Entra OIDC provider and validating token-exchange readiness.

### 1) Set environment variables

```bash
export OIDC_ISSUER="https://<oidc-provider>/oauth2/default"
export OIDC_CLIENT_ID="<oidc-client-id>"
export OIDC_CLIENT_SECRET="<oidc-client-secret>"
export OIDC_AUDIENCE="api://predicate-authority"
export OIDC_SCOPE="authority:check"
```

### 2) Run compatibility test

```bash
# token exchange not supported or intentionally disabled:
export OIDC_COMPAT_CHECK_ENABLED=1
export OIDC_SUPPORTS_TOKEN_EXCHANGE=false
python -m pytest tests/test_oidc_compatibility.py -k "live_check_when_enabled"

# token exchange supported:
export OIDC_COMPAT_CHECK_ENABLED=1
export OIDC_SUPPORTS_TOKEN_EXCHANGE=true
export OIDC_SUBJECT_TOKEN="<subject-access-token>"
python -m pytest tests/test_oidc_compatibility.py -k "live_check_when_enabled"
```

### 3) Run demo script in `examples/`

```bash
python examples/delegation/oidc_compat_demo.py \
  --issuer "$OIDC_ISSUER" \
  --client-id "$OIDC_CLIENT_ID" \
  --client-secret "$OIDC_CLIENT_SECRET" \
  --audience "$OIDC_AUDIENCE" \
  --scope "${OIDC_SCOPE:-authority:check}"
```

If token exchange is supported and subject token is available, add:

```bash
--subject-token "$OIDC_SUBJECT_TOKEN" --supports-token-exchange
```

Expected delegation path output:

- `idp_token_exchange` (if exchange succeeds), or
- `authority_mandate_delegation` (fallback).

---

## Local identity registry + flush queue

Enable ephemeral task identity registry and local ledger queue:

```bash
PYTHONPATH=. predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json \
  --local-identity-enabled \
  --local-identity-registry-file ./.predicate-authorityd/local-identities.json \
  --local-identity-default-ttl-s 900 \
  --flush-worker-enabled \
  --flush-worker-interval-s 2.0 \
  --flush-worker-max-batch-size 50 \
  --flush-worker-dead-letter-max-attempts 5
```

Useful endpoints:

- `POST /identity/task`
- `GET /identity/list`
- `POST /identity/revoke`
- `GET /ledger/flush-queue`
- `POST /ledger/flush-now`
- `GET /ledger/dead-letter`
- `POST /ledger/requeue`

---

## Operations safety patterns

Recommended production defaults:

- keep fail-closed for protected actions,
- use dead-letter threshold to quarantine persistent failures,
- expose `/status` metrics to monitoring,
- provide runbooks for manual flush and dead-letter requeue.

Example manual recovery:

```bash
# trigger immediate flush
curl -s -X POST http://127.0.0.1:8787/ledger/flush-now \
  -H "Content-Type: application/json" \
  -d '{"max_items":50}' | jq

# inspect quarantined items
curl -s http://127.0.0.1:8787/ledger/dead-letter | jq

# requeue a quarantined item
curl -s -X POST http://127.0.0.1:8787/ledger/requeue \
  -H "Content-Type: application/json" \
  -d '{"queue_item_id":"q_abc123"}' | jq
```

---

## Control-plane sync and integrity quick checks

If you run `predicate-authorityd` with control-plane enabled, you can also enable
long-poll sync to pull policy/revocation updates continuously:

```bash
predicate-authorityd \
  --mode cloud_connected \
  --policy-file examples/authorityd/policy.json \
  --control-plane-enabled \
  --control-plane-sync-enabled \
  --control-plane-sync-project-id "dev-project" \
  --control-plane-sync-environment "prod"
```

Check sync counters from daemon:

```bash
curl -s http://127.0.0.1:8787/status | jq '.control_plane_sync_poll_count, .control_plane_sync_update_count, .control_plane_sync_error_count'
```

From control-plane, verify tamper-evident audit integrity endpoints:

```bash
curl -s "http://127.0.0.1:8080/v1/audit/integrity/root?tenant_id=tenant-a" \
  -H "Authorization: Bearer $TOKEN" | jq

curl -s "http://127.0.0.1:8080/v1/audit/integrity/proof/<event_id>?tenant_id=tenant-a" \
  -H "Authorization: Bearer $TOKEN" | jq
```

Operational notes:

- control-plane may return `503 store_circuit_open:<operation>` during upstream DB distress,
- if Kafka streaming is enabled in fail-closed mode, event-stream outages can return
  `503 event_stream_unavailable:<topic>`,
- in fail-open mode, core authority decisions continue even if stream publish fails.

---

## `sdk-python` integration example (boundary adapter flow)

If your web agent uses `sdk-python`, build shared contract evidence before
calling authority:

```python
from predicate.agent_runtime import AgentRuntime

# after snapshot + assertions
request = runtime.build_authority_action_request(
    principal_id="agent:web-checkout",
    action="browser.click",
    resource="https://example.com/checkout",
    intent="click submit order",
    tenant_id="tenant-a",
)

# send request to your authority hook/client
decision = my_authorizer(request)
if not decision.allowed:
    raise RuntimeError("Denied by authority")
```

---

## Troubleshooting

- Denied with `MISSING_REQUIRED_VERIFICATION`:
  - ensure required labels are present and `PASSED` in evidence.
- Denied with `NO_MATCHING_POLICY`:
  - verify principal/action/resource match patterns in active policy.
- Token exchange errors in connected mode:
  - verify identity mode config and credential/refresh-token setup.
- Queue not draining:
  - check `/status` flush counters and control-plane connectivity.

---

## Where to go next

- Operations guide: `docs/authorityd-operations.md`
- Architecture proposal: `docs/predicate_authority_docs/better-sdk-opportunity-proposal.md`
- Governance sign-off tracker: `docs/predicate_authority_docs/governance-signoff-tracker.md`
