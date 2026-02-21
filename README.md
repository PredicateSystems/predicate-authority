# Predicate Authority

**Deterministic Authority for AI Agents: Secure the "Confused Deputy" with your existing Identity stack.**

[![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![PyPI - predicate-authority](https://img.shields.io/pypi/v/predicate-authority.svg)](https://pypi.org/project/predicate-authority/)
[![PyPI - predicate-contracts](https://img.shields.io/pypi/v/predicate-contracts.svg)](https://pypi.org/project/predicate-contracts/)
[![Release Tag](https://img.shields.io/badge/release-vX.Y.Z-blue)](docs/pypi-release-guide.md)

`predicate-authority` is a production-grade pre-execution authority layer that binds AI agent identity to deterministic state. It bridges standard IdPs (Entra ID, Okta, OIDC) with runtime verification so every sensitive action is authorized, bounded, and provable.

## Why Predicate Authority?

Most agent security fails because it relies on static API keys or broad permissions. Predicate introduces short-lived mandates that are cryptographically tied to:

- `state_hash` (what state the agent is in),
- `intent_hash` (what action it intends to perform),
- policy constraints and required verification labels.

This closes the confused-deputy gap where an agent can misuse delegated credentials.

- **Bridge, don't replace**: leverage existing enterprise identity and governance.
- **Fail-closed by design**: deny before execution when state/intent/policy checks fail.
- **Deterministic binding**: authority is tied to runtime evidence, not only identity.
- **Provable controls**: each decision can emit signed proof events for audit pipelines.

### Why not just use IdP directly?

You should still use Entra/Okta/OIDC for identity and token issuance. `predicate-authority` adds the runtime control layer those systems do not provide by default for AI agents:

- pre-execution allow/deny checks right before each sensitive action,
- binding authority to current `state_hash` and `intent_hash`,
- optional required verification labels from runtime checks (currently web-agent only via [predicate-sdk](https://github.com/PredicateSystems/sdk-python) integration),
- fail-closed local enforcement and per-decision proof events.

In practice: IdP answers **who the principal is**, while `predicate-authority` answers **whether this exact action is allowed right now in this state**.

## Repository Components

| Package | Purpose |
| --- | --- |
| `predicate_contracts` | Shared typed contracts and protocols (`ActionRequest`, `PolicyRule`, evidence, decision/proof models). |
| `predicate_authority` | Runtime authorization engine (`PolicyEngine`, `ActionGuard`, mandate signing, proof ledger, telemetry emitter). |
| `examples/` | Browser/MCP/HTTP/sidecar examples for local and connected workflows. |

## Current Capabilities

Implemented in this repository:

- local pre-execution `ActionGuard.authorize(...)` and `enforce(...)`,
- signed local mandates with TTL (`LocalMandateSigner`),
- policy evaluation with deny precedence and required verification labels,
- typed [predicate-sdk](https://github.com/PredicateSystems/sdk-python) integration adapter (`predicate_authority.integrations`),
- OpenTelemetry-compatible trace emitter (`OpenTelemetryTraceEmitter`),
- `predicate-authorityd` sidecar daemon with policy polling and health/status endpoints,
- ops-focused CLI commands for sidecar health/status, policy validate/reload, and revoke controls,
- pytest coverage for authorization, mandate, integration, telemetry, daemon, and CLI flows.

## Installation

```bash
pip install predicate-authority
```

For local editable development in this monorepo, install both package roots
(do not use `pip install -e .` at repo root):

```bash
make dev-install
# equivalent: python -m pip install -e predicate_contracts -e predicate_authority
```

Release note: publish is supported by pushing a synchronized git tag `vX.Y.Z`
(see `docs/pypi-release-guide.md`).

For shared contracts directly:

```bash
pip install predicate-contracts
```

## Quick Start

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
)

guard = ActionGuard(
    policy_engine=PolicyEngine(
        rules=(
            PolicyRule(
                name="allow-payment-submit",
                effect=PolicyEffect.ALLOW,
                principals=("agent:payments",),
                actions=("http.post",),
                resources=("https://finance.example.com/transfers",),
            ),
        )
    ),
    mandate_signer=LocalMandateSigner(secret_key="dev-secret"),
    proof_ledger=InMemoryProofLedger(),
)

request = ActionRequest(
    principal=PrincipalRef(principal_id="agent:payments"),
    action_spec=ActionSpec(
        action="http.post",
        resource="https://finance.example.com/transfers",
        intent="submit transfer request #1234",
    ),
    state_evidence=StateEvidence(source="backend", state_hash="state-hash-abc"),
    verification_evidence=VerificationEvidence(),
)

decision = guard.authorize(request)
if not decision.allowed:
    raise RuntimeError(f"Authority denied: {decision.reason.value}")
```

See runnable examples in:

- `examples/browser_guard_example.py`
- `examples/mcp_tool_guard_example.py`
- `examples/outbound_http_guard_example.py`

### Entra quick command (compatibility check)

```bash
set -a && source .env && set +a
python examples/delegation/entra_obo_compat_demo.py \
  --tenant-id "$ENTRA_TENANT_ID" \
  --client-id "$ENTRA_CLIENT_ID" \
  --client-secret "$ENTRA_CLIENT_SECRET" \
  --scope "$ENTRA_SCOPE"
```

### OIDC quick command (compatibility check)

```bash
set -a && source .env && set +a
python examples/delegation/oidc_compat_demo.py \
  --issuer "$OIDC_ISSUER" \
  --client-id "$OIDC_CLIENT_ID" \
  --client-secret "$OIDC_CLIENT_SECRET" \
  --audience "$OIDC_AUDIENCE" \
  --scope "${OIDC_SCOPE:-authority:check}"
```

### Local IdP quick command

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

### Cloud-connected sidecar (control-plane sync)

Connect the sidecar to Predicate Authority control-plane for policy sync, revocation push, and audit forwarding:

```bash
export PREDICATE_API_KEY="your-api-key"

predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode cloud_connected \
  --control-plane-url https://api.predicatesystems.dev \
  --tenant-id your-tenant \
  --project-id your-project \
  --predicate-api-key $PREDICATE_API_KEY \
  --sync-enabled
```

For the Rust sidecar (`rust-predicate-authorityd`), use the same flags:

```bash
./predicate-authorityd run \
  --mode cloud_connected \
  --control-plane-url https://api.predicatesystems.dev \
  --tenant-id your-tenant \
  --project-id your-project \
  --predicate-api-key $PREDICATE_API_KEY \
  --sync-enabled
```

## Operations CLI

`predicate-authority` provides an ops-focused CLI for sidecar/runtime workflows.

### Ops docs quick links

- Sidecar operations guide: `docs/authorityd-operations.md`
- User manual (sync/integrity/operator behaviors): `docs/predicate-authority-user-manual.md`
- Control-plane production hardening runbook: `../predicate-authority-control-plane/docs/production-hardening-runbook.md`

### Sidecar health and status

```bash
predicate-authority sidecar health --host 127.0.0.1 --port 8787
predicate-authority sidecar status --host 127.0.0.1 --port 8787
```

### Policy validation and reload

```bash
predicate-authority policy validate --file examples/authorityd/policy.json
predicate-authority policy reload --host 127.0.0.1 --port 8787
```

### Revocation controls

```bash
predicate-authority revoke principal --host 127.0.0.1 --port 8787 --id agent:orders-01
predicate-authority revoke intent --host 127.0.0.1 --port 8787 --hash <intent_hash>
```

### Daemon startup

```bash
predicate-authorityd --host 127.0.0.1 --port 8787 --mode local_only --policy-file examples/authorityd/policy.json
```

Mandate cache behavior:

- default is ephemeral in-memory mandate/revocation cache,
- set `--mandate-store-file <path>` to enable optional local persistence and restart recovery.

### Identity mode options (`predicate-authorityd`)

- `--identity-mode local`: deterministic local bridge (default).
- `--identity-mode local-idp`: local IdP-style signed token mode for dev/air-gapped workflows.
- `--identity-mode oidc`: enterprise OIDC bridge mode.
- `--identity-mode entra`: Microsoft Entra bridge mode.

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

### Local identity registry (ephemeral + TTL + flush queue)

Enable sidecar-managed local task identities and local ledger queue:

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

Runtime endpoints:

- `POST /identity/task` (issue ephemeral task identity)
- `GET /identity/list` (list identities)
- `POST /identity/revoke` (revoke identity)
- `GET /ledger/flush-queue` (inspect pending local ledger queue)
- `GET /ledger/dead-letter` (list quarantined queue items only)
- `POST /ledger/flush-ack` (mark queue item as flushed)
- `POST /ledger/flush-now` (manually trigger immediate queue flush)
- `POST /ledger/requeue` (requeue quarantined item for retry)

Background flush worker status fields:

- `flush_cycle_count`
- `flush_sent_count`
- `flush_failed_count`
- `flush_quarantined_count`
- `last_flush_epoch_s`
- `last_flush_error`

### How to run with control-plane shipping (out-of-the-box)

```bash
export CONTROL_PLANE_URL="http://127.0.0.1:8080"
export CONTROL_PLANE_TENANT_ID="dev-tenant"
export CONTROL_PLANE_PROJECT_ID="dev-project"
export PREDICATE_API_KEY="<your-api-key>"

PYTHONPATH=. predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file examples/authorityd/policy.json \
  --control-plane-enabled \
  --control-plane-fail-open
```

The `/status` endpoint now includes:

- `control_plane_emitter_attached`
- `control_plane_audit_push_success_count`
- `control_plane_audit_push_failure_count`
- `control_plane_usage_push_success_count`
- `control_plane_usage_push_failure_count`
- `control_plane_last_push_error`

## Security: Local Kill-Switch Path

`predicate-authority` supports fail-closed checks, local proof emission, and sidecar-managed revocation/token lifecycle for long-running agents.

## Release

- CI workflow: `.github/workflows/phase1-ci-and-release.yml`
- Release guide: `docs/pypi-release-guide.md`

Publish order is always:

1. `predicate-contracts`
2. `predicate-authority`

## License

Dual-licensed under **MIT** and **Apache 2.0**:

- `LICENSE-MIT`
- `LICENSE-APACHE`

---

Copyright (c) 2026 Predicate Systems Inc.
