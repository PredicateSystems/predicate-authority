# Predicate Authority

**Deterministic Authority for AI Agents: Secure the "Confused Deputy" with your existing Identity stack.**

[![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![PyPI - predicate-authority](https://img.shields.io/pypi/v/predicate-authority.svg)](https://pypi.org/project/predicate-authority/)
[![PyPI - predicate-contracts](https://img.shields.io/pypi/v/predicate-contracts.svg)](https://pypi.org/project/predicate-contracts/)

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
| `examples/` | Browser/MCP/HTTP guard examples using the local Phase 1 runtime. |

## Phase 1 Status

Implemented in this repository:

- local pre-execution `ActionGuard.authorize(...)` and `enforce(...)`,
- signed local mandates with TTL (`LocalMandateSigner`),
- policy evaluation with deny precedence and required verification labels,
- typed [predicate-sdk](https://github.com/PredicateSystems/sdk-python) integration adapter (`predicate_authority.integrations`),
- OpenTelemetry-compatible trace emitter (`OpenTelemetryTraceEmitter`),
- pytest coverage for core authorization, mandate, integration, and telemetry flows.

Planned in upcoming phases:

- `predicate-authorityd` sidecar for token lifecycle and local kill-switch,
- enterprise IdP bridge hardening (Entra/Okta/OIDC adapters),
- hosted governance control plane.

## Installation

```bash
pip install predicate-authority
```

For shared contracts directly:

```bash
pip install predicate-contracts
```

## Quick Start (Phase 1 API)

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

## Operations CLI (Phase 2)

`predicate-authority` provides an ops-focused CLI for sidecar/runtime workflows.

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

## Security: Local Kill-Switch Path

The current Phase 1 runtime supports fail-closed checks and local proof emission. The sidecar model (`predicate-authorityd`) is planned to provide instant local revocation and managed token lifecycle for long-running production agents.

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
