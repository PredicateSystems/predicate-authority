# predicate-authority

`predicate-authority` is a deterministic pre-execution authority layer for AI agents.
It binds identity, policy, and runtime evidence so risky actions are authorized
before execution and denied fail-closed when checks do not pass.

Docs: https://www.PredicateSystems.ai/docs
Github Repo: https://github.com/PredicateSystems/predicate-authority

Core pieces:

- `PolicyEngine` for allow/deny + required verification labels,
- `ActionGuard` for pre-action `authorize` / `enforce`,
- `LocalMandateSigner` for signed short-lived mandates,
- `InMemoryProofLedger` and optional `OpenTelemetryTraceEmitter`,
- typed integration adapters (including `sdk-python` mapping helpers),
- control-plane client primitives for shipping proof and usage batches to hosted APIs,
- local identity registry primitives (ephemeral task identities + local flush queue).

## Quick usage example

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
                name="allow-orders",
                effect=PolicyEffect.ALLOW,
                principals=("agent:orders",),
                actions=("http.post",),
                resources=("https://api.vendor.com/orders",),
            ),
        )
    ),
    mandate_signer=LocalMandateSigner(secret_key="replace-with-strong-secret"),
    proof_ledger=InMemoryProofLedger(),
)

request = ActionRequest(
    principal=PrincipalRef(principal_id="agent:orders", tenant_id="tenant-a"),
    action_spec=ActionSpec(
        action="http.post",
        resource="https://api.vendor.com/orders",
        intent="create order",
    ),
    state_evidence=StateEvidence(source="backend", state_hash="sha256:example"),
    verification_evidence=VerificationEvidence(),
)

decision = guard.authorize(request)
print("allowed=", decision.allowed, "reason=", decision.reason.value)
```

## Entra compatibility demo (capability-gated OBO)

```bash
python examples/delegation/entra_obo_compat_demo.py \
  --tenant-id "$ENTRA_TENANT_ID" \
  --client-id "$ENTRA_CLIENT_ID" \
  --client-secret "$ENTRA_CLIENT_SECRET" \
  --scope "${ENTRA_SCOPE:-api://predicate-authority/.default}"
```

## Local IdP quick example

```python
from predicate_authority import LocalIdPBridge, LocalIdPBridgeConfig
from predicate_contracts import PrincipalRef, StateEvidence

bridge = LocalIdPBridge(
    LocalIdPBridgeConfig(
        issuer="http://localhost/predicate-local-idp",
        audience="api://predicate-authority",
        signing_key="replace-with-strong-secret",
        token_ttl_seconds=300,
    )
)

token = bridge.exchange_token(
    PrincipalRef(principal_id="agent:local", tenant_id="tenant-a"),
    StateEvidence(source="backend", state_hash="sha256:local-state"),
)
print(token.provider.value, token.access_token[:24] + "...")
```
