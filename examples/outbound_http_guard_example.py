from __future__ import annotations

import secrets

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


def perform_http_post() -> str:
    # Placeholder for actual outbound HTTP call.
    return "201 Created"


def main() -> None:
    guard = ActionGuard(
        policy_engine=PolicyEngine(
            rules=(
                PolicyRule(
                    name="allow-vendor-api-post",
                    effect=PolicyEffect.ALLOW,
                    principals=("agent:backend-billing",),
                    actions=("http.post",),
                    resources=("https://api.vendor.com/invoices",),
                ),
            )
        ),
        mandate_signer=LocalMandateSigner(secret_key=secrets.token_hex(32)),
        proof_ledger=InMemoryProofLedger(),
    )
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:backend-billing"),
        action_spec=ActionSpec(
            action="http.post",
            resource="https://api.vendor.com/invoices",
            intent="create invoice for order 1432",
        ),
        state_evidence=StateEvidence(source="backend", state_hash="order-1432-input-hash"),
        verification_evidence=VerificationEvidence(),
    )

    result = guard.enforce(perform_http_post, request)
    print(f"http_status={result.value}")
    print(f"authorized={result.decision.allowed}")


if __name__ == "__main__":
    main()
