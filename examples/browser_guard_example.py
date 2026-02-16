from __future__ import annotations

import secrets

from predicate_authority import ActionGuard, InMemoryProofLedger, LocalMandateSigner, PolicyEngine
from predicate_authority.integrations import SdkAssertionRecord, SdkStepEvidence, authorize_sdk_step
from predicate_contracts import PolicyEffect, PolicyRule


def main() -> None:
    guard = ActionGuard(
        policy_engine=PolicyEngine(
            rules=(
                PolicyRule(
                    name="allow-browser-checkout-submit",
                    effect=PolicyEffect.ALLOW,
                    principals=("agent:web-checkout",),
                    actions=("browser.submit",),
                    resources=("https://shop.example.com/checkout",),
                    required_labels=("postcondition.url_contains:/receipt",),
                ),
            )
        ),
        mandate_signer=LocalMandateSigner(secret_key=secrets.token_hex(32)),
        proof_ledger=InMemoryProofLedger(),
    )

    step = SdkStepEvidence(
        principal_id="agent:web-checkout",
        action="browser.submit",
        resource="https://shop.example.com/checkout",
        intent="submit checkout form",
        state_hash="state-hash-from-sdk-python",
        assertions=(
            SdkAssertionRecord(
                label="postcondition.url_contains:/receipt",
                passed=True,
            ),
        ),
    )
    result = authorize_sdk_step(guard, step)
    print(f"allowed={result.decision.allowed}, reason={result.decision.reason.value}")
    if result.decision.mandate is not None:
        print(f"mandate_id={result.decision.mandate.claims.mandate_id}")


if __name__ == "__main__":
    main()
