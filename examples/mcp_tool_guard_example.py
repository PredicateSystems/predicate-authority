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


def main() -> None:
    guard = ActionGuard(
        policy_engine=PolicyEngine(
            rules=(
                PolicyRule(
                    name="allow-safe-tool",
                    effect=PolicyEffect.ALLOW,
                    principals=("agent:mcp-assistant",),
                    actions=("mcp.execute",),
                    resources=("mcp://tools/web_search",),
                ),
            )
        ),
        mandate_signer=LocalMandateSigner(secret_key=secrets.token_hex(32)),
        proof_ledger=InMemoryProofLedger(),
    )
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:mcp-assistant"),
        action_spec=ActionSpec(
            action="mcp.execute",
            resource="mcp://tools/web_search",
            intent="search docs for release notes",
        ),
        state_evidence=StateEvidence(source="mcp", state_hash="tool-context-hash"),
        verification_evidence=VerificationEvidence(),
    )

    result = guard.enforce(lambda: "tool-call-result", request)
    print(f"result={result.value}")
    print(f"mandate_id={result.mandate.claims.mandate_id}")


if __name__ == "__main__":
    main()
