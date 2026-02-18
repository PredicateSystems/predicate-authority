from __future__ import annotations

# pylint: disable=import-error
from predicate_authority import LocalMandateSigner
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
)


def test_mandate_signature_verifies() -> None:
    signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60)
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )

    signed = signer.issue(request)
    verified = signer.verify(signed.token)

    assert verified is not None
    assert verified.claims.mandate_id == signed.claims.mandate_id
    assert verified.claims.intent_hash == signed.claims.intent_hash
    assert verified.claims.delegation_depth == 0
    assert verified.claims.delegated_by is None
    assert verified.claims.delegation_chain_hash is not None


def test_mandate_tamper_is_rejected() -> None:
    signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60)
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )
    signed = signer.issue(request)

    tampered = signed.token[:-1] + ("A" if signed.token[-1] != "A" else "B")
    assert signer.verify(tampered) is None


def test_multi_hop_delegation_claims_and_chain_verification() -> None:
    signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60)
    root_request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:root"),
        action_spec=ActionSpec(
            action="task.delegate",
            resource="worker:queue/main",
            intent="delegate job",
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-root"),
        verification_evidence=VerificationEvidence(),
    )
    root_mandate = signer.issue(root_request)

    child_request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:worker"),
        action_spec=ActionSpec(
            action="job.execute",
            resource="queue://jobs/high-priority",
            intent="execute delegated job",
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-worker"),
        verification_evidence=VerificationEvidence(),
    )
    child_mandate = signer.issue(child_request, parent_mandate=root_mandate)

    assert root_mandate.claims.delegation_depth == 0
    assert root_mandate.claims.delegated_by is None
    assert child_mandate.claims.delegation_depth == 1
    assert child_mandate.claims.delegated_by == "agent:root"
    assert child_mandate.claims.delegation_chain_hash is not None

    assert signer.verify_delegation(root_mandate, parent_mandate=None) is True
    assert signer.verify_delegation(child_mandate, parent_mandate=root_mandate) is True
    assert signer.verify_delegation(child_mandate, parent_mandate=None) is False
