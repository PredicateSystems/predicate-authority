from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

# pylint: disable=import-error
from predicate_authority import AuthorityClient
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    AuthorizationReason,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
)


def test_authority_client_mint_and_verify_with_local_yaml_policy(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "rules:",
                "  - name: allow-orders-create",
                "    effect: allow",
                "    principals:",
                "      - agent:checkout",
                "    actions:",
                "      - http.post",
                "    resources:",
                "      - https://api.vendor.com/orders",
            ]
        ),
        encoding="utf-8",
    )
    context = AuthorityClient.from_policy_file(str(policy), secret_key="local-test-secret")
    client = context.client

    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:checkout"),
        action_spec=ActionSpec(
            action="http.post",
            resource="https://api.vendor.com/orders",
            intent="submit order",
        ),
        state_evidence=StateEvidence(source="unit-test", state_hash="sha256:test"),
        verification_evidence=VerificationEvidence(),
    )
    decision = client.authorize(request)

    assert decision.allowed
    assert decision.mandate is not None
    verified = client.verify_token(decision.mandate.token)
    assert verified is not None
    assert verified.claims.principal_id == "agent:checkout"


def test_authority_client_global_max_depth_from_yaml_is_enforced(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "global_max_delegation_depth: 0",
                "rules:",
                "  - name: allow-orders-create",
                "    effect: allow",
                "    principals:",
                "      - agent:checkout",
                "    actions:",
                "      - http.post",
                "    resources:",
                "      - https://api.vendor.com/orders",
            ]
        ),
        encoding="utf-8",
    )
    context = AuthorityClient.from_policy_file(str(policy), secret_key="local-test-secret")
    client = context.client
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:checkout"),
        action_spec=ActionSpec(
            action="http.post",
            resource="https://api.vendor.com/orders",
            intent="submit order",
        ),
        state_evidence=StateEvidence(source="unit-test", state_hash="sha256:test"),
        verification_evidence=VerificationEvidence(),
    )
    root = client.authorize(request)
    assert root.allowed is True
    assert root.mandate is not None

    child = client.authorize(request, parent_mandate=root.mandate)
    assert child.allowed is False
    assert child.reason == AuthorizationReason.MAX_DELEGATION_DEPTH_EXCEEDED


def test_authority_client_from_env(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "rules:",
                "  - name: allow-orders-create",
                "    effect: allow",
                "    principals:",
                "      - agent:checkout",
                "    actions:",
                "      - http.post",
                "    resources:",
                "      - https://api.vendor.com/orders",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PREDICATE_AUTHORITY_POLICY_FILE", str(policy))
    monkeypatch.setenv("PREDICATE_AUTHORITY_SIGNING_KEY", "env-test-secret")
    monkeypatch.setenv("PREDICATE_AUTHORITY_MANDATE_TTL_SECONDS", "120")
    context = AuthorityClient.from_env()
    assert context.policy_file == str(policy)
