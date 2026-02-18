from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _ensure_repo_root_on_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    root = str(repo_root)
    if root not in sys.path:
        sys.path.insert(0, root)


def _build_request() -> object:
    _ensure_repo_root_on_syspath()
    from predicate_contracts import (  # pylint: disable=import-error
        ActionRequest,
        ActionSpec,
        PrincipalRef,
        StateEvidence,
        VerificationEvidence,
    )

    return ActionRequest(
        principal=PrincipalRef(principal_id="agent:checkout"),
        action_spec=ActionSpec(
            action="http.post",
            resource="https://api.vendor.com/orders",
            intent="submit customer order",
        ),
        state_evidence=StateEvidence(source="sdk-python", state_hash="sha256:example"),
        verification_evidence=VerificationEvidence(),
    )


def run(policy_file: str, secret_key: str) -> dict[str, object]:
    _ensure_repo_root_on_syspath()
    from predicate_authority import AuthorityClient  # pylint: disable=import-error

    context = AuthorityClient.from_policy_file(
        policy_file=policy_file,
        secret_key=secret_key,
        ttl_seconds=120,
    )
    client = context.client
    decision = client.authorize(_build_request())
    token_verified = False
    if decision.mandate is not None:
        token_verified = client.verify_token(decision.mandate.token) is not None
    return {
        "policy_file": policy_file,
        "allowed": decision.allowed,
        "reason": decision.reason.value,
        "token_issued": decision.mandate is not None,
        "token_verified": token_verified,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Local AuthorityClient example using YAML policy.")
    parser.add_argument(
        "--policy-file",
        default="examples/authority_client_local_policy.yaml",
        help="Path to local YAML policy file.",
    )
    parser.add_argument(
        "--secret-key",
        default="dev-secret",
        help="Signing key used for local mandates.",
    )
    args = parser.parse_args()
    payload = run(policy_file=args.policy_file, secret_key=args.secret_key)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
