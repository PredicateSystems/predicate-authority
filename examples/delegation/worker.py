from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _ensure_repo_root_on_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    root = str(repo_root)
    if root not in sys.path:
        sys.path.insert(0, root)


def _load_revocations(path: str) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return []
    revoked = payload.get("revoked_principal_ids", [])
    if not isinstance(revoked, list):
        return []
    return [str(item) for item in revoked]


def _build_worker_request() -> object:
    _ensure_repo_root_on_syspath()
    from predicate_contracts import (  # pylint: disable=import-error
        ActionRequest,
        ActionSpec,
        PrincipalRef,
        StateEvidence,
        VerificationEvidence,
    )

    return ActionRequest(
        principal=PrincipalRef(principal_id="agent:worker"),
        action_spec=ActionSpec(
            action="job.execute",
            resource="queue://jobs/high-priority",
            intent="execute delegated job",
        ),
        state_evidence=StateEvidence(source="worker.py", state_hash="sha256:worker"),
        verification_evidence=VerificationEvidence(),
    )


def run(
    token: str,
    secret_key: str,
    revocation_file: str,
    policy_file: str,
) -> dict[str, object]:
    _ensure_repo_root_on_syspath()
    from predicate_authority import AuthorityClient  # pylint: disable=import-error

    context = AuthorityClient.from_policy_file(
        policy_file=policy_file,
        secret_key=secret_key,
        ttl_seconds=120,
    )
    client = context.client
    revoked_principal_ids = _load_revocations(revocation_file)
    for principal_id in revoked_principal_ids:
        client.revoke_principal(principal_id)

    parent_mandate = client.verify_token(token)
    if parent_mandate is None:
        if "agent:root" in revoked_principal_ids:
            return {"allowed": False, "reason": "revoked_root_token"}
        return {"allowed": False, "reason": "invalid_or_expired_token"}

    decision = client.authorize(
        _build_worker_request(),
        parent_mandate=parent_mandate,
    )
    if not decision.allowed or decision.mandate is None:
        denied_reason = (
            "revoked_root_token"
            if parent_mandate.claims.principal_id in revoked_principal_ids
            else "denied"
        )
        return {"allowed": False, "reason": denied_reason}

    chain_ok = client.verify_delegation_chain(
        token=decision.mandate.token,
        parent_token=token,
    )
    return {
        "allowed": True,
        "reason": "ok",
        "principal_id": decision.mandate.claims.principal_id,
        "delegated_by": decision.mandate.claims.delegated_by,
        "delegation_depth": decision.mandate.claims.delegation_depth,
        "chain_hash": decision.mandate.claims.delegation_chain_hash,
        "chain_verified": chain_ok,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Worker process for delegation simulation.")
    parser.add_argument("--token", required=True)
    parser.add_argument("--secret-key", default="dev-secret")
    parser.add_argument("--revocation-file", required=True)
    parser.add_argument("--policy-file", required=True)
    args = parser.parse_args()
    payload = run(
        token=args.token,
        secret_key=args.secret_key,
        revocation_file=args.revocation_file,
        policy_file=args.policy_file,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
