from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast


def _ensure_repo_root_on_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[2]
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
        principal=PrincipalRef(principal_id="agent:root"),
        action_spec=ActionSpec(
            action="task.delegate",
            resource="worker:queue/main",
            intent="delegate processing to worker agent",
        ),
        state_evidence=StateEvidence(source="delegate.py", state_hash="sha256:delegate"),
        verification_evidence=VerificationEvidence(),
    )


def _run_worker(
    worker_script: str,
    token: str,
    secret_key: str,
    revocation_file: str,
    policy_file: str,
) -> dict[str, object]:
    worker_run = _load_worker_runner(worker_script)
    payload = worker_run(
        token=token,
        secret_key=secret_key,
        revocation_file=revocation_file,
        policy_file=policy_file,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("worker payload must be an object")
    return cast(dict[str, object], payload)


def _load_worker_runner(worker_script: str) -> Callable[..., Any]:
    worker_path = Path(worker_script).resolve()
    spec = importlib.util.spec_from_file_location("delegation_worker_runtime", worker_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load worker module from path: {worker_script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run_callable = getattr(module, "run", None)
    if not callable(run_callable):
        raise RuntimeError("Worker module must expose callable run(...) function.")
    return cast(Callable[..., Any], run_callable)


def run(
    policy_file: str,
    worker_script: str,
    revocation_file: str,
    secret_key: str,
) -> dict[str, object]:
    _ensure_repo_root_on_syspath()
    from predicate_authority import AuthorityClient  # pylint: disable=import-error

    context = AuthorityClient.from_policy_file(
        policy_file=policy_file,
        secret_key=secret_key,
        ttl_seconds=120,
    )
    client = context.client

    decision = client.authorize(_build_request())
    if not decision.allowed or decision.mandate is None:
        return {
            "root_allowed": False,
            "worker_allowed_before_revoke": False,
            "worker_allowed_after_revoke": False,
        }

    token = decision.mandate.token
    Path(revocation_file).write_text(
        json.dumps({"revoked_principal_ids": []}, indent=2),
        encoding="utf-8",
    )
    before = _run_worker(worker_script, token, secret_key, revocation_file, policy_file)

    client.revoke_principal("agent:root")
    Path(revocation_file).write_text(
        json.dumps({"revoked_principal_ids": ["agent:root"]}, indent=2),
        encoding="utf-8",
    )
    after = _run_worker(worker_script, token, secret_key, revocation_file, policy_file)

    return {
        "root_allowed": True,
        "root_delegation_depth": decision.mandate.claims.delegation_depth,
        "root_chain_hash": decision.mandate.claims.delegation_chain_hash,
        "worker_allowed_before_revoke": bool(before.get("allowed", False)),
        "worker_allowed_after_revoke": bool(after.get("allowed", False)),
        "worker_delegation_depth_before_revoke": before.get("delegation_depth"),
        "worker_chain_verified_before_revoke": bool(before.get("chain_verified", False)),
        "before_reason": before.get("reason"),
        "after_reason": after.get("reason"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Delegation simulation for local authority runtime."
    )
    parser.add_argument(
        "--policy-file",
        default="examples/delegation/policy.yaml",
        help="Path to policy file for the root delegating agent.",
    )
    parser.add_argument(
        "--worker-script",
        default="examples/delegation/worker.py",
        help="Path to worker.py.",
    )
    parser.add_argument(
        "--revocation-file",
        default="examples/delegation/revocations.json",
        help="Path to revocation state shared with worker.",
    )
    parser.add_argument("--secret-key", default="dev-secret")
    args = parser.parse_args()
    payload = run(
        policy_file=args.policy_file,
        worker_script=args.worker_script,
        revocation_file=args.revocation_file,
        secret_key=args.secret_key,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
