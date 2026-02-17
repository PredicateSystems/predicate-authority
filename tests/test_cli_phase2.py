from __future__ import annotations

import json
from pathlib import Path

from predicate_authority import (
    ActionGuard,
    AuthorityMode,
    DaemonConfig,
    IdentityBridge,
    InMemoryProofLedger,
    LocalCredentialStore,
    LocalMandateSigner,
    LocalRevocationCache,
    PolicyEngine,
    PredicateAuthorityDaemon,
    PredicateAuthoritySidecar,
    SidecarConfig,
)
from predicate_authority.cli import build_parser
from predicate_contracts import PolicyEffect, PolicyRule


def _build_sidecar(tmp_path: Path, policy_file: Path) -> PredicateAuthoritySidecar:
    policy_engine = PolicyEngine(
        rules=(
            PolicyRule(
                name="allow-any-http",
                effect=PolicyEffect.ALLOW,
                principals=("agent:*",),
                actions=("http.*",),
                resources=("https://*/*",),
            ),
        )
    )
    proof_ledger = InMemoryProofLedger()
    guard = ActionGuard(
        policy_engine=policy_engine,
        mandate_signer=LocalMandateSigner(secret_key="test-secret"),
        proof_ledger=proof_ledger,
    )
    return PredicateAuthoritySidecar(
        config=SidecarConfig(mode=AuthorityMode.LOCAL_ONLY, policy_file_path=str(policy_file)),
        action_guard=guard,
        proof_ledger=proof_ledger,
        identity_bridge=IdentityBridge(),
        credential_store=LocalCredentialStore(str(tmp_path / "credentials.json")),
        revocation_cache=LocalRevocationCache(),
        policy_engine=policy_engine,
    )


def test_cli_policy_validate_success(tmp_path: Path, capsys) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "name": "allow-http",
                        "effect": "allow",
                        "principals": ["agent:*"],
                        "actions": ["http.*"],
                        "resources": ["https://*/*"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    parser = build_parser()
    args = parser.parse_args(["policy", "validate", "--file", str(policy_file)])
    exit_code = args.func(args)
    output = capsys.readouterr().out
    assert exit_code == 0
    assert '"valid": true' in output.lower()


def test_cli_sidecar_health_and_revoke(tmp_path: Path, capsys) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"rules": []}), encoding="utf-8")
    sidecar = _build_sidecar(tmp_path, policy_file)
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=0.05),
    )
    daemon.start()
    try:
        parser = build_parser()
        health_args = parser.parse_args(
            ["sidecar", "health", "--host", "127.0.0.1", "--port", str(daemon.bound_port)]
        )
        health_exit = health_args.func(health_args)
        health_output = capsys.readouterr().out
        assert health_exit == 0
        assert '"status": "ok"' in health_output

        revoke_args = parser.parse_args(
            [
                "revoke",
                "principal",
                "--host",
                "127.0.0.1",
                "--port",
                str(daemon.bound_port),
                "--id",
                "agent:revoked",
            ]
        )
        revoke_exit = revoke_args.func(revoke_args)
        revoke_output = capsys.readouterr().out
        assert revoke_exit == 0
        assert '"ok": true' in revoke_output.lower()
    finally:
        daemon.stop()
