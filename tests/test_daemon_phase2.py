from __future__ import annotations

import http.client
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

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
from predicate_contracts import PolicyEffect, PolicyRule

# pylint: disable=import-error


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
        config=SidecarConfig(
            mode=AuthorityMode.LOCAL_ONLY,
            policy_file_path=str(policy_file),
        ),
        action_guard=guard,
        proof_ledger=proof_ledger,
        identity_bridge=IdentityBridge(),
        credential_store=LocalCredentialStore(str(tmp_path / "credentials.json")),
        revocation_cache=LocalRevocationCache(),
        policy_engine=policy_engine,
    )


def _fetch_json(url: str) -> dict[str, object]:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    connection = http.client.HTTPConnection(parsed.netloc, timeout=2.0)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        payload = response.read().decode("utf-8")
    finally:
        connection.close()
    if response.status >= 400:
        raise RuntimeError(f"HTTP {response.status}: {payload}")
    loaded = json.loads(payload)
    assert isinstance(loaded, dict)
    return loaded


def _post_json(url: str, body: dict[str, str] | None = None) -> dict[str, object]:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    payload = json.dumps(body or {})
    connection = http.client.HTTPConnection(parsed.netloc, timeout=2.0)
    try:
        connection.request("POST", path, body=payload, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        content = response.read().decode("utf-8")
    finally:
        connection.close()
    if response.status >= 400:
        raise RuntimeError(f"HTTP {response.status}: {content}")
    loaded = json.loads(content)
    assert isinstance(loaded, dict)
    return loaded


def test_daemon_exposes_health_and_status_endpoints(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"rules": []}), encoding="utf-8")
    sidecar = _build_sidecar(tmp_path, policy_file)
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=0.05),
    )
    daemon.start()
    try:
        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        health = _fetch_json(f"{base_url}/health")
        status = _fetch_json(f"{base_url}/status")
        assert health["status"] == "ok"
        assert health["mode"] == "local_only"
        assert status["daemon_running"] is True
        assert status["policy_hot_reload_enabled"] is True
    finally:
        daemon.stop()


def test_daemon_policy_polling_tracks_reload_count(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"rules": []}), encoding="utf-8")
    sidecar = _build_sidecar(tmp_path, policy_file)
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=0.05),
    )
    daemon.start()
    try:
        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        initial = _fetch_json(f"{base_url}/status")
        initial_reload_count = int(initial["policy_reload_count"])

        time.sleep(0.1)
        policy_file.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "name": "allow-policy-updated",
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

        deadline = time.time() + 2.0
        while time.time() < deadline:
            status = _fetch_json(f"{base_url}/status")
            if int(status["policy_reload_count"]) > initial_reload_count:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Policy reload count did not increase after policy file update.")

    finally:
        daemon.stop()


def test_daemon_supports_policy_reload_and_revoke_endpoints(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"rules": []}), encoding="utf-8")
    sidecar = _build_sidecar(tmp_path, policy_file)
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=10.0),
    )
    daemon.start()
    try:
        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        reloaded = _post_json(f"{base_url}/policy/reload")
        revoke_principal = _post_json(
            f"{base_url}/revoke/principal", {"principal_id": "agent:test-revoked"}
        )
        revoke_intent = _post_json(
            f"{base_url}/revoke/intent",
            {"intent_hash": "abc123-intent-hash"},
        )
        status = _fetch_json(f"{base_url}/status")

        assert "reloaded" in reloaded
        assert revoke_principal["ok"] is True
        assert revoke_intent["ok"] is True
        assert int(status["revoked_principal_count"]) >= 1
        assert int(status["revoked_intent_count"]) >= 1
    finally:
        daemon.stop()
