from __future__ import annotations

import http.client
import json
import os
import threading
import time
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
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
from predicate_authority.daemon import (
    ControlPlaneBootstrapConfig,
    _build_default_sidecar,
    _build_identity_bridge_from_args,
)
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    PolicyEffect,
    PolicyRule,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
)

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


class _ControlPlaneHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, dict[str, object], dict[str, str]]]

    def do_POST(self) -> None:  # noqa: N802
        raw_length = self.headers.get("Content-Length", "0")
        content_length = int(raw_length) if raw_length.isdigit() else 0
        payload_raw = (
            self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        )
        loaded = json.loads(payload_raw)
        assert isinstance(loaded, dict)
        self.requests.append((self.path, loaded, dict(self.headers.items())))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def _start_control_plane_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    class BoundHandler(_ControlPlaneHandler):
        requests = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_daemon_bootstrap_wires_control_plane_emitter(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "name": "allow-any-http",
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
    server, _ = _start_control_plane_server()
    daemon: PredicateAuthorityDaemon | None = None
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        sidecar = _build_default_sidecar(
            mode=AuthorityMode.LOCAL_ONLY,
            policy_file=str(policy_file),
            credential_store_file=str(tmp_path / "credentials.json"),
            control_plane_config=ControlPlaneBootstrapConfig(
                enabled=True,
                base_url=base_url,
                tenant_id="tenant-a",
                project_id="project-a",
                auth_token="test-token",
                fail_open=False,
            ),
        )
        daemon = PredicateAuthorityDaemon(
            sidecar=sidecar,
            config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=0.2),
        )
        daemon.start()
        request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:test"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="create order",
            ),
            state_evidence=StateEvidence(source="test", state_hash="abc123"),
            verification_evidence=VerificationEvidence(),
        )
        decision = sidecar.issue_mandate(request)
        assert decision.allowed is True
        # Emitter sends both audit and usage payloads.
        handler_cls = server.RequestHandlerClass
        requests = getattr(handler_cls, "requests")
        assert isinstance(requests, list)
        paths = [item[0] for item in requests]
        assert "/v1/audit/events:batch" in paths
        assert "/v1/metering/usage:batch" in paths
        assert any(item[2].get("Authorization") == "Bearer test-token" for item in requests)
        daemon_status = _fetch_json(f"http://127.0.0.1:{daemon.bound_port}/status")
        assert daemon_status["control_plane_emitter_attached"] is True
        assert int(daemon_status["control_plane_audit_push_success_count"]) >= 1
        assert int(daemon_status["control_plane_usage_push_success_count"]) >= 1
        assert int(daemon_status["control_plane_audit_push_failure_count"]) == 0
        assert int(daemon_status["control_plane_usage_push_failure_count"]) == 0
    finally:
        if daemon is not None:
            daemon.stop()
        server.shutdown()
        server.server_close()


def test_daemon_identity_mode_local_idp_builder() -> None:
    os.environ["LOCAL_IDP_SIGNING_KEY"] = "daemon-local-idp-key"
    args = Namespace(
        identity_mode="local-idp",
        idp_token_ttl_s=120,
        local_idp_issuer="http://localhost/local-idp",
        local_idp_audience="api://predicate-authority",
        local_idp_signing_key_env="LOCAL_IDP_SIGNING_KEY",
        oidc_issuer=None,
        oidc_client_id=None,
        oidc_audience=None,
        entra_tenant_id=None,
        entra_client_id=None,
        entra_audience=None,
    )
    bridge = _build_identity_bridge_from_args(args)
    token = bridge.exchange_token(
        PrincipalRef(principal_id="agent:test"),
        StateEvidence(source="test", state_hash="state-1"),
    )
    assert token.provider.value == "local_idp"
    assert len(token.access_token.split(".")) == 3
