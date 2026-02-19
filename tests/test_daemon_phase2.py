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

import pytest

# pylint: disable=import-error
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
    FlushWorkerConfig,
    LocalIdentityBootstrapConfig,
    _build_default_sidecar,
    _build_identity_bridge_from_args,
    _validate_ttl_alignment,
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


def _post_json(url: str, body: dict[str, object] | None = None) -> dict[str, object]:
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


def _fetch_text(url: str) -> str:
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
    return payload


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


def test_daemon_exposes_prometheus_metrics_endpoint(tmp_path: Path) -> None:
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
    sidecar = _build_sidecar(tmp_path, policy_file)
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=0.05),
    )
    daemon.start()
    try:
        request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:metrics"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="create order",
            ),
            state_evidence=StateEvidence(source="test", state_hash="metrics-state"),
            verification_evidence=VerificationEvidence(),
        )
        decision = sidecar.issue_mandate(request)
        assert decision.allowed is True
        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        metrics = _fetch_text(f"{base_url}/metrics")
        assert "predicate_authority_daemon_up 1" in metrics
        assert 'predicate_authority_authz_decision_total{outcome="allow"} 1' in metrics
        assert "predicate_authority_proof_event_total 1" in metrics
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
    sidecar = _build_sidecar(tmp_path, policy_file)
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=10.0),
    )
    daemon.start()
    try:
        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:test"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="create order",
            ),
            state_evidence=StateEvidence(source="test", state_hash="state-1"),
            verification_evidence=VerificationEvidence(),
        )
        decision = sidecar.issue_mandate(request)
        assert decision.allowed is True
        assert decision.mandate is not None

        reloaded = _post_json(f"{base_url}/policy/reload")
        revoke_principal = _post_json(
            f"{base_url}/revoke/principal", {"principal_id": "agent:test-revoked"}
        )
        revoke_intent = _post_json(
            f"{base_url}/revoke/intent",
            {"intent_hash": "abc123-intent-hash"},
        )
        revoke_mandate = _post_json(
            f"{base_url}/revoke/mandate",
            {"mandate_id": decision.mandate.claims.mandate_id},
        )
        status = _fetch_json(f"{base_url}/status")

        assert "reloaded" in reloaded
        assert revoke_principal["ok"] is True
        assert revoke_intent["ok"] is True
        assert revoke_mandate["ok"] is True
        assert int(status["revoked_principal_count"]) >= 1
        assert int(status["revoked_intent_count"]) >= 1
        assert int(status["revoked_mandate_count"]) >= 1
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

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        _ = fmt
        return


def _start_control_plane_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    class BoundHandler(_ControlPlaneHandler):
        requests = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _start_partitionable_control_plane_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    class PartitionableHandler(BaseHTTPRequestHandler):
        requests: list[tuple[str, dict[str, object], dict[str, str]]] = []
        fail_mode = False

        def do_POST(self) -> None:  # noqa: N802
            raw_length = self.headers.get("Content-Length", "0")
            content_length = int(raw_length) if raw_length.isdigit() else 0
            payload_raw = (
                self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            )
            loaded = json.loads(payload_raw)
            assert isinstance(loaded, dict)
            self.requests.append((self.path, loaded, dict(self.headers.items())))
            if self.fail_mode:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"partition"}')
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            _ = fmt
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), PartitionableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _start_failing_control_plane_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    class FailingHandler(BaseHTTPRequestHandler):
        requests: list[tuple[str, dict[str, object], dict[str, str]]] = []

        def do_POST(self) -> None:  # noqa: N802
            raw_length = self.headers.get("Content-Length", "0")
            content_length = int(raw_length) if raw_length.isdigit() else 0
            payload_raw = (
                self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            )
            loaded = json.loads(payload_raw)
            assert isinstance(loaded, dict)
            self.requests.append((self.path, loaded, dict(self.headers.items())))
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"temporary_failure"}')

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            _ = fmt
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), FailingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _start_sync_control_plane_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    class SyncHandler(BaseHTTPRequestHandler):
        requests: list[str] = []

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path != "/v1/sync/authority-updates":
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"not_found"}')
                return
            self.requests.append(self.path)
            query = parsed.query
            changed = "current_token=sync-v1" not in query
            payload = {
                "changed": changed,
                "sync_token": "sync-v1",
                "tenant_id": "tenant-sync",
                "project_id": "project-sync",
                "environment": "prod",
                "policy_id": "pol-sync-1",
                "policy_revision": 1,
                "policy_document": {
                    "rules": [
                        {
                            "name": "allow-sync-http",
                            "effect": "allow",
                            "principals": ["agent:*"],
                            "actions": ["http.*"],
                            "resources": ["https://*/*"],
                        }
                    ]
                },
                "revocations": [
                    {
                        "revocation_id": "rev-sync-1",
                        "tenant_id": "tenant-sync",
                        "type": "principal",
                        "principal_id": "agent:sync-revoked",
                        "intent_hash": None,
                        "tags": [],
                        "reason": "incident",
                        "created_at": "2026-02-19T00:00:00+00:00",
                    }
                ],
            }
            if not changed:
                payload["revocations"] = []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode("utf-8"))

        def do_POST(self) -> None:  # noqa: N802
            raw_length = self.headers.get("Content-Length", "0")
            content_length = int(raw_length) if raw_length.isdigit() else 0
            _ = self.rfile.read(content_length) if content_length > 0 else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            _ = fmt
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), SyncHandler)
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


def test_daemon_long_poll_sync_applies_policy_and_revocations(tmp_path: Path) -> None:
    server, _ = _start_sync_control_plane_server()
    daemon: PredicateAuthorityDaemon | None = None
    try:
        sidecar = _build_default_sidecar(
            mode=AuthorityMode.CLOUD_CONNECTED,
            policy_file=None,
            credential_store_file=str(tmp_path / "credentials.json"),
            control_plane_config=ControlPlaneBootstrapConfig(
                enabled=True,
                base_url=f"http://127.0.0.1:{server.server_port}",
                tenant_id="tenant-sync",
                project_id="project-sync",
                auth_token="token-sync",
                fail_open=False,
                sync_enabled=True,
                sync_wait_timeout_s=0.2,
                sync_poll_interval_ms=50,
                sync_project_id="project-sync",
                sync_environment="prod",
            ),
        )
        daemon = PredicateAuthorityDaemon(
            sidecar=sidecar,
            config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=1.0),
        )
        daemon.start()

        status_url = f"http://127.0.0.1:{daemon.bound_port}/status"
        deadline = time.time() + 2.0
        while time.time() < deadline:
            status = _fetch_json(status_url)
            if int(status["control_plane_sync_update_count"]) >= 1:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("control-plane sync update was not applied in time")

        allowed_request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:sync-ok"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="sync path",
            ),
            state_evidence=StateEvidence(source="test", state_hash="sync-allow"),
            verification_evidence=VerificationEvidence(),
        )
        allowed = sidecar.issue_mandate(allowed_request)
        assert allowed.allowed is True

        revoked_request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:sync-revoked"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="sync path revoked",
            ),
            state_evidence=StateEvidence(source="test", state_hash="sync-deny"),
            verification_evidence=VerificationEvidence(),
        )
        denied = sidecar.issue_mandate(revoked_request)
        assert denied.allowed is False
        assert denied.reason.value == "invalid_mandate"

        metrics = _fetch_text(f"http://127.0.0.1:{daemon.bound_port}/metrics")
        assert 'predicate_authority_control_plane_sync_total{result="poll"}' in metrics
        assert 'predicate_authority_control_plane_sync_total{result="update"} 1' in metrics
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


def test_daemon_identity_mode_okta_builder() -> None:
    args = Namespace(
        mode="local_only",
        identity_mode="okta",
        allow_local_fallback=False,
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
        okta_issuer="https://dev-123456.okta.com/oauth2/default",
        okta_client_id="okta-client-id",
        okta_audience="api://predicate-authority",
    )
    bridge = _build_identity_bridge_from_args(args)
    token = bridge.exchange_token(
        PrincipalRef(principal_id="agent:test"),
        StateEvidence(source="test", state_hash="state-1"),
    )
    assert token.provider.value == "okta"


def test_daemon_identity_mode_okta_builder_maps_claim_scope_role_config() -> None:
    args = Namespace(
        mode="local_only",
        identity_mode="okta",
        allow_local_fallback=False,
        idp_token_ttl_s=300,
        local_idp_issuer="http://localhost/local-idp",
        local_idp_audience="api://predicate-authority",
        local_idp_signing_key_env="LOCAL_IDP_SIGNING_KEY",
        oidc_issuer=None,
        oidc_client_id=None,
        oidc_audience=None,
        entra_tenant_id=None,
        entra_client_id=None,
        entra_audience=None,
        okta_issuer="https://dev-123456.okta.com/oauth2/default",
        okta_client_id="okta-client-id",
        okta_audience="api://predicate-authority",
        okta_required_claims=["sub,tenant_id"],
        okta_allowed_tenants=["tenant-a"],
        okta_required_scopes=["authority:check"],
        okta_required_roles=["authority-operator"],
        okta_tenant_claim="tenant_id",
        okta_scope_claim="scope",
        okta_role_claim="groups",
    )
    bridge = _build_identity_bridge_from_args(args)
    token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0."
        "eyJpc3MiOiJodHRwczovL2Rldi0xMjM0NTYub2t0YS5jb20vb2F1dGgyL2RlZmF1bHQiLCJhdWQiOiJhcGk6Ly9wcmVkaWNhdGUtYXV0aG9yaXR5Iiwic3ViIjoiYWdlbnQ6dGVzdCIsInRlbmFudF9pZCI6InRlbmFudC1hIiwic2NvcGUiOiJhdXRob3JpdHk6Y2hlY2siLCJncm91cHMiOlsiYXV0aG9yaXR5LW9wZXJhdG9yIl0sImV4cCI6MTEwMCwiaWF0IjoxMDAwfQ."
        "eyJzaWciOiJ0ZXN0In0"
    )
    assert hasattr(bridge, "validate_token_claims")
    bridge.validate_token_claims(token, now_epoch_s=1000)  # type: ignore[attr-defined]


def test_validate_ttl_alignment_rejects_idp_shorter_than_mandate() -> None:
    with pytest.raises(SystemExit):
        _validate_ttl_alignment(idp_token_ttl_s=120, mandate_ttl_s=300)


def test_validate_ttl_alignment_accepts_aligned_values() -> None:
    _validate_ttl_alignment(idp_token_ttl_s=300, mandate_ttl_s=300)


def test_daemon_identity_mode_okta_requires_args() -> None:
    args = Namespace(
        mode="local_only",
        identity_mode="okta",
        allow_local_fallback=False,
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
        okta_issuer=None,
        okta_client_id="okta-client-id",
        okta_audience="api://predicate-authority",
    )
    with pytest.raises(SystemExit):
        _build_identity_bridge_from_args(args)


def test_daemon_cloud_connected_local_identity_requires_explicit_fallback() -> None:
    args = Namespace(
        mode="cloud_connected",
        identity_mode="local",
        allow_local_fallback=False,
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
        okta_issuer=None,
        okta_client_id=None,
        okta_audience=None,
    )
    with pytest.raises(SystemExit):
        _build_identity_bridge_from_args(args)


def test_daemon_cloud_connected_local_identity_allows_with_explicit_fallback() -> None:
    args = Namespace(
        mode="cloud_connected",
        identity_mode="local",
        allow_local_fallback=True,
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
        okta_issuer=None,
        okta_client_id=None,
        okta_audience=None,
    )
    bridge = _build_identity_bridge_from_args(args)
    token = bridge.exchange_token(
        PrincipalRef(principal_id="agent:test"),
        StateEvidence(source="test", state_hash="state-1"),
    )
    assert token.provider.value == "local"


def test_daemon_local_identity_registry_endpoints(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"rules": []}), encoding="utf-8")
    sidecar = _build_default_sidecar(
        mode=AuthorityMode.LOCAL_ONLY,
        policy_file=str(policy_file),
        credential_store_file=str(tmp_path / "credentials.json"),
        local_identity_config=LocalIdentityBootstrapConfig(
            enabled=True,
            registry_file_path=str(tmp_path / "local-identities.json"),
            default_ttl_seconds=60,
        ),
    )
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=10.0),
    )
    daemon.start()
    try:
        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        created = _post_json(
            f"{base_url}/identity/task",
            {"principal_id": "agent:local", "task_id": "task-abc", "ttl_seconds": "60"},
        )
        listed = _fetch_json(f"{base_url}/identity/list")
        status = _fetch_json(f"{base_url}/status")
        identity_id = str(created["identity_id"])
        revoked = _post_json(f"{base_url}/identity/revoke", {"identity_id": identity_id})

        assert created["principal_id"] == "agent:local"
        assert isinstance(listed.get("items"), list)
        assert status["local_identity_registry_enabled"] is True
        assert int(status["local_identity_total_count"]) >= 1
        assert revoked["ok"] is True
    finally:
        daemon.stop()


def test_daemon_background_flush_worker_drains_local_queue(tmp_path: Path) -> None:
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
        sidecar = _build_default_sidecar(
            mode=AuthorityMode.LOCAL_ONLY,
            policy_file=str(policy_file),
            credential_store_file=str(tmp_path / "credentials.json"),
            control_plane_config=ControlPlaneBootstrapConfig(
                enabled=True,
                base_url=f"http://127.0.0.1:{server.server_port}",
                tenant_id="tenant-a",
                project_id="project-a",
                auth_token="token-a",
                fail_open=False,
            ),
            local_identity_config=LocalIdentityBootstrapConfig(
                enabled=True,
                registry_file_path=str(tmp_path / "local-identities.json"),
                default_ttl_seconds=60,
            ),
        )
        daemon = PredicateAuthorityDaemon(
            sidecar=sidecar,
            config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=0.1),
            flush_worker=FlushWorkerConfig(enabled=True, interval_s=0.1, max_batch_size=20),
        )
        daemon.start()
        request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:flush"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="create order",
            ),
            state_evidence=StateEvidence(source="test", state_hash="flush-state"),
            verification_evidence=VerificationEvidence(),
        )
        decision = sidecar.issue_mandate(request)
        assert decision.allowed is True

        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        deadline = time.time() + 3.0
        while time.time() < deadline:
            status = _fetch_json(f"{base_url}/status")
            if int(status["local_flush_queue_flushed_count"]) >= 1:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Flush worker did not flush local queue within timeout.")

        status = _fetch_json(f"{base_url}/status")
        assert int(status["flush_sent_count"]) >= 1
        assert int(status["local_flush_queue_pending_count"]) == 0
        assert int(status["local_flush_queue_flushed_count"]) >= 1
        # Immediate control-plane push + queue-flush push should both hit audit endpoint.
        handler_cls = server.RequestHandlerClass
        requests = getattr(handler_cls, "requests")
        assert isinstance(requests, list)
        audit_posts = [item for item in requests if item[0] == "/v1/audit/events:batch"]
        assert len(audit_posts) >= 2
    finally:
        if daemon is not None:
            daemon.stop()
        server.shutdown()
        server.server_close()


def test_daemon_manual_flush_endpoint_drains_queue(tmp_path: Path) -> None:
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
        sidecar = _build_default_sidecar(
            mode=AuthorityMode.LOCAL_ONLY,
            policy_file=str(policy_file),
            credential_store_file=str(tmp_path / "credentials.json"),
            control_plane_config=ControlPlaneBootstrapConfig(
                enabled=True,
                base_url=f"http://127.0.0.1:{server.server_port}",
                tenant_id="tenant-a",
                project_id="project-a",
                auth_token="token-a",
                fail_open=False,
            ),
            local_identity_config=LocalIdentityBootstrapConfig(
                enabled=True,
                registry_file_path=str(tmp_path / "local-identities.json"),
                default_ttl_seconds=60,
            ),
        )
        daemon = PredicateAuthorityDaemon(
            sidecar=sidecar,
            config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=10.0),
            flush_worker=FlushWorkerConfig(enabled=False, interval_s=5.0, max_batch_size=20),
        )
        daemon.start()
        request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:manual-flush"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="create order",
            ),
            state_evidence=StateEvidence(source="test", state_hash="manual-flush"),
            verification_evidence=VerificationEvidence(),
        )
        decision = sidecar.issue_mandate(request)
        assert decision.allowed is True

        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        before = _fetch_json(f"{base_url}/ledger/flush-queue")
        assert len(before.get("items", [])) == 1

        result = _post_json(f"{base_url}/ledger/flush-now", {"max_items": 5})
        assert result["ok"] is True
        assert int(result["sent_count"]) >= 1

        after = _fetch_json(f"{base_url}/ledger/flush-queue")
        assert len(after.get("items", [])) == 0
    finally:
        if daemon is not None:
            daemon.stop()
        server.shutdown()
        server.server_close()


def test_dead_letter_threshold_quarantines_queue_items(tmp_path: Path) -> None:
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
    server, _ = _start_failing_control_plane_server()
    daemon: PredicateAuthorityDaemon | None = None
    try:
        sidecar = _build_default_sidecar(
            mode=AuthorityMode.LOCAL_ONLY,
            policy_file=str(policy_file),
            credential_store_file=str(tmp_path / "credentials.json"),
            control_plane_config=ControlPlaneBootstrapConfig(
                enabled=True,
                base_url=f"http://127.0.0.1:{server.server_port}",
                tenant_id="tenant-a",
                project_id="project-a",
                auth_token="token-a",
                fail_open=True,
            ),
            local_identity_config=LocalIdentityBootstrapConfig(
                enabled=True,
                registry_file_path=str(tmp_path / "local-identities.json"),
                default_ttl_seconds=60,
            ),
        )
        daemon = PredicateAuthorityDaemon(
            sidecar=sidecar,
            config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=10.0),
            flush_worker=FlushWorkerConfig(
                enabled=False,
                interval_s=5.0,
                max_batch_size=20,
                dead_letter_max_attempts=1,
            ),
        )
        daemon.start()
        request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:dead-letter"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="create order",
            ),
            state_evidence=StateEvidence(source="test", state_hash="dead-letter-state"),
            verification_evidence=VerificationEvidence(),
        )
        decision = sidecar.issue_mandate(request)
        assert decision.allowed is True

        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        flush_result = _post_json(f"{base_url}/ledger/flush-now", {"max_items": 10})
        assert int(flush_result["failed_count"]) >= 1
        assert int(flush_result["quarantined_count"]) >= 1

        queue_default = _fetch_json(f"{base_url}/ledger/flush-queue")
        assert len(queue_default.get("items", [])) == 0
        queue_with_quarantine = _fetch_json(
            f"{base_url}/ledger/flush-queue?include_quarantined=true"
        )
        items = queue_with_quarantine.get("items", [])
        assert isinstance(items, list)
        assert len(items) >= 1
        first_item = items[0]
        assert isinstance(first_item, dict)
        assert first_item.get("quarantined") is True
        queue_item_id = str(first_item["queue_item_id"])

        dead_letter = _fetch_json(f"{base_url}/ledger/dead-letter")
        dead_letter_items = dead_letter.get("items", [])
        assert isinstance(dead_letter_items, list)
        assert len(dead_letter_items) >= 1
        assert all(
            bool(item.get("quarantined", False))
            for item in dead_letter_items
            if isinstance(item, dict)
        )
        status_before_requeue = _fetch_json(f"{base_url}/status")
        assert int(status_before_requeue["flush_quarantined_count"]) >= 1
        assert int(status_before_requeue["local_flush_queue_quarantined_count"]) >= 1

        requeued = _post_json(f"{base_url}/ledger/requeue", {"queue_item_id": queue_item_id})
        assert requeued["ok"] is True

        dead_letter_after = _fetch_json(f"{base_url}/ledger/dead-letter")
        dead_letter_after_items = dead_letter_after.get("items", [])
        assert isinstance(dead_letter_after_items, list)
        assert len(dead_letter_after_items) == 0
        pending_after = _fetch_json(f"{base_url}/ledger/flush-queue")
        pending_items_after = pending_after.get("items", [])
        assert isinstance(pending_items_after, list)
        assert len(pending_items_after) >= 1

        status = _fetch_json(f"{base_url}/status")
        assert int(status["flush_quarantined_count"]) >= 1
        assert int(status["local_flush_queue_quarantined_count"]) == 0
    finally:
        if daemon is not None:
            daemon.stop()
        server.shutdown()
        server.server_close()


def test_daemon_network_partition_fail_closed_raises_and_tracks_failure(tmp_path: Path) -> None:
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
    server, _ = _start_partitionable_control_plane_server()
    daemon: PredicateAuthorityDaemon | None = None
    try:
        sidecar = _build_default_sidecar(
            mode=AuthorityMode.LOCAL_ONLY,
            policy_file=str(policy_file),
            credential_store_file=str(tmp_path / "credentials.json"),
            control_plane_config=ControlPlaneBootstrapConfig(
                enabled=True,
                base_url=f"http://127.0.0.1:{server.server_port}",
                tenant_id="tenant-a",
                project_id="project-a",
                auth_token="token-a",
                fail_open=False,
                max_retries=0,
            ),
        )
        daemon = PredicateAuthorityDaemon(
            sidecar=sidecar,
            config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=10.0),
        )
        daemon.start()
        request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:partition"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="create order",
            ),
            state_evidence=StateEvidence(source="test", state_hash="partition-state"),
            verification_evidence=VerificationEvidence(),
        )

        warmup = sidecar.issue_mandate(request)
        assert warmup.allowed is True

        handler_cls = server.RequestHandlerClass
        setattr(handler_cls, "fail_mode", True)

        try:
            _ = sidecar.issue_mandate(request)
            raise AssertionError("Expected fail-closed control-plane error during partition.")
        except RuntimeError as exc:
            assert "control-plane request failed" in str(exc)

        status = _fetch_json(f"http://127.0.0.1:{daemon.bound_port}/status")
        assert int(status["control_plane_audit_push_failure_count"]) >= 1
        assert status["control_plane_last_push_error"] is not None
    finally:
        if daemon is not None:
            daemon.stop()
        server.shutdown()
        server.server_close()


def test_daemon_restart_recovers_queue_after_partition(tmp_path: Path) -> None:
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
    registry_file = tmp_path / "local-identities.json"
    failing_server, _ = _start_failing_control_plane_server()
    daemon: PredicateAuthorityDaemon | None = None
    try:
        sidecar = _build_default_sidecar(
            mode=AuthorityMode.LOCAL_ONLY,
            policy_file=str(policy_file),
            credential_store_file=str(tmp_path / "credentials.json"),
            control_plane_config=ControlPlaneBootstrapConfig(
                enabled=True,
                base_url=f"http://127.0.0.1:{failing_server.server_port}",
                tenant_id="tenant-a",
                project_id="project-a",
                auth_token="token-a",
                fail_open=True,
                max_retries=0,
            ),
            local_identity_config=LocalIdentityBootstrapConfig(
                enabled=True,
                registry_file_path=str(registry_file),
                default_ttl_seconds=60,
            ),
        )
        daemon = PredicateAuthorityDaemon(
            sidecar=sidecar,
            config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=10.0),
            flush_worker=FlushWorkerConfig(enabled=False, interval_s=10.0, max_batch_size=20),
        )
        daemon.start()
        request = ActionRequest(
            principal=PrincipalRef(principal_id="agent:restart"),
            action_spec=ActionSpec(
                action="http.post",
                resource="https://api.vendor.com/orders",
                intent="create order",
            ),
            state_evidence=StateEvidence(source="test", state_hash="restart-state"),
            verification_evidence=VerificationEvidence(),
        )
        decision = sidecar.issue_mandate(request)
        assert decision.allowed is True
        base_url = f"http://127.0.0.1:{daemon.bound_port}"
        pending_before = _fetch_json(f"{base_url}/ledger/flush-queue")
        assert len(pending_before.get("items", [])) == 1
    finally:
        if daemon is not None:
            daemon.stop()
        failing_server.shutdown()
        failing_server.server_close()

    healthy_server, _ = _start_control_plane_server()
    daemon_after_restart: PredicateAuthorityDaemon | None = None
    try:
        restarted_sidecar = _build_default_sidecar(
            mode=AuthorityMode.LOCAL_ONLY,
            policy_file=str(policy_file),
            credential_store_file=str(tmp_path / "credentials.json"),
            control_plane_config=ControlPlaneBootstrapConfig(
                enabled=True,
                base_url=f"http://127.0.0.1:{healthy_server.server_port}",
                tenant_id="tenant-a",
                project_id="project-a",
                auth_token="token-a",
                fail_open=True,
                max_retries=0,
            ),
            local_identity_config=LocalIdentityBootstrapConfig(
                enabled=True,
                registry_file_path=str(registry_file),
                default_ttl_seconds=60,
            ),
        )
        daemon_after_restart = PredicateAuthorityDaemon(
            sidecar=restarted_sidecar,
            config=DaemonConfig(host="127.0.0.1", port=0, policy_poll_interval_s=10.0),
            flush_worker=FlushWorkerConfig(enabled=False, interval_s=10.0, max_batch_size=20),
        )
        daemon_after_restart.start()
        base_url = f"http://127.0.0.1:{daemon_after_restart.bound_port}"
        flush_result = _post_json(f"{base_url}/ledger/flush-now", {"max_items": 10})
        assert flush_result["ok"] is True
        assert int(flush_result["sent_count"]) >= 1
        pending_after = _fetch_json(f"{base_url}/ledger/flush-queue")
        assert len(pending_after.get("items", [])) == 0
    finally:
        if daemon_after_restart is not None:
            daemon_after_restart.stop()
        healthy_server.shutdown()
        healthy_server.server_close()
