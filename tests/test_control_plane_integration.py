from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from predicate_authority.control_plane import (
    AuditEventEnvelope,
    ControlPlaneClient,
    ControlPlaneClientConfig,
    ControlPlaneTraceEmitter,
    UsageCreditRecord,
)
from predicate_contracts import AuthorizationReason, ProofEvent


@dataclass
class Recorder:
    paths: list[str] = field(default_factory=list)
    payloads: list[dict[str, Any]] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)


class _Handler(BaseHTTPRequestHandler):
    recorder: Recorder

    def do_POST(self) -> None:  # noqa: N802
        raw_length = self.headers.get("Content-Length", "0")
        content_length = int(raw_length) if raw_length.isdigit() else 0
        content = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        payload = json.loads(content)
        assert isinstance(payload, dict)
        self.recorder.paths.append(self.path)
        self.recorder.payloads.append(payload)
        self.recorder.headers.append(dict(self.headers.items()))

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def _start_server(recorder: Recorder) -> tuple[ThreadingHTTPServer, threading.Thread]:
    class BoundHandler(_Handler):
        pass

    BoundHandler.recorder = recorder
    server = ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_control_plane_client_posts_audit_and_usage() -> None:
    recorder = Recorder()
    server, _ = _start_server(recorder)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = ControlPlaneClient(
            ControlPlaneClientConfig(
                base_url=base_url,
                tenant_id="tenant-a",
                project_id="project-a",
                auth_token="token-123",
                fail_open=False,
            )
        )
        sent_audit = client.send_audit_events(
            (
                AuditEventEnvelope(
                    event_id="evt_1",
                    tenant_id="tenant-a",
                    principal_id="agent:orders-1",
                    action="http.post",
                    resource="https://api.vendor.com/orders",
                    allowed=True,
                    reason="allowed",
                    timestamp="2026-01-01T00:00:00+00:00",
                ),
            )
        )
        sent_usage = client.send_usage_records(
            (
                UsageCreditRecord(
                    tenant_id="tenant-a",
                    project_id="project-a",
                    action_type="authority_check",
                    credits=1,
                    timestamp="2026-01-01T00:00:00+00:00",
                ),
            )
        )
        assert sent_audit is True
        assert sent_usage is True
        assert "/v1/audit/events:batch" in recorder.paths
        assert "/v1/metering/usage:batch" in recorder.paths
        assert any(
            headers.get("Authorization") == "Bearer token-123" for headers in recorder.headers
        )
        assert all("X-PA-Nonce" in headers for headers in recorder.headers)
        assert all("X-PA-Timestamp" in headers for headers in recorder.headers)
        assert all("X-PA-Idempotency-Token" in headers for headers in recorder.headers)
    finally:
        server.shutdown()
        server.server_close()


def test_control_plane_trace_emitter_sends_from_proof_event() -> None:
    recorder = Recorder()
    server, _ = _start_server(recorder)
    try:
        client = ControlPlaneClient(
            ControlPlaneClientConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                tenant_id="tenant-z",
                project_id="project-z",
                fail_open=False,
            )
        )
        emitter = ControlPlaneTraceEmitter(client=client, trace_id="trace-1")
        event = ProofEvent(
            event_type="authority.decision",
            principal_id="agent:test",
            action="http.post",
            resource="https://api.vendor.com/orders",
            reason=AuthorizationReason.ALLOWED,
            allowed=True,
            mandate_id="mandate-1",
            emitted_at_epoch_s=1_700_000_000,
        )
        emitter.emit(event)
        assert len(recorder.paths) == 2
        assert recorder.paths[0] == "/v1/audit/events:batch"
        assert recorder.paths[1] == "/v1/metering/usage:batch"
        events_payload = recorder.payloads[0]["events"]
        assert isinstance(events_payload, list)
        assert events_payload[0]["tenant_id"] == "tenant-z"
    finally:
        server.shutdown()
        server.server_close()


def test_control_plane_client_includes_replay_signature_when_configured() -> None:
    recorder = Recorder()
    server, _ = _start_server(recorder)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = ControlPlaneClient(
            ControlPlaneClientConfig(
                base_url=base_url,
                tenant_id="tenant-a",
                project_id="project-a",
                replay_signing_secret="test-replay-secret",
                fail_open=False,
            )
        )
        sent = client.send_audit_events(
            (
                AuditEventEnvelope(
                    event_id="evt_1",
                    tenant_id="tenant-a",
                    principal_id="agent:orders-1",
                    action="http.post",
                    resource="https://api.vendor.com/orders",
                    allowed=True,
                    reason="allowed",
                    timestamp="2026-01-01T00:00:00+00:00",
                ),
            )
        )
        assert sent is True
        assert len(recorder.headers) == 1
        assert "X-PA-Signature" in recorder.headers[0]
    finally:
        server.shutdown()
        server.server_close()


def test_control_plane_client_fail_open_returns_false() -> None:
    client = ControlPlaneClient(
        ControlPlaneClientConfig(
            base_url="http://127.0.0.1:65531",
            tenant_id="tenant-a",
            project_id="project-a",
            max_retries=0,
            fail_open=True,
        )
    )
    result = client.send_audit_events(
        (
            AuditEventEnvelope(
                event_id="evt_1",
                tenant_id="tenant-a",
                principal_id="agent:1",
                action="http.post",
                resource="https://api.vendor.com/orders",
                allowed=True,
                reason="allowed",
                timestamp="2026-01-01T00:00:00+00:00",
            ),
        )
    )
    assert result is False
