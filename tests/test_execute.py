"""
Tests for Phase 5: Execution Proxying (Zero-Trust) types and SidecarClient.
"""

from __future__ import annotations

import os

import pytest

from predicate_contracts import (
    CliExecPayload,
    CliExecResult,
    ExecuteErrorCode,
    ExecuteRequest,
    ExecuteResponse,
    FileReadResult,
    FileWritePayload,
    FileWriteResult,
    HttpFetchPayload,
    HttpFetchResult,
)


class TestExecuteTypes:
    """Tests for execute types serialization and dataclass behavior."""

    def test_execute_request_without_payload(self) -> None:
        request = ExecuteRequest(
            mandate_id="m_abc123",
            action="fs.read",
            resource="/src/index.ts",
        )
        assert request.mandate_id == "m_abc123"
        assert request.action == "fs.read"
        assert request.resource == "/src/index.ts"
        assert request.payload is None

    def test_execute_request_with_file_write_payload(self) -> None:
        payload = FileWritePayload(
            content="hello world",
            create=True,
            append=False,
        )
        request = ExecuteRequest(
            mandate_id="m_xyz789",
            action="fs.write",
            resource="/tmp/test.txt",
            payload=payload,
        )
        assert isinstance(request.payload, FileWritePayload)
        assert request.payload.content == "hello world"
        assert request.payload.create is True

    def test_execute_request_with_cli_exec_payload(self) -> None:
        payload = CliExecPayload(
            command="ls",
            args=("-la",),
            cwd="/tmp",
            timeout_ms=5000,
        )
        request = ExecuteRequest(
            mandate_id="m_cli456",
            action="cli.exec",
            resource="ls",
            payload=payload,
        )
        assert isinstance(request.payload, CliExecPayload)
        assert request.payload.command == "ls"
        assert request.payload.args == ("-la",)
        assert request.payload.cwd == "/tmp"
        assert request.payload.timeout_ms == 5000

    def test_execute_request_with_http_fetch_payload(self) -> None:
        payload = HttpFetchPayload(
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"key": "value"}',
        )
        request = ExecuteRequest(
            mandate_id="m_http789",
            action="http.fetch",
            resource="https://api.example.com/data",
            payload=payload,
        )
        assert isinstance(request.payload, HttpFetchPayload)
        assert request.payload.method == "POST"
        assert request.payload.headers == {"Content-Type": "application/json"}


class TestExecuteResults:
    """Tests for execute result types."""

    def test_file_read_result(self) -> None:
        result = FileReadResult(
            content="file content",
            size=12,
            content_hash="sha256:abc123",
        )
        assert result.content == "file content"
        assert result.size == 12
        assert result.content_hash == "sha256:abc123"

    def test_file_write_result(self) -> None:
        result = FileWriteResult(
            bytes_written=100,
            content_hash="sha256:def456",
        )
        assert result.bytes_written == 100
        assert result.content_hash == "sha256:def456"

    def test_cli_exec_result(self) -> None:
        result = CliExecResult(
            exit_code=0,
            stdout="output",
            stderr="",
            duration_ms=150,
        )
        assert result.exit_code == 0
        assert result.stdout == "output"
        assert result.stderr == ""
        assert result.duration_ms == 150

    def test_http_fetch_result(self) -> None:
        result = HttpFetchResult(
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"ok": true}',
            body_hash="sha256:xyz789",
        )
        assert result.status_code == 200
        assert result.headers == {"content-type": "application/json"}
        assert result.body == '{"ok": true}'
        assert result.body_hash == "sha256:xyz789"


class TestExecuteResponse:
    """Tests for ExecuteResponse."""

    def test_execute_response_success(self) -> None:
        result = FileReadResult(
            content="file content",
            size=12,
            content_hash="sha256:abc123",
        )
        response = ExecuteResponse(
            success=True,
            audit_id="exec_123",
            result=result,
            evidence_hash="sha256:def456",
        )
        assert response.success is True
        assert response.audit_id == "exec_123"
        assert isinstance(response.result, FileReadResult)
        assert response.error is None
        assert response.evidence_hash == "sha256:def456"

    def test_execute_response_failure(self) -> None:
        response = ExecuteResponse(
            success=False,
            audit_id="exec_456",
            error="Mandate not found",
        )
        assert response.success is False
        assert response.audit_id == "exec_456"
        assert response.result is None
        assert response.error == "Mandate not found"
        assert response.evidence_hash is None


class TestExecuteErrorCode:
    """Tests for ExecuteErrorCode enum."""

    def test_error_codes(self) -> None:
        assert ExecuteErrorCode.MANDATE_NOT_FOUND.value == "mandate_not_found"
        assert ExecuteErrorCode.MANDATE_EXPIRED.value == "mandate_expired"
        assert ExecuteErrorCode.ACTION_MISMATCH.value == "action_mismatch"
        assert ExecuteErrorCode.RESOURCE_MISMATCH.value == "resource_mismatch"
        assert ExecuteErrorCode.EXECUTION_FAILED.value == "execution_failed"
        assert ExecuteErrorCode.UNSUPPORTED_ACTION.value == "unsupported_action"
        assert ExecuteErrorCode.INVALID_PAYLOAD.value == "invalid_payload"


class TestSidecarClientWireFormat:
    """Tests for SidecarClient wire format conversion."""

    def test_execute_request_to_dict(self) -> None:
        from predicate_authority.sidecar_client import _execute_request_to_dict

        # Request without payload
        request = ExecuteRequest(
            mandate_id="m_abc123",
            action="fs.read",
            resource="/src/index.ts",
        )
        result = _execute_request_to_dict(request)
        assert result == {
            "mandate_id": "m_abc123",
            "action": "fs.read",
            "resource": "/src/index.ts",
        }

    def test_execute_request_to_dict_with_file_write_payload(self) -> None:
        from predicate_authority.sidecar_client import _execute_request_to_dict

        request = ExecuteRequest(
            mandate_id="m_xyz789",
            action="fs.write",
            resource="/tmp/test.txt",
            payload=FileWritePayload(content="hello", create=True, append=False),
        )
        result = _execute_request_to_dict(request)
        assert result["payload"] == {
            "type": "file_write",
            "content": "hello",
            "create": True,
            "append": False,
        }

    def test_execute_request_to_dict_with_cli_exec_payload(self) -> None:
        from predicate_authority.sidecar_client import _execute_request_to_dict

        request = ExecuteRequest(
            mandate_id="m_cli456",
            action="cli.exec",
            resource="ls",
            payload=CliExecPayload(command="ls", args=("-la",), cwd="/tmp", timeout_ms=5000),
        )
        result = _execute_request_to_dict(request)
        assert result["payload"] == {
            "type": "cli_exec",
            "command": "ls",
            "args": ["-la"],
            "cwd": "/tmp",
            "timeout_ms": 5000,
        }

    def test_execute_request_to_dict_with_http_fetch_payload(self) -> None:
        from predicate_authority.sidecar_client import _execute_request_to_dict

        request = ExecuteRequest(
            mandate_id="m_http789",
            action="http.fetch",
            resource="https://api.example.com/data",
            payload=HttpFetchPayload(
                method="POST",
                headers={"Content-Type": "application/json"},
                body='{"key": "value"}',
            ),
        )
        result = _execute_request_to_dict(request)
        assert result["payload"] == {
            "type": "http_fetch",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": '{"key": "value"}',
        }

    def test_parse_execute_response_file_read(self) -> None:
        from predicate_authority.sidecar_client import _parse_execute_response

        data = {
            "success": True,
            "audit_id": "exec_123",
            "result": {
                "type": "file_read",
                "content": "file content",
                "size": 12,
                "content_hash": "sha256:abc123",
            },
            "evidence_hash": "sha256:def456",
        }
        response = _parse_execute_response(data)
        assert response.success is True
        assert response.audit_id == "exec_123"
        assert isinstance(response.result, FileReadResult)
        assert response.result.content == "file content"
        assert response.evidence_hash == "sha256:def456"

    def test_parse_execute_response_cli_exec(self) -> None:
        from predicate_authority.sidecar_client import _parse_execute_response

        data = {
            "success": True,
            "audit_id": "exec_456",
            "result": {
                "type": "cli_exec",
                "exit_code": 0,
                "stdout": "output",
                "stderr": "",
                "duration_ms": 150,
            },
        }
        response = _parse_execute_response(data)
        assert response.success is True
        assert isinstance(response.result, CliExecResult)
        assert response.result.exit_code == 0
        assert response.result.stdout == "output"

    def test_parse_execute_response_failure(self) -> None:
        from predicate_authority.sidecar_client import _parse_execute_response

        data = {
            "success": False,
            "audit_id": "exec_789",
            "error": "Mandate not found",
        }
        response = _parse_execute_response(data)
        assert response.success is False
        assert response.audit_id == "exec_789"
        assert response.result is None
        assert response.error == "Mandate not found"


# Integration tests that require a running sidecar
@pytest.mark.skipif(
    os.environ.get("RUN_SIDECAR_INTEGRATION_TESTS") != "true"
    or not os.environ.get("SIDECAR_BASE_URL"),
    reason="Sidecar integration tests not enabled",
)
class TestSidecarClientIntegration:
    """Integration tests that require a running sidecar."""

    @pytest.fixture
    def client(self):
        from predicate_authority import SidecarClient, SidecarClientConfig

        base_url = os.environ.get("SIDECAR_BASE_URL", "http://127.0.0.1:8787")
        return SidecarClient(SidecarClientConfig(base_url=base_url))

    @pytest.mark.asyncio
    async def test_execute_returns_mandate_not_found_for_invalid_mandate(self, client) -> None:
        response = await client.execute(
            ExecuteRequest(
                mandate_id="m_nonexistent",
                action="fs.read",
                resource="/tmp/test.txt",
            )
        )
        assert response.success is False
        assert "not found" in (response.error or "").lower()
        await client.close()

    @pytest.mark.asyncio
    async def test_authorize_returns_decision(self, client) -> None:
        response = await client.authorize(
            principal="agent:test",
            action="http.get",
            resource="https://example.com",
        )
        # Response should have allowed status and reason
        assert isinstance(response.allowed, bool)
        assert isinstance(response.reason, str)
        await client.close()
