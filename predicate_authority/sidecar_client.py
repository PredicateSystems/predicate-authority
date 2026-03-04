"""
Sidecar HTTP client for Phase 5: Execution Proxying (Zero-Trust).

This client communicates with the predicate-authorityd sidecar via HTTP
to authorize and execute operations in a zero-trust manner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from predicate_contracts import (
    CliExecPayload,
    CliExecResult,
    DirectoryEntry,
    EnvReadPayload,
    EnvReadResult,
    ExecuteRequest,
    ExecuteResponse,
    FileDeletePayload,
    FileDeleteResult,
    FileListResult,
    FileReadResult,
    FileWritePayload,
    FileWriteResult,
    HttpFetchPayload,
    HttpFetchResult,
)


class SidecarClientError(Exception):
    """Error communicating with the sidecar."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "unknown",
        status: int | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details


@dataclass(frozen=True)
class SidecarClientConfig:
    """Configuration for the SidecarClient."""

    base_url: str = "http://127.0.0.1:8787"
    timeout_s: float = 2.0
    max_retries: int = 0
    backoff_initial_s: float = 0.2
    authorize_endpoint: str = "/v1/authorize"
    execute_endpoint: str = "/v1/execute"


@dataclass
class AuthorizationResponse:
    """Response from the /v1/authorize endpoint."""

    allowed: bool
    reason: str
    mandate_id: str | None = None
    missing_labels: list[str] = field(default_factory=list)


@dataclass
class AuthorizeAndExecuteOptions:
    """Options for authorize_and_execute convenience method."""

    principal: str
    action: str
    resource: str
    intent_hash: str | None = None
    labels: list[str] = field(default_factory=list)
    payload: FileWritePayload | CliExecPayload | HttpFetchPayload | None = None


class SidecarClient:
    """
    HTTP client for communicating with the predicate-authorityd sidecar.

    This client supports Phase 5 Execution Proxying (Zero-Trust) where the sidecar
    executes operations on behalf of agents, preventing "confused deputy" attacks.

    Example:
        >>> client = SidecarClient()
        >>> # Direct execute with existing mandate
        >>> response = await client.execute(ExecuteRequest(
        ...     mandate_id="m_abc123",
        ...     action="fs.read",
        ...     resource="/src/index.ts"
        ... ))
        >>> print(response.result)

        >>> # Combined authorize + execute
        >>> response = await client.authorize_and_execute(AuthorizeAndExecuteOptions(
        ...     principal="agent:web",
        ...     action="fs.read",
        ...     resource="/src/index.ts"
        ... ))
    """

    def __init__(self, config: SidecarClientConfig | None = None) -> None:
        self._config = config or SidecarClientConfig()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._config.base_url,
                timeout=self._config.timeout_s,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> SidecarClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def authorize(
        self,
        principal: str,
        action: str,
        resource: str,
        intent_hash: str | None = None,
        labels: list[str] | None = None,
    ) -> AuthorizationResponse:
        """
        Request authorization from the sidecar.

        Args:
            principal: The principal making the request (e.g., "agent:web")
            action: The action to perform (e.g., "fs.read")
            resource: The resource to operate on (e.g., "/src/index.ts")
            intent_hash: Optional intent hash for the mandate
            labels: Optional labels for authorization

        Returns:
            AuthorizationResponse with allowed status and mandate_id if allowed
        """
        client = await self._get_client()

        request_body = {
            "principal": principal,
            "action": action,
            "resource": resource,
            "intent_hash": intent_hash or f"{action}:{resource}",
            "labels": labels or [],
        }

        attempts = self._config.max_retries + 1
        last_error: Exception | None = None

        for attempt in range(attempts):
            try:
                response = await client.post(
                    self._config.authorize_endpoint,
                    json=request_body,
                )

                # Sidecar returns 403 for deny decisions with valid response body
                if response.status_code == 403:
                    data = response.json()
                    return AuthorizationResponse(
                        allowed=data.get("allowed", False),
                        reason=data.get("reason", "unknown"),
                        mandate_id=data.get("mandate_id"),
                        missing_labels=data.get("missing_labels", []),
                    )

                if response.status_code >= 500 and attempt < self._config.max_retries:
                    await self._backoff(attempt)
                    continue

                if not response.is_success:
                    raise SidecarClientError(
                        f"authorize request failed: {response.status_code}",
                        code="server_error" if response.status_code >= 500 else "client_error",
                        status=response.status_code,
                        details=response.text,
                    )

                data = response.json()
                return AuthorizationResponse(
                    allowed=data.get("allowed", False),
                    reason=data.get("reason", "unknown"),
                    mandate_id=data.get("mandate_id"),
                    missing_labels=data.get("missing_labels", []),
                )

            except httpx.TimeoutException as e:
                last_error = e
                if attempt < self._config.max_retries:
                    await self._backoff(attempt)
                    continue
                raise SidecarClientError(
                    "authorize request timed out",
                    code="timeout",
                ) from e
            except httpx.RequestError as e:
                last_error = e
                if attempt < self._config.max_retries:
                    await self._backoff(attempt)
                    continue
                raise SidecarClientError(
                    f"authorize request failed: {e}",
                    code="network_error",
                ) from e

        raise SidecarClientError(
            "authorize request exhausted retry budget",
            code="network_error",
        ) from last_error

    async def execute(self, request: ExecuteRequest) -> ExecuteResponse:
        """
        Execute an operation through the sidecar (Phase 5: Execution Proxying).

        The sidecar validates the mandate and executes the operation on behalf of
        the agent, preventing "confused deputy" attacks where an agent could request
        authorization for one resource but access another.

        Args:
            request: Execute request with mandate_id from prior authorization

        Returns:
            ExecuteResponse with success status and action-specific result
        """
        client = await self._get_client()

        request_body = _execute_request_to_dict(request)

        attempts = self._config.max_retries + 1
        last_error: Exception | None = None

        for attempt in range(attempts):
            try:
                response = await client.post(
                    self._config.execute_endpoint,
                    json=request_body,
                )

                # Execute may return 4xx with valid ExecuteResponse containing error info
                if response.status_code >= 400 and response.status_code < 500:
                    data = response.json()
                    if "success" in data and "audit_id" in data:
                        return _parse_execute_response(data)

                if response.status_code >= 500 and attempt < self._config.max_retries:
                    await self._backoff(attempt)
                    continue

                if not response.is_success:
                    raise SidecarClientError(
                        f"execute request failed: {response.status_code}",
                        code="server_error" if response.status_code >= 500 else "client_error",
                        status=response.status_code,
                        details=response.text,
                    )

                data = response.json()
                return _parse_execute_response(data)

            except httpx.TimeoutException as e:
                last_error = e
                if attempt < self._config.max_retries:
                    await self._backoff(attempt)
                    continue
                raise SidecarClientError(
                    "execute request timed out",
                    code="timeout",
                ) from e
            except httpx.RequestError as e:
                last_error = e
                if attempt < self._config.max_retries:
                    await self._backoff(attempt)
                    continue
                raise SidecarClientError(
                    f"execute request failed: {e}",
                    code="network_error",
                ) from e

        raise SidecarClientError(
            "execute request exhausted retry budget",
            code="network_error",
        ) from last_error

    async def authorize_and_execute(
        self,
        options: AuthorizeAndExecuteOptions,
    ) -> ExecuteResponse:
        """
        Convenience method that combines authorize + execute in a single call.

        This is the recommended pattern for zero-trust execution:
        1. Authorize the action and obtain a mandate
        2. Execute the operation through the sidecar using the mandate

        Args:
            options: Authorization and execution options

        Returns:
            ExecuteResponse with success status and action-specific result

        Raises:
            SidecarClientError: If authorization is denied or execution fails
        """
        # Step 1: Authorize and get mandate
        auth_response = await self.authorize(
            principal=options.principal,
            action=options.action,
            resource=options.resource,
            intent_hash=options.intent_hash,
            labels=options.labels,
        )

        if not auth_response.allowed:
            raise SidecarClientError(
                f"authorization denied: {auth_response.reason}",
                code="forbidden",
                details={
                    "reason": auth_response.reason,
                    "missing_labels": auth_response.missing_labels,
                },
            )

        if not auth_response.mandate_id:
            raise SidecarClientError(
                "authorization succeeded but no mandate_id returned",
                code="protocol_error",
                details={"auth_response": auth_response},
            )

        # Step 2: Execute through sidecar
        return await self.execute(
            ExecuteRequest(
                mandate_id=auth_response.mandate_id,
                action=options.action,
                resource=options.resource,
                payload=options.payload,
            )
        )

    async def _backoff(self, attempt: int) -> None:
        """Exponential backoff between retry attempts."""
        delay = self._config.backoff_initial_s * (attempt + 1)
        await _async_sleep(delay)


async def _async_sleep(seconds: float) -> None:
    """Async sleep helper."""
    import asyncio

    await asyncio.sleep(seconds)


def _execute_request_to_dict(request: ExecuteRequest) -> dict[str, Any]:
    """Convert ExecuteRequest to wire format dict."""
    result: dict[str, Any] = {
        "mandate_id": request.mandate_id,
        "action": request.action,
        "resource": request.resource,
    }

    if request.payload is not None:
        if isinstance(request.payload, FileWritePayload):
            result["payload"] = {
                "type": "file_write",
                "content": request.payload.content,
                "create": request.payload.create,
                "append": request.payload.append,
            }
        elif isinstance(request.payload, CliExecPayload):
            payload_dict: dict[str, Any] = {
                "type": "cli_exec",
                "command": request.payload.command,
                "args": list(request.payload.args),
            }
            if request.payload.cwd is not None:
                payload_dict["cwd"] = request.payload.cwd
            if request.payload.timeout_ms is not None:
                payload_dict["timeout_ms"] = request.payload.timeout_ms
            result["payload"] = payload_dict
        elif isinstance(request.payload, HttpFetchPayload):
            payload_dict = {
                "type": "http_fetch",
                "method": request.payload.method,
            }
            if request.payload.headers is not None:
                payload_dict["headers"] = request.payload.headers
            if request.payload.body is not None:
                payload_dict["body"] = request.payload.body
            result["payload"] = payload_dict
        elif isinstance(request.payload, FileDeletePayload):
            result["payload"] = {
                "type": "file_delete",
                "recursive": request.payload.recursive,
            }
        elif isinstance(request.payload, EnvReadPayload):
            result["payload"] = {
                "type": "env_read",
                "keys": list(request.payload.keys),
            }

    return result


def _parse_execute_response(data: dict[str, Any]) -> ExecuteResponse:
    """Parse execute response from wire format."""
    result: (
        FileReadResult
        | FileWriteResult
        | CliExecResult
        | HttpFetchResult
        | FileListResult
        | FileDeleteResult
        | EnvReadResult
        | None
    ) = None
    if "result" in data and data["result"] is not None:
        result_data = data["result"]
        result_type = result_data.get("type")

        if result_type == "file_read":
            result = FileReadResult(
                content=result_data["content"],
                size=result_data["size"],
                content_hash=result_data["content_hash"],
            )
        elif result_type == "file_write":
            result = FileWriteResult(
                bytes_written=result_data["bytes_written"],
                content_hash=result_data["content_hash"],
            )
        elif result_type == "cli_exec":
            result = CliExecResult(
                exit_code=result_data["exit_code"],
                stdout=result_data["stdout"],
                stderr=result_data["stderr"],
                duration_ms=result_data["duration_ms"],
            )
        elif result_type == "http_fetch":
            result = HttpFetchResult(
                status_code=result_data["status_code"],
                headers=result_data["headers"],
                body=result_data["body"],
                body_hash=result_data["body_hash"],
            )
        elif result_type == "file_list":
            entries = tuple(
                DirectoryEntry(
                    name=e["name"],
                    entry_type=e["type"],
                    size=e["size"],
                    modified=e.get("modified"),
                )
                for e in result_data["entries"]
            )
            result = FileListResult(
                entries=entries,
                total_entries=result_data["total_entries"],
            )
        elif result_type == "file_delete":
            result = FileDeleteResult(
                paths_removed=result_data["paths_removed"],
            )
        elif result_type == "env_read":
            result = EnvReadResult(
                values=result_data["values"],
            )

    return ExecuteResponse(
        success=data["success"],
        audit_id=data["audit_id"],
        result=result,
        error=data.get("error"),
        evidence_hash=data.get("evidence_hash"),
    )
