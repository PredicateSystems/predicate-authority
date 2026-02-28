"""
Post-execution verification module.

The Verifier class compares actual operations against what was
authorized via a mandate, detecting unauthorized deviations.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

import httpx

from predicate_authority.verify.comparators import actions_match, resources_match
from predicate_authority.verify.types import (
    ActualOperation,
    AuthorizedOperation,
    BrowserEvidence,
    CliEvidence,
    DbEvidence,
    ExecutionEvidence,
    FileEvidence,
    GenericEvidence,
    HttpEvidence,
    MandateDetails,
    RecordVerificationRequest,
    VerificationFailureReason,
    VerifyRequest,
    VerifyResult,
)


class MandateProvider(Protocol):
    """Interface for mandate retrieval."""

    def get_mandate(self, mandate_id: str) -> MandateDetails | None:
        """
        Retrieve mandate details by ID.

        Args:
            mandate_id: The mandate ID to look up

        Returns:
            Mandate details or None if not found
        """
        ...

    def record_verification(self, request: RecordVerificationRequest) -> str:
        """
        Record a verification result in the audit log.

        Args:
            request: Verification details to record

        Returns:
            Audit trail ID
        """
        ...


@dataclass
class VerifierOptions:
    """Options for creating a Verifier."""

    base_url: str
    """Base URL of the sidecar."""

    timeout_seconds: float = 2.0
    """Request timeout in seconds."""


class Verifier:
    """
    Verifier for post-execution authorization checks.

    Compares actual operations against mandates to detect unauthorized
    deviations from what was authorized.

    Example:
        >>> verifier = Verifier(base_url="http://127.0.0.1:8787")
        >>> result = verifier.verify(VerifyRequest(
        ...     mandate_id=decision.mandate_id,
        ...     actual=ActualOperation(
        ...         action="fs.read",
        ...         resource="/src/index.ts",
        ...     ),
        ... ))
        >>> if not result.verified:
        ...     print(f"Operation mismatch: {result.reason}")
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 2.0,
    ) -> None:
        """
        Initialize a Verifier.

        Args:
            base_url: Base URL of the sidecar
            timeout_seconds: Request timeout in seconds
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._client = httpx.Client(timeout=timeout_seconds)

    def verify(self, request: VerifyRequest) -> VerifyResult:
        """
        Verify that an actual operation matches its mandate.

        Args:
            request: Verification request with mandate ID and actual operation

        Returns:
            Verification result
        """
        # 1. Retrieve mandate details
        mandate = self.get_mandate(request.mandate_id)

        if mandate is None:
            return VerifyResult(
                verified=False,
                reason=VerificationFailureReason.MANDATE_NOT_FOUND,
            )

        # 2. Check mandate expiration
        expires_at = datetime.fromisoformat(mandate.expires_at.replace("Z", "+00:00"))
        if expires_at.timestamp() < time.time():
            return VerifyResult(
                verified=False,
                reason=VerificationFailureReason.MANDATE_EXPIRED,
            )

        # 3. Compare action
        if not actions_match(mandate.action, request.actual.action):
            result = VerifyResult(
                verified=False,
                reason=VerificationFailureReason.ACTION_MISMATCH,
                authorized=AuthorizedOperation(
                    action=mandate.action,
                    resource=mandate.resource,
                ),
                actual=request.actual,
            )

            # Record failed verification
            self.record_verification(
                RecordVerificationRequest(
                    mandate_id=request.mandate_id,
                    verified=False,
                    actual=request.actual,
                    reason=VerificationFailureReason.ACTION_MISMATCH,
                )
            )

            return result

        # 4. Compare resource (with normalization)
        if not resources_match(mandate.resource, request.actual.resource):
            result = VerifyResult(
                verified=False,
                reason=VerificationFailureReason.RESOURCE_MISMATCH,
                authorized=AuthorizedOperation(
                    action=mandate.action,
                    resource=mandate.resource,
                ),
                actual=request.actual,
            )

            # Record failed verification
            self.record_verification(
                RecordVerificationRequest(
                    mandate_id=request.mandate_id,
                    verified=False,
                    actual=request.actual,
                    reason=VerificationFailureReason.RESOURCE_MISMATCH,
                )
            )

            return result

        # 5. Record successful verification
        audit_id = self.record_verification(
            RecordVerificationRequest(
                mandate_id=request.mandate_id,
                verified=True,
                actual=request.actual,
            )
        )

        return VerifyResult(
            verified=True,
            audit_id=audit_id,
        )

    def verify_local(self, mandate: MandateDetails, request: VerifyRequest) -> VerifyResult:
        """
        Verify an operation locally without sidecar communication.

        Use this when the sidecar endpoints are not available yet (Phase 2).
        This performs the same matching logic but skips mandate retrieval
        and audit logging.

        Args:
            mandate: Known mandate details
            request: Verification request

        Returns:
            Verification result (without audit_id)
        """
        # Check mandate expiration
        expires_at = datetime.fromisoformat(mandate.expires_at.replace("Z", "+00:00"))
        if expires_at.timestamp() < time.time():
            return VerifyResult(
                verified=False,
                reason=VerificationFailureReason.MANDATE_EXPIRED,
            )

        # Compare action
        if not actions_match(mandate.action, request.actual.action):
            return VerifyResult(
                verified=False,
                reason=VerificationFailureReason.ACTION_MISMATCH,
                authorized=AuthorizedOperation(
                    action=mandate.action,
                    resource=mandate.resource,
                ),
                actual=request.actual,
            )

        # Compare resource
        if not resources_match(mandate.resource, request.actual.resource):
            return VerifyResult(
                verified=False,
                reason=VerificationFailureReason.RESOURCE_MISMATCH,
                authorized=AuthorizedOperation(
                    action=mandate.action,
                    resource=mandate.resource,
                ),
                actual=request.actual,
            )

        return VerifyResult(verified=True)

    def get_mandate(self, mandate_id: str) -> MandateDetails | None:
        """
        Retrieve mandate details from the sidecar.

        Args:
            mandate_id: Mandate ID to look up

        Returns:
            Mandate details or None if not found
        """
        try:
            response = self._client.get(
                f"{self._base_url}/v1/mandates/{mandate_id}",
                headers={"Accept": "application/json"},
            )

            if response.status_code == 404:
                return None

            response.raise_for_status()
            data = response.json()

            return MandateDetails(
                mandate_id=data["mandate_id"],
                principal=data["principal"],
                action=data["action"],
                resource=data["resource"],
                intent_hash=data["intent_hash"],
                issued_at=data["issued_at"],
                expires_at=data["expires_at"],
            )
        except httpx.HTTPError:
            raise
        except Exception:
            return None

    def record_verification(self, request: RecordVerificationRequest) -> str:
        """
        Record a verification result in the sidecar's audit log.

        Args:
            request: Verification details to record

        Returns:
            Audit trail ID
        """
        try:
            # Build actual payload based on evidence type
            actual_payload = self._build_actual_payload(request.actual)

            response = self._client.post(
                f"{self._base_url}/v1/verify",
                headers={"Content-Type": "application/json"},
                json={
                    "mandate_id": request.mandate_id,
                    "verified": request.verified,
                    "actual": actual_payload,
                    "reason": request.reason.value if request.reason else None,
                    "verified_at": datetime.utcnow().isoformat() + "Z",
                },
            )

            response.raise_for_status()
            data = response.json()

            if isinstance(data, dict) and "audit_id" in data:
                audit_id = data["audit_id"]
                if isinstance(audit_id, str):
                    return audit_id

            # Graceful fallback: generate a local audit ID
            return f"local_audit_{int(time.time() * 1000)}_{secrets.token_hex(4)}"
        except httpx.HTTPError:
            raise
        except Exception:
            # Graceful fallback: generate a local audit ID
            return f"local_audit_{int(time.time() * 1000)}_{secrets.token_hex(4)}"

    def _build_actual_payload(
        self, actual: ExecutionEvidence | ActualOperation
    ) -> dict[str, object]:
        """
        Build the actual operation payload for the verification request.

        Handles the discriminated union by extracting type-specific fields.
        """
        # Common fields present on all evidence types
        payload: dict[str, object] = {
            "action": actual.action,
            "resource": actual.resource,
            "executed_at": actual.executed_at,
        }

        # Add type-specific fields based on evidence type
        if isinstance(actual, FileEvidence):
            payload["type"] = "file"
            payload["content_hash"] = actual.content_hash
            payload["file_size"] = actual.file_size
            payload["permissions"] = actual.permissions
            payload["modified_at"] = actual.modified_at
        elif isinstance(actual, CliEvidence):
            payload["type"] = "cli"
            payload["command"] = actual.command
            payload["exit_code"] = actual.exit_code
            payload["stdout_hash"] = actual.stdout_hash
            payload["stderr_hash"] = actual.stderr_hash
            payload["transcript_hash"] = actual.transcript_hash
            payload["cwd"] = actual.cwd
            payload["duration_ms"] = actual.duration_ms
        elif isinstance(actual, BrowserEvidence):
            payload["type"] = "browser"
            payload["final_url"] = actual.final_url
            payload["selector"] = actual.selector
            payload["a11y_tree_hash"] = actual.a11y_tree_hash
            payload["dom_state_hash"] = actual.dom_state_hash
            payload["screenshot_hash"] = actual.screenshot_hash
            payload["page_title"] = actual.page_title
        elif isinstance(actual, HttpEvidence):
            payload["type"] = "http"
            payload["method"] = actual.method
            payload["status_code"] = actual.status_code
            payload["response_body_hash"] = actual.response_body_hash
            payload["content_type"] = actual.content_type
            payload["response_size"] = actual.response_size
            payload["duration_ms"] = actual.duration_ms
        elif isinstance(actual, DbEvidence):
            payload["type"] = "db"
            payload["query_hash"] = actual.query_hash
            payload["rows_affected"] = actual.rows_affected
            payload["result_hash"] = actual.result_hash
            payload["duration_ms"] = actual.duration_ms
        elif isinstance(actual, GenericEvidence):
            payload["type"] = "generic"
            payload["evidence_hash"] = actual.evidence_hash
            payload["metadata"] = actual.metadata
        elif isinstance(actual, ActualOperation):
            # Legacy ActualOperation - extract known fields
            payload["content_hash"] = actual.content_hash
            payload["transcript_hash"] = actual.transcript_hash

        return payload

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> Verifier:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
