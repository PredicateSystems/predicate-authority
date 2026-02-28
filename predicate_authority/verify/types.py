"""
Types for post-execution verification.

These types support verifying that actual operations match
what was authorized via a mandate.

The verification system uses discriminated unions to support different
evidence schemas based on the action domain:

- `file`: File system operations with content hashes
- `cli`: Terminal/shell operations with transcript evidence
- `browser`: Web operations with DOM/A11y state
- `http`: HTTP requests with response evidence
- `db`: Database operations with query evidence
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Union

# =============================================================================
# Evidence Type Discriminator
# =============================================================================

EvidenceType = Literal["file", "cli", "browser", "http", "db", "generic"]


def get_evidence_type(action: str) -> EvidenceType:
    """
    Extract the evidence type from an action string.

    Args:
        action: Action string (e.g., "fs.read", "cli.exec")

    Returns:
        Evidence type based on action prefix

    Examples:
        >>> get_evidence_type("fs.read")
        'file'
        >>> get_evidence_type("cli.exec")
        'cli'
        >>> get_evidence_type("browser.click")
        'browser'
        >>> get_evidence_type("custom.action")
        'generic'
    """
    prefix = action.split(".")[0]
    domain_map: dict[str, EvidenceType] = {
        "fs": "file",
        "file": "file",
        "cli": "cli",
        "shell": "cli",
        "terminal": "cli",
        "browser": "browser",
        "web": "browser",
        "http": "http",
        "https": "http",
        "db": "db",
        "database": "db",
        "sql": "db",
    }
    return domain_map.get(prefix, "generic")


# =============================================================================
# Discriminated Union Evidence Types
# =============================================================================


@dataclass(frozen=True)
class FileEvidence:
    """Evidence for file system operations (fs.read, fs.write, etc.)"""

    type: Literal["file"]
    """Discriminator field."""

    action: str
    """The action that was performed (e.g., 'fs.read')."""

    resource: str
    """The file path that was accessed."""

    executed_at: str | None = None
    """Timestamp when operation was executed (ISO 8601)."""

    content_hash: str | None = None
    """Hash of file content (SHA-256)."""

    file_size: int | None = None
    """File size in bytes."""

    permissions: str | None = None
    """File permissions (octal string, e.g., '644')."""

    modified_at: str | None = None
    """Last modified timestamp (ISO 8601)."""


@dataclass(frozen=True)
class CliEvidence:
    """Evidence for terminal/CLI operations (cli.exec, cli.spawn, etc.)"""

    type: Literal["cli"]
    """Discriminator field."""

    action: str
    """The action that was performed (e.g., 'cli.exec')."""

    resource: str
    """The command that was executed."""

    executed_at: str | None = None
    """Timestamp when operation was executed (ISO 8601)."""

    command: str | None = None
    """The exact command that was executed."""

    exit_code: int | None = None
    """Exit code of the process."""

    stdout_hash: str | None = None
    """Hash of stdout transcript."""

    stderr_hash: str | None = None
    """Hash of stderr transcript."""

    transcript_hash: str | None = None
    """Combined transcript hash (stdout + stderr)."""

    cwd: str | None = None
    """Working directory where command was executed."""

    duration_ms: int | None = None
    """Duration in milliseconds."""


@dataclass(frozen=True)
class BrowserEvidence:
    """Evidence for browser/web operations (browser.click, browser.navigate, etc.)"""

    type: Literal["browser"]
    """Discriminator field."""

    action: str
    """The action that was performed (e.g., 'browser.click')."""

    resource: str
    """The URL or selector that was accessed."""

    executed_at: str | None = None
    """Timestamp when operation was executed (ISO 8601)."""

    final_url: str | None = None
    """Final URL after navigation."""

    selector: str | None = None
    """DOM selector that was interacted with."""

    a11y_tree_hash: str | None = None
    """Hash of accessibility tree state."""

    dom_state_hash: str | None = None
    """Hash of visible DOM state."""

    screenshot_hash: str | None = None
    """Screenshot hash (if captured)."""

    page_title: str | None = None
    """Page title after operation."""


@dataclass(frozen=True)
class HttpEvidence:
    """Evidence for HTTP operations (http.get, http.post, etc.)"""

    type: Literal["http"]
    """Discriminator field."""

    action: str
    """The action that was performed (e.g., 'http.get')."""

    resource: str
    """The URL that was accessed."""

    executed_at: str | None = None
    """Timestamp when operation was executed (ISO 8601)."""

    method: str | None = None
    """HTTP method used."""

    status_code: int | None = None
    """Response status code."""

    response_body_hash: str | None = None
    """Hash of response body."""

    content_type: str | None = None
    """Response content type."""

    response_size: int | None = None
    """Response size in bytes."""

    duration_ms: int | None = None
    """Request duration in milliseconds."""


@dataclass(frozen=True)
class DbEvidence:
    """Evidence for database operations (db.query, db.insert, etc.)"""

    type: Literal["db"]
    """Discriminator field."""

    action: str
    """The action that was performed (e.g., 'db.query')."""

    resource: str
    """The table or collection that was accessed."""

    executed_at: str | None = None
    """Timestamp when operation was executed (ISO 8601)."""

    query_hash: str | None = None
    """Hash of query/statement."""

    rows_affected: int | None = None
    """Number of rows affected."""

    result_hash: str | None = None
    """Hash of result set (for queries)."""

    duration_ms: int | None = None
    """Query duration in milliseconds."""


@dataclass(frozen=True)
class GenericEvidence:
    """Evidence for unknown or custom action types."""

    type: Literal["generic"]
    """Discriminator field."""

    action: str
    """The action that was performed."""

    resource: str
    """The resource that was accessed."""

    executed_at: str | None = None
    """Timestamp when operation was executed (ISO 8601)."""

    evidence_hash: str | None = None
    """Arbitrary evidence hash."""

    metadata: dict | None = None
    """Additional metadata."""


# Discriminated union of all evidence types
ExecutionEvidence = Union[
    FileEvidence,
    CliEvidence,
    BrowserEvidence,
    HttpEvidence,
    DbEvidence,
    GenericEvidence,
]


# =============================================================================
# Core Verification Types
# =============================================================================


class VerificationFailureReason(str, Enum):
    """Reason codes for verification failure."""

    RESOURCE_MISMATCH = "resource_mismatch"
    ACTION_MISMATCH = "action_mismatch"
    MANDATE_EXPIRED = "mandate_expired"
    MANDATE_NOT_FOUND = "mandate_not_found"
    EVIDENCE_MISMATCH = "evidence_mismatch"


@dataclass(frozen=True)
class AuthorizedOperation:
    """Details about an authorized operation from a mandate."""

    action: str
    resource: str


@dataclass(frozen=True)
class ActualOperation:
    """
    Legacy interface for backward compatibility.

    Deprecated: Use ExecutionEvidence discriminated union instead.
    """

    action: str
    """The action that was actually performed."""

    resource: str
    """The resource that was actually accessed."""

    executed_at: str | None = None
    """Timestamp when operation was executed (ISO 8601)."""

    content_hash: str | None = None
    """Deprecated: Use FileEvidence.content_hash instead."""

    transcript_hash: str | None = None
    """Deprecated: Use CliEvidence.transcript_hash instead."""


@dataclass(frozen=True)
class VerifyRequest:
    """
    Request to verify an operation against its mandate.

    Supports both the legacy ActualOperation format and the new
    discriminated union ExecutionEvidence format.
    """

    mandate_id: str
    """Mandate ID from the authorization decision."""

    actual: ExecutionEvidence | ActualOperation
    """The actual operation that was performed."""


@dataclass(frozen=True)
class VerifyResult:
    """Result of verification."""

    verified: bool
    """Whether the operation matched the authorization."""

    reason: VerificationFailureReason | None = None
    """Reason for verification failure (if verified is False)."""

    authorized: AuthorizedOperation | None = None
    """Authorized operation details (if verification failed)."""

    actual: ExecutionEvidence | ActualOperation | None = None
    """Actual operation details (if verification failed)."""

    audit_id: str | None = None
    """Audit trail ID from the sidecar (if verification succeeded)."""


# =============================================================================
# Mandate Types
# =============================================================================


@dataclass(frozen=True)
class MandateDetails:
    """Mandate details retrieved from the sidecar."""

    mandate_id: str
    """Unique mandate identifier."""

    principal: str
    """Principal that was granted authorization."""

    action: str
    """Action that was authorized."""

    resource: str
    """Resource that was authorized."""

    intent_hash: str
    """Hash of the stated intent."""

    issued_at: str
    """When the mandate was issued (ISO 8601)."""

    expires_at: str
    """When the mandate expires (ISO 8601)."""


# =============================================================================
# Audit Types
# =============================================================================


@dataclass(frozen=True)
class RecordVerificationRequest:
    """Request to record a verification in the audit log."""

    mandate_id: str
    """Mandate ID that was verified."""

    verified: bool
    """Whether verification succeeded."""

    actual: ExecutionEvidence | ActualOperation
    """The actual operation details."""

    reason: VerificationFailureReason | None = None
    """Reason for failure (if verified is False)."""


@dataclass(frozen=True)
class RecordVerificationResponse:
    """Response from recording a verification."""

    audit_id: str
    """Audit trail ID."""
