from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class VerificationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AuthorizationReason(str, Enum):
    ALLOWED = "allowed"
    NO_MATCHING_POLICY = "no_matching_policy"
    EXPLICIT_DENY = "explicit_deny"
    MISSING_REQUIRED_VERIFICATION = "missing_required_verification"
    MAX_DELEGATION_DEPTH_EXCEEDED = "max_delegation_depth_exceeded"
    INVALID_MANDATE = "invalid_mandate"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


@dataclass(frozen=True)
class PrincipalRef:
    principal_id: str
    tenant_id: str | None = None
    session_id: str | None = None


@dataclass(frozen=True)
class ActionSpec:
    action: str
    resource: str
    intent: str


@dataclass(frozen=True)
class StateEvidence:
    source: str
    state_hash: str
    schema_version: str = "v1"
    confidence: float | None = None


@dataclass(frozen=True)
class VerificationSignal:
    label: str
    status: VerificationStatus
    required: bool = True
    reason: str | None = None


@dataclass(frozen=True)
class VerificationEvidence:
    signals: tuple[VerificationSignal, ...] = field(default_factory=tuple)

    def is_label_passed(self, label: str) -> bool:
        for signal in self.signals:
            if signal.label == label and signal.status == VerificationStatus.PASSED:
                return True
        return False


@dataclass(frozen=True)
class ActionRequest:
    principal: PrincipalRef
    action_spec: ActionSpec
    state_evidence: StateEvidence
    verification_evidence: VerificationEvidence


@dataclass(frozen=True)
class PolicyRule:
    name: str
    effect: PolicyEffect
    principals: tuple[str, ...]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    required_labels: tuple[str, ...] = field(default_factory=tuple)
    max_delegation_depth: int | None = None


@dataclass(frozen=True)
class MandateClaims:
    mandate_id: str
    principal_id: str
    action: str
    resource: str
    intent_hash: str
    state_hash: str
    issued_at_epoch_s: int
    expires_at_epoch_s: int
    delegated_by: str | None = None
    parent_mandate_id: str | None = None
    delegation_depth: int = 0
    delegation_chain_hash: str | None = None
    iss: str | None = None
    aud: str | None = None
    sub: str | None = None
    iat: int | None = None
    exp: int | None = None
    nbf: int | None = None
    jti: str | None = None


@dataclass(frozen=True)
class SignedMandate:
    token: str
    claims: MandateClaims
    signature: str


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: AuthorizationReason
    mandate: SignedMandate | None = None
    violated_rule: str | None = None
    missing_labels: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ProofEvent:
    event_type: str
    principal_id: str
    action: str
    resource: str
    reason: AuthorizationReason
    allowed: bool
    mandate_id: str | None
    emitted_at_epoch_s: int


# =============================================================================
# Execute types for Phase 5: Execution Proxying (Zero-Trust)
# =============================================================================


class ExecuteErrorCode(str, Enum):
    """Execution error codes returned by the sidecar."""

    MANDATE_NOT_FOUND = "mandate_not_found"
    MANDATE_EXPIRED = "mandate_expired"
    ACTION_MISMATCH = "action_mismatch"
    RESOURCE_MISMATCH = "resource_mismatch"
    EXECUTION_FAILED = "execution_failed"
    UNSUPPORTED_ACTION = "unsupported_action"
    INVALID_PAYLOAD = "invalid_payload"


@dataclass(frozen=True)
class FileWritePayload:
    """Payload for fs.write operations."""

    content: str
    create: bool = False
    append: bool = False


@dataclass(frozen=True)
class CliExecPayload:
    """Payload for cli.exec operations."""

    command: str
    args: tuple[str, ...] = field(default_factory=tuple)
    cwd: str | None = None
    timeout_ms: int | None = None


@dataclass(frozen=True)
class HttpFetchPayload:
    """Payload for http.fetch operations."""

    method: str
    headers: dict[str, str] | None = None
    body: str | None = None


@dataclass(frozen=True)
class FileDeletePayload:
    """Payload for fs.delete operations."""

    recursive: bool = False


@dataclass(frozen=True)
class EnvReadPayload:
    """Payload for env.read operations."""

    keys: tuple[str, ...]


@dataclass(frozen=True)
class ExecuteRequest:
    """POST /v1/execute request body."""

    mandate_id: str
    action: str
    resource: str
    payload: (
        FileWritePayload
        | CliExecPayload
        | HttpFetchPayload
        | FileDeletePayload
        | EnvReadPayload
        | None
    ) = None


@dataclass(frozen=True)
class FileReadResult:
    """Result of fs.read operation."""

    content: str
    size: int
    content_hash: str


@dataclass(frozen=True)
class FileWriteResult:
    """Result of fs.write operation."""

    bytes_written: int
    content_hash: str


@dataclass(frozen=True)
class CliExecResult:
    """Result of cli.exec operation."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


@dataclass(frozen=True)
class HttpFetchResult:
    """Result of http.fetch operation."""

    status_code: int
    headers: dict[str, str]
    body: str
    body_hash: str


@dataclass(frozen=True)
class DirectoryEntry:
    """Directory entry for fs.list result."""

    name: str
    entry_type: str  # "file", "dir", "symlink"
    size: int
    modified: int | None = None


@dataclass(frozen=True)
class FileListResult:
    """Result of fs.list operation."""

    entries: tuple[DirectoryEntry, ...]
    total_entries: int


@dataclass(frozen=True)
class FileDeleteResult:
    """Result of fs.delete operation."""

    paths_removed: int


@dataclass(frozen=True)
class EnvReadResult:
    """Result of env.read operation."""

    values: dict[str, str]


@dataclass(frozen=True)
class ExecuteResponse:
    """POST /v1/execute response body."""

    success: bool
    audit_id: str
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
    error: str | None = None
    evidence_hash: str | None = None
