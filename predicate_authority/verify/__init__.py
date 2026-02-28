"""
Post-execution verification module.

This module provides verification capability to compare actual operations
against what was authorized via a mandate, detecting unauthorized deviations.

Example:
    >>> from predicate_authority.verify import Verifier
    >>> verifier = Verifier(base_url="http://127.0.0.1:8787")
    >>> result = verifier.verify(
    ...     mandate_id=decision.mandate_id,
    ...     actual={
    ...         "action": "fs.read",
    ...         "resource": "/src/index.ts",
    ...     },
    ... )
    >>> if not result.verified:
    ...     print(f"Operation mismatch: {result.reason}")
"""

from predicate_authority.verify.comparators import (
    actions_match,
    normalize_resource,
    resources_match,
)
from predicate_authority.verify.types import (  # Evidence types (discriminated union); Core types
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
    RecordVerificationResponse,
    VerificationFailureReason,
    VerifyRequest,
    VerifyResult,
    get_evidence_type,
)
from predicate_authority.verify.verifier import Verifier

__all__ = [
    # Evidence types (discriminated union)
    "BrowserEvidence",
    "CliEvidence",
    "DbEvidence",
    "ExecutionEvidence",
    "FileEvidence",
    "GenericEvidence",
    "HttpEvidence",
    "get_evidence_type",
    # Core types
    "ActualOperation",
    "AuthorizedOperation",
    "MandateDetails",
    "RecordVerificationRequest",
    "RecordVerificationResponse",
    "VerificationFailureReason",
    "VerifyRequest",
    "VerifyResult",
    # Comparators
    "actions_match",
    "normalize_resource",
    "resources_match",
    # Verifier
    "Verifier",
]
