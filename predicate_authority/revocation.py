from __future__ import annotations

import hashlib
from threading import Lock

from predicate_contracts import ActionRequest, SignedMandate


class LocalRevocationCache:
    def __init__(self) -> None:
        self._revoked_principal_ids: set[str] = set()
        self._revoked_intent_hashes: set[str] = set()
        self._revoked_mandate_ids: set[str] = set()
        self._lock = Lock()

    @property
    def revoked_principal_ids(self) -> set[str]:
        with self._lock:
            return set(self._revoked_principal_ids)

    @property
    def revoked_intent_hashes(self) -> set[str]:
        with self._lock:
            return set(self._revoked_intent_hashes)

    @property
    def revoked_mandate_ids(self) -> set[str]:
        with self._lock:
            return set(self._revoked_mandate_ids)

    def revoked_principal_count(self) -> int:
        with self._lock:
            return len(self._revoked_principal_ids)

    def revoked_intent_count(self) -> int:
        with self._lock:
            return len(self._revoked_intent_hashes)

    def revoked_mandate_count(self) -> int:
        with self._lock:
            return len(self._revoked_mandate_ids)

    def revoke_principal(self, principal_id: str) -> None:
        with self._lock:
            self._revoked_principal_ids.add(principal_id)

    def revoke_intent_hash(self, intent_hash: str) -> None:
        with self._lock:
            self._revoked_intent_hashes.add(intent_hash)

    def revoke_mandate_id(self, mandate_id: str) -> None:
        with self._lock:
            self._revoked_mandate_ids.add(mandate_id)

    def is_request_revoked(self, request: ActionRequest) -> bool:
        with self._lock:
            if request.principal.principal_id in self._revoked_principal_ids:
                return True
            intent_hash = hashlib.sha256(request.action_spec.intent.encode("utf-8")).hexdigest()
            return intent_hash in self._revoked_intent_hashes

    def is_mandate_revoked(self, mandate: SignedMandate) -> bool:
        with self._lock:
            if mandate.claims.principal_id in self._revoked_principal_ids:
                return True
            if mandate.claims.intent_hash in self._revoked_intent_hashes:
                return True
            return mandate.claims.mandate_id in self._revoked_mandate_ids
