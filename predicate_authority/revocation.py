from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from predicate_contracts import ActionRequest, SignedMandate


@dataclass
class LocalRevocationCache:
    revoked_principal_ids: set[str] = field(default_factory=set)
    revoked_intent_hashes: set[str] = field(default_factory=set)
    revoked_mandate_ids: set[str] = field(default_factory=set)

    def revoke_principal(self, principal_id: str) -> None:
        self.revoked_principal_ids.add(principal_id)

    def revoke_intent_hash(self, intent_hash: str) -> None:
        self.revoked_intent_hashes.add(intent_hash)

    def revoke_mandate_id(self, mandate_id: str) -> None:
        self.revoked_mandate_ids.add(mandate_id)

    def is_request_revoked(self, request: ActionRequest) -> bool:
        if request.principal.principal_id in self.revoked_principal_ids:
            return True
        intent_hash = hashlib.sha256(request.action_spec.intent.encode("utf-8")).hexdigest()
        return intent_hash in self.revoked_intent_hashes

    def is_mandate_revoked(self, mandate: SignedMandate) -> bool:
        if mandate.claims.principal_id in self.revoked_principal_ids:
            return True
        if mandate.claims.intent_hash in self.revoked_intent_hashes:
            return True
        return mandate.claims.mandate_id in self.revoked_mandate_ids
