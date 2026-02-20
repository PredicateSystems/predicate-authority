from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from threading import Lock
from typing import Any

from predicate_contracts import ActionRequest, SignedMandate


class LocalRevocationCache:
    def __init__(self, store_file_path: str | None = None) -> None:
        self._store_file_path = (
            Path(store_file_path)
            if isinstance(store_file_path, str) and store_file_path.strip() != ""
            else None
        )
        self._revoked_principal_ids: set[str] = set()
        self._revoked_intent_hashes: set[str] = set()
        self._revoked_mandate_ids: set[str] = set()
        self._mandate_parent_by_id: dict[str, str] = {}
        self._mandate_children_by_id: dict[str, set[str]] = {}
        self._lock = Lock()
        if self._store_file_path is not None:
            self._ensure_store_path()
            self._load_from_store()

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

    def persistence_enabled(self) -> bool:
        return self._store_file_path is not None

    def revoke_principal(self, principal_id: str) -> None:
        with self._lock:
            self._revoked_principal_ids.add(principal_id)
            self._persist_unlocked()

    def revoke_intent_hash(self, intent_hash: str) -> None:
        with self._lock:
            self._revoked_intent_hashes.add(intent_hash)
            self._persist_unlocked()

    def revoke_mandate_id(self, mandate_id: str, cascade: bool = False) -> int:
        with self._lock:
            self._revoked_mandate_ids.add(mandate_id)
            revoked_count = 1
            if cascade:
                revoked_count += self._revoke_mandate_descendants_locked(mandate_id)
            self._persist_unlocked()
            return revoked_count

    def register_mandate(self, mandate: SignedMandate) -> None:
        with self._lock:
            mandate_id = mandate.claims.mandate_id
            parent_mandate_id = mandate.claims.parent_mandate_id
            if parent_mandate_id is None or parent_mandate_id.strip() == "":
                return
            parent_id = parent_mandate_id.strip()
            self._mandate_parent_by_id[mandate_id] = parent_id
            children = self._mandate_children_by_id.setdefault(parent_id, set())
            children.add(mandate_id)
            self._persist_unlocked()

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

    def _revoke_mandate_descendants_locked(self, root_mandate_id: str) -> int:
        revoked_count = 0
        queue = [root_mandate_id]
        visited: set[str] = set()
        while len(queue) > 0:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            children = self._mandate_children_by_id.get(current, set())
            for child_id in children:
                if child_id not in self._revoked_mandate_ids:
                    self._revoked_mandate_ids.add(child_id)
                    revoked_count += 1
                queue.append(child_id)
        return revoked_count

    def _ensure_store_path(self) -> None:
        if self._store_file_path is None:
            return
        self._store_file_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._store_file_path.parent, 0o700)
        except OSError:
            pass
        if not self._store_file_path.exists():
            self._atomic_write_json(self._default_payload())
        self._chmod_file_safe()

    def _load_from_store(self) -> None:
        if self._store_file_path is None:
            return
        loaded = self._read_store_payload()
        self._revoked_principal_ids = self._parse_string_set(loaded.get("revoked_principal_ids"))
        self._revoked_intent_hashes = self._parse_string_set(loaded.get("revoked_intent_hashes"))
        self._revoked_mandate_ids = self._parse_string_set(loaded.get("revoked_mandate_ids"))
        self._mandate_parent_by_id = self._parse_string_map(loaded.get("mandate_parent_by_id"))
        self._mandate_children_by_id = self._parse_children_map(
            loaded.get("mandate_children_by_id")
        )

    def _persist_unlocked(self) -> None:
        if self._store_file_path is None:
            return
        payload = {
            "schema_version": 1,
            "revoked_principal_ids": sorted(self._revoked_principal_ids),
            "revoked_intent_hashes": sorted(self._revoked_intent_hashes),
            "revoked_mandate_ids": sorted(self._revoked_mandate_ids),
            "mandate_parent_by_id": dict(sorted(self._mandate_parent_by_id.items())),
            "mandate_children_by_id": {
                parent_id: sorted(children)
                for parent_id, children in sorted(self._mandate_children_by_id.items())
            },
        }
        self._atomic_write_json(payload)
        self._chmod_file_safe()

    def _read_store_payload(self) -> dict[str, Any]:
        if self._store_file_path is None or not self._store_file_path.exists():
            return self._default_payload()
        content = self._store_file_path.read_text(encoding="utf-8").strip()
        if content == "":
            return self._default_payload()
        try:
            loaded = json.loads(content)
        except json.JSONDecodeError:
            return self._default_payload()
        if not isinstance(loaded, dict):
            return self._default_payload()
        return loaded

    def _atomic_write_json(self, payload: dict[str, Any]) -> None:
        if self._store_file_path is None:
            return
        tmp_path = self._store_file_path.with_name(
            f"{self._store_file_path.name}.{uuid.uuid4().hex}.tmp"
        )
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp_path, self._store_file_path)

    def _chmod_file_safe(self) -> None:
        if self._store_file_path is None:
            return
        try:
            os.chmod(self._store_file_path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _default_payload() -> dict[str, Any]:
        return {
            "schema_version": 1,
            "revoked_principal_ids": [],
            "revoked_intent_hashes": [],
            "revoked_mandate_ids": [],
            "mandate_parent_by_id": {},
            "mandate_children_by_id": {},
        }

    @staticmethod
    def _parse_string_set(raw: object) -> set[str]:
        if not isinstance(raw, list):
            return set()
        return {str(item) for item in raw if isinstance(item, str) and item.strip() != ""}

    @staticmethod
    def _parse_string_map(raw: object) -> dict[str, str]:
        if not isinstance(raw, dict):
            return {}
        result: dict[str, str] = {}
        for key, value in raw.items():
            if not isinstance(key, str) or key.strip() == "":
                continue
            if not isinstance(value, str) or value.strip() == "":
                continue
            result[key] = value
        return result

    @classmethod
    def _parse_children_map(cls, raw: object) -> dict[str, set[str]]:
        if not isinstance(raw, dict):
            return {}
        result: dict[str, set[str]] = {}
        for key, value in raw.items():
            if not isinstance(key, str) or key.strip() == "":
                continue
            result[key] = cls._parse_string_set(value)
        return result
