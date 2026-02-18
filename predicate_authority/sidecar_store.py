from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class CredentialRecord:
    principal_id: str
    refresh_token: str
    expires_at_epoch_s: int


class LocalCredentialStore:
    """Local credential persistence for sidecar mode.

    This MVP store uses file permissions for local hardening and avoids logging secrets.
    """

    def __init__(self, file_path: str) -> None:
        self._file_path = Path(file_path)
        self._lock = Lock()
        self._ensure_store_path()

    def save(self, record: CredentialRecord) -> None:
        with self._lock:
            payload = self._read_all_unlocked()
            payload[record.principal_id] = asdict(record)
            self._write_all_unlocked(payload)

    def get(self, principal_id: str) -> CredentialRecord | None:
        with self._lock:
            payload = self._read_all_unlocked()
            item = payload.get(principal_id)
            if not isinstance(item, dict):
                return None
            item_principal = item.get("principal_id")
            item_refresh = item.get("refresh_token")
            item_expires = item.get("expires_at_epoch_s")
            if not isinstance(item_principal, str) or not isinstance(item_refresh, str):
                return None
            if not isinstance(item_expires, (int, str)):
                return None
            expires_at = int(item_expires)
            if expires_at <= int(time.time()):
                return None
            return CredentialRecord(
                principal_id=item_principal,
                refresh_token=item_refresh,
                expires_at_epoch_s=expires_at,
            )

    def _read_all_unlocked(self) -> dict[str, Any]:
        if not self._file_path.exists():
            return {}
        content = self._file_path.read_text(encoding="utf-8").strip()
        if content == "":
            return {}
        try:
            loaded = json.loads(content)
        except json.JSONDecodeError:
            return {}
        if isinstance(loaded, dict):
            return loaded
        return {}

    def _write_all_unlocked(self, payload: dict[str, Any]) -> None:
        self._atomic_write_json(payload)
        self._chmod_file_safe()

    def _ensure_store_path(self) -> None:
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._file_path.parent, 0o700)
        except OSError:
            pass
        if not self._file_path.exists():
            self._atomic_write_json({})
        self._chmod_file_safe()

    def _chmod_file_safe(self) -> None:
        try:
            os.chmod(self._file_path, 0o600)
        except OSError:
            pass

    def _atomic_write_json(self, payload: dict[str, Any]) -> None:
        tmp_path = self._file_path.with_name(f"{self._file_path.name}.{uuid.uuid4().hex}.tmp")
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp_path, self._file_path)
