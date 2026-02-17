from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
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
        self._ensure_store_path()

    def save(self, record: CredentialRecord) -> None:
        payload = self._read_all()
        payload[record.principal_id] = asdict(record)
        self._file_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._chmod_file_safe()

    def get(self, principal_id: str) -> CredentialRecord | None:
        payload = self._read_all()
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
        return CredentialRecord(
            principal_id=item_principal,
            refresh_token=item_refresh,
            expires_at_epoch_s=int(item_expires),
        )

    def _read_all(self) -> dict[str, Any]:
        if not self._file_path.exists():
            return {}
        content = self._file_path.read_text(encoding="utf-8").strip()
        if content == "":
            return {}
        loaded = json.loads(content)
        if isinstance(loaded, dict):
            return loaded
        return {}

    def _ensure_store_path(self) -> None:
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._file_path.parent, 0o700)
        except OSError:
            pass
        if not self._file_path.exists():
            self._file_path.write_text("{}", encoding="utf-8")
        self._chmod_file_safe()

    def _chmod_file_safe(self) -> None:
        try:
            os.chmod(self._file_path, 0o600)
        except OSError:
            pass
