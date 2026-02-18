from __future__ import annotations

import time
from pathlib import Path

# pylint: disable=import-error
from predicate_authority import CredentialRecord, LocalCredentialStore


def test_credential_store_get_returns_none_for_expired_record(tmp_path: Path) -> None:
    store = LocalCredentialStore(str(tmp_path / "credentials.json"))
    store.save(
        CredentialRecord(
            principal_id="agent:expired",
            refresh_token="expired-token",
            expires_at_epoch_s=int(time.time()) - 10,
        )
    )
    assert store.get("agent:expired") is None


def test_credential_store_handles_corrupt_json_file(tmp_path: Path) -> None:
    file_path = tmp_path / "credentials.json"
    file_path.write_text("{this-is-not-json}", encoding="utf-8")
    store = LocalCredentialStore(str(file_path))
    assert store.get("agent:any") is None
