from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

from predicate_contracts import ProofEvent, TraceEmitter


@dataclass(frozen=True)
class TaskIdentityRecord:
    identity_id: str
    principal_id: str
    task_id: str
    issued_at_epoch_s: int
    expires_at_epoch_s: int
    revoked: bool = False
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LedgerQueueItem:
    queue_item_id: str
    enqueued_at_epoch_s: int
    payload: dict[str, object]
    flushed: bool = False
    flush_attempts: int = 0
    last_error: str | None = None
    flushed_at_epoch_s: int | None = None
    quarantined: bool = False
    quarantine_reason: str | None = None
    quarantined_at_epoch_s: int | None = None


@dataclass(frozen=True)
class LocalIdentityRegistryStats:
    total_identity_count: int
    active_identity_count: int
    pending_flush_queue_count: int
    flushed_queue_count: int
    failed_queue_count: int
    quarantined_queue_count: int


class LocalIdentityRegistry:
    def __init__(self, file_path: str, default_ttl_seconds: int = 900) -> None:
        if default_ttl_seconds <= 0:
            raise ValueError("default_ttl_seconds must be > 0")
        self._file_path = Path(file_path)
        self._default_ttl_seconds = default_ttl_seconds
        self._lock = Lock()
        self._ensure_store_path()

    def issue_task_identity(
        self,
        principal_id: str,
        task_id: str,
        ttl_seconds: int | None = None,
        metadata: dict[str, str] | None = None,
    ) -> TaskIdentityRecord:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
        if ttl <= 0:
            raise ValueError("ttl_seconds must be > 0")
        now = int(time.time())
        record = TaskIdentityRecord(
            identity_id="lid_" + uuid.uuid4().hex[:16],
            principal_id=principal_id,
            task_id=task_id,
            issued_at_epoch_s=now,
            expires_at_epoch_s=now + ttl,
            revoked=False,
            metadata=metadata or {},
        )
        with self._lock:
            payload = self._read_all_unlocked()
            identities = payload.setdefault("identities", {})
            identities[record.identity_id] = asdict(record)
            self._write_all_unlocked(payload)
        return record

    def revoke_identity(self, identity_id: str) -> bool:
        with self._lock:
            payload = self._read_all_unlocked()
            identities = payload.setdefault("identities", {})
            item = identities.get(identity_id)
            if not isinstance(item, dict):
                return False
            item["revoked"] = True
            identities[identity_id] = item
            self._write_all_unlocked(payload)
            return True

    def is_identity_active(self, identity_id: str, now_epoch_s: int | None = None) -> bool:
        now = now_epoch_s if now_epoch_s is not None else int(time.time())
        record = self.get_identity(identity_id)
        if record is None:
            return False
        if record.revoked:
            return False
        return now < record.expires_at_epoch_s

    def get_identity(self, identity_id: str) -> TaskIdentityRecord | None:
        with self._lock:
            payload = self._read_all_unlocked()
            identities = payload.setdefault("identities", {})
            raw = identities.get(identity_id)
        if not isinstance(raw, dict):
            return None
        try:
            return TaskIdentityRecord(
                identity_id=str(raw["identity_id"]),
                principal_id=str(raw["principal_id"]),
                task_id=str(raw["task_id"]),
                issued_at_epoch_s=int(raw["issued_at_epoch_s"]),
                expires_at_epoch_s=int(raw["expires_at_epoch_s"]),
                revoked=bool(raw.get("revoked", False)),
                metadata={
                    str(k): str(v)
                    for k, v in dict(raw.get("metadata", {})).items()
                    if isinstance(k, str)
                },
            )
        except Exception:
            return None

    def list_identities(self, active_only: bool = True) -> list[TaskIdentityRecord]:
        with self._lock:
            payload = self._read_all_unlocked()
            identities = payload.setdefault("identities", {})
            raw_items = list(identities.values())
        result: list[TaskIdentityRecord] = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            record = self.get_identity(str(raw.get("identity_id", "")))
            if record is None:
                continue
            if active_only and not self.is_identity_active(record.identity_id):
                continue
            result.append(record)
        return sorted(result, key=lambda item: item.issued_at_epoch_s, reverse=True)

    def expire_identities(self, now_epoch_s: int | None = None) -> int:
        now = now_epoch_s if now_epoch_s is not None else int(time.time())
        expired_count = 0
        with self._lock:
            payload = self._read_all_unlocked()
            identities = payload.setdefault("identities", {})
            for identity_id, raw in list(identities.items()):
                if not isinstance(raw, dict):
                    continue
                expires_at = int(raw.get("expires_at_epoch_s", now + 1))
                revoked = bool(raw.get("revoked", False))
                if not revoked and expires_at <= now:
                    raw["revoked"] = True
                    identities[identity_id] = raw
                    expired_count += 1
            if expired_count > 0:
                self._write_all_unlocked(payload)
        return expired_count

    def enqueue_proof_event(
        self, event: ProofEvent, source: str = "predicate-authorityd"
    ) -> LedgerQueueItem:
        item = LedgerQueueItem(
            queue_item_id="q_" + uuid.uuid4().hex[:16],
            enqueued_at_epoch_s=int(time.time()),
            payload={
                "source": source,
                "event_type": event.event_type,
                "principal_id": event.principal_id,
                "action": event.action,
                "resource": event.resource,
                "reason": event.reason.value,
                "allowed": event.allowed,
                "mandate_id": event.mandate_id,
                "emitted_at_epoch_s": event.emitted_at_epoch_s,
            },
        )
        with self._lock:
            payload = self._read_all_unlocked()
            queue = payload.setdefault("flush_queue", {})
            queue[item.queue_item_id] = asdict(item)
            self._write_all_unlocked(payload)
        return item

    def list_flush_queue(
        self,
        include_flushed: bool = False,
        include_quarantined: bool = False,
        limit: int | None = None,
    ) -> list[LedgerQueueItem]:
        with self._lock:
            payload = self._read_all_unlocked()
            queue = payload.setdefault("flush_queue", {})
            raw_items = list(queue.values())
        result: list[LedgerQueueItem] = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            item = self._parse_queue_item(raw)
            if item is None:
                continue
            if not include_flushed and item.flushed:
                continue
            if not include_quarantined and item.quarantined:
                continue
            result.append(item)
        result = sorted(result, key=lambda item: item.enqueued_at_epoch_s)
        if limit is not None and limit >= 0:
            return result[:limit]
        return result

    def mark_flush_ack(self, queue_item_id: str) -> bool:
        with self._lock:
            payload = self._read_all_unlocked()
            queue = payload.setdefault("flush_queue", {})
            raw = queue.get(queue_item_id)
            if not isinstance(raw, dict):
                return False
            raw["flushed"] = True
            raw["flush_attempts"] = int(raw.get("flush_attempts", 0)) + 1
            raw["last_error"] = None
            raw["flushed_at_epoch_s"] = int(time.time())
            queue[queue_item_id] = raw
            self._write_all_unlocked(payload)
            return True

    def mark_flush_failed(self, queue_item_id: str, error: str) -> bool:
        with self._lock:
            payload = self._read_all_unlocked()
            queue = payload.setdefault("flush_queue", {})
            raw = queue.get(queue_item_id)
            if not isinstance(raw, dict):
                return False
            raw["flush_attempts"] = int(raw.get("flush_attempts", 0)) + 1
            raw["last_error"] = error
            queue[queue_item_id] = raw
            self._write_all_unlocked(payload)
            return True

    def quarantine_queue_item(self, queue_item_id: str, reason: str) -> bool:
        with self._lock:
            payload = self._read_all_unlocked()
            queue = payload.setdefault("flush_queue", {})
            raw = queue.get(queue_item_id)
            if not isinstance(raw, dict):
                return False
            raw["quarantined"] = True
            raw["quarantine_reason"] = reason
            raw["quarantined_at_epoch_s"] = int(time.time())
            queue[queue_item_id] = raw
            self._write_all_unlocked(payload)
            return True

    def list_dead_letter_queue(self, limit: int | None = None) -> list[LedgerQueueItem]:
        return self.list_flush_queue(
            include_flushed=True,
            include_quarantined=True,
            limit=limit,
        )

    def requeue_item(self, queue_item_id: str, reset_attempts: bool = True) -> bool:
        with self._lock:
            payload = self._read_all_unlocked()
            queue = payload.setdefault("flush_queue", {})
            raw = queue.get(queue_item_id)
            if not isinstance(raw, dict):
                return False
            if not bool(raw.get("quarantined", False)):
                return False
            raw["quarantined"] = False
            raw["quarantine_reason"] = None
            raw["quarantined_at_epoch_s"] = None
            raw["flushed"] = False
            raw["flushed_at_epoch_s"] = None
            raw["last_error"] = None
            if reset_attempts:
                raw["flush_attempts"] = 0
            queue[queue_item_id] = raw
            self._write_all_unlocked(payload)
            return True

    def stats(self) -> LocalIdentityRegistryStats:
        active = len(self.list_identities(active_only=True))
        all_identities = len(self.list_identities(active_only=False))
        queue_all = self.list_flush_queue(include_flushed=True, include_quarantined=True)
        queue_pending = len(
            [item for item in queue_all if not item.flushed and not item.quarantined]
        )
        queue_flushed = len([item for item in queue_all if item.flushed])
        queue_failed = len(
            [
                item
                for item in queue_all
                if item.last_error is not None and not item.flushed and not item.quarantined
            ]
        )
        queue_quarantined = len([item for item in queue_all if item.quarantined])
        return LocalIdentityRegistryStats(
            total_identity_count=all_identities,
            active_identity_count=active,
            pending_flush_queue_count=queue_pending,
            flushed_queue_count=queue_flushed,
            failed_queue_count=queue_failed,
            quarantined_queue_count=queue_quarantined,
        )

    def _read_all_unlocked(self) -> dict[str, Any]:
        if not self._file_path.exists():
            return {"identities": {}, "flush_queue": {}}
        content = self._file_path.read_text(encoding="utf-8").strip()
        if content == "":
            return {"identities": {}, "flush_queue": {}}
        loaded = json.loads(content)
        if isinstance(loaded, dict):
            if "identities" not in loaded:
                loaded["identities"] = {}
            if "flush_queue" not in loaded:
                loaded["flush_queue"] = {}
            return loaded
        return {"identities": {}, "flush_queue": {}}

    def _parse_queue_item(self, raw: dict[str, Any]) -> LedgerQueueItem | None:
        try:
            return LedgerQueueItem(
                queue_item_id=str(raw["queue_item_id"]),
                enqueued_at_epoch_s=int(raw["enqueued_at_epoch_s"]),
                payload=dict(raw.get("payload", {})),
                flushed=bool(raw.get("flushed", False)),
                flush_attempts=int(raw.get("flush_attempts", 0)),
                last_error=(str(raw["last_error"]) if raw.get("last_error") is not None else None),
                flushed_at_epoch_s=(
                    int(raw["flushed_at_epoch_s"])
                    if raw.get("flushed_at_epoch_s") is not None
                    else None
                ),
                quarantined=bool(raw.get("quarantined", False)),
                quarantine_reason=(
                    str(raw["quarantine_reason"])
                    if raw.get("quarantine_reason") is not None
                    else None
                ),
                quarantined_at_epoch_s=(
                    int(raw["quarantined_at_epoch_s"])
                    if raw.get("quarantined_at_epoch_s") is not None
                    else None
                ),
            )
        except Exception:
            return None

    def _write_all_unlocked(self, payload: dict[str, Any]) -> None:
        self._file_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._chmod_file_safe()

    def _ensure_store_path(self) -> None:
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._file_path.parent, 0o700)
        except OSError:
            pass
        if not self._file_path.exists():
            self._file_path.write_text(
                json.dumps({"identities": {}, "flush_queue": {}}, indent=2),
                encoding="utf-8",
            )
        self._chmod_file_safe()

    def _chmod_file_safe(self) -> None:
        try:
            os.chmod(self._file_path, 0o600)
        except OSError:
            pass


@dataclass
class LocalLedgerQueueEmitter(TraceEmitter):
    registry: LocalIdentityRegistry
    source: str = "predicate-authorityd"

    def emit(self, event: ProofEvent) -> None:
        self.registry.enqueue_proof_event(event, source=self.source)


@dataclass
class CompositeTraceEmitter(TraceEmitter):
    emitters: tuple[TraceEmitter, ...]

    def emit(self, event: ProofEvent) -> None:
        for emitter in self.emitters:
            emitter.emit(event)
