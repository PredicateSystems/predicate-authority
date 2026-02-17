from __future__ import annotations

from pathlib import Path

from predicate_authority import LocalIdentityRegistry
from predicate_contracts import AuthorizationReason, ProofEvent


def test_local_identity_registry_issue_revoke_and_expire(tmp_path: Path) -> None:
    registry = LocalIdentityRegistry(str(tmp_path / "local-identities.json"), default_ttl_seconds=2)
    issued = registry.issue_task_identity(
        principal_id="agent:test",
        task_id="task-123",
        ttl_seconds=1,
        metadata={"kind": "codegen"},
    )
    assert registry.is_identity_active(issued.identity_id, now_epoch_s=issued.issued_at_epoch_s)
    assert issued.metadata["kind"] == "codegen"

    expired = registry.expire_identities(now_epoch_s=issued.expires_at_epoch_s)
    assert expired == 1
    assert (
        registry.is_identity_active(issued.identity_id, now_epoch_s=issued.expires_at_epoch_s)
        is False
    )

    issued_2 = registry.issue_task_identity(principal_id="agent:test", task_id="task-456")
    assert registry.revoke_identity(issued_2.identity_id) is True
    assert registry.is_identity_active(issued_2.identity_id) is False


def test_local_identity_registry_flush_queue_lifecycle(tmp_path: Path) -> None:
    registry = LocalIdentityRegistry(str(tmp_path / "local-identities.json"))
    event = ProofEvent(
        event_type="authority.decision",
        principal_id="agent:test",
        action="http.post",
        resource="https://api.vendor.com/orders",
        reason=AuthorizationReason.ALLOWED,
        allowed=True,
        mandate_id="mandate-1",
        emitted_at_epoch_s=1_700_000_000,
    )
    item = registry.enqueue_proof_event(event)
    pending = registry.list_flush_queue()
    assert len(pending) == 1
    assert pending[0].queue_item_id == item.queue_item_id

    assert registry.mark_flush_failed(item.queue_item_id, "temporary outage") is True
    pending_after_fail = registry.list_flush_queue()
    assert pending_after_fail[0].last_error == "temporary outage"

    assert registry.mark_flush_ack(item.queue_item_id) is True
    pending_after_ack = registry.list_flush_queue()
    assert len(pending_after_ack) == 0
    all_items = registry.list_flush_queue(include_flushed=True)
    assert len(all_items) == 1
    assert all_items[0].flushed is True

    stats = registry.stats()
    assert stats.total_identity_count == 0
    assert stats.pending_flush_queue_count == 0
    assert stats.flushed_queue_count == 1
