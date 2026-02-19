from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DaemonMetricsSnapshot:
    daemon_up: int
    policy_reload_total: int
    policy_poll_error_total: int
    proof_event_total: int
    authz_decision_total: int
    authz_allow_total: int
    authz_deny_total: int
    authz_deny_no_matching_policy_total: int
    authz_deny_explicit_deny_total: int
    authz_deny_missing_required_verification_total: int
    authz_deny_max_delegation_depth_total: int
    authz_deny_invalid_mandate_total: int
    authz_deny_rate_limit_exceeded_total: int
    revoked_principal_total: int
    revoked_intent_total: int
    revoked_mandate_total: int
    flush_cycle_total: int
    flush_sent_total: int
    flush_failed_total: int
    flush_quarantined_total: int
    control_plane_sync_poll_total: int
    control_plane_sync_update_total: int
    control_plane_sync_error_total: int
    local_flush_queue_pending: int
    local_flush_queue_flushed: int
    local_flush_queue_failed: int
    local_flush_queue_quarantined: int
    control_plane_audit_push_success_total: int
    control_plane_audit_push_failure_total: int
    control_plane_usage_push_success_total: int
    control_plane_usage_push_failure_total: int

    @classmethod
    def from_status_payload(cls, payload: dict[str, object]) -> DaemonMetricsSnapshot:
        def _to_int(key: str) -> int:
            value = payload.get(key, 0)
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, int):
                return value
            if isinstance(value, float):
                return int(value)
            if isinstance(value, str) and value.strip() != "":
                return int(float(value))
            return 0

        return cls(
            daemon_up=_to_int("daemon_running"),
            policy_reload_total=_to_int("policy_reload_count"),
            policy_poll_error_total=_to_int("policy_poll_error_count"),
            proof_event_total=_to_int("proof_event_count"),
            authz_decision_total=_to_int("authorization_decision_total"),
            authz_allow_total=_to_int("authorization_allow_total"),
            authz_deny_total=_to_int("authorization_deny_total"),
            authz_deny_no_matching_policy_total=_to_int(
                "authorization_deny_no_matching_policy_total"
            ),
            authz_deny_explicit_deny_total=_to_int("authorization_deny_explicit_deny_total"),
            authz_deny_missing_required_verification_total=_to_int(
                "authorization_deny_missing_required_verification_total"
            ),
            authz_deny_max_delegation_depth_total=_to_int(
                "authorization_deny_max_delegation_depth_total"
            ),
            authz_deny_invalid_mandate_total=_to_int("authorization_deny_invalid_mandate_total"),
            authz_deny_rate_limit_exceeded_total=_to_int(
                "authorization_deny_rate_limit_exceeded_total"
            ),
            revoked_principal_total=_to_int("revoked_principal_count"),
            revoked_intent_total=_to_int("revoked_intent_count"),
            revoked_mandate_total=_to_int("revoked_mandate_count"),
            flush_cycle_total=_to_int("flush_cycle_count"),
            flush_sent_total=_to_int("flush_sent_count"),
            flush_failed_total=_to_int("flush_failed_count"),
            flush_quarantined_total=_to_int("flush_quarantined_count"),
            control_plane_sync_poll_total=_to_int("control_plane_sync_poll_count"),
            control_plane_sync_update_total=_to_int("control_plane_sync_update_count"),
            control_plane_sync_error_total=_to_int("control_plane_sync_error_count"),
            local_flush_queue_pending=_to_int("local_flush_queue_pending_count"),
            local_flush_queue_flushed=_to_int("local_flush_queue_flushed_count"),
            local_flush_queue_failed=_to_int("local_flush_queue_failed_count"),
            local_flush_queue_quarantined=_to_int("local_flush_queue_quarantined_count"),
            control_plane_audit_push_success_total=_to_int(
                "control_plane_audit_push_success_count"
            ),
            control_plane_audit_push_failure_total=_to_int(
                "control_plane_audit_push_failure_count"
            ),
            control_plane_usage_push_success_total=_to_int(
                "control_plane_usage_push_success_count"
            ),
            control_plane_usage_push_failure_total=_to_int(
                "control_plane_usage_push_failure_count"
            ),
        )


def render_daemon_prometheus_metrics(payload: dict[str, object]) -> str:
    snapshot = DaemonMetricsSnapshot.from_status_payload(payload)
    lines = [
        "# HELP predicate_authority_daemon_up Daemon process liveness (1=running,0=stopped).",
        "# TYPE predicate_authority_daemon_up gauge",
        f"predicate_authority_daemon_up {snapshot.daemon_up}",
        "# HELP predicate_authority_policy_reload_total Policy reload count.",
        "# TYPE predicate_authority_policy_reload_total counter",
        f"predicate_authority_policy_reload_total {snapshot.policy_reload_total}",
        "# HELP predicate_authority_policy_poll_error_total Policy poll error count.",
        "# TYPE predicate_authority_policy_poll_error_total counter",
        f"predicate_authority_policy_poll_error_total {snapshot.policy_poll_error_total}",
        "# HELP predicate_authority_proof_event_total Recorded proof events.",
        "# TYPE predicate_authority_proof_event_total counter",
        f"predicate_authority_proof_event_total {snapshot.proof_event_total}",
        "# HELP predicate_authority_authz_decision_total Authorization decision totals by outcome.",
        "# TYPE predicate_authority_authz_decision_total counter",
        f'predicate_authority_authz_decision_total{{outcome="allow"}} {snapshot.authz_allow_total}',
        f'predicate_authority_authz_decision_total{{outcome="deny"}} {snapshot.authz_deny_total}',
        "# HELP predicate_authority_authz_deny_reason_total Authorization deny totals by reason.",
        "# TYPE predicate_authority_authz_deny_reason_total counter",
        (
            'predicate_authority_authz_deny_reason_total{reason="no_matching_policy"} '
            f"{snapshot.authz_deny_no_matching_policy_total}"
        ),
        (
            'predicate_authority_authz_deny_reason_total{reason="explicit_deny"} '
            f"{snapshot.authz_deny_explicit_deny_total}"
        ),
        (
            'predicate_authority_authz_deny_reason_total{reason="missing_required_verification"} '
            f"{snapshot.authz_deny_missing_required_verification_total}"
        ),
        (
            'predicate_authority_authz_deny_reason_total{reason="max_delegation_depth_exceeded"} '
            f"{snapshot.authz_deny_max_delegation_depth_total}"
        ),
        (
            'predicate_authority_authz_deny_reason_total{reason="invalid_mandate"} '
            f"{snapshot.authz_deny_invalid_mandate_total}"
        ),
        (
            'predicate_authority_authz_deny_reason_total{reason="rate_limit_exceeded"} '
            f"{snapshot.authz_deny_rate_limit_exceeded_total}"
        ),
        "# HELP predicate_authority_revocation_total Revocations by type.",
        "# TYPE predicate_authority_revocation_total gauge",
        (
            'predicate_authority_revocation_total{type="principal"} '
            f"{snapshot.revoked_principal_total}"
        ),
        f'predicate_authority_revocation_total{{type="intent"}} {snapshot.revoked_intent_total}',
        f'predicate_authority_revocation_total{{type="mandate"}} {snapshot.revoked_mandate_total}',
        "# HELP predicate_authority_flush_total Flush loop counters by result.",
        "# TYPE predicate_authority_flush_total counter",
        f'predicate_authority_flush_total{{result="cycle"}} {snapshot.flush_cycle_total}',
        f'predicate_authority_flush_total{{result="sent"}} {snapshot.flush_sent_total}',
        f'predicate_authority_flush_total{{result="failed"}} {snapshot.flush_failed_total}',
        (
            'predicate_authority_flush_total{result="quarantined"} '
            f"{snapshot.flush_quarantined_total}"
        ),
        "# HELP predicate_authority_control_plane_sync_total Control-plane sync loop counters by result.",
        "# TYPE predicate_authority_control_plane_sync_total counter",
        (
            'predicate_authority_control_plane_sync_total{result="poll"} '
            f"{snapshot.control_plane_sync_poll_total}"
        ),
        (
            'predicate_authority_control_plane_sync_total{result="update"} '
            f"{snapshot.control_plane_sync_update_total}"
        ),
        (
            'predicate_authority_control_plane_sync_total{result="error"} '
            f"{snapshot.control_plane_sync_error_total}"
        ),
        "# HELP predicate_authority_local_flush_queue Queue depth and lifecycle gauges.",
        "# TYPE predicate_authority_local_flush_queue gauge",
        (
            'predicate_authority_local_flush_queue{state="pending"} '
            f"{snapshot.local_flush_queue_pending}"
        ),
        (
            'predicate_authority_local_flush_queue{state="flushed"} '
            f"{snapshot.local_flush_queue_flushed}"
        ),
        (
            'predicate_authority_local_flush_queue{state="failed"} '
            f"{snapshot.local_flush_queue_failed}"
        ),
        (
            'predicate_authority_local_flush_queue{state="quarantined"} '
            f"{snapshot.local_flush_queue_quarantined}"
        ),
        "# HELP predicate_authority_control_plane_push_total Control-plane push attempts by stream/result.",
        "# TYPE predicate_authority_control_plane_push_total counter",
        (
            'predicate_authority_control_plane_push_total{stream="audit",result="success"} '
            f"{snapshot.control_plane_audit_push_success_total}"
        ),
        (
            'predicate_authority_control_plane_push_total{stream="audit",result="failure"} '
            f"{snapshot.control_plane_audit_push_failure_total}"
        ),
        (
            'predicate_authority_control_plane_push_total{stream="usage",result="success"} '
            f"{snapshot.control_plane_usage_push_success_total}"
        ),
        (
            'predicate_authority_control_plane_push_total{stream="usage",result="failure"} '
            f"{snapshot.control_plane_usage_push_failure_total}"
        ),
    ]
    return "\n".join(lines) + "\n"
