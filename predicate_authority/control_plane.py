from __future__ import annotations

import hashlib
import http.client
import json
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from predicate_contracts import ProofEvent


@dataclass(frozen=True)
class ControlPlaneClientConfig:
    base_url: str
    tenant_id: str
    project_id: str
    auth_token: str | None = None
    timeout_s: float = 2.0
    max_retries: int = 2
    backoff_initial_s: float = 0.2
    fail_open: bool = True


@dataclass(frozen=True)
class AuditEventEnvelope:
    event_id: str
    tenant_id: str
    principal_id: str
    action: str
    resource: str
    allowed: bool
    reason: str
    mandate_id: str | None = None
    timestamp: str = ""
    trace_id: str | None = None

    @staticmethod
    def from_proof_event(
        event: ProofEvent, tenant_id: str, trace_id: str | None = None
    ) -> AuditEventEnvelope:
        timestamp = datetime.fromtimestamp(event.emitted_at_epoch_s, tz=timezone.utc).isoformat()
        event_id_seed = (
            f"{event.principal_id}|{event.action}|{event.resource}|"
            f"{event.emitted_at_epoch_s}|{event.allowed}|{event.reason.value}"
        )
        event_id = "evt_" + hashlib.sha256(event_id_seed.encode("utf-8")).hexdigest()[:16]
        return AuditEventEnvelope(
            event_id=event_id,
            tenant_id=tenant_id,
            principal_id=event.principal_id,
            action=event.action,
            resource=event.resource,
            allowed=event.allowed,
            reason=event.reason.value,
            mandate_id=event.mandate_id,
            timestamp=timestamp,
            trace_id=trace_id,
        )


@dataclass(frozen=True)
class UsageCreditRecord:
    tenant_id: str
    project_id: str
    action_type: str
    credits: int
    timestamp: str

    @staticmethod
    def authority_check(tenant_id: str, project_id: str, credits: int = 1) -> UsageCreditRecord:
        return UsageCreditRecord(
            tenant_id=tenant_id,
            project_id=project_id,
            action_type="authority_check",
            credits=credits,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
        )


class ControlPlaneClient:
    def __init__(self, config: ControlPlaneClientConfig) -> None:
        self.config = config
        self._base = urlsplit(config.base_url)
        if self._base.scheme not in {"http", "https"}:
            raise ValueError("base_url must use http or https scheme")
        if self._base.netloc == "":
            raise ValueError("base_url must include host:port")

    def send_audit_events(self, events: tuple[AuditEventEnvelope, ...]) -> bool:
        payload = {"events": [asdict(event) for event in events]}
        return self._post_json("/v1/audit/events:batch", payload)

    def send_usage_records(self, records: tuple[UsageCreditRecord, ...]) -> bool:
        payload = {"records": [asdict(record) for record in records]}
        return self._post_json("/v1/metering/usage:batch", payload)

    def send_audit_payload(self, payload: Mapping[str, object]) -> bool:
        return self._post_json("/v1/audit/events:batch", payload)

    def _post_json(self, path: str, payload: Mapping[str, object]) -> bool:
        attempts = self.config.max_retries + 1
        for attempt in range(attempts):
            try:
                self._post_json_once(path, payload)
                return True
            except Exception as exc:
                is_last_attempt = attempt == attempts - 1
                if is_last_attempt:
                    if self.config.fail_open:
                        return False
                    raise RuntimeError(f"control-plane request failed: {path}") from exc
                time.sleep(self.config.backoff_initial_s * (2**attempt))
        return False

    def _post_json_once(self, path: str, payload: Mapping[str, object]) -> None:
        target_path = path if path.startswith("/") else f"/{path}"
        connection = self._new_connection()
        headers = {"Content-Type": "application/json"}
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        body = json.dumps(payload)
        try:
            connection.request("POST", target_path, body=body, headers=headers)
            response = connection.getresponse()
            content = response.read().decode("utf-8")
        finally:
            connection.close()
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {content}")

    def _new_connection(self) -> http.client.HTTPConnection:
        if self._base.scheme == "https":
            return http.client.HTTPSConnection(self._base.netloc, timeout=self.config.timeout_s)
        return http.client.HTTPConnection(self._base.netloc, timeout=self.config.timeout_s)


@dataclass
class ControlPlaneTraceEmitter:
    client: ControlPlaneClient
    trace_id: str | None = None
    emit_usage_credits: bool = True
    usage_credits_per_decision: int = 1
    audit_push_success_count: int = 0
    audit_push_failure_count: int = 0
    usage_push_success_count: int = 0
    usage_push_failure_count: int = 0
    last_push_error: str | None = None

    def emit(self, event: ProofEvent) -> None:
        audit_event = AuditEventEnvelope.from_proof_event(
            event=event, tenant_id=self.client.config.tenant_id, trace_id=self.trace_id
        )
        self._send_audit_event(audit_event)
        if self.emit_usage_credits:
            usage = UsageCreditRecord.authority_check(
                tenant_id=self.client.config.tenant_id,
                project_id=self.client.config.project_id,
                credits=self.usage_credits_per_decision,
            )
            self._send_usage_record(usage)

    def status_payload(self) -> dict[str, int | str | None]:
        return {
            "control_plane_audit_push_success_count": self.audit_push_success_count,
            "control_plane_audit_push_failure_count": self.audit_push_failure_count,
            "control_plane_usage_push_success_count": self.usage_push_success_count,
            "control_plane_usage_push_failure_count": self.usage_push_failure_count,
            "control_plane_last_push_error": self.last_push_error,
        }

    def _send_audit_event(self, audit_event: AuditEventEnvelope) -> None:
        try:
            sent = self.client.send_audit_events((audit_event,))
            if sent:
                self.audit_push_success_count += 1
                self.last_push_error = None
            else:
                self.audit_push_failure_count += 1
                self.last_push_error = "audit_push_failed"
        except Exception as exc:
            self.audit_push_failure_count += 1
            self.last_push_error = str(exc)
            raise

    def _send_usage_record(self, usage: UsageCreditRecord) -> None:
        try:
            sent = self.client.send_usage_records((usage,))
            if sent:
                self.usage_push_success_count += 1
                self.last_push_error = None
            else:
                self.usage_push_failure_count += 1
                self.last_push_error = "usage_push_failed"
        except Exception as exc:
            self.usage_push_failure_count += 1
            self.last_push_error = str(exc)
            raise
