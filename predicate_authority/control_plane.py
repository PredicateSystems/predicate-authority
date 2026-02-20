from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit

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
    sync_enabled: bool = False
    sync_wait_timeout_s: float = 15.0
    sync_poll_interval_ms: int = 200
    sync_project_id: str | None = None
    sync_environment: str | None = None
    replay_signing_secret: str | None = None


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


@dataclass(frozen=True)
class RemoteRevocation:
    revocation_id: str
    type: str
    principal_id: str | None = None
    intent_hash: str | None = None
    tags: tuple[str, ...] = ()
    reason: str | None = None
    created_at: str = ""


@dataclass(frozen=True)
class AuthoritySyncSnapshot:
    changed: bool
    sync_token: str
    tenant_id: str
    project_id: str | None = None
    environment: str | None = None
    policy_id: str | None = None
    policy_revision: int | None = None
    policy_document: dict[str, object] | None = None
    revocations: tuple[RemoteRevocation, ...] = ()

    @staticmethod
    def from_payload(payload: Mapping[str, object]) -> AuthoritySyncSnapshot:
        revocations_payload = payload.get("revocations")
        parsed_revocations: list[RemoteRevocation] = []
        if isinstance(revocations_payload, list):
            for item in revocations_payload:
                if not isinstance(item, Mapping):
                    continue
                raw_tags = item.get("tags")
                tags: tuple[str, ...] = ()
                if isinstance(raw_tags, list):
                    tags = tuple(str(tag) for tag in raw_tags if isinstance(tag, str))
                parsed_revocations.append(
                    RemoteRevocation(
                        revocation_id=str(item.get("revocation_id", "")),
                        type=str(item.get("type", "")),
                        principal_id=(
                            str(item["principal_id"])
                            if isinstance(item.get("principal_id"), str)
                            else None
                        ),
                        intent_hash=(
                            str(item["intent_hash"])
                            if isinstance(item.get("intent_hash"), str)
                            else None
                        ),
                        tags=tags,
                        reason=str(item["reason"]) if isinstance(item.get("reason"), str) else None,
                        created_at=str(item.get("created_at", "")),
                    )
                )
        policy_document = payload.get("policy_document")
        raw_policy_revision = payload.get("policy_revision")
        policy_revision: int | None = None
        if isinstance(raw_policy_revision, int):
            policy_revision = raw_policy_revision
        elif isinstance(raw_policy_revision, str) and raw_policy_revision.strip() != "":
            try:
                policy_revision = int(raw_policy_revision)
            except ValueError:
                policy_revision = None
        return AuthoritySyncSnapshot(
            changed=bool(payload.get("changed", False)),
            sync_token=str(payload.get("sync_token", "")),
            tenant_id=str(payload.get("tenant_id", "")),
            project_id=(
                str(payload["project_id"]) if isinstance(payload.get("project_id"), str) else None
            ),
            environment=(
                str(payload["environment"]) if isinstance(payload.get("environment"), str) else None
            ),
            policy_id=(
                str(payload["policy_id"]) if isinstance(payload.get("policy_id"), str) else None
            ),
            policy_revision=policy_revision,
            policy_document=(dict(policy_document) if isinstance(policy_document, dict) else None),
            revocations=tuple(parsed_revocations),
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

    def poll_authority_updates(
        self,
        current_token: str | None,
        wait_timeout_s: float = 15.0,
        poll_interval_ms: int = 200,
        project_id: str | None = None,
        environment: str | None = None,
    ) -> AuthoritySyncSnapshot:
        query: dict[str, str | float | int] = {
            "tenant_id": self.config.tenant_id,
            "wait_timeout_s": max(0.0, float(wait_timeout_s)),
            "poll_interval_ms": max(50, int(poll_interval_ms)),
        }
        if current_token is not None and current_token.strip() != "":
            query["current_token"] = current_token
        if project_id is not None and project_id.strip() != "":
            query["project_id"] = project_id
        if environment is not None and environment.strip() != "":
            query["environment"] = environment
        path = "/v1/sync/authority-updates?" + urlencode(query)
        payload = self._get_json(path)
        return AuthoritySyncSnapshot.from_payload(payload)

    def _post_json(self, path: str, payload: Mapping[str, object]) -> bool:
        replay_headers = self._build_replay_headers(path)
        attempts = self.config.max_retries + 1
        for attempt in range(attempts):
            try:
                self._post_json_once(path, payload, replay_headers=replay_headers)
                return True
            except Exception as exc:
                is_last_attempt = attempt == attempts - 1
                if is_last_attempt:
                    if self.config.fail_open:
                        return False
                    raise RuntimeError(f"control-plane request failed: {path}") from exc
                time.sleep(self.config.backoff_initial_s * (2**attempt))
        return False

    def _get_json(self, path: str) -> Mapping[str, object]:
        attempts = self.config.max_retries + 1
        for attempt in range(attempts):
            try:
                return self._get_json_once(path)
            except Exception as exc:
                is_last_attempt = attempt == attempts - 1
                if is_last_attempt:
                    if self.config.fail_open:
                        return {}
                    raise RuntimeError(f"control-plane request failed: {path}") from exc
                time.sleep(self.config.backoff_initial_s * (2**attempt))
        return {}

    def _post_json_once(
        self,
        path: str,
        payload: Mapping[str, object],
        *,
        replay_headers: Mapping[str, str],
    ) -> None:
        target_path = path if path.startswith("/") else f"/{path}"
        connection = self._new_connection()
        headers = {"Content-Type": "application/json"}
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        headers.update(replay_headers)
        body = json.dumps(payload)
        try:
            connection.request("POST", target_path, body=body, headers=headers)
            response = connection.getresponse()
            content = response.read().decode("utf-8")
        finally:
            connection.close()
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {content}")

    def _get_json_once(self, path: str) -> Mapping[str, object]:
        target_path = path if path.startswith("/") else f"/{path}"
        connection = self._new_connection()
        headers: dict[str, str] = {}
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        try:
            connection.request("GET", target_path, headers=headers)
            response = connection.getresponse()
            content = response.read().decode("utf-8")
        finally:
            connection.close()
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {content}")
        loaded = json.loads(content) if content.strip() != "" else {}
        if not isinstance(loaded, dict):
            raise RuntimeError("Expected object JSON payload from control-plane GET response.")
        return loaded

    def _new_connection(self) -> http.client.HTTPConnection:
        if self._base.scheme == "https":
            return http.client.HTTPSConnection(self._base.netloc, timeout=self.config.timeout_s)
        return http.client.HTTPConnection(self._base.netloc, timeout=self.config.timeout_s)

    def _build_replay_headers(self, path: str) -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = hashlib.sha256(
            f"{self.config.tenant_id}|{path}|{time.time_ns()}".encode()
        ).hexdigest()[:32]
        headers = {
            "X-PA-Nonce": nonce,
            "X-PA-Timestamp": timestamp,
            "X-PA-Idempotency-Token": hashlib.sha256(
                f"{nonce}|{timestamp}|{path}".encode()
            ).hexdigest()[:32],
        }
        if self.config.replay_signing_secret is not None:
            message = f"{nonce}:{timestamp}:POST:{path}".encode()
            signature = hmac.new(
                self.config.replay_signing_secret.encode("utf-8"), message, hashlib.sha256
            ).hexdigest()
            headers["X-PA-Signature"] = signature
        return headers


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
            if not self.client.config.fail_open:
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
            if not self.client.config.fail_open:
                raise
