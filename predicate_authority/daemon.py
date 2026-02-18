from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from predicate_authority.bridge import (
    EntraBridgeConfig,
    EntraIdentityBridge,
    IdentityBridge,
    LocalIdPBridge,
    LocalIdPBridgeConfig,
    OIDCBridgeConfig,
    OIDCIdentityBridge,
)
from predicate_authority.control_plane import (
    ControlPlaneClient,
    ControlPlaneClientConfig,
    ControlPlaneTraceEmitter,
)
from predicate_authority.guard import ActionGuard
from predicate_authority.local_identity import (
    CompositeTraceEmitter,
    LedgerQueueItem,
    LocalIdentityRegistry,
    LocalLedgerQueueEmitter,
)
from predicate_authority.mandate import LocalMandateSigner
from predicate_authority.policy import PolicyEngine
from predicate_authority.policy_source import PolicyFileSource
from predicate_authority.proof import InMemoryProofLedger
from predicate_authority.revocation import LocalRevocationCache
from predicate_authority.sidecar import (
    AuthorityMode,
    ExchangeTokenBridge,
    PredicateAuthoritySidecar,
    SidecarConfig,
)
from predicate_authority.sidecar_store import LocalCredentialStore
from predicate_contracts import PolicyRule, TraceEmitter


@dataclass(frozen=True)
class DaemonConfig:
    host: str = "127.0.0.1"
    port: int = 8787
    policy_poll_interval_s: float = 2.0


@dataclass(frozen=True)
class ControlPlaneBootstrapConfig:
    enabled: bool = False
    base_url: str | None = None
    tenant_id: str = "dev-tenant"
    project_id: str = "dev-project"
    auth_token: str | None = None
    timeout_s: float = 2.0
    max_retries: int = 2
    backoff_initial_s: float = 0.2
    fail_open: bool = True
    usage_credits_per_decision: int = 1


@dataclass(frozen=True)
class LocalIdentityBootstrapConfig:
    enabled: bool = False
    registry_file_path: str | None = None
    default_ttl_seconds: int = 900


@dataclass(frozen=True)
class FlushWorkerConfig:
    enabled: bool = True
    interval_s: float = 2.0
    max_batch_size: int = 50
    dead_letter_max_attempts: int = 5


@dataclass
class DaemonRuntime:
    started_at_epoch_s: float
    is_running: bool = False
    policy_reload_count: int = 0
    policy_poll_error_count: int = 0
    last_policy_reload_epoch_s: float | None = None
    last_policy_poll_error: str | None = None
    flush_cycle_count: int = 0
    flush_sent_count: int = 0
    flush_failed_count: int = 0
    flush_quarantined_count: int = 0
    last_flush_epoch_s: float | None = None
    last_flush_error: str | None = None


@dataclass(frozen=True)
class FlushCycleResult:
    scanned_count: int = 0
    sent_count: int = 0
    failed_count: int = 0
    quarantined_count: int = 0


class _DaemonHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
        daemon_ref: PredicateAuthorityDaemon,
    ) -> None:
        super().__init__(server_address, request_handler_class)
        self.daemon_ref = daemon_ref


class _DaemonRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, self.server.daemon_ref.health_payload())  # type: ignore[attr-defined]
            return
        if parsed.path == "/status":
            self._send_json(200, self.server.daemon_ref.status_payload())  # type: ignore[attr-defined]
            return
        if parsed.path == "/identity/list":
            active_only = True
            query = urlparse(self.path).query
            if "active_only=false" in query:
                active_only = False
            payload = self.server.daemon_ref.list_task_identities(active_only=active_only)  # type: ignore[attr-defined]
            self._send_json(200, {"items": payload, "active_only": active_only})
            return
        if parsed.path == "/ledger/flush-queue":
            query = parsed.query
            include_flushed = "include_flushed=true" in query
            include_quarantined = "include_quarantined=true" in query
            payload = self.server.daemon_ref.list_flush_queue(  # type: ignore[attr-defined]
                include_flushed=include_flushed,
                include_quarantined=include_quarantined,
            )
            self._send_json(
                200,
                {
                    "items": payload,
                    "include_flushed": include_flushed,
                    "include_quarantined": include_quarantined,
                },
            )
            return
        if parsed.path == "/ledger/dead-letter":
            payload = self.server.daemon_ref.list_dead_letter_queue()  # type: ignore[attr-defined]
            self._send_json(200, {"items": payload})
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        handlers: dict[str, Any] = {
            "/policy/reload": self._handle_policy_reload,
            "/revoke/principal": self._handle_revoke_principal,
            "/revoke/intent": self._handle_revoke_intent,
            "/identity/task": self._handle_identity_task,
            "/identity/revoke": self._handle_identity_revoke,
            "/ledger/flush-ack": self._handle_ledger_flush_ack,
            "/ledger/flush-now": self._handle_ledger_flush_now,
            "/ledger/requeue": self._handle_ledger_requeue,
        }
        handler = handlers.get(parsed.path)
        if handler is None:
            self._send_json(404, {"error": "not_found"})
            return
        handler()

    def _handle_policy_reload(self) -> None:
        reloaded = self.server.daemon_ref.reload_policy_now()  # type: ignore[attr-defined]
        self._send_json(200, {"reloaded": reloaded})

    def _handle_revoke_principal(self) -> None:
        payload = self._read_json_body()
        principal_id = payload.get("principal_id")
        if not isinstance(principal_id, str) or principal_id.strip() == "":
            self._send_json(400, {"error": "principal_id is required"})
            return
        self.server.daemon_ref.revoke_principal(principal_id.strip())  # type: ignore[attr-defined]
        self._send_json(200, {"ok": True, "principal_id": principal_id.strip()})

    def _handle_revoke_intent(self) -> None:
        payload = self._read_json_body()
        intent_hash = payload.get("intent_hash")
        if not isinstance(intent_hash, str) or intent_hash.strip() == "":
            self._send_json(400, {"error": "intent_hash is required"})
            return
        self.server.daemon_ref.revoke_intent(intent_hash.strip())  # type: ignore[attr-defined]
        self._send_json(200, {"ok": True, "intent_hash": intent_hash.strip()})

    def _handle_identity_task(self) -> None:
        payload = self._read_json_body()
        principal_id = payload.get("principal_id")
        task_id = payload.get("task_id")
        ttl = payload.get("ttl_seconds")
        metadata = payload.get("metadata")
        if not isinstance(principal_id, str) or principal_id.strip() == "":
            self._send_json(400, {"error": "principal_id is required"})
            return
        if not isinstance(task_id, str) or task_id.strip() == "":
            self._send_json(400, {"error": "task_id is required"})
            return
        ttl_value = int(ttl) if isinstance(ttl, (int, str)) else None
        metadata_dict = metadata if isinstance(metadata, dict) else None
        try:
            created = self.server.daemon_ref.issue_task_identity(  # type: ignore[attr-defined]
                principal_id=principal_id.strip(),
                task_id=task_id.strip(),
                ttl_seconds=ttl_value,
                metadata=metadata_dict,
            )
        except RuntimeError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, created)

    def _handle_identity_revoke(self) -> None:
        payload = self._read_json_body()
        identity_id = payload.get("identity_id")
        if not isinstance(identity_id, str) or identity_id.strip() == "":
            self._send_json(400, {"error": "identity_id is required"})
            return
        ok = self.server.daemon_ref.revoke_task_identity(identity_id.strip())  # type: ignore[attr-defined]
        self._send_json(200, {"ok": ok, "identity_id": identity_id.strip()})

    def _handle_ledger_flush_ack(self) -> None:
        payload = self._read_json_body()
        queue_item_id = payload.get("queue_item_id")
        if not isinstance(queue_item_id, str) or queue_item_id.strip() == "":
            self._send_json(400, {"error": "queue_item_id is required"})
            return
        ok = self.server.daemon_ref.ack_flush_queue_item(queue_item_id.strip())  # type: ignore[attr-defined]
        self._send_json(200, {"ok": ok, "queue_item_id": queue_item_id.strip()})

    def _handle_ledger_flush_now(self) -> None:
        payload = self._read_json_body()
        max_items_raw = payload.get("max_items")
        max_items = int(max_items_raw) if isinstance(max_items_raw, (int, str)) else None
        result = self.server.daemon_ref.flush_queue_now(max_items=max_items)  # type: ignore[attr-defined]
        self._send_json(200, result)

    def _handle_ledger_requeue(self) -> None:
        payload = self._read_json_body()
        queue_item_id = payload.get("queue_item_id")
        if not isinstance(queue_item_id, str) or queue_item_id.strip() == "":
            self._send_json(400, {"error": "queue_item_id is required"})
            return
        ok = self.server.daemon_ref.requeue_dead_letter_item(queue_item_id.strip())  # type: ignore[attr-defined]
        self._send_json(200, {"ok": ok, "queue_item_id": queue_item_id.strip()})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Keep daemon output deterministic and quiet by default.
        return

    def _read_json_body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            content_length = int(raw_length)
        except ValueError:
            return {}
        if content_length <= 0:
            return {}
        payload = self.rfile.read(content_length).decode("utf-8")
        try:
            loaded = json.loads(payload)
        except json.JSONDecodeError:
            return {}
        if isinstance(loaded, dict):
            return loaded
        return {}

    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class PredicateAuthorityDaemon:
    def __init__(
        self,
        sidecar: PredicateAuthoritySidecar,
        config: DaemonConfig,
        flush_worker: FlushWorkerConfig | None = None,
    ) -> None:
        self._sidecar = sidecar
        self._config = config
        self._flush_worker = flush_worker or FlushWorkerConfig()
        self._runtime = DaemonRuntime(started_at_epoch_s=time.time())
        self._stop_event = threading.Event()
        self._http_server: _DaemonHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._poll_thread: threading.Thread | None = None
        self._flush_thread: threading.Thread | None = None

    @property
    def bound_port(self) -> int:
        if self._http_server is None:
            return self._config.port
        return int(self._http_server.server_address[1])

    def start(self) -> None:
        if self._runtime.is_running:
            return
        self._runtime.is_running = True
        self._http_server = _DaemonHTTPServer(
            (self._config.host, self._config.port),
            _DaemonRequestHandler,
            self,
        )
        self._server_thread = threading.Thread(target=self._http_server.serve_forever, daemon=True)
        self._poll_thread = threading.Thread(target=self._policy_poll_loop, daemon=True)
        self._flush_thread = threading.Thread(target=self._flush_queue_loop, daemon=True)
        self._server_thread.start()
        self._poll_thread.start()
        self._flush_thread.start()

    def stop(self) -> None:
        if not self._runtime.is_running:
            return
        self._runtime.is_running = False
        self._stop_event.set()
        if self._http_server is not None:
            self._http_server.shutdown()
            self._http_server.server_close()
        if self._server_thread is not None:
            self._server_thread.join(timeout=3.0)
        if self._poll_thread is not None:
            self._poll_thread.join(timeout=3.0)
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=3.0)

    def health_payload(self) -> dict[str, Any]:
        uptime_s = int(max(0, time.time() - self._runtime.started_at_epoch_s))
        return {
            "status": "ok" if self._runtime.is_running else "stopped",
            "mode": self._sidecar.status().mode.value,
            "uptime_s": uptime_s,
        }

    def status_payload(self) -> dict[str, Any]:
        sidecar_status = self._sidecar.status()
        payload = asdict(sidecar_status)
        payload["mode"] = sidecar_status.mode.value
        payload.update(
            {
                "daemon_running": self._runtime.is_running,
                "policy_reload_count": self._runtime.policy_reload_count,
                "policy_poll_error_count": self._runtime.policy_poll_error_count,
                "last_policy_reload_epoch_s": self._runtime.last_policy_reload_epoch_s,
                "last_policy_poll_error": self._runtime.last_policy_poll_error,
                "flush_cycle_count": self._runtime.flush_cycle_count,
                "flush_sent_count": self._runtime.flush_sent_count,
                "flush_failed_count": self._runtime.flush_failed_count,
                "flush_quarantined_count": self._runtime.flush_quarantined_count,
                "last_flush_epoch_s": self._runtime.last_flush_epoch_s,
                "last_flush_error": self._runtime.last_flush_error,
                "dead_letter_max_attempts": self._flush_worker.dead_letter_max_attempts,
            }
        )
        return payload

    def reload_policy_now(self) -> bool:
        changed = self._sidecar.hot_reload_policy()
        if changed:
            self._runtime.policy_reload_count += 1
            self._runtime.last_policy_reload_epoch_s = time.time()
        return changed

    def revoke_principal(self, principal_id: str) -> None:
        self._sidecar.revoke_by_invariant(principal_id)

    def revoke_intent(self, intent_hash: str) -> None:
        self._sidecar.revoke_intent_hash(intent_hash)

    def issue_task_identity(
        self,
        principal_id: str,
        task_id: str,
        ttl_seconds: int | None = None,
        metadata: dict[str, str] | None = None,
    ) -> dict[str, object]:
        registry = self._sidecar.local_identity_registry()
        if registry is None:
            raise RuntimeError("local identity registry is not enabled")
        issued = registry.issue_task_identity(
            principal_id=principal_id,
            task_id=task_id,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
        return asdict(issued)

    def revoke_task_identity(self, identity_id: str) -> bool:
        registry = self._sidecar.local_identity_registry()
        if registry is None:
            return False
        return registry.revoke_identity(identity_id)

    def list_task_identities(self, active_only: bool = True) -> list[dict[str, object]]:
        registry = self._sidecar.local_identity_registry()
        if registry is None:
            return []
        return [asdict(item) for item in registry.list_identities(active_only=active_only)]

    def list_flush_queue(
        self, include_flushed: bool = False, include_quarantined: bool = False
    ) -> list[dict[str, object]]:
        registry = self._sidecar.local_identity_registry()
        if registry is None:
            return []
        return [
            asdict(item)
            for item in registry.list_flush_queue(
                include_flushed=include_flushed,
                include_quarantined=include_quarantined,
            )
        ]

    def ack_flush_queue_item(self, queue_item_id: str) -> bool:
        registry = self._sidecar.local_identity_registry()
        if registry is None:
            return False
        return registry.mark_flush_ack(queue_item_id)

    def list_dead_letter_queue(self) -> list[dict[str, object]]:
        registry = self._sidecar.local_identity_registry()
        if registry is None:
            return []
        return [asdict(item) for item in registry.list_dead_letter_queue() if item.quarantined]

    def requeue_dead_letter_item(self, queue_item_id: str) -> bool:
        registry = self._sidecar.local_identity_registry()
        if registry is None:
            return False
        return registry.requeue_item(queue_item_id=queue_item_id, reset_attempts=True)

    def flush_queue_now(self, max_items: int | None = None) -> dict[str, object]:
        cycle = self._flush_once(max_items=max_items, force=True)
        return {
            "ok": True,
            "scanned_count": cycle.scanned_count,
            "sent_count": cycle.sent_count,
            "failed_count": cycle.failed_count,
            "quarantined_count": cycle.quarantined_count,
            "dead_letter_max_attempts": self._flush_worker.dead_letter_max_attempts,
            "last_flush_error": self._runtime.last_flush_error,
        }

    def _policy_poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                changed = self._sidecar.hot_reload_policy()
                if changed:
                    self._runtime.policy_reload_count += 1
                    self._runtime.last_policy_reload_epoch_s = time.time()
            except Exception as exc:  # noqa: BLE001
                self._runtime.policy_poll_error_count += 1
                self._runtime.last_policy_poll_error = str(exc)
            self._stop_event.wait(timeout=self._config.policy_poll_interval_s)

    def _flush_queue_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._flush_once()
            except Exception as exc:  # noqa: BLE001
                self._runtime.flush_failed_count += 1
                self._runtime.last_flush_error = str(exc)
            self._stop_event.wait(timeout=self._flush_worker.interval_s)

    def _flush_once(
        self,
        max_items: int | None = None,
        force: bool = False,
    ) -> FlushCycleResult:
        result = FlushCycleResult()
        if not self._flush_worker.enabled and not force:
            return result
        registry = self._sidecar.local_identity_registry()
        if registry is None:
            return result
        client = self._resolve_control_plane_client()
        if client is None:
            return result
        batch_size = self._flush_worker.max_batch_size if max_items is None else max(0, max_items)
        queue_items = registry.list_flush_queue(limit=max(0, batch_size))
        if len(queue_items) == 0:
            return result
        self._runtime.flush_cycle_count += 1
        self._runtime.last_flush_epoch_s = time.time()
        scanned_count = 0
        sent_count = 0
        failed_count = 0
        quarantined_count = 0
        for item in queue_items:
            scanned_count += 1
            if item.flush_attempts >= self._flush_worker.dead_letter_max_attempts:
                registry.quarantine_queue_item(
                    item.queue_item_id,
                    "dead_letter_max_attempts_exceeded",
                )
                quarantined_count += 1
                self._runtime.flush_quarantined_count += 1
                self._runtime.last_flush_error = "dead_letter_max_attempts_exceeded"
                continue
            sent = self._send_queue_item_to_control_plane(item=item, client=client)
            if sent:
                registry.mark_flush_ack(item.queue_item_id)
                self._runtime.flush_sent_count += 1
                sent_count += 1
                self._runtime.last_flush_error = None
            else:
                registry.mark_flush_failed(item.queue_item_id, "control_plane_flush_failed")
                self._runtime.flush_failed_count += 1
                failed_count += 1
                self._runtime.last_flush_error = "control_plane_flush_failed"
                if item.flush_attempts + 1 >= self._flush_worker.dead_letter_max_attempts:
                    registry.quarantine_queue_item(
                        item.queue_item_id,
                        "dead_letter_max_attempts_exceeded",
                    )
                    quarantined_count += 1
                    self._runtime.flush_quarantined_count += 1
                    self._runtime.last_flush_error = "dead_letter_max_attempts_exceeded"
        return FlushCycleResult(
            scanned_count=scanned_count,
            sent_count=sent_count,
            failed_count=failed_count,
            quarantined_count=quarantined_count,
        )

    def _send_queue_item_to_control_plane(
        self, item: LedgerQueueItem, client: ControlPlaneClient
    ) -> bool:
        payload = item.payload if isinstance(item.payload, dict) else {}
        principal_id = str(payload.get("principal_id", "unknown-principal"))
        action = str(payload.get("action", "unknown-action"))
        resource = str(payload.get("resource", "unknown-resource"))
        reason = str(payload.get("reason", "unknown"))
        allowed = bool(payload.get("allowed", False))
        mandate_id_raw = payload.get("mandate_id")
        mandate_id = str(mandate_id_raw) if isinstance(mandate_id_raw, str) else None
        emitted_at_raw = payload.get("emitted_at_epoch_s")
        emitted_at = (
            int(emitted_at_raw) if isinstance(emitted_at_raw, (int, str)) else int(time.time())
        )
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(emitted_at))
        audit_envelope = {
            "event_id": f"qevt_{item.queue_item_id}",
            "tenant_id": client.config.tenant_id,
            "principal_id": principal_id,
            "action": action,
            "resource": resource,
            "allowed": allowed,
            "reason": reason,
            "mandate_id": mandate_id,
            "timestamp": timestamp,
            "trace_id": None,
        }
        return client.send_audit_payload({"events": [audit_envelope]})

    def _resolve_control_plane_client(self) -> ControlPlaneClient | None:
        trace_emitter = self._sidecar.trace_emitter()
        if isinstance(trace_emitter, ControlPlaneTraceEmitter):
            return trace_emitter.client
        if isinstance(trace_emitter, CompositeTraceEmitter):
            for emitter in trace_emitter.emitters:
                if isinstance(emitter, ControlPlaneTraceEmitter):
                    return emitter.client
        return None


def _build_default_sidecar(
    mode: AuthorityMode,
    policy_file: str | None,
    credential_store_file: str,
    control_plane_config: ControlPlaneBootstrapConfig | None = None,
    local_identity_config: LocalIdentityBootstrapConfig | None = None,
    identity_bridge: ExchangeTokenBridge | None = None,
) -> PredicateAuthoritySidecar:
    policy_rules: tuple[PolicyRule, ...] = ()
    global_max_delegation_depth: int | None = None
    if policy_file is not None and Path(policy_file).exists():
        policy_rules, global_max_delegation_depth = PolicyFileSource(policy_file).load_policy()
    policy_engine = PolicyEngine(
        rules=policy_rules,
        global_max_delegation_depth=global_max_delegation_depth,
    )

    trace_emitters: list[TraceEmitter] = []
    if (
        control_plane_config is not None
        and control_plane_config.enabled
        and control_plane_config.base_url is not None
    ):
        control_plane_client = ControlPlaneClient(
            config=ControlPlaneClientConfig(
                base_url=control_plane_config.base_url,
                tenant_id=control_plane_config.tenant_id,
                project_id=control_plane_config.project_id,
                auth_token=control_plane_config.auth_token,
                timeout_s=control_plane_config.timeout_s,
                max_retries=control_plane_config.max_retries,
                backoff_initial_s=control_plane_config.backoff_initial_s,
                fail_open=control_plane_config.fail_open,
            )
        )
        trace_emitters.append(
            ControlPlaneTraceEmitter(
                client=control_plane_client,
                emit_usage_credits=True,
                usage_credits_per_decision=control_plane_config.usage_credits_per_decision,
            )
        )
    local_identity_registry: LocalIdentityRegistry | None = None
    if (
        local_identity_config is not None
        and local_identity_config.enabled
        and local_identity_config.registry_file_path is not None
    ):
        local_identity_registry = LocalIdentityRegistry(
            file_path=local_identity_config.registry_file_path,
            default_ttl_seconds=local_identity_config.default_ttl_seconds,
        )
        trace_emitters.append(LocalLedgerQueueEmitter(registry=local_identity_registry))
    trace_emitter = (
        CompositeTraceEmitter(tuple(trace_emitters))
        if len(trace_emitters) > 1
        else (trace_emitters[0] if len(trace_emitters) == 1 else None)
    )
    proof_ledger = InMemoryProofLedger(trace_emitter=trace_emitter)

    guard = ActionGuard(
        policy_engine=policy_engine,
        mandate_signer=LocalMandateSigner(secret_key=secrets.token_hex(32)),
        proof_ledger=proof_ledger,
    )
    return PredicateAuthoritySidecar(
        config=SidecarConfig(mode=mode, policy_file_path=policy_file),
        action_guard=guard,
        proof_ledger=proof_ledger,
        identity_bridge=identity_bridge or IdentityBridge(),
        credential_store=LocalCredentialStore(credential_store_file),
        revocation_cache=LocalRevocationCache(),
        policy_engine=policy_engine,
        local_identity_registry=local_identity_registry,
    )


def _build_identity_bridge_from_args(args: argparse.Namespace) -> ExchangeTokenBridge:
    mode = str(args.identity_mode)
    if mode == "local":
        return IdentityBridge(token_ttl_seconds=int(args.idp_token_ttl_s))
    if mode == "local-idp":
        signing_key = os.getenv(args.local_idp_signing_key_env, "predicate-local-idp-dev-key")
        return LocalIdPBridge(
            LocalIdPBridgeConfig(
                issuer=str(args.local_idp_issuer),
                audience=str(args.local_idp_audience),
                signing_key=signing_key,
                token_ttl_seconds=int(args.idp_token_ttl_s),
            )
        )
    if mode == "oidc":
        if args.oidc_issuer is None or args.oidc_client_id is None or args.oidc_audience is None:
            raise SystemExit(
                "identity-mode=oidc requires --oidc-issuer, --oidc-client-id, and --oidc-audience."
            )
        return OIDCIdentityBridge(
            OIDCBridgeConfig(
                issuer=str(args.oidc_issuer),
                client_id=str(args.oidc_client_id),
                audience=str(args.oidc_audience),
                token_ttl_seconds=int(args.idp_token_ttl_s),
            )
        )
    if mode == "entra":
        if (
            args.entra_tenant_id is None
            or args.entra_client_id is None
            or args.entra_audience is None
        ):
            raise SystemExit(
                "identity-mode=entra requires --entra-tenant-id, --entra-client-id, and --entra-audience."
            )
        return EntraIdentityBridge(
            EntraBridgeConfig(
                tenant_id=str(args.entra_tenant_id),
                client_id=str(args.entra_client_id),
                audience=str(args.entra_audience),
                token_ttl_seconds=int(args.idp_token_ttl_s),
            )
        )
    raise SystemExit(f"Unsupported identity mode: {mode}")


def main() -> None:
    parser = argparse.ArgumentParser(description="predicate-authorityd sidecar daemon")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--mode",
        choices=[AuthorityMode.LOCAL_ONLY.value, AuthorityMode.CLOUD_CONNECTED.value],
        default=AuthorityMode.LOCAL_ONLY.value,
    )
    parser.add_argument("--policy-file", default=None)
    parser.add_argument("--policy-poll-interval-s", type=float, default=2.0)
    parser.add_argument(
        "--credential-store-file",
        default=str(Path.home() / ".predicate-authorityd" / "credentials.json"),
    )
    parser.add_argument(
        "--local-identity-enabled",
        action="store_true",
        help="Enable local ephemeral task identity registry and flush queue.",
    )
    parser.add_argument(
        "--local-identity-registry-file",
        default=str(Path.home() / ".predicate-authorityd" / "local-identities.json"),
    )
    parser.add_argument("--local-identity-default-ttl-s", type=int, default=900)
    parser.add_argument(
        "--identity-mode",
        choices=["local", "local-idp", "oidc", "entra"],
        default="local",
        help="Identity source for token exchange: local, local-idp, oidc, or entra.",
    )
    parser.add_argument("--idp-token-ttl-s", type=int, default=300)
    parser.add_argument(
        "--local-idp-issuer",
        default=os.getenv("LOCAL_IDP_ISSUER", "http://localhost/predicate-local-idp"),
    )
    parser.add_argument(
        "--local-idp-audience",
        default=os.getenv("LOCAL_IDP_AUDIENCE", "api://predicate-authority"),
    )
    parser.add_argument(
        "--local-idp-signing-key-env",
        default="LOCAL_IDP_SIGNING_KEY",
        help="Env var name for Local IdP signing key.",
    )
    parser.add_argument("--oidc-issuer", default=os.getenv("OIDC_ISSUER"))
    parser.add_argument("--oidc-client-id", default=os.getenv("OIDC_CLIENT_ID"))
    parser.add_argument("--oidc-audience", default=os.getenv("OIDC_AUDIENCE"))
    parser.add_argument("--entra-tenant-id", default=os.getenv("ENTRA_TENANT_ID"))
    parser.add_argument("--entra-client-id", default=os.getenv("ENTRA_CLIENT_ID"))
    parser.add_argument("--entra-audience", default=os.getenv("ENTRA_AUDIENCE"))
    parser.add_argument(
        "--control-plane-enabled",
        action="store_true",
        help="Enable control-plane audit/usage shipping via trace emitter.",
    )
    parser.add_argument(
        "--control-plane-url",
        default=None,
        help="Control plane base URL (e.g. https://authority.example.com).",
    )
    parser.add_argument(
        "--control-plane-tenant-id",
        default=None,
        help="Tenant ID for emitted audit/usage records.",
    )
    parser.add_argument(
        "--control-plane-project-id",
        default=None,
        help="Project ID for emitted usage records.",
    )
    parser.add_argument(
        "--control-plane-auth-token-env",
        default="CONTROL_PLANE_AUTH_TOKEN",
        help="Env var name that stores Bearer token for control-plane APIs.",
    )
    parser.add_argument("--control-plane-timeout-s", type=float, default=2.0)
    parser.add_argument("--control-plane-max-retries", type=int, default=2)
    parser.add_argument("--control-plane-backoff-initial-s", type=float, default=0.2)
    parser.add_argument(
        "--flush-worker-enabled",
        action="store_true",
        help="Enable background local queue flush worker.",
    )
    parser.add_argument(
        "--flush-worker-disabled",
        dest="flush_worker_enabled",
        action="store_false",
        help="Disable background local queue flush worker.",
    )
    parser.set_defaults(flush_worker_enabled=True)
    parser.add_argument("--flush-worker-interval-s", type=float, default=2.0)
    parser.add_argument("--flush-worker-max-batch-size", type=int, default=50)
    parser.add_argument("--flush-worker-dead-letter-max-attempts", type=int, default=5)
    parser.add_argument(
        "--control-plane-fail-open",
        action="store_true",
        help="If true, local authorization continues when control-plane push fails.",
    )
    parser.add_argument(
        "--control-plane-fail-closed",
        dest="control_plane_fail_open",
        action="store_false",
        help="If set, control-plane push failures become hard errors.",
    )
    parser.set_defaults(control_plane_fail_open=True)
    parser.add_argument("--control-plane-usage-credits-per-decision", type=int, default=1)
    args = parser.parse_args()

    mode = AuthorityMode(args.mode)
    control_plane_auth_token = os.getenv(args.control_plane_auth_token_env)
    control_plane_url = args.control_plane_url or os.getenv("CONTROL_PLANE_URL")
    control_plane_tenant = args.control_plane_tenant_id or os.getenv(
        "CONTROL_PLANE_TENANT_ID", "dev-tenant"
    )
    control_plane_project = args.control_plane_project_id or os.getenv(
        "CONTROL_PLANE_PROJECT_ID", "dev-project"
    )
    control_plane_enabled = bool(args.control_plane_enabled)
    if control_plane_enabled and (control_plane_url is None or control_plane_url.strip() == ""):
        raise SystemExit(
            "control-plane is enabled but no URL provided. "
            "Set --control-plane-url or CONTROL_PLANE_URL."
        )
    control_plane_bootstrap = ControlPlaneBootstrapConfig(
        enabled=control_plane_enabled,
        base_url=control_plane_url,
        tenant_id=control_plane_tenant,
        project_id=control_plane_project,
        auth_token=control_plane_auth_token,
        timeout_s=args.control_plane_timeout_s,
        max_retries=args.control_plane_max_retries,
        backoff_initial_s=args.control_plane_backoff_initial_s,
        fail_open=bool(args.control_plane_fail_open),
        usage_credits_per_decision=max(0, int(args.control_plane_usage_credits_per_decision)),
    )
    local_identity_bootstrap = LocalIdentityBootstrapConfig(
        enabled=bool(args.local_identity_enabled),
        registry_file_path=str(args.local_identity_registry_file),
        default_ttl_seconds=max(1, int(args.local_identity_default_ttl_s)),
    )
    identity_bridge = _build_identity_bridge_from_args(args)
    sidecar = _build_default_sidecar(
        mode=mode,
        policy_file=args.policy_file,
        credential_store_file=args.credential_store_file,
        control_plane_config=control_plane_bootstrap,
        local_identity_config=local_identity_bootstrap,
        identity_bridge=identity_bridge,
    )
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(
            host=args.host,
            port=args.port,
            policy_poll_interval_s=args.policy_poll_interval_s,
        ),
        flush_worker=FlushWorkerConfig(
            enabled=bool(args.flush_worker_enabled),
            interval_s=max(0.1, float(args.flush_worker_interval_s)),
            max_batch_size=max(1, int(args.flush_worker_max_batch_size)),
            dead_letter_max_attempts=max(1, int(args.flush_worker_dead_letter_max_attempts)),
        ),
    )
    daemon.start()
    print(
        f"predicate-authorityd listening on http://{args.host}:{daemon.bound_port} "
        f"(mode={mode.value}, identity_mode={args.identity_mode}, "
        f"control_plane_enabled={control_plane_enabled})"
    )
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        daemon.stop()
        print("predicate-authorityd stopped")


if __name__ == "__main__":
    main()
