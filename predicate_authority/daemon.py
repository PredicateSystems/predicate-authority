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
from predicate_contracts import PolicyRule


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


@dataclass
class DaemonRuntime:
    started_at_epoch_s: float
    is_running: bool = False
    policy_reload_count: int = 0
    policy_poll_error_count: int = 0
    last_policy_reload_epoch_s: float | None = None
    last_policy_poll_error: str | None = None


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
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/policy/reload":
            reloaded = self.server.daemon_ref.reload_policy_now()  # type: ignore[attr-defined]
            self._send_json(200, {"reloaded": reloaded})
            return
        if parsed.path == "/revoke/principal":
            payload = self._read_json_body()
            principal_id = payload.get("principal_id")
            if not isinstance(principal_id, str) or principal_id.strip() == "":
                self._send_json(400, {"error": "principal_id is required"})
                return
            self.server.daemon_ref.revoke_principal(principal_id.strip())  # type: ignore[attr-defined]
            self._send_json(200, {"ok": True, "principal_id": principal_id.strip()})
            return
        if parsed.path == "/revoke/intent":
            payload = self._read_json_body()
            intent_hash = payload.get("intent_hash")
            if not isinstance(intent_hash, str) or intent_hash.strip() == "":
                self._send_json(400, {"error": "intent_hash is required"})
                return
            self.server.daemon_ref.revoke_intent(intent_hash.strip())  # type: ignore[attr-defined]
            self._send_json(200, {"ok": True, "intent_hash": intent_hash.strip()})
            return
        self._send_json(404, {"error": "not_found"})

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
    def __init__(self, sidecar: PredicateAuthoritySidecar, config: DaemonConfig) -> None:
        self._sidecar = sidecar
        self._config = config
        self._runtime = DaemonRuntime(started_at_epoch_s=time.time())
        self._stop_event = threading.Event()
        self._http_server: _DaemonHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._poll_thread: threading.Thread | None = None

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
        self._server_thread.start()
        self._poll_thread.start()

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


def _build_default_sidecar(
    mode: AuthorityMode,
    policy_file: str | None,
    credential_store_file: str,
    control_plane_config: ControlPlaneBootstrapConfig | None = None,
    identity_bridge: ExchangeTokenBridge | None = None,
) -> PredicateAuthoritySidecar:
    policy_rules: tuple[PolicyRule, ...] = ()
    if policy_file is not None and Path(policy_file).exists():
        policy_rules = PolicyFileSource(policy_file).load_rules()
    policy_engine = PolicyEngine(rules=policy_rules)

    trace_emitter = None
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
        trace_emitter = ControlPlaneTraceEmitter(
            client=control_plane_client,
            emit_usage_credits=True,
            usage_credits_per_decision=control_plane_config.usage_credits_per_decision,
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
    identity_bridge = _build_identity_bridge_from_args(args)
    sidecar = _build_default_sidecar(
        mode=mode,
        policy_file=args.policy_file,
        credential_store_file=args.credential_store_file,
        control_plane_config=control_plane_bootstrap,
        identity_bridge=identity_bridge,
    )
    daemon = PredicateAuthorityDaemon(
        sidecar=sidecar,
        config=DaemonConfig(
            host=args.host,
            port=args.port,
            policy_poll_interval_s=args.policy_poll_interval_s,
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
