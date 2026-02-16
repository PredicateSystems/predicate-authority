from __future__ import annotations

import argparse
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from predicate_authority.bridge import IdentityBridge
from predicate_authority.guard import ActionGuard
from predicate_authority.mandate import LocalMandateSigner
from predicate_authority.policy import PolicyEngine
from predicate_authority.policy_source import PolicyFileSource
from predicate_authority.proof import InMemoryProofLedger
from predicate_authority.revocation import LocalRevocationCache
from predicate_authority.sidecar import AuthorityMode, PredicateAuthoritySidecar, SidecarConfig
from predicate_authority.sidecar_store import LocalCredentialStore
from predicate_contracts import PolicyRule


@dataclass(frozen=True)
class DaemonConfig:
    host: str = "127.0.0.1"
    port: int = 8787
    policy_poll_interval_s: float = 2.0


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

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Keep daemon output deterministic and quiet by default.
        return

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
    mode: AuthorityMode, policy_file: str | None, credential_store_file: str
) -> PredicateAuthoritySidecar:
    policy_rules: tuple[PolicyRule, ...] = ()
    if policy_file is not None and Path(policy_file).exists():
        policy_rules = PolicyFileSource(policy_file).load_rules()
    policy_engine = PolicyEngine(rules=policy_rules)
    proof_ledger = InMemoryProofLedger()
    guard = ActionGuard(
        policy_engine=policy_engine,
        mandate_signer=LocalMandateSigner(secret_key=secrets.token_hex(32)),
        proof_ledger=proof_ledger,
    )
    return PredicateAuthoritySidecar(
        config=SidecarConfig(mode=mode, policy_file_path=policy_file),
        action_guard=guard,
        proof_ledger=proof_ledger,
        identity_bridge=IdentityBridge(),
        credential_store=LocalCredentialStore(credential_store_file),
        revocation_cache=LocalRevocationCache(),
        policy_engine=policy_engine,
    )


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
    args = parser.parse_args()

    mode = AuthorityMode(args.mode)
    sidecar = _build_default_sidecar(
        mode=mode,
        policy_file=args.policy_file,
        credential_store_file=args.credential_store_file,
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
        f"(mode={mode.value})"
    )
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        daemon.stop()
        print("predicate-authorityd stopped")


if __name__ == "__main__":
    main()
