from __future__ import annotations

import argparse
import http.client
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from predicate_authority.policy_source import PolicyFileSource


def _request_json(
    method: str, url: str, payload: dict[str, str] | None = None
) -> tuple[int, dict[str, object]]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError(f"Unsupported URL scheme: {parsed.scheme}")
    if parsed.netloc == "":
        raise RuntimeError("URL must include host:port.")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    body = None
    headers: dict[str, str] = {}
    if payload is not None:
        body = json.dumps(payload)
        headers["Content-Type"] = "application/json"
    connection_cls = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_cls(parsed.netloc, timeout=5.0)
    try:
        connection.request(method.upper(), path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
    finally:
        connection.close()
    if raw.strip() == "":
        return int(response.status), {}
    loaded = json.loads(raw)
    if not isinstance(loaded, dict):
        raise RuntimeError("Expected JSON object response.")
    return int(response.status), loaded


def _base_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def _print_json(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _cmd_sidecar_health(args: argparse.Namespace) -> int:
    status, payload = _request_json("GET", f"{_base_url(args.host, args.port)}/health")
    _print_json(payload)
    return 0 if status < 400 else 1


def _cmd_sidecar_status(args: argparse.Namespace) -> int:
    status, payload = _request_json("GET", f"{_base_url(args.host, args.port)}/status")
    _print_json(payload)
    return 0 if status < 400 else 1


def _cmd_policy_validate(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"Policy file not found: {path}", file=sys.stderr)
        return 1
    try:
        rules = PolicyFileSource(str(path)).load_rules()
    except Exception as exc:  # noqa: BLE001
        print(f"Policy validation failed: {exc}", file=sys.stderr)
        return 1
    _print_json({"valid": True, "rule_count": len(rules), "file": str(path)})
    return 0


def _cmd_policy_reload(args: argparse.Namespace) -> int:
    status, payload = _request_json("POST", f"{_base_url(args.host, args.port)}/policy/reload")
    _print_json(payload)
    return 0 if status < 400 else 1


def _cmd_revoke_principal(args: argparse.Namespace) -> int:
    status, payload = _request_json(
        "POST",
        f"{_base_url(args.host, args.port)}/revoke/principal",
        payload={"principal_id": args.id},
    )
    _print_json(payload)
    return 0 if status < 400 else 1


def _cmd_revoke_intent(args: argparse.Namespace) -> int:
    status, payload = _request_json(
        "POST",
        f"{_base_url(args.host, args.port)}/revoke/intent",
        payload={"intent_hash": args.hash},
    )
    _print_json(payload)
    return 0 if status < 400 else 1


def _add_host_port_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="predicate-authority operational CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sidecar_parser = subparsers.add_parser("sidecar", help="Sidecar inspection commands")
    sidecar_sub = sidecar_parser.add_subparsers(dest="sidecar_command", required=True)

    sidecar_health = sidecar_sub.add_parser("health", help="Query sidecar /health")
    _add_host_port_args(sidecar_health)
    sidecar_health.set_defaults(func=_cmd_sidecar_health)

    sidecar_status = sidecar_sub.add_parser("status", help="Query sidecar /status")
    _add_host_port_args(sidecar_status)
    sidecar_status.set_defaults(func=_cmd_sidecar_status)

    policy_parser = subparsers.add_parser("policy", help="Policy utility commands")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)

    policy_validate = policy_sub.add_parser("validate", help="Validate policy file")
    policy_validate.add_argument("--file", required=True)
    policy_validate.set_defaults(func=_cmd_policy_validate)

    policy_reload = policy_sub.add_parser("reload", help="Request sidecar policy reload")
    _add_host_port_args(policy_reload)
    policy_reload.set_defaults(func=_cmd_policy_reload)

    revoke_parser = subparsers.add_parser("revoke", help="Revocation commands")
    revoke_sub = revoke_parser.add_subparsers(dest="revoke_command", required=True)

    revoke_principal = revoke_sub.add_parser("principal", help="Revoke by principal_id")
    _add_host_port_args(revoke_principal)
    revoke_principal.add_argument("--id", required=True)
    revoke_principal.set_defaults(func=_cmd_revoke_principal)

    revoke_intent = revoke_sub.add_parser("intent", help="Revoke by intent hash")
    _add_host_port_args(revoke_intent)
    revoke_intent.add_argument("--hash", required=True)
    revoke_intent.set_defaults(func=_cmd_revoke_intent)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    exit_code = args.func(args)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
