from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _ensure_repo_root_on_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    root = str(repo_root)
    if root not in sys.path:
        sys.path.insert(0, root)


def run(
    issuer: str,
    client_id: str,
    client_secret: str,
    audience: str,
    scope: str,
    supports_token_exchange: bool,
    timeout_s: float,
) -> dict[str, object]:
    _ensure_repo_root_on_syspath()
    from predicate_authority import (  # pylint: disable=import-error
        OktaCompatibilityConfig,
        OktaTenantCapabilities,
        run_okta_obo_compatibility_check,
    )

    result = run_okta_obo_compatibility_check(
        config=OktaCompatibilityConfig(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            audience=audience,
            scope=scope,
        ),
        capabilities=OktaTenantCapabilities(supports_token_exchange=supports_token_exchange),
        timeout_s=timeout_s,
    )
    result["delegation_path"] = (
        "idp_token_exchange"
        if bool(result.get("token_exchange_ok", False))
        else "authority_mandate_delegation"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Okta OBO compatibility demo for delegation flow.")
    parser.add_argument("--issuer", default=os.getenv("OKTA_ISSUER"))
    parser.add_argument("--client-id", default=os.getenv("OKTA_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("OKTA_CLIENT_SECRET"))
    parser.add_argument("--audience", default=os.getenv("OKTA_AUDIENCE"))
    parser.add_argument("--scope", default=os.getenv("OKTA_SCOPE", "authority:check"))
    parser.add_argument(
        "--supports-token-exchange",
        action="store_true",
        help="Set if this Okta tenant is expected to support token exchange/OBO.",
    )
    parser.add_argument("--timeout-s", type=float, default=5.0)
    args = parser.parse_args()

    missing = [
        name
        for name, value in (
            ("issuer", args.issuer),
            ("client_id", args.client_id),
            ("client_secret", args.client_secret),
            ("audience", args.audience),
        )
        if value is None or str(value).strip() == ""
    ]
    if missing:
        raise SystemExit(f"Missing required arguments/env vars: {', '.join(missing)}")

    payload = run(
        issuer=str(args.issuer),
        client_id=str(args.client_id),
        client_secret=str(args.client_secret),
        audience=str(args.audience),
        scope=str(args.scope),
        supports_token_exchange=bool(args.supports_token_exchange),
        timeout_s=float(args.timeout_s),
    )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
