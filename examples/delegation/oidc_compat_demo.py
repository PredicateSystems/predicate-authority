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
    subject_token: str | None,
    timeout_s: float,
) -> dict[str, object]:
    _ensure_repo_root_on_syspath()
    from predicate_authority import (  # pylint: disable=import-error
        OidcCompatibilityConfig,
        OidcProviderCapabilities,
        run_oidc_token_exchange_compatibility_check,
    )

    result = run_oidc_token_exchange_compatibility_check(
        config=OidcCompatibilityConfig(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            audience=audience,
            scope=scope,
        ),
        capabilities=OidcProviderCapabilities(supports_token_exchange=supports_token_exchange),
        subject_token=subject_token,
        timeout_s=timeout_s,
    )
    result["delegation_path"] = (
        "idp_token_exchange"
        if bool(result.get("token_exchange_ok", False))
        else "authority_mandate_delegation"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="OIDC token exchange compatibility demo.")
    parser.add_argument("--issuer", default=os.getenv("OIDC_ISSUER"))
    parser.add_argument("--client-id", default=os.getenv("OIDC_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("OIDC_CLIENT_SECRET"))
    parser.add_argument("--audience", default=os.getenv("OIDC_AUDIENCE"))
    parser.add_argument("--scope", default=os.getenv("OIDC_SCOPE", "authority:check"))
    parser.add_argument("--subject-token", default=os.getenv("OIDC_SUBJECT_TOKEN"))
    parser.add_argument("--supports-token-exchange", action="store_true")
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
        subject_token=(str(args.subject_token) if args.subject_token is not None else None),
        timeout_s=float(args.timeout_s),
    )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
