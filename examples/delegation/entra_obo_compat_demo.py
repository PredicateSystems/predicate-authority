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
    tenant_id: str,
    client_id: str,
    client_secret: str,
    scope: str,
    supports_obo: bool,
    user_assertion: str | None,
    authority_host: str,
    authority_scheme: str,
    timeout_s: float,
) -> dict[str, object]:
    _ensure_repo_root_on_syspath()
    from predicate_authority import (  # pylint: disable=import-error
        EntraCompatibilityConfig,
        EntraTenantCapabilities,
        run_entra_obo_compatibility_check,
    )

    result = run_entra_obo_compatibility_check(
        config=EntraCompatibilityConfig(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            authority_host=authority_host,
            authority_scheme=authority_scheme,
        ),
        capabilities=EntraTenantCapabilities(supports_obo=supports_obo),
        user_assertion=user_assertion,
        timeout_s=timeout_s,
    )
    result["delegation_path"] = (
        "idp_obo_token_exchange"
        if bool(result.get("obo_ok", False))
        else "authority_mandate_delegation"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Entra OBO compatibility demo for delegation flow."
    )
    parser.add_argument("--tenant-id", default=os.getenv("ENTRA_TENANT_ID"))
    parser.add_argument("--client-id", default=os.getenv("ENTRA_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("ENTRA_CLIENT_SECRET"))
    parser.add_argument(
        "--scope", default=os.getenv("ENTRA_SCOPE", "api://predicate-authority/.default")
    )
    parser.add_argument("--user-assertion", default=os.getenv("ENTRA_USER_ASSERTION"))
    parser.add_argument(
        "--authority-host", default=os.getenv("ENTRA_AUTHORITY_HOST", "login.microsoftonline.com")
    )
    parser.add_argument("--authority-scheme", default=os.getenv("ENTRA_AUTHORITY_SCHEME", "https"))
    parser.add_argument("--timeout-s", type=float, default=5.0)
    parser.add_argument("--supports-obo", action="store_true")
    args = parser.parse_args()

    missing = [
        name
        for name, value in (
            ("tenant_id", args.tenant_id),
            ("client_id", args.client_id),
            ("client_secret", args.client_secret),
            ("scope", args.scope),
        )
        if value is None or str(value).strip() == ""
    ]
    if missing:
        raise SystemExit(f"Missing required arguments/env vars: {', '.join(missing)}")

    payload = run(
        tenant_id=str(args.tenant_id),
        client_id=str(args.client_id),
        client_secret=str(args.client_secret),
        scope=str(args.scope),
        supports_obo=bool(args.supports_obo),
        user_assertion=(str(args.user_assertion) if args.user_assertion is not None else None),
        authority_host=str(args.authority_host),
        authority_scheme=str(args.authority_scheme),
        timeout_s=float(args.timeout_s),
    )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
