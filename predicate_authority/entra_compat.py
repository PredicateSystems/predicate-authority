from __future__ import annotations

import http.client
import json
import urllib.parse
from dataclasses import dataclass


class EntraCompatibilityError(RuntimeError):
    pass


STATUS_REASON_CAPABILITY_DISABLED = "tenant_capability_disabled"
STATUS_REASON_OK = "ok"
STATUS_REASON_USER_ASSERTION_REQUIRED = "user_assertion_required"
GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
REQUESTED_TOKEN_USE_OBO = "on_behalf_of"  # nosec B105


@dataclass(frozen=True)
class EntraTenantCapabilities:
    supports_obo: bool = False


@dataclass(frozen=True)
class EntraCompatibilityConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    scope: str = "api://predicate-authority/.default"
    authority_host: str = "login.microsoftonline.com"
    authority_scheme: str = "https"


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "y", "on"}:
        return True
    if lowered in {"0", "false", "no", "n", "off"}:
        return False
    return default


def run_entra_obo_compatibility_check(
    config: EntraCompatibilityConfig,
    capabilities: EntraTenantCapabilities,
    user_assertion: str | None = None,
    timeout_s: float = 5.0,
) -> dict[str, object]:
    token_endpoint = (
        f"{config.authority_scheme}://{config.authority_host}/"
        f"{config.tenant_id}/oauth2/v2.0/token"
    )
    cc_payload = {
        "grant_type": "client_credentials",
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "scope": config.scope,
    }
    cc_response = _http_post_form(url=token_endpoint, payload=cc_payload, timeout_s=timeout_s)
    access_token = cc_response.get("access_token")
    if not isinstance(access_token, str) or access_token.strip() == "":
        raise EntraCompatibilityError("Client credentials flow did not return access_token.")

    result: dict[str, object] = {
        "tenant_id": config.tenant_id,
        "token_endpoint": token_endpoint,
        "client_credentials_ok": True,
        "supports_obo": capabilities.supports_obo,
    }

    if not capabilities.supports_obo:
        result["obo_ok"] = False
        result["obo_reason"] = STATUS_REASON_CAPABILITY_DISABLED
        return result

    if user_assertion is None or user_assertion.strip() == "":
        result["obo_ok"] = False
        result["obo_reason"] = STATUS_REASON_USER_ASSERTION_REQUIRED
        return result

    obo_payload = {
        "grant_type": GRANT_TYPE_JWT_BEARER,
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "assertion": user_assertion,
        "requested_token_use": REQUESTED_TOKEN_USE_OBO,
        "scope": config.scope,
    }
    obo_response = _http_post_form(url=token_endpoint, payload=obo_payload, timeout_s=timeout_s)
    obo_token = obo_response.get("access_token")
    if not isinstance(obo_token, str) or obo_token.strip() == "":
        raise EntraCompatibilityError("OBO token exchange did not return access_token.")
    result["obo_ok"] = True
    result["obo_reason"] = STATUS_REASON_OK
    return result


def _http_post_form(url: str, payload: dict[str, str], timeout_s: float) -> dict[str, object]:
    body = urllib.parse.urlencode(payload).encode("utf-8")
    raw = _http_request(
        url=url,
        method="POST",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout_s=timeout_s,
    )
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EntraCompatibilityError(f"Invalid JSON response from token endpoint {url}") from exc
    if not isinstance(loaded, dict):
        raise EntraCompatibilityError(f"Expected object JSON response from token endpoint {url}")
    return loaded


def _http_request(
    url: str,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    timeout_s: float,
) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.netloc == "":
        raise EntraCompatibilityError(f"Invalid URL: {url}")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if parsed.scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            parsed.netloc, timeout=timeout_s
        )
    else:
        conn = http.client.HTTPConnection(parsed.netloc, timeout=timeout_s)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
    except OSError as exc:
        raise EntraCompatibilityError(f"Network error reaching {url}: {exc}") from exc
    finally:
        conn.close()
    if response.status >= 400:
        raise EntraCompatibilityError(f"HTTP {response.status} from {url}: {raw}")
    return raw
