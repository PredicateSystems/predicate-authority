from __future__ import annotations

import http.client
import json
import urllib.parse
from dataclasses import dataclass


class OidcCompatibilityError(RuntimeError):
    pass


STATUS_REASON_CAPABILITY_DISABLED = "provider_capability_disabled"
STATUS_REASON_OK = "ok"
STATUS_REASON_SUBJECT_TOKEN_REQUIRED = "subject_token_required"  # nosec B105
STATUS_REASON_UNSUPPORTED_GRANT = "unsupported_grant_or_provider"
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # nosec B105
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"  # nosec B105


@dataclass(frozen=True)
class OidcProviderCapabilities:
    supports_token_exchange: bool = False


@dataclass(frozen=True)
class OidcCompatibilityConfig:
    issuer: str
    client_id: str
    client_secret: str
    audience: str
    scope: str = "authority:check"


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "y", "on"}:
        return True
    if lowered in {"0", "false", "no", "n", "off"}:
        return False
    return default


def run_oidc_token_exchange_compatibility_check(
    config: OidcCompatibilityConfig,
    capabilities: OidcProviderCapabilities,
    subject_token: str | None = None,
    timeout_s: float = 5.0,
) -> dict[str, object]:
    discovery_url = f"{config.issuer.rstrip('/')}/.well-known/openid-configuration"
    discovery = _http_get_json(url=discovery_url, timeout_s=timeout_s)
    token_endpoint = discovery.get("token_endpoint")
    if not isinstance(token_endpoint, str) or token_endpoint.strip() == "":
        raise OidcCompatibilityError("OIDC discovery did not return token_endpoint.")

    cc_payload = {
        "grant_type": "client_credentials",
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "scope": config.scope,
        "audience": config.audience,
    }
    cc_response = _http_post_form(url=token_endpoint, payload=cc_payload, timeout_s=timeout_s)
    access_token = cc_response.get("access_token")
    if not isinstance(access_token, str) or access_token.strip() == "":
        raise OidcCompatibilityError("Client credentials flow did not return access_token.")

    result: dict[str, object] = {
        "issuer": config.issuer,
        "token_endpoint": token_endpoint,
        "client_credentials_ok": True,
        "supports_token_exchange": capabilities.supports_token_exchange,
    }

    if not capabilities.supports_token_exchange:
        result["token_exchange_ok"] = False
        result["token_exchange_reason"] = STATUS_REASON_CAPABILITY_DISABLED
        return result

    subject = subject_token if subject_token and subject_token.strip() != "" else None
    if subject is None:
        result["token_exchange_ok"] = False
        result["token_exchange_reason"] = STATUS_REASON_SUBJECT_TOKEN_REQUIRED
        return result

    te_payload = {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "subject_token": subject,
        "subject_token_type": TOKEN_TYPE_ACCESS,
        "requested_token_type": TOKEN_TYPE_ACCESS,
        "audience": config.audience,
        "scope": config.scope,
    }
    try:
        te_response = _http_post_form(url=token_endpoint, payload=te_payload, timeout_s=timeout_s)
    except OidcCompatibilityError as exc:
        text = str(exc).lower()
        if "unsupported_grant_type" in text or "unauthorized_client" in text:
            result["token_exchange_ok"] = False
            result["token_exchange_reason"] = STATUS_REASON_UNSUPPORTED_GRANT
            return result
        raise
    delegated_token = te_response.get("access_token")
    if not isinstance(delegated_token, str) or delegated_token.strip() == "":
        raise OidcCompatibilityError("Token exchange did not return access_token.")
    result["token_exchange_ok"] = True
    result["token_exchange_reason"] = STATUS_REASON_OK
    return result


def _http_get_json(url: str, timeout_s: float) -> dict[str, object]:
    raw = _http_request(url=url, method="GET", body=None, headers={}, timeout_s=timeout_s)
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OidcCompatibilityError(f"Invalid JSON response from {url}") from exc
    if not isinstance(loaded, dict):
        raise OidcCompatibilityError(f"Expected object JSON response from {url}")
    return loaded


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
        raise OidcCompatibilityError(f"Invalid JSON response from token endpoint {url}") from exc
    if not isinstance(loaded, dict):
        raise OidcCompatibilityError(f"Expected object JSON response from token endpoint {url}")
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
        raise OidcCompatibilityError(f"Invalid URL: {url}")
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
        raise OidcCompatibilityError(f"Network error reaching {url}: {exc}") from exc
    finally:
        conn.close()
    if response.status >= 400:
        raise OidcCompatibilityError(f"HTTP {response.status} from {url}: {raw}")
    return raw
