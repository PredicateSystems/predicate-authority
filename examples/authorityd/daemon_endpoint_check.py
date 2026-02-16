from __future__ import annotations

import http.client
import json
from urllib.parse import urlsplit


def fetch_json(url: str) -> dict[str, object]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError(f"Unsupported URL scheme: {parsed.scheme}")
    if parsed.netloc == "":
        raise RuntimeError("URL must include host:port.")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    connection_cls = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_cls(parsed.netloc, timeout=2.0)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        payload = response.read().decode("utf-8")
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {payload}")
    finally:
        connection.close()

    loaded = json.loads(payload)
    if not isinstance(loaded, dict):
        raise RuntimeError("Expected JSON object response.")
    return loaded


def main() -> None:
    base_url = "http://127.0.0.1:8787"
    health = fetch_json(f"{base_url}/health")
    status = fetch_json(f"{base_url}/status")
    print("health:", json.dumps(health, indent=2))
    print("status:", json.dumps(status, indent=2))


if __name__ == "__main__":
    main()
