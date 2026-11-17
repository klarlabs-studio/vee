#!/usr/bin/env python3
"""Smoke-test the local Vero UI and same-origin API against a running `vero ui`."""
import json
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def get(url):
    with urlopen(url, timeout=10) as response:
        return response.status, response.headers, response.read()


def main():
    origin = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:7878"
    checks = [("/", b"Vero"), ("/app.js", b"createApp"), ("/app.css", b"--green")]
    for path, marker in checks:
        status, _, body = get(origin + path)
        assert status == 200 and marker in body, f"UI asset failed: {path}"
    status, _, body = get(origin + "/api/health")
    health = json.loads(body)
    assert status == 200 and health["status"] == "ok", health
    _, _, config_body = get(origin + "/api/config")
    config = json.loads(config_body)
    assert "config" in config and isinstance(config["reviewer_ids"], list), config
    _, _, reviews_body = get(origin + "/api/reviews")
    assert isinstance(json.loads(reviews_body), list)

    # Mutating operations must reject a foreign Origin before parsing or writing.
    request = Request(origin + "/api/config", data=b'{"config":{}}', method="PUT", headers={
        "Content-Type": "application/json", "Origin": "http://attacker.invalid"
    })
    try:
        urlopen(request, timeout=10)
        raise AssertionError("cross-origin config write unexpectedly succeeded")
    except HTTPError as error:
        assert error.code == 400, f"unexpected cross-origin status {error.code}"

    # Invalid configuration must be rejected without modifying the repository file.
    config_path = Path(".vero.yaml")
    before = config_path.read_bytes()
    invalid = Request(origin + "/api/config", data=b'{"config":{"version":1,"unknown":true}}', method="PUT", headers={
        "Content-Type": "application/json", "Origin": origin
    })
    try:
        urlopen(invalid, timeout=10)
        raise AssertionError("invalid config unexpectedly saved")
    except HTTPError as error:
        assert error.code == 400, f"unexpected invalid-config status {error.code}"
    assert config_path.read_bytes() == before, "rejected config changed .vero.yaml"
    print(json.dumps({"status": "pass", "checks": ["assets", "health", "config", "reviews", "origin_guard", "invalid_config_is_atomic"]}))


if __name__ == "__main__":
    main()
