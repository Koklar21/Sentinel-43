# =============================================================================
# Sentinel-43 -- target-acceptance helpers (kept out of conftest.py so
# `from conftest import ...` never collides with browser_tests/conftest.py).
#
# Real DNS, real trusted-CA TLS, the same endpoint for browser and API. No
# CERT_NONE, no SPKI exception, no Host override, no loopback mapping.
# =============================================================================

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

import pytest

BASE_URL = os.environ.get("S43_TARGET_BASE_URL", "")
CA_BUNDLE = os.environ.get("S43_TARGET_CA_BUNDLE", "")


def tls_context() -> ssl.SSLContext:
    """Standard verification. An approved private CA is TRUSTED by adding it,
    never by turning verification off."""
    return ssl.create_default_context(cafile=CA_BUNDLE or None)


def require_https_base() -> str:
    if not BASE_URL:
        pytest.fail(
            "S43_TARGET_BASE_URL is not set -- target acceptance cannot run. "
            "This is an INCOMPLETE result, not a pass. Set it to "
            "https://<beta-fqdn> and re-run browser_tests/run_target.sh.",
            pytrace=False,
        )
    if not BASE_URL.startswith("https://"):
        pytest.fail(f"S43_TARGET_BASE_URL must be https://, got {BASE_URL!r}",
                    pytrace=False)
    return BASE_URL.rstrip("/")


def read_cred(env_var: str, *, purpose: str) -> tuple[str, str]:
    """Load {username,password} from the file named by `env_var` (two lines or
    a JSON object). Never logged, never echoed."""
    path = os.environ.get(env_var, "")
    if not path:
        pytest.fail(
            f"{env_var} is not set -- {purpose} requires a dedicated beta test "
            "account supplied through a credentials file. Missing credentials "
            "is an INCOMPLETE result, not a green skip.",
            pytrace=False,
        )
    try:
        raw = open(path, encoding="utf-8").read().strip()
    except OSError as exc:
        pytest.fail(f"{env_var}={path!r} could not be read: {exc}", pytrace=False)
    try:
        obj = json.loads(raw)
        return str(obj["username"]), str(obj["password"])
    except (ValueError, KeyError):
        parts = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if len(parts) >= 2:
            return parts[0], parts[1]
    pytest.fail(f"{env_var} file is neither JSON {{username,password}} nor two "
                "non-empty lines", pytrace=False)


def target_request(method: str, path: str, *, headers: dict | None = None,
                   body: dict | None = None) -> tuple[int, dict]:
    """Out-of-band API call to the SAME endpoint the browser uses."""
    base = require_https_base()
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", "Origin": base,
         "User-Agent": "s43-target-acceptance"}
    h.update(headers or {})
    req = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=15, context=tls_context()) as resp:
            txt = resp.read().decode()
            return resp.status, (json.loads(txt) if txt else {})
    except urllib.error.HTTPError as exc:
        txt = exc.read().decode()
        return exc.code, (json.loads(txt) if txt else {})
