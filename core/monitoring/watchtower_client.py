# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================

"""
Canonical Watchtower HTTP client for internal Sentinel-43 service callers.

DEFECT_INVENTORY.md D-15/D-16: 12 near-identical `_watchtower_request`
implementations existed across the codebase. 10 of them built the outgoing
request with no `Authorization` header, so every POST to a
`_require_service_token`-protected Watchtower route (register/heartbeat/
report/analyze) returned 401. `urllib.request.urlopen` raises `HTTPError` on
that 401, and the caller's surrounding `except Exception` (`pass`, in
several cases) swallowed it — the caller believed the report was delivered.
It never reached Watchtower. Lost telemetry included expectation/contract
failures, invalid-log-level events, event-normalization reports, and
dependency-module registrations.

Every internal caller must use `watchtower_request()` here instead of
building its own `urllib.request.Request`. It always attaches
`Authorization: Bearer <S43_WATCHTOWER_SERVICE_TOKEN>` when the token is
configured, and a non-2xx / unreachable result is surfaced via a
rate-limited WARNING log (never silently swallowed) so an outage or a bad
token is visible without flooding logs on every call during a sustained
Watchtower outage.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# The Watchtower routes live on the s43-core service (see docker-compose.yml
# S43_WATCHTOWER_URL=http://s43-core:9100) — there is no separate
# "s43-watchtower" host in this deployment topology. Several of the
# now-replaced call sites defaulted to http://s43-watchtower:9100, which
# only worked because docker-compose always set the env var explicitly.
WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-core:9100").rstrip("/")
WATCHTOWER_SERVICE_TOKEN_ENV = "S43_WATCHTOWER_SERVICE_TOKEN"


def _float_env(name: str, default: float) -> float:
    # Parsed defensively (not a bare float() at module scope) so an
    # operator's malformed env value degrades to the default instead of
    # crashing import for every module that imports this client.
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "Invalid value %r for %s, falling back to default %s", raw, name, default,
        )
        return default


WATCHTOWER_TIMEOUT = _float_env("S43_WATCHTOWER_TIMEOUT", 2.0)

# Suppress repeat WARNINGs for the same (path, error-kind) pair within this
# window, so a sustained outage logs once per window instead of once per
# call (callers here can fire many times per second).
_LOG_SUPPRESS_SECONDS = 60.0
_last_logged: dict[tuple[str, str], float] = {}
_last_logged_lock = threading.Lock()


def _should_log(key: tuple[str, str]) -> bool:
    now = time.monotonic()
    with _last_logged_lock:
        last = _last_logged.get(key, 0.0)
        if now - last < _LOG_SUPPRESS_SECONDS:
            return False
        _last_logged[key] = now
        return True


# Default cap on a Watchtower response body. Bounded so a compromised or
# misbehaving Watchtower can't exhaust caller memory via urlopen().read().
_DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024


def watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout: float | None = None,
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """
    Send a request to a Watchtower route with the internal service token
    attached. Never raises — every failure mode (bad payload, HTTP error,
    unreachable host) is returned as `{"error": ..., "detail": ...}` and
    also logged at WARNING (rate-limited per path+kind). Callers must check
    for the "error" key; a returned dict is not automatically success.
    """
    url = f"{WATCHTOWER_URL}{path}"
    data = None
    headers = {"Content-Type": "application/json"}

    token = os.getenv(WATCHTOWER_SERVICE_TOKEN_ENV, "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if payload is not None:
        try:
            data = json.dumps(payload).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return {"error": "watchtower_payload_serialization_error", "detail": str(exc)}

    request = urllib.request.Request(url=url, data=data, headers=headers, method=method.upper())
    effective_timeout = WATCHTOWER_TIMEOUT if timeout is None else timeout

    try:
        with urllib.request.urlopen(request, timeout=effective_timeout) as response:
            body = response.read(max_response_bytes).decode("utf-8")
            if not body:
                return {"status_code": response.status}
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                parsed.setdefault("status_code", response.status)
                return parsed
            return {"status_code": response.status, "body": parsed}
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read(max_response_bytes).decode("utf-8")
        except Exception:
            detail = str(exc)
        if _should_log((path, "http_error")):
            no_token_note = (
                " (no S43_WATCHTOWER_SERVICE_TOKEN configured)"
                if exc.code in (401, 403) and not token else ""
            )
            logger.warning(
                "Watchtower request %s %s failed: HTTP %s%s",
                method.upper(), path, exc.code, no_token_note,
            )
        return {"error": "watchtower_http_error", "status_code": exc.code, "detail": detail}
    except Exception as exc:
        if _should_log((path, "unreachable")):
            logger.warning(
                "Watchtower request %s %s failed: %s: %s",
                method.upper(), path, type(exc).__name__, exc,
            )
        return {"error": "watchtower_unreachable", "detail": str(exc)}
