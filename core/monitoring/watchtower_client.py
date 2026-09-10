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

There is exactly one Watchtower client contract: ``watchtower_request()``
(and the best-effort ``watchtower_report()`` wrapper built on it). Every
internal caller -- the API bridge routes in ``core.api.main``, the remote
gateway, and dependency-layer telemetry -- goes through it. No caller builds
its own ``urllib.request.Request`` and no other module parses the Watchtower
connection settings.

DEFECT_INVENTORY.md D-15/D-16: ~12 near-identical ``_watchtower_request``
implementations used to exist; ~10 sent no ``Authorization`` header, so every
POST to a ``_require_service_token``-protected route returned 401, and the
caller's surrounding ``except Exception`` swallowed it -- lost telemetry.
This client always attaches ``Authorization: Bearer
<S43_WATCHTOWER_SERVICE_TOKEN>`` when a token is configured, and surfaces
every non-2xx / unreachable / malformed result as ``{"error": ...}`` plus a
rate-limited WARNING (never a silent success, never a raise).

Configuration: the API composition root (``core.api.main`` lifespan) calls
``configure(base_url=..., timeout_seconds=...)`` once at startup with the
values it parsed from the environment. Until then -- and for scripts / tests
that never run the lifespan -- the base URL and timeout fall back to
``S43_WATCHTOWER_URL`` / ``S43_WATCHTOWER_TIMEOUT``. The service token is
always resolved from ``S43_WATCHTOWER_SERVICE_TOKEN`` at call time so an
operator can rotate it without a restart.
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

logger = logging.getLogger(__name__)

# The Watchtower routes live on the s43-core service (see docker-compose.yml
# S43_WATCHTOWER_URL=http://s43-core:9100) — there is no separate
# "s43-watchtower" host in this deployment topology. Several of the
# now-replaced call sites defaulted to http://s43-watchtower:9100, which
# only worked because docker-compose always set the env var explicitly.
#
# These module-level values are the effective connection settings. They are
# seeded from the environment on import so non-lifespan contexts work, and
# replaced in place by configure() when the composition root injects the
# values it parsed. There is no mutable client object -- watchtower_request()
# is a stateless function that reads these each call.
WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-core:9100").rstrip("/")
WATCHTOWER_SERVICE_TOKEN_ENV = "S43_WATCHTOWER_SERVICE_TOKEN"

_configured = False


def configure(
    *,
    base_url: str | None = None,
    timeout_seconds: float | None = None,
) -> None:
    """Inject the Watchtower connection settings from the composition root.

    Called once by ``core.api.main`` at startup. Idempotent-safe: a second
    call with different values logs a warning and applies the new values
    (relevant only to tests that reconfigure between cases).
    """
    global WATCHTOWER_URL, WATCHTOWER_TIMEOUT, _configured

    if base_url is not None:
        cleaned = base_url.strip().rstrip("/")
        if not cleaned:
            raise ValueError("watchtower base_url must not be empty")
        if _configured and cleaned != WATCHTOWER_URL:
            logger.warning(
                "Watchtower client reconfigured: base_url %s -> %s",
                WATCHTOWER_URL,
                cleaned,
            )
        WATCHTOWER_URL = cleaned

    if timeout_seconds is not None:
        WATCHTOWER_TIMEOUT = _validate_timeout(timeout_seconds)

    _configured = True


def watchtower_base_url() -> str:
    """The effective Watchtower base URL (for status/diagnostic payloads)."""
    return WATCHTOWER_URL


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

# Ceiling on the max_response_bytes argument itself -- a caller passing an
# unbounded or absurd value defeats the whole point of the cap.
_MAX_ALLOWED_RESPONSE_BYTES = 64 * 1024 * 1024

# Ceiling on the timeout argument itself -- large enough for any legitimate
# internal call, small enough that a misconfigured caller can't hang a
# request thread indefinitely.
_MAX_ALLOWED_TIMEOUT_SECONDS = 300.0


def _validate_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"timeout must be a real number, got {type(value).__name__}")
    if not math.isfinite(value) or value <= 0 or value > _MAX_ALLOWED_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout must be finite and in (0, {_MAX_ALLOWED_TIMEOUT_SECONDS}], got {value!r}"
        )
    return float(value)


def _validate_max_response_bytes(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"max_response_bytes must be an int, got {type(value).__name__}")
    if value <= 0 or value > _MAX_ALLOWED_RESPONSE_BYTES:
        raise ValueError(
            f"max_response_bytes must be in (0, {_MAX_ALLOWED_RESPONSE_BYTES}], got {value!r}"
        )
    return value


def _bounded_read(
    read_fn: Callable[[int], bytes],
    get_header_fn: Callable[[str], str | None],
    max_response_bytes: int,
) -> tuple[bytes, bool]:
    """
    Read at most `max_response_bytes` from a urlopen response/error object,
    proving the cap was respected rather than merely truncating silently.

    Returns (body, oversized). `oversized` is True when the response is (or
    would be) larger than the cap -- either because a declared
    Content-Length already exceeds it (no body read attempted), or because
    reading max_response_bytes + 1 bytes actually yielded that many (an
    undeclared-length or chunked body that overruns the cap). Callers must
    treat an oversized body as failure, never as a truncated success.
    """
    declared_length: int | None = None
    try:
        raw_length = get_header_fn("Content-Length")
    except Exception:
        raw_length = None
    if raw_length is not None:
        try:
            declared_length = int(str(raw_length).strip())
        except ValueError:
            declared_length = None

    if declared_length is not None and declared_length > max_response_bytes:
        return b"", True

    chunk = read_fn(max_response_bytes + 1)
    if len(chunk) > max_response_bytes:
        return chunk[:max_response_bytes], True
    return chunk, False


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
    timeout, unreachable host, oversized or malformed response, invalid
    arguments) is returned as `{"error": ..., "detail": ...}` and also
    logged at WARNING (rate-limited per path+kind, except invalid-argument
    misuse which is a caller bug, not a Watchtower outage, and is not
    rate-limited into invisibility). Callers must check for the "error"
    key; a returned dict is not automatically success. Never logs the
    bearer token, the Authorization header, payload contents, or response
    bodies -- those are returned to the caller (who owns them already), not
    written to shared logs.
    """
    try:
        effective_timeout = _validate_timeout(
            WATCHTOWER_TIMEOUT if timeout is None else timeout
        )
    except ValueError as exc:
        logger.warning("Watchtower request %s %s rejected: %s", method.upper(), path, exc)
        return {"error": "watchtower_invalid_timeout", "detail": str(exc)}

    try:
        max_response_bytes = _validate_max_response_bytes(max_response_bytes)
    except ValueError as exc:
        logger.warning("Watchtower request %s %s rejected: %s", method.upper(), path, exc)
        return {"error": "watchtower_invalid_max_response_bytes", "detail": str(exc)}

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
            if _should_log((path, "payload_serialization")):
                logger.warning(
                    "Watchtower request %s %s failed: payload could not be "
                    "serialized (%s)",
                    method.upper(), path, type(exc).__name__,
                )
            return {"error": "watchtower_payload_serialization_error", "detail": str(exc)}

    request = urllib.request.Request(url=url, data=data, headers=headers, method=method.upper())

    try:
        with urllib.request.urlopen(request, timeout=effective_timeout) as response:
            body_bytes, oversized = _bounded_read(
                response.read, response.getheader, max_response_bytes,
            )
            if oversized:
                if _should_log((path, "oversized_response")):
                    logger.warning(
                        "Watchtower request %s %s failed: response exceeded "
                        "the %d byte cap",
                        method.upper(), path, max_response_bytes,
                    )
                return {"error": "watchtower_response_too_large", "status_code": response.status}

            if not body_bytes:
                return {"status_code": response.status}

            try:
                body = body_bytes.decode("utf-8")
                parsed = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                if _should_log((path, "malformed_response")):
                    logger.warning(
                        "Watchtower request %s %s failed: response body was "
                        "not valid JSON",
                        method.upper(), path,
                    )
                return {"error": "watchtower_malformed_response", "status_code": response.status}

            if isinstance(parsed, dict):
                parsed.setdefault("status_code", response.status)
                return parsed
            return {"status_code": response.status, "body": parsed}

    except urllib.error.HTTPError as exc:
        body_bytes, oversized = _bounded_read(
            exc.read,
            (lambda name: exc.headers.get(name) if exc.headers is not None else None),
            max_response_bytes,
        )
        if oversized:
            if _should_log((path, "oversized_error_body")):
                logger.warning(
                    "Watchtower request %s %s failed: HTTP %s (error body "
                    "exceeded the %d byte cap)",
                    method.upper(), path, exc.code, max_response_bytes,
                )
            return {
                "error": "watchtower_http_error",
                "status_code": exc.code,
                "detail": "response body exceeded size limit",
            }
        try:
            detail = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            detail = "<non-utf8 body>"
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

    except TimeoutError:
        if _should_log((path, "timeout")):
            logger.warning(
                "Watchtower request %s %s failed: timed out after %.1fs",
                method.upper(), path, effective_timeout,
            )
        return {"error": "watchtower_timeout", "detail": "request timed out"}

    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            if _should_log((path, "timeout")):
                logger.warning(
                    "Watchtower request %s %s failed: timed out after %.1fs",
                    method.upper(), path, effective_timeout,
                )
            return {"error": "watchtower_timeout", "detail": "request timed out"}
        if _should_log((path, "unreachable")):
            logger.warning(
                "Watchtower request %s %s failed: %s",
                method.upper(), path, type(exc.reason).__name__,
            )
        return {"error": "watchtower_unreachable", "detail": str(exc.reason)}

    except Exception as exc:
        if _should_log((path, "unreachable")):
            logger.warning(
                "Watchtower request %s %s failed: %s: %s",
                method.upper(), path, type(exc).__name__, exc,
            )
        return {"error": "watchtower_unreachable", "detail": str(exc)}


def watchtower_report(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Best-effort Watchtower telemetry: fire and forget.

    Returns the parsed response dict on success, or ``None`` when the call
    failed (``watchtower_request`` already logged, rate-limited). Use this for
    telemetry that must never affect the caller's own outcome -- module
    registration, dependency-status reports, config-load notifications. Use
    ``watchtower_request`` directly when the caller needs to react to the
    result (the API bridge routes).
    """
    try:
        result = watchtower_request(method, path, payload)
    except Exception:  # pragma: no cover - watchtower_request never raises
        logger.debug(
            "Watchtower telemetry raised unexpectedly: %s %s",
            method,
            path,
            exc_info=True,
        )
        return None

    if "error" in result:
        return None
    return result
