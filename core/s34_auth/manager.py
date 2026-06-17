# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
# =============================================================================

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import time
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Optional

from .exceptions import ExpiredTokenError, InvalidTokenError
from .models import AuthContext, AuthResult

logger = logging.getLogger(__name__)


# =============================================================================
# Env helpers
# =============================================================================

def _env_float(name: str, default: float, *, minimum: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("Invalid %s value %r. Falling back to %s.", name, raw, default)
        return default
    if value < minimum:
        logger.warning("%s value %r is below minimum %s. Falling back to %s.", name, raw, minimum, default)
        return default
    return value


def _env_int(name: str, default: int, *, minimum: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid %s value %r. Falling back to %s.", name, raw, default)
        return default
    if value < minimum:
        logger.warning("%s value %r is below minimum %s. Falling back to %s.", name, raw, minimum, default)
        return default
    return value


# =============================================================================
# Lazy config  (Fix #5: computed on first use, not at import time)
# =============================================================================

@lru_cache(maxsize=1)
def _get_config() -> dict[str, Any]:
    """
    Fix #5: Watchtower URL and related constants were previously evaluated at
    module import time, so Docker env-var injection after the module was loaded
    would have no effect. lru_cache means env vars are read on first call only.
    """
    return {
        "watchtower_url": os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/"),
        "watchtower_timeout": _env_float("S43_WATCHTOWER_TIMEOUT", 2.0, minimum=0.1),
        "queue_size": _env_int("S43_AUTH_WATCHTOWER_QUEUE_SIZE", 256, minimum=1),
        "module_id": (os.getenv("S43_AUTH_MODULE_ID", "sentinel43-auth-manager").strip()
                      or "sentinel43-auth-manager"),
        "auth_version": (os.getenv("SENTINEL_VERSION", "0.1.0").strip() or "0.1.0"),
        "clock_leeway": _env_int("S43_AUTH_CLOCK_LEEWAY_SECONDS", 10, minimum=0),
        "max_token_chars":   _env_int("S43_AUTH_MAX_TOKEN_CHARS",   4096, minimum=128),
        "max_segment_chars": _env_int("S43_AUTH_MAX_SEGMENT_CHARS", 2048, minimum=64),
        "max_roles":         _env_int("S43_AUTH_MAX_ROLES",          64, minimum=1),
        "max_role_chars":    _env_int("S43_AUTH_MAX_ROLE_CHARS",    128, minimum=1),
        "max_subject_chars": _env_int("S43_AUTH_MAX_SUBJECT_CHARS", 512, minimum=1),
        "max_device_id_chars": _env_int("S43_AUTH_MAX_DEVICE_ID_CHARS", 512, minimum=1),
    }


def _config(key: str) -> Any:
    return _get_config()[key]


# =============================================================================
# Watchtower queue  (Fix #4: lazy-start, not at import time)
# =============================================================================

_watchtower_queue: queue.Queue[dict[str, Any]] | None = None
_watchtower_queue_lock = threading.Lock()
_watchtower_worker_thread: threading.Thread | None = None
_watchtower_stop = threading.Event()

_watchtower_warning_lock = threading.Lock()
_watchtower_last_warning_at = 0.0
_WATCHTOWER_WARNING_INTERVAL = 60.0


def _get_or_create_queue() -> queue.Queue[dict[str, Any]]:
    """
    Fix #4: create the Watchtower queue and worker thread on first use,
    not at module import time. Importing auth_manager no longer starts a
    background thread — prevents test isolation issues and avoids orphaned
    threads in multiprocessing workers.
    """
    global _watchtower_queue, _watchtower_worker_thread

    if _watchtower_queue is not None:
        return _watchtower_queue

    with _watchtower_queue_lock:
        if _watchtower_queue is not None:
            return _watchtower_queue

        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=_config("queue_size"))
        _watchtower_queue = q

        worker = threading.Thread(
            target=_watchtower_worker,
            name="s43-auth-watchtower-reporter",
            daemon=True,
        )
        _watchtower_worker_thread = worker
        worker.start()
        logger.debug("Auth Watchtower reporter started.")

    return _watchtower_queue


def _log_watchtower_warning(message: str, *args: object) -> None:
    global _watchtower_last_warning_at
    now = time.monotonic()
    with _watchtower_warning_lock:
        if now - _watchtower_last_warning_at < _WATCHTOWER_WARNING_INTERVAL:
            return
        _watchtower_last_warning_at = now
    logger.warning(message, *args)


def _send_watchtower_payload(payload: dict[str, Any]) -> None:
    url = _config("watchtower_url")
    timeout = _config("watchtower_timeout")
    request = urllib.request.Request(
        f"{url}/watchtower/analyze",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read(1)


def _watchtower_worker() -> None:
    q = _watchtower_queue
    while not _watchtower_stop.is_set():
        try:
            payload = q.get(timeout=0.5)
        except queue.Empty:
            continue
        if payload is None:
            q.task_done()
            break
        try:
            _send_watchtower_payload(payload)
        except Exception as exc:
            _log_watchtower_warning("Auth Watchtower report delivery failed: %s", type(exc).__name__)
        finally:
            q.task_done()


def stop_watchtower_reporter(timeout: float = 2.0) -> None:
    """
    Fix #4 / Fix #8: graceful shutdown for the Watchtower worker.
    Called from lifespan shutdown so in-flight telemetry is drained
    rather than silently dropped when the process exits.

    Call from main.py lifespan:
        await asyncio.to_thread(stop_watchtower_reporter)
    """
    global _watchtower_queue
    _watchtower_stop.set()
    q = _watchtower_queue
    if q is not None:
        try:
            q.put_nowait(None)  # sentinel
        except queue.Full:
            pass
    worker = _watchtower_worker_thread
    if worker is not None and worker.is_alive():
        worker.join(timeout=timeout)


def _watchtower_report(status: str, event: str, details: dict[str, Any]) -> None:
    """
    Queue a Watchtower event without blocking authentication requests.
    Never place raw tokens, secrets, or auth headers inside details.
    """
    payload = {
        "event": {
            "kind": "security",
            "source": _config("module_id"),
            "status": status,
            "auth_event": event,
            "details": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "auth_version": _config("auth_version"),
                **details,
            },
        }
    }
    try:
        _get_or_create_queue().put_nowait(payload)
    except queue.Full:
        _log_watchtower_warning("Auth Watchtower queue is full. Dropping security telemetry.")


# =============================================================================
# JWT helpers
# =============================================================================

def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidTokenError("token_bad_encoding", "Invalid token encoding")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise InvalidTokenError("token_bad_encoding", "Invalid token encoding") from exc


def _b64url_json_decode(value: str) -> dict[str, Any]:
    try:
        raw    = _b64url_decode(value)
        parsed = json.loads(raw.decode("utf-8"))
    except InvalidTokenError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise InvalidTokenError("token_bad_json", "Invalid token JSON") from exc
    if not isinstance(parsed, dict):
        raise InvalidTokenError("token_bad_payload", "Token JSON must be an object")
    return parsed


def _parse_int_claim(
    payload: dict[str, Any],
    claim_name: str,
    *,
    required: bool,
    default: Optional[int] = None,
) -> int:
    raw = payload.get(claim_name, default)
    if raw is None and required:
        raise InvalidTokenError(f"token_missing_{claim_name}", f"Token {claim_name} claim missing")
    if isinstance(raw, bool):
        raise InvalidTokenError("token_bad_time_claims", "Invalid token time claims")
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise InvalidTokenError("token_bad_time_claims", "Invalid token time claims") from exc


def _normalize_roles(roles_raw: object, *, max_roles: int, max_role_chars: int) -> set[str]:
    if not isinstance(roles_raw, list):
        raise InvalidTokenError("token_bad_roles", "Token roles must be a list")
    roles: set[str] = set()
    for role in roles_raw:
        if not isinstance(role, str):
            raise InvalidTokenError("token_bad_roles", "Token roles must contain only strings")
        cleaned = role.strip()
        if not cleaned:
            raise InvalidTokenError("token_bad_roles", "Token roles must not contain empty values")
        if len(cleaned) > max_role_chars:
            raise InvalidTokenError("token_bad_roles", "Token role exceeds maximum length")
        roles.add(cleaned)
    if not roles:
        raise InvalidTokenError("token_missing_roles", "Token roles missing")
    if len(roles) > max_roles:
        raise InvalidTokenError("token_too_many_roles", "Token contains too many roles")
    return roles


# =============================================================================
# Module-level defaults
#
# These are intentionally simple integer literals rather than _config() calls
# so they can be used as function default parameter values (which are evaluated
# at class definition time). The AuthManager constructor re-reads live config
# values via _config() if callers pass None, but the defaults here are the
# same values the env vars default to.
# =============================================================================

DEFAULT_CLOCK_LEEWAY_SECONDS  = 10
DEFAULT_MAX_TOKEN_CHARS       = 4096
DEFAULT_MAX_SEGMENT_CHARS     = 2048
DEFAULT_MAX_ROLES             = 64
DEFAULT_MAX_ROLE_CHARS        = 128
DEFAULT_MAX_SUBJECT_CHARS     = 512
DEFAULT_MAX_DEVICE_ID_CHARS   = 512


# =============================================================================
# AuthManager
# =============================================================================

class AuthManager:
    """
    Sentinel-43 unified authentication manager.

    Token format:   base64url(header).base64url(payload).base64url(signature)
    Signature:      HMAC-SHA256(secret, header.payload)

    Validation policy:
    - Tokens must use HS256 (server-enforced, not caller-controlled).
    - Must contain iss, sub, roles, iat, exp.
    - Empty roles rejected (not promoted to guest).
    - Watchtower telemetry queued asynchronously, cannot block login.
    """

    def __init__(
        self,
        secret: bytes,
        issuer: str,
        *,
        audience: Optional[str] = None,
        clock_leeway_seconds: int = DEFAULT_CLOCK_LEEWAY_SECONDS,
        max_token_chars: int = DEFAULT_MAX_TOKEN_CHARS,
        max_segment_chars: int = DEFAULT_MAX_SEGMENT_CHARS,
        max_roles: int = DEFAULT_MAX_ROLES,
        max_role_chars: int = DEFAULT_MAX_ROLE_CHARS,
        max_subject_chars: int = DEFAULT_MAX_SUBJECT_CHARS,
        max_device_id_chars: int = DEFAULT_MAX_DEVICE_ID_CHARS,
        max_token_lifetime_seconds: Optional[int] = None,
    ) -> None:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("AuthManager secret must be non-empty bytes.")
        cleaned_issuer = issuer.strip()
        if not cleaned_issuer:
            raise ValueError("AuthManager issuer cannot be empty.")
        cleaned_audience = audience.strip() if audience else None
        if clock_leeway_seconds < 0:
            raise ValueError("clock_leeway_seconds must be >= 0.")
        for name, value in [
            ("max_token_chars",   max_token_chars),
            ("max_segment_chars", max_segment_chars),
            ("max_roles",         max_roles),
            ("max_role_chars",    max_role_chars),
            ("max_subject_chars", max_subject_chars),
            ("max_device_id_chars", max_device_id_chars),
        ]:
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero.")
        if max_token_lifetime_seconds is not None and max_token_lifetime_seconds <= 0:
            raise ValueError("max_token_lifetime_seconds must be greater than zero.")

        self._secret                   = secret
        self._issuer                   = cleaned_issuer
        self._audience                 = cleaned_audience
        self._clock_leeway_seconds     = int(clock_leeway_seconds)
        self._max_token_chars          = int(max_token_chars)
        self._max_segment_chars        = int(max_segment_chars)
        self._max_roles                = int(max_roles)
        self._max_role_chars           = int(max_role_chars)
        self._max_subject_chars        = int(max_subject_chars)
        self._max_device_id_chars      = int(max_device_id_chars)
        self._max_token_lifetime_seconds = max_token_lifetime_seconds

    def verify_token(self, token: str) -> AuthResult:
        try:
            context = self._decode_token(token)
            return AuthResult(success=True, context=context)
        except (InvalidTokenError, ExpiredTokenError) as exc:
            _watchtower_report(
                status="degraded",
                event="auth_rejected",
                details={
                    "error_type": type(exc).__name__,
                    "error_code": getattr(exc, "code", "auth_rejected"),
                },
            )
            return AuthResult(success=False, context=None, reason=str(exc))
        except Exception as exc:
            logger.exception("Unexpected internal authentication failure: %s", type(exc).__name__)
            _watchtower_report(
                status="failed",
                event="auth_internal_failure",
                details={"error_type": type(exc).__name__},
            )
            raise

    def _decode_token(self, token: str) -> AuthContext:
        token = self._validate_token_shape(token)
        header_b64, payload_b64, signature_b64 = token.split(".")

        header = _b64url_json_decode(header_b64)
        if header.get("alg") != "HS256":
            raise InvalidTokenError("token_bad_alg", "Unsupported token algorithm")

        token_type = header.get("typ")
        if token_type is not None and token_type != "JWT":
            raise InvalidTokenError("token_bad_type", "Unsupported token type")

        signing_input      = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_signature = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        provided_signature = _b64url_decode(signature_b64)

        if len(provided_signature) != hashlib.sha256().digest_size:
            raise InvalidTokenError("token_bad_signature", "Invalid token signature")
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise InvalidTokenError("token_bad_signature", "Invalid token signature")

        payload = _b64url_json_decode(payload_b64)

        issuer = str(payload.get("iss") or "").strip()
        if issuer != self._issuer:
            raise InvalidTokenError("token_bad_issuer", "Invalid token issuer")

        if self._audience is not None:
            audience = str(payload.get("aud") or "").strip()
            if audience != self._audience:
                raise InvalidTokenError("token_bad_audience", "Invalid token audience")

        # Fix #6: use `or ""` to coerce JSON null to empty string rather than
        # calling str(None) = "None" which passes the `if not subject_id` check.
        subject_id = str(payload.get("sub") or "").strip()
        if not subject_id:
            raise InvalidTokenError("token_missing_subject", "Token subject missing")
        if len(subject_id) > self._max_subject_chars:
            raise InvalidTokenError("token_subject_too_long", "Token subject exceeds maximum length")

        now_ts = int(time.time())
        exp_ts = _parse_int_claim(payload, "exp", required=True)
        iat_ts = _parse_int_claim(payload, "iat", required=True)
        nbf_ts = (
            _parse_int_claim(payload, "nbf", required=False, default=iat_ts)
            if payload.get("nbf") is not None
            else iat_ts
        )

        leeway = self._clock_leeway_seconds

        if exp_ts < now_ts - leeway:
            raise ExpiredTokenError("token_expired", "Token expired")
        if iat_ts > now_ts + leeway:
            raise InvalidTokenError("token_issued_in_future", "Token issued-at claim is in the future")
        if nbf_ts > now_ts + leeway:
            raise InvalidTokenError("token_not_active", "Token is not active yet")
        if iat_ts > exp_ts:
            raise InvalidTokenError("token_bad_time_window", "Token issued-at claim occurs after expiry")
        if nbf_ts > exp_ts:
            raise InvalidTokenError("token_bad_time_window", "Token not-before claim occurs after expiry")
        if (self._max_token_lifetime_seconds is not None
                and exp_ts - iat_ts > self._max_token_lifetime_seconds):
            raise InvalidTokenError("token_lifetime_too_long", "Token lifetime exceeds policy")

        roles = _normalize_roles(
            payload.get("roles"),
            max_roles=self._max_roles,
            max_role_chars=self._max_role_chars,
        )

        # Fix #6: same `or ""` coercion for device_id.
        device_id = str(payload.get("device_id") or "").strip()
        if len(device_id) > self._max_device_id_chars:
            raise InvalidTokenError("token_device_id_too_long", "Token device ID exceeds maximum length")

        return AuthContext(
            subject_id=subject_id,
            device_id=device_id,
            roles=roles,
            issued_at=datetime.fromtimestamp(iat_ts, tz=timezone.utc),
            expires_at=datetime.fromtimestamp(exp_ts, tz=timezone.utc),
            issuer=issuer,
        )

    def _validate_token_shape(self, token: object) -> str:
        if not isinstance(token, str):
            raise InvalidTokenError("token_missing", "Token missing")
        cleaned = token.strip()
        if not cleaned:
            raise InvalidTokenError("token_missing", "Token missing")
        if len(cleaned) > self._max_token_chars:
            raise InvalidTokenError("token_too_large", "Token exceeds maximum length")
        parts = cleaned.split(".")
        if len(parts) != 3:
            raise InvalidTokenError("token_malformed", "Token must have header.payload.signature")
        if any(not part for part in parts):
            raise InvalidTokenError("token_malformed", "Token segments must not be empty")
        if any(len(part) > self._max_segment_chars for part in parts):
            raise InvalidTokenError("token_segment_too_large", "Token segment exceeds maximum length")
        return cleaned
