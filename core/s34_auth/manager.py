from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import AuthContext, AuthResult
from .exceptions import InvalidTokenError, ExpiredTokenError
from .hashing import constant_time_compare


WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
AUTH_MODULE_ID = os.getenv("S43_AUTH_MODULE_ID", "sentinel43-auth-manager")
AUTH_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_report(status: str, event: str, details: dict[str, Any]) -> None:
    payload = {
        "event": {
            "kind": "security",
            "source": AUTH_MODULE_ID,
            "status": status,
            "auth_event": event,
            "details": {
                "timestamp": utc_now(),
                **details,
            },
        }
    }

    try:
        request = urllib.request.Request(
            f"{WATCHTOWER_URL}/watchtower/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT)
    except Exception:
        pass


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


def _b64url_json_decode(value: str) -> dict[str, Any]:
    raw = _b64url_decode(value)
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise InvalidTokenError("invalid_token_payload", "Token payload must be an object")
    return parsed


class AuthManager:
    """
    Sentinel-43 unified authentication manager.

    Token format:
        base64url(header).base64url(payload).base64url(signature)

    Signature:
        HMAC-SHA256(secret, header.payload)
    """

    def __init__(self, secret: bytes, issuer: str):
        if not secret:
            raise ValueError("AuthManager secret cannot be empty.")
        if not issuer:
            raise ValueError("AuthManager issuer cannot be empty.")

        self._secret = secret
        self._issuer = issuer

    def verify_token(self, token: str) -> AuthResult:
        try:
            context = self._decode_token(token)

            if context.expires_at < datetime.now(timezone.utc):
                raise ExpiredTokenError("token_expired", "Token expired")

            return AuthResult(
                success=True,
                context=context,
            )

        except (InvalidTokenError, ExpiredTokenError) as exc:
            _watchtower_report(
                status="degraded",
                event="auth_rejected",
                details={
                    "reason": str(exc),
                    "error_type": type(exc).__name__,
                },
            )

            return AuthResult(
                success=False,
                context=None,
                reason=str(exc),
            )

        except Exception as exc:
            _watchtower_report(
                status="failed",
                event="auth_internal_failure",
                details={
                    "reason": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
            raise

    def _decode_token(self, token: str) -> AuthContext:
        if not token or not token.strip():
            raise InvalidTokenError("token_missing", "Token missing")

        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidTokenError("token_malformed", "Token must have header.payload.signature")

        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        expected_signature = hmac.new(
            self._secret,
            signing_input,
            hashlib.sha256,
        ).digest()

        try:
            provided_signature = _b64url_decode(signature_b64)
        except Exception as exc:
            raise InvalidTokenError("token_bad_signature_encoding", "Invalid token signature encoding") from exc

        expected_hex = expected_signature.hex()
        provided_hex = provided_signature.hex()

        if not constant_time_compare(provided_hex, expected_hex):
            raise InvalidTokenError("token_bad_signature", "Invalid token signature")

        header = _b64url_json_decode(header_b64)
        payload = _b64url_json_decode(payload_b64)

        alg = header.get("alg")
        if alg != "HS256":
            raise InvalidTokenError("token_bad_alg", "Unsupported token algorithm")

        issuer = str(payload.get("iss", ""))
        if issuer != self._issuer:
            raise InvalidTokenError("token_bad_issuer", "Invalid token issuer")

        subject_id = str(payload.get("sub", "")).strip()
        if not subject_id:
            raise InvalidTokenError("token_missing_subject", "Token subject missing")

        now_ts = int(time.time())
        exp = payload.get("exp")
        iat = payload.get("iat", now_ts)

        try:
            exp_ts = int(exp)
            iat_ts = int(iat)
        except (TypeError, ValueError) as exc:
            raise InvalidTokenError("token_bad_time_claims", "Invalid token time claims") from exc

        if exp_ts < now_ts:
            raise ExpiredTokenError("token_expired", "Token expired")

        roles_raw = payload.get("roles", [])
        if isinstance(roles_raw, str):
            roles = {roles_raw}
        elif isinstance(roles_raw, list):
            roles = {str(role) for role in roles_raw if str(role).strip()}
        else:
            roles = set()

        if not roles:
            roles = {"guest"}

        device_id = str(payload.get("device_id", "unknown"))

        return AuthContext(
            subject_id=subject_id,
            device_id=device_id,
            roles=roles,
            issued_at=datetime.fromtimestamp(iat_ts, tz=timezone.utc),
            expires_at=datetime.fromtimestamp(exp_ts, tz=timezone.utc),
            issuer=issuer,
        )