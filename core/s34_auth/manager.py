from **future** import annotations

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
from typing import Any, Optional

from .exceptions import ExpiredTokenError, InvalidTokenError
from .models import AuthContext, AuthResult

logger = logging.getLogger(**name**)

def _env_float(name: str, default: float, *, minimum: float) -> float:
raw = os.getenv(name, "").strip()

```
if not raw:
    return default

try:
    value = float(raw)
except ValueError:
    logger.warning(
        "Invalid %s value %r. Falling back to %s.",
        name,
        raw,
        default,
    )
    return default

if value < minimum:
    logger.warning(
        "%s value %r is below minimum %s. Falling back to %s.",
        name,
        raw,
        minimum,
        default,
    )
    return default

return value
```

def _env_int(name: str, default: int, *, minimum: int) -> int:
raw = os.getenv(name, "").strip()

```
if not raw:
    return default

try:
    value = int(raw)
except ValueError:
    logger.warning(
        "Invalid %s value %r. Falling back to %s.",
        name,
        raw,
        default,
    )
    return default

if value < minimum:
    logger.warning(
        "%s value %r is below minimum %s. Falling back to %s.",
        name,
        raw,
        minimum,
        default,
    )
    return default

return value
```

WATCHTOWER_URL = os.getenv(
"S43_WATCHTOWER_URL",
"http://s43-watchtower:9100",
).rstrip("/")

WATCHTOWER_TIMEOUT = _env_float(
"S43_WATCHTOWER_TIMEOUT",
2.0,
minimum=0.1,
)

WATCHTOWER_QUEUE_SIZE = _env_int(
"S43_AUTH_WATCHTOWER_QUEUE_SIZE",
256,
minimum=1,
)

AUTH_MODULE_ID = os.getenv(
"S43_AUTH_MODULE_ID",
"sentinel43-auth-manager",
).strip() or "sentinel43-auth-manager"

AUTH_VERSION = os.getenv(
"SENTINEL_VERSION",
"0.1.0",
).strip() or "0.1.0"

DEFAULT_CLOCK_LEEWAY_SECONDS = _env_int(
"S43_AUTH_CLOCK_LEEWAY_SECONDS",
10,
minimum=0,
)

DEFAULT_MAX_TOKEN_CHARS = _env_int(
"S43_AUTH_MAX_TOKEN_CHARS",
4096,
minimum=128,
)

DEFAULT_MAX_SEGMENT_CHARS = _env_int(
"S43_AUTH_MAX_SEGMENT_CHARS",
2048,
minimum=64,
)

DEFAULT_MAX_ROLES = _env_int(
"S43_AUTH_MAX_ROLES",
64,
minimum=1,
)

DEFAULT_MAX_ROLE_CHARS = _env_int(
"S43_AUTH_MAX_ROLE_CHARS",
128,
minimum=1,
)

DEFAULT_MAX_SUBJECT_CHARS = _env_int(
"S43_AUTH_MAX_SUBJECT_CHARS",
512,
minimum=1,
)

DEFAULT_MAX_DEVICE_ID_CHARS = _env_int(
"S43_AUTH_MAX_DEVICE_ID_CHARS",
512,
minimum=1,
)

_watchtower_queue: queue.Queue[dict[str, Any]] = queue.Queue(
maxsize=WATCHTOWER_QUEUE_SIZE
)

_watchtower_warning_lock = threading.Lock()
_watchtower_last_warning_at = 0.0
_watchtower_warning_interval_seconds = 60.0

def utc_now() -> str:
return datetime.now(timezone.utc).isoformat()

def _log_watchtower_warning(message: str, *args: object) -> None:
"""
Rate-limit Watchtower delivery warnings so an outage does not become
a log-flood denial-of-service problem.
"""

```
global _watchtower_last_warning_at

now = time.monotonic()

with _watchtower_warning_lock:
    if now - _watchtower_last_warning_at < _watchtower_warning_interval_seconds:
        return

    _watchtower_last_warning_at = now

logger.warning(message, *args)
```

def _send_watchtower_payload(payload: dict[str, Any]) -> None:
request = urllib.request.Request(
f"{WATCHTOWER_URL}/watchtower/analyze",
data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
headers={"Content-Type": "application/json"},
method="POST",
)

```
with urllib.request.urlopen(
    request,
    timeout=WATCHTOWER_TIMEOUT,
) as response:
    response.read(1)
```

def _watchtower_worker() -> None:
while True:
payload = _watchtower_queue.get()

```
    try:
        _send_watchtower_payload(payload)
    except Exception as exc:
        _log_watchtower_warning(
            "Auth Watchtower report delivery failed: %s",
            type(exc).__name__,
        )
    finally:
        _watchtower_queue.task_done()
```

def _start_watchtower_worker() -> None:
worker = threading.Thread(
target=_watchtower_worker,
name="s43-auth-watchtower-reporter",
daemon=True,
)

```
worker.start()
```

_start_watchtower_worker()

def _watchtower_report(
status: str,
event: str,
details: dict[str, Any],
) -> None:
"""
Queue a Watchtower event without blocking authentication requests.

```
Important:
- Never place raw tokens, secrets, passwords, or authorization headers
  inside details.
- Watchtower unavailability must never block or crash authentication.
"""

payload = {
    "event": {
        "kind": "security",
        "source": AUTH_MODULE_ID,
        "status": status,
        "auth_event": event,
        "details": {
            "timestamp": utc_now(),
            "auth_version": AUTH_VERSION,
            **details,
        },
    }
}

try:
    _watchtower_queue.put_nowait(payload)
except queue.Full:
    _log_watchtower_warning(
        "Auth Watchtower queue is full. Dropping security telemetry event."
    )
```

def _b64url_decode(value: str) -> bytes:
"""
Decode strict base64url input.

```
Invalid characters, malformed padding, or oversized segments are rejected
by the caller before they can become internal server errors.
"""

if not isinstance(value, str):
    raise InvalidTokenError(
        "token_bad_encoding",
        "Invalid token encoding",
    )

padded = value + "=" * (-len(value) % 4)

try:
    return base64.b64decode(
        padded.encode("ascii"),
        altchars=b"-_",
        validate=True,
    )
except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
    raise InvalidTokenError(
        "token_bad_encoding",
        "Invalid token encoding",
    ) from exc
```

def _b64url_json_decode(value: str) -> dict[str, Any]:
try:
raw = _b64url_decode(value)
parsed = json.loads(raw.decode("utf-8"))
except InvalidTokenError:
raise
except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
raise InvalidTokenError(
"token_bad_json",
"Invalid token JSON",
) from exc

```
if not isinstance(parsed, dict):
    raise InvalidTokenError(
        "token_bad_payload",
        "Token JSON must be an object",
    )

return parsed
```

def _parse_int_claim(
payload: dict[str, Any],
claim_name: str,
*,
required: bool,
default: Optional[int] = None,
) -> int:
raw = payload.get(claim_name, default)

```
if raw is None and required:
    raise InvalidTokenError(
        f"token_missing_{claim_name}",
        f"Token {claim_name} claim missing",
    )

if isinstance(raw, bool):
    raise InvalidTokenError(
        "token_bad_time_claims",
        "Invalid token time claims",
    )

try:
    return int(raw)
except (TypeError, ValueError) as exc:
    raise InvalidTokenError(
        "token_bad_time_claims",
        "Invalid token time claims",
    ) from exc
```

def _normalize_roles(
roles_raw: object,
*,
max_roles: int,
max_role_chars: int,
) -> set[str]:
if not isinstance(roles_raw, list):
raise InvalidTokenError(
"token_bad_roles",
"Token roles must be a list",
)

```
roles: set[str] = set()

for role in roles_raw:
    if not isinstance(role, str):
        raise InvalidTokenError(
            "token_bad_roles",
            "Token roles must contain only strings",
        )

    cleaned = role.strip()

    if not cleaned:
        raise InvalidTokenError(
            "token_bad_roles",
            "Token roles must not contain empty values",
        )

    if len(cleaned) > max_role_chars:
        raise InvalidTokenError(
            "token_bad_roles",
            "Token role exceeds maximum length",
        )

    roles.add(cleaned)

if not roles:
    raise InvalidTokenError(
        "token_missing_roles",
        "Token roles missing",
    )

if len(roles) > max_roles:
    raise InvalidTokenError(
        "token_too_many_roles",
        "Token contains too many roles",
    )

return roles
```

class AuthManager:
"""
Sentinel-43 unified authentication manager.

```
Token format:
    base64url(header).base64url(payload).base64url(signature)

Signature:
    HMAC-SHA256(secret, header.payload)

Validation policy:
- Tokens must use HS256.
- Tokens must contain issuer, subject, roles, issued-at, and expiry claims.
- Tokens may optionally contain audience, not-before, and device_id claims.
- Empty roles are rejected rather than silently promoted to guest.
- Watchtower telemetry is queued asynchronously and cannot block login.
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

    if max_token_chars <= 0:
        raise ValueError("max_token_chars must be greater than zero.")

    if max_segment_chars <= 0:
        raise ValueError("max_segment_chars must be greater than zero.")

    if max_roles <= 0:
        raise ValueError("max_roles must be greater than zero.")

    if max_role_chars <= 0:
        raise ValueError("max_role_chars must be greater than zero.")

    if max_subject_chars <= 0:
        raise ValueError("max_subject_chars must be greater than zero.")

    if max_device_id_chars <= 0:
        raise ValueError("max_device_id_chars must be greater than zero.")

    if (
        max_token_lifetime_seconds is not None
        and max_token_lifetime_seconds <= 0
    ):
        raise ValueError(
            "max_token_lifetime_seconds must be greater than zero."
        )

    self._secret = secret
    self._issuer = cleaned_issuer
    self._audience = cleaned_audience
    self._clock_leeway_seconds = int(clock_leeway_seconds)
    self._max_token_chars = int(max_token_chars)
    self._max_segment_chars = int(max_segment_chars)
    self._max_roles = int(max_roles)
    self._max_role_chars = int(max_role_chars)
    self._max_subject_chars = int(max_subject_chars)
    self._max_device_id_chars = int(max_device_id_chars)
    self._max_token_lifetime_seconds = max_token_lifetime_seconds

def verify_token(self, token: str) -> AuthResult:
    try:
        context = self._decode_token(token)

        return AuthResult(
            success=True,
            context=context,
        )

    except (InvalidTokenError, ExpiredTokenError) as exc:
        _watchtower_report(
            status="degraded",
            event="auth_rejected",
            details={
                "error_type": type(exc).__name__,
                "error_code": getattr(exc, "code", "auth_rejected"),
            },
        )

        return AuthResult(
            success=False,
            context=None,
            reason=str(exc),
        )

    except Exception as exc:
        logger.exception(
            "Unexpected internal authentication failure: %s",
            type(exc).__name__,
        )

        _watchtower_report(
            status="failed",
            event="auth_internal_failure",
            details={
                "error_type": type(exc).__name__,
            },
        )

        raise

def _decode_token(self, token: str) -> AuthContext:
    token = self._validate_token_shape(token)

    header_b64, payload_b64, signature_b64 = token.split(".")

    header = _b64url_json_decode(header_b64)

    if header.get("alg") != "HS256":
        raise InvalidTokenError(
            "token_bad_alg",
            "Unsupported token algorithm",
        )

    token_type = header.get("typ")

    if token_type is not None and token_type != "JWT":
        raise InvalidTokenError(
            "token_bad_type",
            "Unsupported token type",
        )

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    expected_signature = hmac.new(
        self._secret,
        signing_input,
        hashlib.sha256,
    ).digest()

    provided_signature = _b64url_decode(signature_b64)

    if len(provided_signature) != hashlib.sha256().digest_size:
        raise InvalidTokenError(
            "token_bad_signature",
            "Invalid token signature",
        )

    if not hmac.compare_digest(
        expected_signature,
        provided_signature,
    ):
        raise InvalidTokenError(
            "token_bad_signature",
            "Invalid token signature",
        )

    payload = _b64url_json_decode(payload_b64)

    issuer = str(payload.get("iss", "")).strip()

    if issuer != self._issuer:
        raise InvalidTokenError(
            "token_bad_issuer",
            "Invalid token issuer",
        )

    if self._audience is not None:
        audience = str(payload.get("aud", "")).strip()

        if audience != self._audience:
            raise InvalidTokenError(
                "token_bad_audience",
                "Invalid token audience",
            )

    subject_id = str(payload.get("sub", "")).strip()

    if not subject_id:
        raise InvalidTokenError(
            "token_missing_subject",
            "Token subject missing",
        )

    if len(subject_id) > self._max_subject_chars:
        raise InvalidTokenError(
            "token_subject_too_long",
            "Token subject exceeds maximum length",
        )

    now_ts = int(time.time())

    exp_ts = _parse_int_claim(
        payload,
        "exp",
        required=True,
    )

    iat_ts = _parse_int_claim(
        payload,
        "iat",
        required=True,
    )

    nbf_raw = payload.get("nbf")

    if nbf_raw is None:
        nbf_ts = iat_ts
    else:
        nbf_ts = _parse_int_claim(
            payload,
            "nbf",
            required=False,
            default=iat_ts,
        )

    leeway = self._clock_leeway_seconds

    if exp_ts < now_ts - leeway:
        raise ExpiredTokenError(
            "token_expired",
            "Token expired",
        )

    if iat_ts > now_ts + leeway:
        raise InvalidTokenError(
            "token_issued_in_future",
            "Token issued-at claim is in the future",
        )

    if nbf_ts > now_ts + leeway:
        raise InvalidTokenError(
            "token_not_active",
            "Token is not active yet",
        )

    if iat_ts > exp_ts:
        raise InvalidTokenError(
            "token_bad_time_window",
            "Token issued-at claim occurs after expiry",
        )

    if nbf_ts > exp_ts:
        raise InvalidTokenError(
            "token_bad_time_window",
            "Token not-before claim occurs after expiry",
        )

    if (
        self._max_token_lifetime_seconds is not None
        and exp_ts - iat_ts > self._max_token_lifetime_seconds
    ):
        raise InvalidTokenError(
            "token_lifetime_too_long",
            "Token lifetime exceeds policy",
        )

    roles = _normalize_roles(
        payload.get("roles"),
        max_roles=self._max_roles,
        max_role_chars=self._max_role_chars,
    )

    device_id = str(payload.get("device_id", "")).strip()

    if len(device_id) > self._max_device_id_chars:
        raise InvalidTokenError(
            "token_device_id_too_long",
            "Token device ID exceeds maximum length",
        )

    return AuthContext(
        subject_id=subject_id,
        device_id=device_id,
        roles=roles,
        issued_at=datetime.fromtimestamp(
            iat_ts,
            tz=timezone.utc,
        ),
        expires_at=datetime.fromtimestamp(
            exp_ts,
            tz=timezone.utc,
        ),
        issuer=issuer,
    )

def _validate_token_shape(self, token: object) -> str:
    if not isinstance(token, str):
        raise InvalidTokenError(
            "token_missing",
            "Token missing",
        )

    cleaned = token.strip()

    if not cleaned:
        raise InvalidTokenError(
            "token_missing",
            "Token missing",
        )

    if len(cleaned) > self._max_token_chars:
        raise InvalidTokenError(
            "token_too_large",
            "Token exceeds maximum length",
        )

    parts = cleaned.split(".")

    if len(parts) != 3:
        raise InvalidTokenError(
            "token_malformed",
            "Token must have header.payload.signature",
        )

    if any(not part for part in parts):
        raise InvalidTokenError(
            "token_malformed",
            "Token segments must not be empty",
        )

    if any(len(part) > self._max_segment_chars for part in parts):
        raise InvalidTokenError(
            "token_segment_too_large",
            "Token segment exceeds maximum length",
        )

    return cleaned
```
