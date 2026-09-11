"""
Sentinel-43 Dashboard Service
WebSocket Client Helpers

WebSocket URL, authentication-header, encoding, decoding,
subscription, and heartbeat helpers.
"""

from __future__ import annotations

import copy
from collections import OrderedDict
import html
import json
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit


MAX_FRAME_BYTES = 64 * 1024
MAX_NESTING_DEPTH = 12
MAX_ERROR_PREVIEW_LENGTH = 80

LOCAL_ENVIRONMENTS = frozenset({
    "development",
    "dev",
    "local",
    "test",
})

LOCAL_WS_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "::1",
    "s43-api",
    "sentinel-api",
})

VALID_OUTBOUND_EVENT_TYPES = frozenset({
    "subscribe",
    "unsubscribe",
    "ping",
    "ack",
})

CHANNEL_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")
EVENT_TYPE_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")

SENSITIVE_QUERY_KEYS = frozenset({
    "token",
    "access_token",
    "auth",
    "authorization",
    "api_key",
    "apikey",
})


def get_websocket_url() -> str:
    """
    Return the configured Sentinel-43 WebSocket URL.

    Local development may fall back to ws://localhost:8000/ws.
    Non-local deployments require an explicit wss:// URL.
    """
    environment = os.getenv("SENTINEL_ENV", "development").lower().strip()
    configured_url = os.getenv("SENTINEL_WS_URL", "").strip()

    if not configured_url:
        if environment in LOCAL_ENVIRONMENTS:
            configured_url = "ws://localhost:8000/ws"
        else:
            raise RuntimeError(
                "SENTINEL_WS_URL must be configured outside local development"
            )

    return _validate_websocket_url(
        configured_url,
        environment=environment,
    )


def build_websocket_headers(
    *,
    token: str | None = None,
) -> dict[str, str]:
    """
    Build WebSocket handshake headers for Python-side clients.

    Browser WebSocket constructors cannot attach arbitrary headers.
    Browser clients should authenticate using a secure HttpOnly cookie
    or another backend-supported authentication exchange.
    """
    resolved_token = token or os.getenv("SENTINEL_WS_TOKEN")

    if resolved_token is None:
        return {}

    if not isinstance(resolved_token, str):
        raise ValueError("WebSocket token must be a string")

    cleaned = resolved_token.strip()

    if not cleaned:
        raise ValueError("WebSocket token must not be empty")

    if "\r" in cleaned or "\n" in cleaned:
        raise ValueError("WebSocket token must not contain CRLF characters")

    return {
        "Authorization": f"Bearer {cleaned}",
    }


def encode_ws_message(
    event_type: str,
    payload: dict[str, Any] | None = None,
) -> str:
    """
    Encode a validated outbound dashboard WebSocket message.
    """
    normalized_event_type = _validate_outbound_event_type(event_type)

    if payload is None:
        safe_payload: dict[str, Any] = {}
    elif isinstance(payload, dict):
        safe_payload = copy.deepcopy(payload)
    else:
        raise ValueError("payload must be a dictionary")

    _validate_nesting_depth(safe_payload)

    try:
        encoded = json.dumps(
            {
                "type": normalized_event_type,
                "payload": safe_payload,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("WebSocket payload must be JSON serializable") from exc

    encoded_size = len(encoded.encode("utf-8"))

    if encoded_size > MAX_FRAME_BYTES:
        raise ValueError(
            f"Encoded WebSocket message exceeds {MAX_FRAME_BYTES} bytes"
        )

    return encoded


def decode_ws_message(message: str) -> dict[str, Any]:
    """
    Decode and validate an inbound dashboard WebSocket JSON message.

    Invalid raw input is never echoed back verbatim.
    """
    if not isinstance(message, str):
        return _decode_error("WebSocket message must be a string")

    message_size = len(message.encode("utf-8"))

    if message_size > MAX_FRAME_BYTES:
        return _decode_error(
            f"WebSocket message exceeds {MAX_FRAME_BYTES} bytes"
        )

    try:
        decoded = json.loads(message)
    except json.JSONDecodeError as exc:
        return _decode_error(
            "WebSocket message is not valid JSON",
            preview=_safe_preview(message),
            detail=f"line {exc.lineno}, column {exc.colno}",
        )
    except RecursionError:
        return _decode_error("WebSocket message nesting is too deep")

    if not isinstance(decoded, dict):
        return _decode_error("WebSocket message must decode to an object")

    event_type = decoded.get("type")
    payload = decoded.get("payload")

    if not isinstance(event_type, str):
        return _decode_error("WebSocket message type must be a string")

    normalized_event_type = event_type.strip()

    if not EVENT_TYPE_RE.fullmatch(normalized_event_type):
        return _decode_error("WebSocket message type has an invalid format")

    if not isinstance(payload, dict):
        return _decode_error("WebSocket message payload must be an object")

    try:
        _validate_nesting_depth(payload)
    except ValueError as exc:
        return _decode_error(str(exc))

    return {
        "type": normalized_event_type,
        "payload": payload,
        # The canonical envelope, extracted HERE and only here. Widgets read
        # these fields; they do not re-parse frames themselves.
        "envelope": extract_envelope(payload),
    }


# ---------------------------------------------------------------------------
# Canonical event envelope
#
# The core stamps every event with identity and provenance. The dashboard used
# to read only {type, payload}, so it could not tell two deliveries of one
# logical event apart, could not follow a causal chain, and could not notice an
# event from a future schema. This is the ONE boundary where a frame becomes an
# envelope -- conversion logic must not spread into individual widgets.
# ---------------------------------------------------------------------------

#: Envelope versions this dashboard build understands. An event declaring
#: anything else is surfaced as unsupported rather than half-rendered against
#: today's assumptions.
SUPPORTED_EVENT_SCHEMA_VERSIONS: frozenset[str] = frozenset({"1.0"})

_ENVELOPE_FIELDS: tuple[str, ...] = (
    "event_id",
    "correlation_id",
    "parent_event_id",
    "schema_version",
    "source",
    "source_identity",
    "event_type",
    "created_at",
    "ingested_at",
)


def extract_envelope(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull the canonical envelope out of an event payload.

    Tolerant by design: a payload that predates the envelope simply yields
    empty fields rather than being rejected, because the dashboard observes
    the system and must not go blind on an older producer.
    """
    envelope: dict[str, Any] = {}
    for field in _ENVELOPE_FIELDS:
        value = payload.get(field)
        envelope[field] = str(value).strip() if value is not None else ""

    declared = envelope["schema_version"]
    envelope["schema_supported"] = (
        True if not declared else declared in SUPPORTED_EVENT_SCHEMA_VERSIONS
    )
    # A derived finding names the signal it came from.
    envelope["is_derived"] = bool(envelope["parent_event_id"])
    return envelope


class EventDeduplicator:
    """Bounded, event_id-keyed guard against rendering one event twice.

    The core reliability layer already prevents duplicate *processing*. This
    prevents duplicate *display*: a reconnect or an operator-approved replay
    re-delivers the same logical event, and it must not appear as a second,
    unrelated incident.

    Keyed on event_id only. Deduplicating by payload text would collapse
    genuinely distinct findings that happen to look identical.
    """

    def __init__(self, max_entries: int = 2048) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max_entries = max_entries
        self._seen: OrderedDict[str, None] = OrderedDict()

    def is_duplicate(self, envelope: dict[str, Any]) -> bool:
        """True when this event_id has already been displayed.

        An event with no id cannot be deduplicated, so it is always shown --
        dropping it would lose a finding.
        """
        event_id = str(envelope.get("event_id") or "").strip()
        if not event_id:
            return False

        if event_id in self._seen:
            self._seen.move_to_end(event_id)
            return True

        self._seen[event_id] = None
        while len(self._seen) > self._max_entries:
            self._seen.popitem(last=False)
        return False

    def reset(self) -> None:
        self._seen.clear()

    def __len__(self) -> int:
        return len(self._seen)


def build_subscribe_message(channel: str) -> str:
    """
    Build a validated channel subscription message.
    """
    return encode_ws_message(
        "subscribe",
        {
            "channel": _validate_channel(channel),
        },
    )


def build_unsubscribe_message(channel: str) -> str:
    """
    Build a validated channel unsubscribe message.
    """
    return encode_ws_message(
        "unsubscribe",
        {
            "channel": _validate_channel(channel),
        },
    )


def build_ping_message() -> str:
    """
    Build an application-level heartbeat message.
    """
    return encode_ws_message(
        "ping",
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


def build_ack_message(event_id: str) -> str:
    """
    Build an acknowledgement message for a received WebSocket event.
    """
    if not isinstance(event_id, str):
        raise ValueError("event_id must be a string")

    cleaned = event_id.strip()

    if not EVENT_TYPE_RE.fullmatch(cleaned):
        raise ValueError("event_id has an invalid format")

    return encode_ws_message(
        "ack",
        {
            "event_id": cleaned,
        },
    )


def _validate_websocket_url(
    url: str,
    *,
    environment: str,
) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("WebSocket URL must be a non-empty string")

    cleaned = url.strip()

    if "\r" in cleaned or "\n" in cleaned:
        raise ValueError("WebSocket URL must not contain CRLF characters")

    parsed = urlsplit(cleaned)

    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError("WebSocket URL must use ws:// or wss://")

    if not parsed.hostname:
        raise ValueError("WebSocket URL must include a host")

    if parsed.username or parsed.password:
        raise ValueError("WebSocket URL must not contain embedded credentials")

    if parsed.fragment:
        raise ValueError("WebSocket URL must not contain a fragment")

    if parsed.query:
        query_keys = {
            item.split("=", 1)[0].lower().strip()
            for item in parsed.query.split("&")
            if item.strip()
        }

        if query_keys.intersection(SENSITIVE_QUERY_KEYS):
            raise ValueError(
                "WebSocket credentials must not be placed in URL query parameters"
            )

    if parsed.scheme == "ws":
        is_local_environment = environment in LOCAL_ENVIRONMENTS
        is_local_host = parsed.hostname in LOCAL_WS_HOSTS

        if not is_local_environment or not is_local_host:
            raise ValueError(
                "Plaintext ws:// is only allowed for local development hosts"
            )

    return cleaned


def _validate_outbound_event_type(event_type: str) -> str:
    if not isinstance(event_type, str):
        raise ValueError("event_type must be a string")

    cleaned = event_type.lower().strip()

    if cleaned not in VALID_OUTBOUND_EVENT_TYPES:
        raise ValueError(f"Invalid outbound event_type: {event_type!r}")

    return cleaned


def _validate_channel(channel: str) -> str:
    if not isinstance(channel, str):
        raise ValueError("channel must be a string")

    cleaned = channel.strip()

    if not CHANNEL_RE.fullmatch(cleaned):
        raise ValueError(
            "channel must be 1-64 alphanumeric, dash, underscore, or dot characters"
        )

    return cleaned


def _validate_nesting_depth(
    value: Any,
    *,
    depth: int = 0,
) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValueError(
            f"WebSocket payload exceeds maximum nesting depth of {MAX_NESTING_DEPTH}"
        )

    if isinstance(value, dict):
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise ValueError("WebSocket payload keys must be strings")

            _validate_nesting_depth(
                nested_value,
                depth=depth + 1,
            )

    elif isinstance(value, list):
        for nested_value in value:
            _validate_nesting_depth(
                nested_value,
                depth=depth + 1,
            )


def _safe_preview(message: str) -> str:
    preview = message[:MAX_ERROR_PREVIEW_LENGTH]
    preview = preview.replace("\r", "\\r").replace("\n", "\\n")
    return html.escape(preview, quote=True)


def _decode_error(
    message: str,
    *,
    preview: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "error": message,
    }

    if detail:
        payload["detail"] = detail

    if preview:
        payload["raw_preview"] = preview

    return {
        "type": "error",
        "payload": payload,
    }
