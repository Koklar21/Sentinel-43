"""
dashboard/services/websocket_client.py

WebSocket URL and message helpers for Sentinel-43 Dashboard.
"""

from __future__ import annotations

import json
import os
from typing import Any


DEFAULT_WS_URL = os.getenv(
    "SENTINEL_WS_URL",
    "ws://localhost:8000/ws",
)


def get_websocket_url() -> str:
    """
    Return configured Sentinel-43 WebSocket URL.
    """
    return DEFAULT_WS_URL


def encode_ws_message(
    event_type: str,
    payload: dict[str, Any] | None = None,
) -> str:
    """
    Encode a dashboard WebSocket message as JSON.
    """

    return json.dumps(
        {
            "type": event_type,
            "payload": payload or {},
        }
    )


def decode_ws_message(message: str) -> dict[str, Any]:
    """
    Decode a dashboard WebSocket JSON message.
    """

    try:
        decoded = json.loads(message)

        if isinstance(decoded, dict):
            return decoded

        return {
            "type": "invalid",
            "payload": decoded,
        }

    except json.JSONDecodeError as exc:
        return {
            "type": "error",
            "payload": {
                "error": str(exc),
                "raw": message,
            },
        }


def build_subscribe_message(channel: str) -> str:
    """
    Build a channel subscription message.
    """

    return encode_ws_message(
        "subscribe",
        {
            "channel": channel,
        },
    )


def build_unsubscribe_message(channel: str) -> str:
    """
    Build a channel unsubscribe message.
    """

    return encode_ws_message(
        "unsubscribe",
        {
            "channel": channel,
        },
    )
