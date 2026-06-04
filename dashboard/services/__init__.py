"""
dashboard.services

Service layer exports for the Sentinel-43 Dashboard.
"""

from .api_client import APIClient, api_client

from .audit_client import (
    fetch_audit_logs,
    get_audit_records,
    normalize_audit_logs,
)

from .remote_gateway_client import (
    fetch_remote_operations,
    get_remote_gateway_records,
    normalize_remote_operations,
    submit_remote_gateway_event,
)

from .watchtower_client import (
    fetch_watchtower_status,
    get_watchtower_dashboard_status,
    normalize_watchtower_status,
)

from .websocket_client import (
    build_subscribe_message,
    build_unsubscribe_message,
    decode_ws_message,
    encode_ws_message,
    get_websocket_url,
)

__all__ = [
    # API
    "APIClient",
    "api_client",

    # Audit
    "fetch_audit_logs",
    "get_audit_records",
    "normalize_audit_logs",

    # Remote Gateway
    "fetch_remote_operations",
    "get_remote_gateway_records",
    "normalize_remote_operations",
    "submit_remote_gateway_event",

    # Watchtower
    "fetch_watchtower_status",
    "get_watchtower_dashboard_status",
    "normalize_watchtower_status",

    # WebSocket
    "build_subscribe_message",
    "build_unsubscribe_message",
    "decode_ws_message",
    "encode_ws_message",
    "get_websocket_url",
]
