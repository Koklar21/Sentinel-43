from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status

router = APIRouter(tags=["websocket"])


class DashboardConnectionManager:
    """Manages active human-gated dashboard sockets and handles system broadcasts."""
    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Pushes system-wide events (like fresh threats) to all active operators."""
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                # Handle dead or lingering socket drops cleanly
                self.disconnect(connection)


manager = DashboardConnectionManager()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.websocket("/ws")
async def sentinel_dashboard_ws(
    websocket: WebSocket,
    token: str | None = Query(None)  # Enforce basic query-param token extraction on handshake
) -> None:
    # 1. Human-Gated Authorization Check
    if not token or token == "undefined":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)

    # Initial Connection Acknowledgment & System Baseline Drop
    await websocket.send_json({
        "type": "connection_ack",
        "event_type": "dashboard_connected",
        "message": "Sentinel-43 active state pipeline synchronized.",
        "timestamp": utc_now(),
    })

    try:
        while True:
            raw_message = await websocket.receive_text()

            try:
                payload: dict[str, Any] = json.loads(raw_message)
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "event_type": "invalid_json",
                    "message": "Malformed payload dropped by security policy.",
                    "timestamp": utc_now(),
                })
                continue

            message_type = payload.get("type", "unknown")

            if message_type == "dashboard_ping":
                await websocket.send_json({
                    "type": "dashboard_pong",
                    "event_type": "heartbeat",
                    "message": "pong",
                    "timestamp": utc_now(),
                })
                continue

            # Default fallback loop for generic client interactions
            await websocket.send_json({
                "type": "dashboard_event",
                "event_type": message_type,
                "payload": payload,
                "timestamp": utc_now(),
            })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
