from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.websocket("/ws")
async def sentinel_dashboard_ws(websocket: WebSocket) -> None:
    await websocket.accept()

    await websocket.send_json(
        {
            "type": "connection_ack",
            "event_type": "dashboard_connected",
            "message": "Sentinel-43 dashboard WebSocket connected.",
            "timestamp": utc_now(),
        }
    )

    try:
        while True:
            raw_message = await websocket.receive_text()

            try:
                payload: dict[str, Any] = json.loads(raw_message)
            except json.JSONDecodeError:
                await websocket.send_json(
                    {
                        "type": "error",
                        "event_type": "invalid_json",
                        "message": "Invalid JSON payload received.",
                        "timestamp": utc_now(),
                    }
                )
                continue

            message_type = payload.get("type", "unknown")

            if message_type == "dashboard_ping":
                await websocket.send_json(
                    {
                        "type": "dashboard_pong",
                        "event_type": "heartbeat",
                        "message": "pong",
                        "timestamp": utc_now(),
                    }
                )
                continue

            await websocket.send_json(
                {
                    "type": "dashboard_event",
                    "event_type": message_type,
                    "message": "WebSocket message received.",
                    "payload": payload,
                    "timestamp": utc_now(),
                }
            )

    except WebSocketDisconnect:
        return
