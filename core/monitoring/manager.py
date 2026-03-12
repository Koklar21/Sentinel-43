from __future__ import annotations

from typing import Any, Dict, List, Union

from .event_types import BaseEvent, normalize_event
from .watchtower import WatchtowerConfig, WatchtowerNode


class MonitoringManager:
    """
    High-level orchestration layer for Sentinel monitoring.
    Keeps the rest of the system from depending on Watchtower internals.
    """

    def __init__(self, config: WatchtowerConfig):
        self.node = WatchtowerNode(config)

    def start(self) -> None:
        self.node.start()

    def analyze_event(self, event: Union[Dict[str, Any], BaseEvent]) -> Dict[str, Any]:
        if isinstance(event, BaseEvent):
            payload = event.to_dict()
        else:
            payload = normalize_event(event).to_dict()

        alerts = self.node.scan_event(payload)
        return {
            "alerts": alerts,
            "alert_count": len(alerts),
        }

    def get_status(self) -> Dict[str, Any]:
        return self.node.get_status()