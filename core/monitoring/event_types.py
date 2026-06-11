# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict
import uuid


EVENT_TYPES_MODULE_ID = os.getenv("S43_EVENT_TYPES_MODULE_ID", "sentinel43-event-types")
EVENT_TYPES_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")
WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _report_event_type_issue(
    status: str,
    issue: str,
    details: dict[str, Any],
) -> None:
    payload = {
        "event": {
            "kind": "runtime",
            "source": EVENT_TYPES_MODULE_ID,
            "status": status,
            "details": {
                "issue": issue,
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


@dataclass
class BaseEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    kind: str = "base"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RequestEvent(BaseEvent):
    kind: str = "request"
    status_code: int = 200
    latency_ms: int = 0


@dataclass
class ExpectationEvent(BaseEvent):
    kind: str = "expectation"
    expectation_status: str = "passed"
    failed_checks: int = 0


@dataclass
class ConfigEvent(BaseEvent):
    kind: str = "config"
    drift_detected: bool = False
    config_age_seconds: int = 0


@dataclass
class LogEvent(BaseEvent):
    kind: str = "log"
    missing_required_fields: bool = False
    integrity_status: str = "ok"


@dataclass
class RuntimeEvent(BaseEvent):
    kind: str = "runtime"
    error_rate_percent: int = 0
    crash_loop: bool = False


@dataclass
class DependencyEvent(BaseEvent):
    kind: str = "dependency"
    dependency_status: str = "up"
    version_mismatch: bool = False


@dataclass
class ResourceEvent(BaseEvent):
    kind: str = "resource"
    cpu_percent: int = 0
    memory_percent: int = 0
    disk_percent: int = 0


@dataclass
class SecurityEvent(BaseEvent):
    kind: str = "security"
    unsigned_artifact: bool = False
    secrets_exposed: bool = False
    debug_mode_enabled: bool = False


_EVENT_TYPE_MAP = {
    "request": RequestEvent,
    "expectation": ExpectationEvent,
    "config": ConfigEvent,
    "log": LogEvent,
    "runtime": RuntimeEvent,
    "dependency": DependencyEvent,
    "resource": ResourceEvent,
    "security": SecurityEvent,
}


def normalize_event(event: Dict[str, Any]) -> BaseEvent:
    """
    Convert a raw event dict into the appropriate typed event object.
    Falls back to BaseEvent if the kind is unknown.
    """

    if not isinstance(event, dict):
        _report_event_type_issue(
            status="failed",
            issue="event_not_dict",
            details={"received_type": type(event).__name__},
        )
        return BaseEvent(kind="base")

    raw_kind = event.get("kind", "base")
    kind = str(raw_kind).lower().strip() or "base"
    event_cls = _EVENT_TYPE_MAP.get(kind, BaseEvent)

    local_event = dict(event)

    if "id" not in local_event or not local_event["id"]:
        local_event["id"] = str(uuid.uuid4())

    if kind not in _EVENT_TYPE_MAP and kind != "base":
        _report_event_type_issue(
            status="degraded",
            issue="unknown_event_kind",
            details={
                "kind": kind,
                "event_id": local_event["id"],
            },
        )

    try:
        return event_cls(**local_event)

    except TypeError as exc:
        _report_event_type_issue(
            status="degraded",
            issue="event_type_coercion_failed",
            details={
                "kind": kind,
                "event_id": local_event["id"],
                "error": str(exc),
                "fallback": "BaseEvent",
            },
        )

        return BaseEvent(
            id=local_event["id"],
            kind=kind,
        )
