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
import logging
import os
import threading
import urllib.request
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict
import uuid

logger = logging.getLogger("SentinelEventTypes")

EVENT_TYPES_MODULE_ID = os.getenv("S43_EVENT_TYPES_MODULE_ID", "sentinel43-event-types")

# Fix #5: prefer the S43_* naming convention used elsewhere, fall back to
# the legacy SENTINEL_VERSION name for backwards compatibility. Now also
# actually used (see _report_event_type_issue) instead of being dead code.
EVENT_TYPES_VERSION = os.getenv("S43_EVENT_TYPES_VERSION", os.getenv("SENTINEL_VERSION", "0.1.0"))

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")


def _float_env(name: str, default: float) -> float:
    """
    Fix #4: WATCHTOWER_TIMEOUT used to be `float(os.getenv(...))`, an
    unguarded cast performed at import time. An invalid value for the env
    var would raise ValueError and crash the entire module on import.

    Falls back to the provided default (and logs a warning) if the env var
    is missing or not a valid float.
    """
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "Invalid value %r for %s, falling back to default %s", raw, name, default,
        )
        return default


WATCHTOWER_TIMEOUT = _float_env("S43_WATCHTOWER_TIMEOUT", 2.0)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _send_watchtower_report(payload: dict[str, Any]) -> None:
    """
    Actually perform the Watchtower POST. Runs on a background thread (see
    _report_event_type_issue) so it can never block event normalization.
    """
    try:
        request = urllib.request.Request(
            f"{WATCHTOWER_URL}/watchtower/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT)
    except Exception as exc:
        # Fix #6: log instead of silently swallowing -- this is the only
        # visibility we have into normalization issues reaching Watchtower.
        logger.debug("Failed to report event-type issue to Watchtower: %s", exc)


def _report_event_type_issue(
    status: str,
    issue: str,
    details: dict[str, Any],
) -> None:
    payload = {
        "event": {
            "kind": "runtime",
            "source": EVENT_TYPES_MODULE_ID,
            "source_version": EVENT_TYPES_VERSION,
            "status": status,
            "details": {
                "issue": issue,
                "timestamp": utc_now(),
                **details,
            },
        }
    }

    # Fix #3: normalize_event() is on the event-ingestion hot path. The
    # previous implementation made a blocking urlopen() call (up to
    # WATCHTOWER_TIMEOUT) directly inline, so any unknown-kind or
    # coercion-failure event added up to 2s of latency. Fire this off on a
    # daemon thread instead -- it's best-effort telemetry and must never
    # slow down (or fail) event normalization itself.
    try:
        threading.Thread(target=_send_watchtower_report, args=(payload,), daemon=True).start()
    except Exception as exc:
        logger.debug("Failed to spawn Watchtower reporting thread: %s", exc)


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

# Cache of valid field names per event class, used to drop unrecognized
# keys (Fix #2) without an exception-driven try/except.
_EVENT_TYPE_FIELDS: dict[type, set[str]] = {
    event_cls: {f.name for f in fields(event_cls)}
    for event_cls in {BaseEvent, *_EVENT_TYPE_MAP.values()}
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

    # Fix #1: previously `local_event["kind"]` retained whatever raw value
    # was supplied (e.g. mixed case / whitespace), while `kind` (the
    # normalized value used for type dispatch) was discarded. That meant
    # the constructed event's `.kind` attribute could differ from the
    # normalized dispatch key, even though the fallback BaseEvent path
    # below always used the normalized value. Normalize it consistently
    # for both paths.
    local_event["kind"] = kind

    if kind not in _EVENT_TYPE_MAP and kind != "base":
        _report_event_type_issue(
            status="degraded",
            issue="unknown_event_kind",
            details={
                "kind": kind,
                "event_id": local_event["id"],
            },
        )

    # Fix #2: previously, ANY key in `local_event` that wasn't a field on
    # `event_cls` caused `event_cls(**local_event)` to raise TypeError,
    # which discarded the entire event -- including otherwise-valid fields
    # like status_code/latency_ms -- collapsing it to a bare BaseEvent.
    #
    # This is a forward-compatibility hazard: any new field a client (e.g.
    # the mobile app) starts sending before the dataclasses are updated to
    # include it would silently wipe out the whole event on every
    # occurrence. Instead, drop only the unrecognized keys (reporting them
    # for visibility) and construct the event from the fields it does
    # recognize.
    valid_fields = _EVENT_TYPE_FIELDS.get(event_cls, _EVENT_TYPE_FIELDS[BaseEvent])
    unknown_keys = set(local_event) - valid_fields

    if unknown_keys:
        _report_event_type_issue(
            status="degraded",
            issue="unknown_event_fields_dropped",
            details={
                "kind": kind,
                "event_id": local_event["id"],
                "dropped_fields": sorted(unknown_keys),
            },
        )
        local_event = {k: v for k, v in local_event.items() if k in valid_fields}

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
