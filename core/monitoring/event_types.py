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
import time
import threading
import urllib.request
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

logger = logging.getLogger("SentinelEventTypes")

EVENT_TYPES_MODULE_ID = os.getenv("S43_EVENT_TYPES_MODULE_ID", "sentinel43-event-types")

EVENT_TYPES_VERSION = os.getenv("S43_EVENT_TYPES_VERSION", os.getenv("SENTINEL_VERSION", "0.1.0"))

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")


def _float_env(name: str, default: float) -> float:
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
    try:
        request = urllib.request.Request(
            f"{WATCHTOWER_URL}/watchtower/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT)
    except Exception as exc:
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

    try:
        threading.Thread(target=_send_watchtower_report, args=(payload,), daemon=True).start()
    except Exception as exc:
        logger.debug("Failed to spawn Watchtower reporting thread: %s", exc)


# ============================================================
# Base event
# ============================================================

@dataclass
class BaseEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    kind: str = "base"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================
# System / infrastructure events
# ============================================================

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


# ============================================================
# Mobile / network-origin events
#
# MobileEvent carries the three fields SentinelWindowStore
# requires on every EventContext it ingests:
#
#   source_identity  -- the authenticated caller/session ID
#   source_ip        -- client IP (extracted at the gateway)
#   timestamp        -- UNIX epoch float (SentinelWindowStore
#                       compares this against time.time())
#
# It also carries mobile-specific metadata and an optional
# raw payload (bytes) that the window store can store
# separately for threat-detector inspection.
#
# to_event_context() on the module level is the bridge
# between any BaseEvent and an EventContext for the
# SentinelWindowStore -- MobileEvent populates all fields
# natively; other event types require the caller to supply
# source_ip / source_identity at the gateway layer.
# ============================================================

@dataclass
class MobileEvent(BaseEvent):
    kind: str = "mobile"

    # Required by SentinelWindowStore / EventContext
    source_identity: str = ""       # authenticated caller / session id
    source_ip: str = ""             # extracted at the gateway, not trusted from client
    timestamp: float = field(default_factory=time.time)

    # Mobile-specific metadata
    app_version: str = ""
    device_id: str = ""             # will be hashed by governance layer if hash_device_ids=True
    session_id: str = ""
    action: str = ""                # e.g. "approve", "veto", "login", "request"

    # Raw payload bytes for the window store's payload buffer.
    # Excluded from to_dict() / JSON serialization -- bytes
    # are not JSON-serializable and belong in the window store,
    # not in monitoring telemetry.
    payload: Optional[bytes] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # payload is bytes; drop it from the telemetry dict.
        # The window store holds it separately via to_event_context().
        d.pop("payload", None)
        return d


# ============================================================
# Type registry
# ============================================================

_EVENT_TYPE_MAP = {
    "request": RequestEvent,
    "expectation": ExpectationEvent,
    "config": ConfigEvent,
    "log": LogEvent,
    "runtime": RuntimeEvent,
    "dependency": DependencyEvent,
    "resource": ResourceEvent,
    "security": SecurityEvent,
    "mobile": MobileEvent,
}

# Cache of valid field names per event class, used to drop unrecognized
# keys without an exception-driven try/except.
_EVENT_TYPE_FIELDS: dict[type, set[str]] = {
    event_cls: {f.name for f in fields(event_cls)}
    for event_cls in {BaseEvent, *_EVENT_TYPE_MAP.values()}
}


# ============================================================
# normalize_event
# ============================================================

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

    # Normalized kind written back so the constructed event's .kind
    # attribute always matches the dispatch key.
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

    # Drop unrecognized keys individually rather than failing the whole
    # event -- preserves forward compatibility with new client fields
    # (e.g. new mobile app fields) before dataclasses are updated.
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


# ============================================================
# SentinelWindowStore bridge
#
# to_event_context() converts any BaseEvent into an EventContext
# that SentinelWindowStore.add_event() can ingest.
#
# MobileEvent carries all required fields natively (source_identity,
# source_ip, timestamp, payload).
#
# For all other event types, the gateway layer must supply source_ip
# and optionally source_identity and timestamp:
#
#     ctx = to_event_context(event, source_ip=request.client.host)
#     window_store.add_event(ctx)
#     window = window_store.build_window(ctx.source_identity, ctx.source_ip)
#     threat_score = threat_detector.score(window)
# ============================================================

def to_event_context(
    event: BaseEvent,
    *,
    source_ip: Optional[str] = None,
    source_identity: Optional[str] = None,
    timestamp: Optional[float] = None,
    payload: Optional[bytes] = None,
) -> Any:
    """
    Bridge a BaseEvent subclass into an EventContext for SentinelWindowStore.

    Field resolution order (first non-empty value wins):

        source_identity: event.source_identity → kwarg → event.id
        source_ip:       event.source_ip       → kwarg  (required)
        timestamp:       event.timestamp        → kwarg → time.time()
        payload:         event.payload          → kwarg → None

    Raises ValueError if source_ip cannot be resolved, since
    SentinelWindowStore keys its deques on (identity, ip) and
    will reject any event missing either field.
    """
    # Import here to avoid a hard dependency on the AI detection package
    # at module import time -- if sentinel_43_ai is not installed,
    # everything except to_event_context() still works normally.
    try:
        from sentinel_43_ai.detection.sentinel_threat_detector import EventContext
    except ImportError as exc:
        raise ImportError(
            "to_event_context() requires sentinel_43_ai to be installed: "
            f"{exc}"
        ) from exc

    resolved_identity: str = (
        getattr(event, "source_identity", None)
        or source_identity
        or event.id
    )

    resolved_ip: str = getattr(event, "source_ip", None) or source_ip or ""
    if not resolved_ip:
        raise ValueError(
            f"to_event_context: source_ip is required for {type(event).__name__} "
            "but was not found on the event and was not supplied as a keyword argument. "
            "The gateway layer should extract it from the request and pass it explicitly."
        )

    resolved_ts: float = (
        getattr(event, "timestamp", None)
        or timestamp
        or time.time()
    )

    resolved_payload: Optional[bytes] = (
        getattr(event, "payload", None)
        or payload
    )

    return EventContext(
        source_identity=resolved_identity,
        source_ip=resolved_ip,
        timestamp=resolved_ts,
        payload=resolved_payload,
    )
