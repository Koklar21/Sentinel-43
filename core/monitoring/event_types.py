from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional
import uuid


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
    kind = str(event.get("kind", "base")).lower()
    event_cls = _EVENT_TYPE_MAP.get(kind, BaseEvent)

    if "id" not in event or not event["id"]:
        event["id"] = str(uuid.uuid4())

    try:
        return event_cls(**event)
    except TypeError:
        # If extra/unexpected fields appear, preserve minimum compatibility
        return BaseEvent(
            id=event["id"],
            kind=kind,
        )