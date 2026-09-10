# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Canonical monitoring event models and normalization helpers.

This module is intentionally side-effect free:
    - no environment reads
    - no Watchtower calls
    - no logging threads
    - no network I/O

Callers may report normalization failures at their own boundary.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Final


# Subclasses below chain to BaseEvent.__post_init__ by explicit class
# reference, never zero-arg super(). @dataclass(slots=True) cannot add
# __slots__ in place, so it builds and returns a *new* class object; the
# __class__ cell that zero-arg super() closes over still points at the
# original, discarded class. Every such call raised
# "super(type, obj): obj is not an instance or subtype of type" at
# construction time, which normalize_event() surfaced as
# "invalid <kind> event" -- silently disabling 8 of the 9 typed event kinds
# (only SecurityEvent, which declares no __post_init__, and BaseEvent
# itself were unaffected).
@dataclass(slots=True)
class BaseEvent:
    id: str = field(
        default_factory=lambda: str(
            uuid.uuid4()
        )
    )
    kind: str = "base"

    def __post_init__(self) -> None:
        self.id = str(
            self.id
        ).strip()

        self.kind = str(
            self.kind
        ).strip().lower()

        if not self.id:
            raise ValueError(
                "event id must not be empty"
            )

        if not self.kind:
            raise ValueError(
                "event kind must not be empty"
            )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return asdict(
            self
        )


@dataclass(slots=True)
class RequestEvent(BaseEvent):
    kind: str = "request"
    status_code: int = 200
    latency_ms: int = 0

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        if not 100 <= int(self.status_code) <= 599:
            raise ValueError(
                "status_code must be between 100 and 599"
            )

        if int(self.latency_ms) < 0:
            raise ValueError(
                "latency_ms must be >= 0"
            )

        self.status_code = int(
            self.status_code
        )

        self.latency_ms = int(
            self.latency_ms
        )


@dataclass(slots=True)
class ExpectationEvent(BaseEvent):
    kind: str = "expectation"
    expectation_status: str = "passed"
    failed_checks: int = 0

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        self.expectation_status = str(
            self.expectation_status
        ).strip().lower()

        if not self.expectation_status:
            raise ValueError(
                "expectation_status must not be empty"
            )

        if int(self.failed_checks) < 0:
            raise ValueError(
                "failed_checks must be >= 0"
            )

        self.failed_checks = int(
            self.failed_checks
        )


@dataclass(slots=True)
class ConfigEvent(BaseEvent):
    kind: str = "config"
    drift_detected: bool = False
    config_age_seconds: int = 0

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        if int(self.config_age_seconds) < 0:
            raise ValueError(
                "config_age_seconds must be >= 0"
            )

        self.config_age_seconds = int(
            self.config_age_seconds
        )


@dataclass(slots=True)
class LogEvent(BaseEvent):
    kind: str = "log"
    missing_required_fields: bool = False
    integrity_status: str = "ok"

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        self.integrity_status = str(
            self.integrity_status
        ).strip().lower()

        if not self.integrity_status:
            raise ValueError(
                "integrity_status must not be empty"
            )


@dataclass(slots=True)
class RuntimeEvent(BaseEvent):
    kind: str = "runtime"
    error_rate_percent: int | float = 0
    crash_loop: bool = False

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        value = float(
            self.error_rate_percent
        )

        if not 0.0 <= value <= 100.0:
            raise ValueError(
                "error_rate_percent must be between 0 and 100"
            )

        self.error_rate_percent = value


@dataclass(slots=True)
class DependencyEvent(BaseEvent):
    kind: str = "dependency"
    dependency_status: str = "up"
    version_mismatch: bool = False

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        self.dependency_status = str(
            self.dependency_status
        ).strip().lower()

        if not self.dependency_status:
            raise ValueError(
                "dependency_status must not be empty"
            )


@dataclass(slots=True)
class ResourceEvent(BaseEvent):
    kind: str = "resource"
    cpu_percent: int | float = 0
    memory_percent: int | float = 0
    disk_percent: int | float = 0

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        for field_name in (
            "cpu_percent",
            "memory_percent",
            "disk_percent",
        ):
            value = float(
                getattr(
                    self,
                    field_name,
                )
            )

            if not 0.0 <= value <= 100.0:
                raise ValueError(
                    f"{field_name} must be between 0 and 100"
                )

            setattr(
                self,
                field_name,
                value,
            )


@dataclass(slots=True)
class SecurityEvent(BaseEvent):
    kind: str = "security"
    unsigned_artifact: bool = False
    secrets_exposed: bool = False
    debug_mode_enabled: bool = False


@dataclass(slots=True)
class MobileEvent(BaseEvent):
    kind: str = "mobile"

    source_identity: str = ""
    source_ip: str = ""
    timestamp: float = field(
        default_factory=time.time
    )

    app_version: str = ""
    device_id: str = ""
    session_id: str = ""
    action: str = ""

    payload: bytes | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        self.source_identity = str(
            self.source_identity
        ).strip()

        self.source_ip = str(
            self.source_ip
        ).strip()

        self.app_version = str(
            self.app_version
        ).strip()

        self.device_id = str(
            self.device_id
        ).strip()

        self.session_id = str(
            self.session_id
        ).strip()

        self.action = str(
            self.action
        ).strip().lower()

        self.timestamp = float(
            self.timestamp
        )

        if self.timestamp <= 0:
            raise ValueError(
                "timestamp must be > 0"
            )

        if (
            self.payload is not None
            and not isinstance(
                self.payload,
                bytes,
            )
        ):
            raise TypeError(
                "payload must be bytes or None"
            )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        payload = asdict(
            self
        )

        payload.pop(
            "payload",
            None,
        )

        return payload


_EVENT_TYPE_MAP: Final[
    dict[
        str,
        type[BaseEvent],
    ]
] = {
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


_EVENT_TYPE_FIELDS: Final[
    dict[
        type[BaseEvent],
        frozenset[str],
    ]
] = {
    event_cls: frozenset(
        item.name
        for item in fields(
            event_cls
        )
    )
    for event_cls in {
        BaseEvent,
        *_EVENT_TYPE_MAP.values(),
    }
}


@dataclass(frozen=True, slots=True)
class EventNormalizationResult:
    event: BaseEvent
    dropped_fields: tuple[str, ...] = ()
    unknown_kind: str | None = None


def normalize_event(
    raw_event: dict[str, Any],
    *,
    allow_unknown_fields: bool = True,
) -> EventNormalizationResult:
    """Normalize a raw event dict into a typed event.

    Unknown event kinds are rejected instead of being converted into a
    misleading BaseEvent with an arbitrary kind.
    """
    if not isinstance(
        raw_event,
        dict,
    ):
        raise TypeError(
            "raw_event must be a dict"
        )

    local_event = dict(
        raw_event
    )

    raw_kind = local_event.get(
        "kind",
        "base",
    )

    kind = str(
        raw_kind
    ).strip().lower()

    if not kind:
        kind = "base"

    if kind == "base":
        event_cls: type[
            BaseEvent
        ] = BaseEvent

    else:
        try:
            event_cls = _EVENT_TYPE_MAP[
                kind
            ]
        except KeyError as exc:
            raise ValueError(
                f"unknown event kind {kind!r}"
            ) from exc

    local_event[
        "kind"
    ] = kind

    if not local_event.get(
        "id"
    ):
        local_event[
            "id"
        ] = str(
            uuid.uuid4()
        )

    valid_fields = _EVENT_TYPE_FIELDS[
        event_cls
    ]

    unknown_fields = tuple(
        sorted(
            set(
                local_event
            )
            - valid_fields
        )
    )

    if (
        unknown_fields
        and not allow_unknown_fields
    ):
        raise ValueError(
            "unknown event fields: "
            + ", ".join(
                unknown_fields
            )
        )

    if unknown_fields:
        local_event = {
            key: value
            for key, value
            in local_event.items()
            if key in valid_fields
        }

    try:
        event = event_cls(
            **local_event
        )

    except (
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(
            f"invalid {kind!r} event"
        ) from exc

    return EventNormalizationResult(
        event=event,
        dropped_fields=unknown_fields,
    )


def to_event_context(
    event: BaseEvent,
    *,
    source_ip: str | None = None,
    source_identity: str | None = None,
    timestamp: float | None = None,
    payload: bytes | None = None,
) -> Any:
    """Convert an event into SentinelWindowStore EventContext.

    Identity and source IP must come from the event or caller explicitly.
    No synthetic identity is invented from event.id.
    """
    try:
        from core.detection.sentinel_threat_detector import EventContext
    except ImportError as exc:
        raise ImportError(
            "EventContext is unavailable from "
            "core.detection.sentinel_threat_detector"
        ) from exc

    event_identity = getattr(
        event,
        "source_identity",
        None,
    )

    resolved_identity = str(
        event_identity
        or source_identity
        or ""
    ).strip()

    if not resolved_identity:
        raise ValueError(
            "source_identity is required for EventContext"
        )

    event_ip = getattr(
        event,
        "source_ip",
        None,
    )

    resolved_ip = str(
        event_ip
        or source_ip
        or ""
    ).strip()

    if not resolved_ip:
        raise ValueError(
            "source_ip is required for EventContext"
        )

    event_timestamp = getattr(
        event,
        "timestamp",
        None,
    )

    resolved_timestamp = float(
        event_timestamp
        if event_timestamp is not None
        else (
            timestamp
            if timestamp is not None
            else time.time()
        )
    )

    if resolved_timestamp <= 0:
        raise ValueError(
            "timestamp must be > 0"
        )

    event_payload = getattr(
        event,
        "payload",
        None,
    )

    resolved_payload = (
        event_payload
        if event_payload is not None
        else payload
    )

    if (
        resolved_payload is not None
        and not isinstance(
            resolved_payload,
            bytes,
        )
    ):
        raise TypeError(
            "payload must be bytes or None"
        )

    return EventContext(
        source_identity=resolved_identity,
        source_ip=resolved_ip,
        timestamp=resolved_timestamp,
        payload=resolved_payload,
    )


__all__ = [
    "BaseEvent",
    "ConfigEvent",
    "DependencyEvent",
    "EventNormalizationResult",
    "ExpectationEvent",
    "LogEvent",
    "MobileEvent",
    "RequestEvent",
    "ResourceEvent",
    "RuntimeEvent",
    "SecurityEvent",
    "normalize_event",
    "to_event_context",
]
