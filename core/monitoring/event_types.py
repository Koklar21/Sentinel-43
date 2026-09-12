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
from datetime import datetime, timezone
from typing import Any, Final, Mapping


#: Version of the normalized event envelope. Bump only for a breaking change
#: to the envelope itself, never for a new event kind.
EVENT_SCHEMA_VERSION: Final[str] = "1.0"

#: Envelope versions this build understands. An event declaring anything else
#: is REJECTED rather than half-interpreted -- a future producer must not be
#: silently parsed against older assumptions.
SUPPORTED_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1.0"})


#: Canonical integrity-status vocabulary for LogEvent.integrity_status.
#: Producer (SpartaCore) and scanner (WatchtowerNode) must agree on these
#: exact values -- a second, undocumented vocabulary is how a real integrity
#: compromise reaches the scanner and produces no alert.
INTEGRITY_STATUS_OK: Final[str] = "ok"
INTEGRITY_STATUS_COMPROMISED: Final[str] = "compromised"

#: Anything outside this set is treated as suspect, never as healthy.
KNOWN_INTEGRITY_STATUSES: Final[frozenset[str]] = frozenset(
    {INTEGRITY_STATUS_OK, INTEGRITY_STATUS_COMPROMISED}
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    # --- normalized envelope -------------------------------------------------
    # Provenance travels with the event. ``ingested_at`` is stamped by
    # normalize_event() at the trust boundary and is ours, not the producer's.
    schema_version: str = EVENT_SCHEMA_VERSION
    source: str = ""
    source_identity: str = ""
    correlation_id: str = ""
    created_at: str = ""
    ingested_at: str = ""
    #: The event this one was derived FROM, if any. A derived finding gets its
    #: own event_id (it is genuinely a new event) but keeps causal linkage to
    #: the signal that produced it, so one originating signal stays traceable
    #: end to end. Empty for an originating event.
    parent_event_id: str = ""

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

        self.schema_version = str(
            self.schema_version
        ).strip() or EVENT_SCHEMA_VERSION

        if self.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(
                f"unsupported event schema_version "
                f"{self.schema_version!r}; supported: "
                f"{sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            )

        self.source = str(self.source).strip()
        self.source_identity = str(self.source_identity).strip()
        self.correlation_id = str(self.correlation_id).strip()
        self.created_at = str(self.created_at).strip()
        self.ingested_at = str(self.ingested_at).strip()
        self.parent_event_id = str(self.parent_event_id).strip()

    @property
    def event_id(self) -> str:
        """Envelope name for the event's unique id."""
        return self.id

    def to_dict(
        self,
    ) -> dict[str, Any]:
        payload = asdict(
            self
        )
        payload["event_id"] = self.id
        return payload


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


#: Bounds for SecurityEvent's finding-content fields -- producer data, so
#: never trusted to be well-formed or bounded on its own.
_MAX_SEVERITY_LEN: Final[int] = 64
_MAX_THREAT_KIND_LEN: Final[int] = 128
_MAX_SOURCE_IP_LEN: Final[int] = 64
_MAX_INDICATORS: Final[int] = 50
_MAX_INDICATOR_LEN: Final[int] = 256


@dataclass(slots=True)
class SecurityEvent(BaseEvent):
    kind: str = "security"
    unsigned_artifact: bool = False
    secrets_exposed: bool = False
    debug_mode_enabled: bool = False

    # Finding content -- what a detection producer (Fenrir, Sparta) actually
    # found, not just that it reported something. Optional: producers that
    # only need the base security signal (firewall, governance) leave these
    # at their defaults, and normalize_event()'s allow_unknown_fields path
    # already drops anything a caller doesn't set. Bounded and typed in
    # __post_init__ below -- this is producer-supplied data reaching the
    # canonical monitoring path, held to the same "never trust producer
    # shape" standard as every other envelope field.
    severity: str = ""
    threat_kind: str = ""
    source_ip: str = ""
    indicators: tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 0.0

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)

        self.severity = str(self.severity).strip()[:_MAX_SEVERITY_LEN]
        self.threat_kind = str(self.threat_kind).strip()[:_MAX_THREAT_KIND_LEN]
        self.source_ip = str(self.source_ip).strip()[:_MAX_SOURCE_IP_LEN]

        raw_indicators = self.indicators or ()
        if isinstance(raw_indicators, str):
            # A single string is not "many indicators split some other way"
            # -- treat it as exactly one, rather than iterating characters.
            raw_indicators = (raw_indicators,)
        self.indicators = tuple(
            str(item).strip()[:_MAX_INDICATOR_LEN]
            for item in list(raw_indicators)[:_MAX_INDICATORS]
            if str(item).strip()
        )

        try:
            confidence = float(self.confidence or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        self.confidence = max(0.0, min(1.0, confidence))


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

    # Event identity. "event_id" is the envelope's outward name for the same
    # value as the internal "id" field, so a producer may supply either.
    #
    # Order matters: generating a fallback id BEFORE consulting "event_id"
    # made the producer-supplied identifier unreachable and silently replaced
    # it with a fresh UUID, breaking any cross-system correlation the
    # producer had established. Resolve the supplied identity first, and
    # generate exactly once only when neither was given.
    #
    # Event identity is NOT correlation identity: correlation_id is a separate
    # envelope field and is never derived from, or used as, the event id.
    raw_event_id = local_event.get("event_id")
    raw_id = local_event.get("id")

    supplied_event_id = str(
        raw_event_id or ""
    ).strip()

    supplied_id = str(
        raw_id or ""
    ).strip()

    # A key that is present but blank is malformed input, not an absent one.
    # Generating a fresh identity for it would silently accept a producer bug;
    # reject instead, matching BaseEvent's own "must not be empty" contract.
    if raw_event_id is not None and not supplied_event_id:
        raise ValueError(
            "event_id must not be empty"
        )

    if raw_id is not None and not supplied_id:
        raise ValueError(
            "event id must not be empty"
        )

    if (
        supplied_event_id
        and supplied_id
        and supplied_event_id != supplied_id
    ):
        # Two different identities for one event is ambiguous. Reject rather
        # than silently picking one and discarding the other.
        raise ValueError(
            "conflicting event identity: "
            f"id={supplied_id!r} != event_id={supplied_event_id!r}"
        )

    resolved_id = (
        supplied_event_id
        or supplied_id
        or str(uuid.uuid4())
    )

    local_event["id"] = resolved_id
    local_event.pop("event_id", None)

    # Reject an unsupported envelope version explicitly and BEFORE
    # construction, so the caller learns the actual reason instead of a
    # generic "invalid <kind> event".
    declared_version = str(
        local_event.get("schema_version") or EVENT_SCHEMA_VERSION
    ).strip()
    if declared_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(
            f"unsupported event schema_version {declared_version!r}; "
            f"supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        )
    local_event["schema_version"] = declared_version

    # Ingestion time is stamped HERE, at the trust boundary. A producer may
    # assert when it created an event; it may not assert when we accepted it.
    local_event["ingested_at"] = _utc_now_iso()

    if not local_event.get("created_at"):
        local_event["created_at"] = local_event["ingested_at"]

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



# =============================================================================
# Causation and loop prevention
# =============================================================================

def derive_envelope(
    parent: Mapping[str, Any],
    *,
    source: str,
    source_identity: str = "",
    event_type: str = "",
) -> dict[str, Any]:
    """Build a causally-linked child envelope for a DERIVED finding.

    A derived finding (e.g. a Watchtower assessment of an inbound event) is
    genuinely a new event and gets its own ``event_id``. It keeps the
    parent's ``correlation_id`` so both sit on the same trace, and records
    ``parent_event_id`` so the causal chain is explicit rather than inferred.
    """
    parent_id = str(
        parent.get("event_id") or parent.get("id") or ""
    ).strip()

    return {
        "event_id": str(uuid.uuid4()),
        "parent_event_id": parent_id,
        "correlation_id": str(parent.get("correlation_id") or "").strip()
        or parent_id,
        "event_type": event_type or str(parent.get("event_type") or ""),
        "schema_version": str(
            parent.get("schema_version") or EVENT_SCHEMA_VERSION
        ),
        "source": source,
        "source_identity": source_identity,
        "created_at": _utc_now_iso(),
    }


def is_derived(event: Mapping[str, Any]) -> bool:
    """True when this event was produced BY analysis of another event."""
    return bool(str(event.get("parent_event_id") or "").strip())


def would_loop(event: Mapping[str, Any], *, analyzer_source: str) -> bool:
    """Would re-submitting ``event`` to ``analyzer_source`` create a cycle?

    An analyzer's own derived output must not be fed back into that same
    analyzer: Watchtower finding -> monitoring -> Watchtower -> ... is
    unbounded. The check is an explicit origin contract (is this analyzer's
    own derived output?) rather than a global depth counter, so the rule
    stays readable and cannot be defeated by resetting a hop count.
    """
    if not is_derived(event):
        return False

    origin = str(event.get("source") or "").strip().lower()
    return origin == str(analyzer_source or "").strip().lower()


__all__ = [
    "would_loop",
    "is_derived",
    "derive_envelope",
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
