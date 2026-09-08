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

"""Sentinel-43 threat detection and scoring.

Pure detection layer:
    - normalizes event input
    - maintains bounded sequence windows
    - scores suspicious behavior
    - returns structured threat assessments

No blocking, firewall mutation, approval/veto, secret handling, or enforcement.
"""

from __future__ import annotations

import ipaddress
import math
import time
from collections import Counter, OrderedDict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Final

from .sentinel_threat_types import (
    ThreatAssessment,
    ThreatKind,
    ThreatSeverity,
    ThreatSourceKind,
)


_DEFAULT_FAILURE_STATUS_CODES: Final[frozenset[int]] = frozenset(
    {400, 401, 403, 404, 409, 429}
)

_SUSPICIOUS_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "brute_force",
        "credential_stuffing",
        "login_failure",
        "auth_failure",
        "malware_beacon",
        "exfiltration",
        "port_scan",
        "payload_rejected",
        "waf_block",
    }
)


@dataclass(frozen=True, slots=True)
class EventContext:
    """Normalized event input for detector/window consumers."""

    source_identity: str
    source_ip: str
    event_type: str
    timestamp: float = field(
        default_factory=time.time
    )
    success: bool | None = None
    status_code: int | None = None
    payload: bytes | bytearray | None = None
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(
                self.source_identity,
                str,
            )
            or not self.source_identity.strip()
        ):
            raise ValueError(
                "source_identity must be a non-empty string"
            )

        if (
            not isinstance(
                self.source_ip,
                str,
            )
            or not self.source_ip.strip()
        ):
            raise ValueError(
                "source_ip must be a non-empty string"
            )

        if (
            not isinstance(
                self.event_type,
                str,
            )
            or not self.event_type.strip()
        ):
            raise ValueError(
                "event_type must be a non-empty string"
            )

        if (
            not isinstance(
                self.timestamp,
                (int, float),
            )
            or not math.isfinite(
                float(self.timestamp)
            )
        ):
            raise ValueError(
                "timestamp must be finite"
            )

        if (
            self.status_code is not None
            and not 100 <= self.status_code <= 599
        ):
            raise ValueError(
                "status_code must be between 100 and 599"
            )

        if (
            self.payload is not None
            and not isinstance(
                self.payload,
                (bytes, bytearray),
            )
        ):
            raise ValueError(
                "payload must be bytes, bytearray, or None"
            )


@dataclass(frozen=True, slots=True)
class DetectorConfig:
    window_seconds: float = 60.0
    max_events_per_window: int = 500

    medium_events_per_window: int = 25
    high_events_per_window: int = 75
    critical_events_per_window: int = 150

    medium_failures: int = 8
    high_failures: int = 20
    critical_failures: int = 50

    identity_spray_threshold: int = 10
    ip_spray_threshold: int = 10

    suspicious_payload_bytes: int = 128 * 1024
    abusive_payload_bytes: int = 512 * 1024

    future_skew_seconds: float = 60.0
    out_of_order_penalty: float = 5.0

    automation_event_rate: int = 60
    automation_failure_rate: int = 15

    failure_status_codes: frozenset[int] = (
        _DEFAULT_FAILURE_STATUS_CODES
    )

    max_keys_hint: int = 0

    def __post_init__(self) -> None:
        if not 0 < self.window_seconds <= 86_400:
            raise ValueError(
                "window_seconds must be between 0 and 86400"
            )

        if not 0 < self.max_events_per_window <= 100_000:
            raise ValueError(
                "max_events_per_window must be between 1 and 100000"
            )

        if not (
            0
            < self.medium_events_per_window
            <= self.high_events_per_window
            <= self.critical_events_per_window
        ):
            raise ValueError(
                "rate thresholds must be ordered and positive"
            )

        if not (
            0
            < self.medium_failures
            <= self.high_failures
            <= self.critical_failures
        ):
            raise ValueError(
                "failure thresholds must be ordered and positive"
            )

        if not (
            0
            < self.suspicious_payload_bytes
            <= self.abusive_payload_bytes
        ):
            raise ValueError(
                "payload thresholds must be positive and ordered"
            )

        if self.future_skew_seconds < 0:
            raise ValueError(
                "future_skew_seconds must be >= 0"
            )

        if self.out_of_order_penalty < 0:
            raise ValueError(
                "out_of_order_penalty must be >= 0"
            )

        if self.automation_event_rate < 1:
            raise ValueError(
                "automation_event_rate must be >= 1"
            )

        if self.automation_failure_rate < 1:
            raise ValueError(
                "automation_failure_rate must be >= 1"
            )

        if not self.failure_status_codes:
            raise ValueError(
                "failure_status_codes must not be empty"
            )

        if any(
            code < 100 or code > 599
            for code in self.failure_status_codes
        ):
            raise ValueError(
                "failure_status_codes must contain valid HTTP status codes"
            )

        if self.max_keys_hint < 0:
            raise ValueError(
                "max_keys_hint must be >= 0"
            )


class SequenceWindow:
    """Bounded, timestamp-ordered event window."""

    def __init__(
        self,
        max_events: int = 500,
    ) -> None:
        if max_events <= 0:
            raise ValueError(
                "max_events must be > 0"
            )

        self.max_events = int(
            max_events
        )

        self._events: deque[
            EventContext
        ] = deque(
            maxlen=self.max_events
        )

    def add_event(
        self,
        event: EventContext,
    ) -> bool:
        """Append event if it is not older than the current newest event."""
        if (
            self._events
            and event.timestamp
            < self._events[-1].timestamp
        ):
            return False

        self._events.append(
            event
        )
        return True

    def extend(
        self,
        events: Iterable[EventContext],
    ) -> None:
        for event in events:
            self.add_event(
                event
            )

    def events(
        self,
    ) -> list[EventContext]:
        return list(
            self._events
        )

    def __iter__(self):
        return iter(
            self._events
        )

    def __len__(self) -> int:
        return len(
            self._events
        )

    def prune(
        self,
        *,
        now: float | None = None,
        window_seconds: float = 60.0,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be > 0"
            )

        current = (
            time.time()
            if now is None
            else float(now)
        )

        cutoff = (
            current
            - window_seconds
        )

        while (
            self._events
            and self._events[0].timestamp
            < cutoff
        ):
            self._events.popleft()


class SentinelThreatDetector:
    """Scores event sequences and returns structured assessments."""

    def __init__(
        self,
        cfg: DetectorConfig | None = None,
    ) -> None:
        self.cfg = (
            cfg
            or DetectorConfig()
        )

        self._lock = RLock()

        self._windows: OrderedDict[
            tuple[str, str],
            SequenceWindow,
        ] = OrderedDict()

    def ingest(
        self,
        event: EventContext,
    ) -> ThreatAssessment:
        now = time.time()

        self._validate_event_time(
            event,
            now=now,
        )

        normalized_ip = _normalize_ip(
            event.source_ip
        )

        key = (
            event.source_identity.strip(),
            normalized_ip,
        )

        with self._lock:
            is_new_key = (
                key
                not in self._windows
            )

            if (
                self.cfg.max_keys_hint
                and is_new_key
                and len(self._windows)
                >= self.cfg.max_keys_hint
            ):
                self._windows.popitem(
                    last=False
                )

            window = self._windows.get(
                key
            )

            if window is None:
                window = SequenceWindow(
                    max_events=self.cfg.max_events_per_window
                )

                self._windows[
                    key
                ] = window
            else:
                self._windows.move_to_end(
                    key
                )

            window.add_event(
                event
            )

            window.prune(
                now=now,
                window_seconds=self.cfg.window_seconds,
            )

            return self.assess_window(
                identity=key[0],
                source_ip=key[1],
                window=window,
                now=now,
            )

    def assess_window(
        self,
        *,
        identity: str,
        source_ip: str,
        window: SequenceWindow,
        now: float | None = None,
    ) -> ThreatAssessment:
        current = (
            time.time()
            if now is None
            else float(now)
        )

        cutoff = (
            current
            - self.cfg.window_seconds
        )

        event_count = 0
        failure_count = 0
        payload_max = 0

        status_counter: Counter[int] = Counter()
        type_counter: Counter[str] = Counter()

        for event in window:
            if event.timestamp < cutoff:
                continue

            event_count += 1

            if event.status_code is not None:
                status_counter[
                    event.status_code
                ] += 1

            normalized_type = _event_type_norm(
                event.event_type
            )

            type_counter[
                normalized_type
            ] += 1

            if event.payload is not None:
                payload_max = max(
                    payload_max,
                    len(event.payload),
                )

            if event.success is False:
                failure_count += 1

            elif (
                event.status_code
                in self.cfg.failure_status_codes
            ):
                failure_count += 1

            elif normalized_type in {
                "login_failure",
                "auth_failure",
                "failed_login",
                "waf_block",
                "blocked",
            }:
                failure_count += 1

        if event_count == 0:
            return ThreatAssessment(
                identity=identity,
                source_ip=source_ip,
                threat_kind=ThreatKind.UNKNOWN,
                severity=ThreatSeverity.LOW,
                source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
                score=0.0,
                indicators={
                    "reason": "empty_window"
                },
                supporting_tags=[
                    "empty_window"
                ],
                window_size=0,
            )

        indicators: dict[
            str,
            Any,
        ] = {
            "event_count": event_count,
            "failure_count": failure_count,
            "max_payload_bytes": payload_max,
            "top_event_types": dict(
                type_counter.most_common(
                    5
                )
            ),
            "status_codes": dict(
                status_counter.most_common(
                    8
                )
            ),
        }

        tags: list[str] = []
        score = 0.0

        if (
            event_count
            >= self.cfg.critical_events_per_window
        ):
            score += 55
            tags.append(
                "critical_rate"
            )

        elif (
            event_count
            >= self.cfg.high_events_per_window
        ):
            score += 35
            tags.append(
                "high_rate"
            )

        elif (
            event_count
            >= self.cfg.medium_events_per_window
        ):
            score += 20
            tags.append(
                "medium_rate"
            )

        if (
            failure_count
            >= self.cfg.critical_failures
        ):
            score += 45
            tags.append(
                "critical_failure_volume"
            )

        elif (
            failure_count
            >= self.cfg.high_failures
        ):
            score += 30
            tags.append(
                "high_failure_volume"
            )

        elif (
            failure_count
            >= self.cfg.medium_failures
        ):
            score += 15
            tags.append(
                "medium_failure_volume"
            )

        matched_types = sorted(
            event_type
            for event_type in type_counter
            if event_type
            in _SUSPICIOUS_EVENT_TYPES
        )

        if matched_types:
            score += min(
                25,
                5
                * len(
                    matched_types
                ),
            )

            tags.extend(
                f"type:{event_type}"
                for event_type
                in matched_types
            )

            indicators[
                "matched_suspicious_types"
            ] = matched_types

        if (
            payload_max
            >= self.cfg.abusive_payload_bytes
        ):
            score += 25
            tags.append(
                "abusive_payload_size"
            )

        elif (
            payload_max
            >= self.cfg.suspicious_payload_bytes
        ):
            score += 10
            tags.append(
                "suspicious_payload_size"
            )

        if (
            status_counter.get(
                401,
                0,
            )
            + status_counter.get(
                403,
                0,
            )
            >= self.cfg.medium_failures
        ):
            score += 10
            tags.append(
                "auth_status_errors"
            )

        if (
            status_counter.get(
                429,
                0,
            )
            >= 3
        ):
            score += 10
            tags.append(
                "rate_limited_repeatedly"
            )

        if (
            status_counter.get(
                500,
                0,
            )
            >= 5
        ):
            score += 5
            tags.append(
                "server_error_cluster"
            )

        source_kind = (
            self._classify_source(
                event_count=event_count,
                failure_count=failure_count,
            )
        )

        if (
            source_kind
            is ThreatSourceKind.AI_AUTOMATION_LIKELY
        ):
            score += 10
            tags.append(
                "automation_likely"
            )

        score = max(
            0.0,
            min(
                100.0,
                score,
            ),
        )

        kind = self._choose_kind(
            type_counter=type_counter,
            tags=tags,
            failure_count=failure_count,
            event_count=event_count,
        )

        severity = _severity_from_score(
            score
        )

        return ThreatAssessment(
            identity=identity,
            source_ip=source_ip,
            threat_kind=kind,
            severity=severity,
            source_kind=source_kind,
            score=round(
                score,
                2,
            ),
            indicators=indicators,
            supporting_tags=sorted(
                set(tags)
            ),
            window_size=event_count,
        )

    def assess_all(
        self,
    ) -> list[ThreatAssessment]:
        now = time.time()

        with self._lock:
            assessments: list[
                ThreatAssessment
            ] = []

            for (
                identity,
                source_ip,
            ), window in list(
                self._windows.items()
            ):
                window.prune(
                    now=now,
                    window_seconds=self.cfg.window_seconds,
                )

                if len(window) == 0:
                    self._windows.pop(
                        (
                            identity,
                            source_ip,
                        ),
                        None,
                    )
                    continue

                assessments.append(
                    self.assess_window(
                        identity=identity,
                        source_ip=source_ip,
                        window=window,
                        now=now,
                    )
                )

            return assessments

    def events_in_interval(
        self,
        identity: str,
        ip: str,
        interval_seconds: float,
    ) -> int:
        if interval_seconds <= 0:
            raise ValueError(
                "interval_seconds must be > 0"
            )

        key = (
            identity.strip(),
            _normalize_ip(
                ip
            ),
        )

        now = time.time()
        cutoff = (
            now
            - interval_seconds
        )

        with self._lock:
            window = self._windows.get(
                key
            )

            if window is None:
                return 0

            self._windows.move_to_end(
                key
            )

            count = 0

            for event in reversed(
                window.events()
            ):
                if event.timestamp < cutoff:
                    break

                count += 1

            return count

    def reset(
        self,
    ) -> None:
        with self._lock:
            self._windows.clear()

    def _validate_event_time(
        self,
        event: EventContext,
        *,
        now: float,
    ) -> None:
        if (
            event.timestamp
            > now
            + self.cfg.future_skew_seconds
        ):
            raise ValueError(
                "event timestamp is too far in the future"
            )

    def _classify_source(
        self,
        *,
        event_count: int,
        failure_count: int,
    ) -> ThreatSourceKind:
        if (
            event_count
            >= self.cfg.automation_event_rate
            or failure_count
            >= self.cfg.automation_failure_rate
        ):
            return (
                ThreatSourceKind.AI_AUTOMATION_LIKELY
            )

        if (
            event_count <= 5
            and failure_count <= 2
        ):
            return (
                ThreatSourceKind.HUMAN_LIKELY
            )

        return (
            ThreatSourceKind.MIXED_OR_UNKNOWN
        )

    def _choose_kind(
        self,
        *,
        type_counter: Counter[str],
        tags: list[str],
        failure_count: int,
        event_count: int,
    ) -> ThreatKind:
        event_types = set(
            type_counter
        )

        if {
            "credential_stuffing",
            "brute_force",
            "login_failure",
            "auth_failure",
        } & event_types:
            return (
                ThreatKind.CREDENTIAL_ATTACK
            )

        if "malware_beacon" in event_types:
            return (
                ThreatKind.MALWARE_DELIVERY
            )

        if {
            "spyware",
            "spyware_activity",
        } & event_types:
            return (
                ThreatKind.SPYWARE_ACTIVITY
            )

        if {
            "exfiltration",
            "data_exfiltration",
        } & event_types:
            return (
                ThreatKind.DATA_EXFILTRATION
            )

        if (
            "abusive_payload_size"
            in tags
            or "suspicious_payload_size"
            in tags
        ):
            return (
                ThreatKind.PAYLOAD_ABUSE
            )

        if (
            event_count
            >= self.cfg.medium_events_per_window
        ):
            return (
                ThreatKind.RATE_ANOMALY
            )

        if (
            failure_count
            >= self.cfg.medium_failures
        ):
            return (
                ThreatKind.CREDENTIAL_ATTACK
            )

        return ThreatKind.UNKNOWN


def _normalize_ip(
    ip: str,
) -> str:
    value = str(
        ip
        or ""
    ).strip()

    try:
        return str(
            ipaddress.ip_address(
                value
            )
        )

    except ValueError as exc:
        raise ValueError(
            f"source_ip is not a valid IP address: {value!r}"
        ) from exc


def _event_type_norm(
    value: str,
) -> str:
    return (
        str(
            value
            or ""
        )
        .strip()
        .lower()
        .replace(
            " ",
            "_",
        )
        .replace(
            "-",
            "_",
        )
    )


def _severity_from_score(
    score: float,
) -> ThreatSeverity:
    if score >= 85:
        return ThreatSeverity.CRITICAL

    if score >= 65:
        return ThreatSeverity.HIGH

    if score >= 40:
        return ThreatSeverity.MEDIUM

    return ThreatSeverity.LOW


__all__ = [
    "DetectorConfig",
    "EventContext",
    "SequenceWindow",
    "SentinelThreatDetector",
    "ThreatAssessment",
    "ThreatKind",
    "ThreatSeverity",
    "ThreatSourceKind",
]
