"""
Sentinel-43 Dashboard State
Health State
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any


DEFAULT_STALE_THRESHOLD = timedelta(minutes=5)
MAX_SECTION_BYTES = 256 * 1024
MAX_NESTING_DEPTH = 12

SECTION_NAMES = frozenset({
    "api_health",
    "ready_status",
    "system_status",
    "metrics",
    "system_routes",
    "routes_status",
})

SNAPSHOT_SECTION_MAP = {
    "health": "api_health",
    "ready": "ready_status",
    "status": "system_status",
    "metrics": "metrics",
    "routes": "system_routes",
    "routes_status": "routes_status",
}


class HealthState:
    """
    Stores dashboard health and telemetry state.

    Supports:
    - Atomic REST snapshot application
    - Targeted section updates
    - Last-known-good data retention
    - Per-section freshness tracking
    - Partial failure isolation
    - Concurrent loading source tracking

    Authorization note:
    - This object stores metrics.
    - It does not decide who may view them.
    - Call to_dict(include_metrics=True) only after the request layer confirms
      that the caller has the required scope.
    """

    def __init__(
        self,
        *,
        stale_threshold: timedelta = DEFAULT_STALE_THRESHOLD,
    ) -> None:
        if not isinstance(stale_threshold, timedelta):
            raise TypeError("stale_threshold must be a timedelta")

        if stale_threshold <= timedelta(seconds=0):
            raise ValueError("stale_threshold must be greater than 0")

        self._lock = RLock()
        self._stale_threshold = stale_threshold

        self._sections: dict[str, dict[str, Any]] = {
            section: {}
            for section in SECTION_NAMES
        }

        self._section_updated_at: dict[str, datetime | None] = {
            section: None
            for section in SECTION_NAMES
        }

        self._section_errors: dict[str, str | None] = {
            section: None
            for section in SECTION_NAMES
        }

        self._section_ok: dict[str, bool | None] = {
            section: None
            for section in SECTION_NAMES
        }

        self._pending_loads: dict[str, int] = {}

        self._error: str | None = None
        self._last_updated: datetime | None = None
        self._last_successful_update: datetime | None = None
        self._last_error_at: datetime | None = None
        self._last_clear_reason: str | None = None

    @property
    def api_health(self) -> dict[str, Any]:
        return self.get_section("api_health")

    @property
    def ready_status(self) -> dict[str, Any]:
        return self.get_section("ready_status")

    @property
    def system_status(self) -> dict[str, Any]:
        return self.get_section("system_status")

    @property
    def metrics(self) -> dict[str, Any]:
        return self.get_section("metrics")

    @property
    def system_routes(self) -> dict[str, Any]:
        return self.get_section("system_routes")

    @property
    def routes_status(self) -> dict[str, Any]:
        return self.get_section("routes_status")

    @property
    def loading(self) -> bool:
        with self._lock:
            return bool(self._pending_loads)

    @property
    def error(self) -> str | None:
        with self._lock:
            if self._error:
                return self._error

            section_errors = [
                f"{section}: {message}"
                for section, message in self._section_errors.items()
                if message
            ]

            return "; ".join(section_errors) if section_errors else None

    @property
    def last_updated(self) -> datetime | None:
        """
        Timestamp of the most recent state mutation, including errors or
        loading-state changes.
        """
        with self._lock:
            return self._last_updated

    @property
    def last_successful_update(self) -> datetime | None:
        """
        Timestamp of the most recent successful data update.
        """
        with self._lock:
            return self._last_successful_update

    @property
    def last_error_at(self) -> datetime | None:
        with self._lock:
            return self._last_error_at

    @property
    def is_api_healthy(self) -> bool:
        return self._section_is_ok("api_health")

    @property
    def is_ready(self) -> bool:
        return self._section_is_ok("ready_status")

    @property
    def degraded(self) -> bool:
        """
        Return True when a non-critical section is unavailable or stale while
        core API health and readiness remain available.
        """
        noncritical_sections = {
            "system_status",
            "metrics",
            "system_routes",
            "routes_status",
        }

        return any(
            not self._section_is_ok(section)
            or self.is_stale(section=section)
            for section in noncritical_sections
        )

    def set_api_health(self, value: dict[str, Any]) -> None:
        self._set_section("api_health", value)

    def set_ready_status(self, value: dict[str, Any]) -> None:
        self._set_section("ready_status", value)

    def set_system_status(self, value: dict[str, Any]) -> None:
        self._set_section("system_status", value)

    def set_metrics(self, value: dict[str, Any]) -> None:
        self._set_section("metrics", value)

    def set_system_routes(self, value: dict[str, Any]) -> None:
        self._set_section("system_routes", value)

    def set_routes_status(self, value: dict[str, Any]) -> None:
        self._set_section("routes_status", value)

    def get_section(self, section: str) -> dict[str, Any]:
        cleaned = self._validate_section_name(section)

        with self._lock:
            return copy.deepcopy(self._sections[cleaned])

    def apply_snapshot(
        self,
        snapshot: dict[str, Any],
    ) -> None:
        """
        Apply one health-client snapshot atomically.

        Expected input:
        - The full ApiResponse dictionary returned by get_health_snapshot(), or
        - The inner snapshot data dictionary.

        Successful sections replace stored data.
        Failed sections preserve their previous last-known-good data and record
        localized errors.
        """
        payload = self._unwrap_snapshot(snapshot)
        raw_results = payload.get("raw", {})

        if raw_results is None:
            raw_results = {}

        if not isinstance(raw_results, dict):
            raise TypeError("snapshot raw field must be a dictionary")

        staged_updates: dict[str, dict[str, Any]] = {}
        staged_errors: dict[str, str | None] = {}
        staged_ok: dict[str, bool | None] = {}

        for snapshot_key, section_name in SNAPSHOT_SECTION_MAP.items():
            section_payload = payload.get(snapshot_key)
            raw_result = raw_results.get(snapshot_key)

            raw_ok: bool | None = None
            raw_error: str | None = None

            if isinstance(raw_result, dict):
                candidate_ok = raw_result.get("ok")

                if isinstance(candidate_ok, bool):
                    raw_ok = candidate_ok

                candidate_error = raw_result.get("error")

                if isinstance(candidate_error, str) and candidate_error.strip():
                    raw_error = candidate_error.strip()

            if raw_ok is False:
                staged_errors[section_name] = (
                    raw_error
                    or f"{snapshot_key} endpoint returned an unsuccessful response"
                )
                staged_ok[section_name] = False
                continue

            if section_payload is None:
                staged_errors[section_name] = (
                    raw_error
                    or f"{snapshot_key} endpoint returned no data"
                )
                staged_ok[section_name] = False
                continue

            try:
                sanitized = self._sanitize_mapping(
                    section_payload,
                    field_name=section_name,
                )
            except (TypeError, ValueError) as exc:
                staged_errors[section_name] = str(exc)
                staged_ok[section_name] = False
                continue

            staged_updates[section_name] = sanitized
            staged_errors[section_name] = None
            staged_ok[section_name] = (
                raw_ok
                if raw_ok is not None
                else self._infer_ok(sanitized)
            )

        now = datetime.now(timezone.utc)

        with self._lock:
            for section_name, sanitized in staged_updates.items():
                self._sections[section_name] = sanitized
                self._section_updated_at[section_name] = now

            for section_name, section_error in staged_errors.items():
                self._section_errors[section_name] = section_error

            for section_name, section_ok in staged_ok.items():
                self._section_ok[section_name] = section_ok

            top_level_error = snapshot.get("error")

            if isinstance(top_level_error, str) and top_level_error.strip():
                self._error = top_level_error.strip()
                self._last_error_at = now
            elif any(staged_errors.values()):
                self._error = None
                self._last_error_at = now
            else:
                self._error = None
                self._last_error_at = None

            self._last_updated = now

            if staged_updates:
                self._last_successful_update = now

    def begin_loading(self, source: str) -> None:
        """
        Register one pending health-state load operation.
        """
        cleaned = self._validate_loading_source(source)

        with self._lock:
            self._pending_loads[cleaned] = (
                self._pending_loads.get(cleaned, 0) + 1
            )
            self._touch()

    def finish_loading(self, source: str) -> None:
        """
        Complete one pending health-state load operation.
        """
        cleaned = self._validate_loading_source(source)

        with self._lock:
            current = self._pending_loads.get(cleaned)

            if current is None:
                raise ValueError(
                    f"loading source was not registered: {cleaned!r}"
                )

            if current <= 1:
                del self._pending_loads[cleaned]
            else:
                self._pending_loads[cleaned] = current - 1

            self._touch()

    def set_loading(
        self,
        value: bool,
        *,
        source: str = "health",
    ) -> None:
        """
        Compatibility helper for older callers.

        New wiring should use begin_loading() and finish_loading() so concurrent
        requests cannot dismiss the loading state too early.
        """
        if not isinstance(value, bool):
            raise TypeError("loading value must be a boolean")

        cleaned = self._validate_loading_source(source)

        with self._lock:
            if value:
                self._pending_loads[cleaned] = 1
            else:
                self._pending_loads.pop(cleaned, None)

            self._touch()

    def set_error(self, error: str | None) -> None:
        """
        Set or clear a health-state error.

        Section-specific errors created by apply_snapshot() remain separate.
        """
        if error is not None:
            if not isinstance(error, str):
                raise TypeError("error must be None or a string")

            error = error.strip()

            if not error:
                raise ValueError("error must not be empty")

        now = datetime.now(timezone.utc)

        with self._lock:
            self._error = error
            self._last_updated = now

            if error is not None:
                self._last_error_at = now

    def clear_errors(self) -> None:
        """
        Clear top-level and section-specific errors.
        """
        with self._lock:
            self._error = None
            self._last_error_at = None

            self._section_errors = {
                section: None
                for section in SECTION_NAMES
            }

            self._touch()

    def is_stale(
        self,
        *,
        section: str | None = None,
        threshold: timedelta | None = None,
        now: datetime | None = None,
    ) -> bool:
        """
        Return True when stored health information is too old to trust.

        When no section is specified, every required section is checked.
        """
        current_time = now or datetime.now(timezone.utc)
        effective_threshold = threshold or self._stale_threshold

        if current_time.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        if effective_threshold <= timedelta(seconds=0):
            raise ValueError("threshold must be greater than 0")

        with self._lock:
            if section is not None:
                cleaned = self._validate_section_name(section)
                updated_at = self._section_updated_at[cleaned]

                return (
                    updated_at is None
                    or current_time - updated_at > effective_threshold
                )

            timestamps = list(self._section_updated_at.values())

        return any(
            updated_at is None
            or current_time - updated_at > effective_threshold
            for updated_at in timestamps
        )

    def clear(self, *, reason: str) -> None:
        """
        Reset health state explicitly.

        The application layer should also send this reason to the audit sink.
        """
        if not isinstance(reason, str):
            raise TypeError("clear reason must be a string")

        cleaned_reason = reason.strip()

        if not cleaned_reason:
            raise ValueError("clear reason must not be empty")

        now = datetime.now(timezone.utc)

        with self._lock:
            self._sections = {
                section: {}
                for section in SECTION_NAMES
            }

            self._section_updated_at = {
                section: None
                for section in SECTION_NAMES
            }

            self._section_errors = {
                section: None
                for section in SECTION_NAMES
            }

            self._section_ok = {
                section: None
                for section in SECTION_NAMES
            }

            self._pending_loads = {}
            self._error = None
            self._last_updated = now
            self._last_successful_update = None
            self._last_error_at = None
            self._last_clear_reason = cleaned_reason

    def to_dict(
        self,
        *,
        include_metrics: bool = False,
    ) -> dict[str, Any]:
        """
        Return a serialization-safe state snapshot.

        Metrics are omitted by default. The route layer must opt in only after
        confirming that the caller is authorized to view telemetry.
        """
        if not isinstance(include_metrics, bool):
            raise TypeError("include_metrics must be a boolean")

        now = datetime.now(timezone.utc)

        with self._lock:
            sections = copy.deepcopy(self._sections)
            section_updated_at = dict(self._section_updated_at)
            section_errors = dict(self._section_errors)
            section_ok = dict(self._section_ok)
            pending_loads = dict(self._pending_loads)

            error = self._error
            last_updated = self._last_updated
            last_successful_update = self._last_successful_update
            last_error_at = self._last_error_at
            last_clear_reason = self._last_clear_reason

        stale_by_section = {
            section: (
                updated_at is None
                or now - updated_at > self._stale_threshold
            )
            for section, updated_at in section_updated_at.items()
        }

        aggregated_section_errors = [
            f"{section}: {message}"
            for section, message in section_errors.items()
            if message
        ]

        effective_error = error or (
            "; ".join(aggregated_section_errors)
            if aggregated_section_errors
            else None
        )

        return {
            "api_health": sections["api_health"],
            "ready_status": sections["ready_status"],
            "system_status": sections["system_status"],
            "metrics": sections["metrics"] if include_metrics else {},
            "metrics_included": include_metrics,
            "system_routes": sections["system_routes"],
            "routes_status": sections["routes_status"],
            "loading": bool(pending_loads),
            "pending_loads": pending_loads,
            "error": effective_error,
            "is_api_healthy": self._section_is_ok("api_health"),
            "is_ready": self._section_is_ok("ready_status"),
            "degraded": self.degraded,
            "is_stale": any(stale_by_section.values()),
            "last_updated": (
                last_updated.isoformat()
                if last_updated is not None
                else None
            ),
            "last_successful_update": (
                last_successful_update.isoformat()
                if last_successful_update is not None
                else None
            ),
            "last_error_at": (
                last_error_at.isoformat()
                if last_error_at is not None
                else None
            ),
            "last_clear_reason": last_clear_reason,
            "sections": {
                section: {
                    "ok": section_ok[section],
                    "error": section_errors[section],
                    "is_stale": stale_by_section[section],
                    "last_updated": (
                        section_updated_at[section].isoformat()
                        if section_updated_at[section] is not None
                        else None
                    ),
                }
                for section in SECTION_NAMES
            },
        }

    def _set_section(
        self,
        section: str,
        value: dict[str, Any],
    ) -> None:
        cleaned_section = self._validate_section_name(section)
        sanitized = self._sanitize_mapping(
            value,
            field_name=cleaned_section,
        )
        now = datetime.now(timezone.utc)

        with self._lock:
            self._sections[cleaned_section] = sanitized
            self._section_updated_at[cleaned_section] = now
            self._section_errors[cleaned_section] = None
            self._section_ok[cleaned_section] = self._infer_ok(sanitized)
            self._last_updated = now
            self._last_successful_update = now

    def _section_is_ok(self, section: str) -> bool:
        cleaned = self._validate_section_name(section)

        with self._lock:
            stored_ok = self._section_ok[cleaned]
            payload = copy.deepcopy(self._sections[cleaned])

        if isinstance(stored_ok, bool):
            return stored_ok

        return self._infer_ok(payload)

    def _touch(self) -> None:
        self._last_updated = datetime.now(timezone.utc)

    @staticmethod
    def _unwrap_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(snapshot, dict):
            raise TypeError("snapshot must be a dictionary")

        if "data" in snapshot and "ok" in snapshot:
            payload = snapshot.get("data")

            if not isinstance(payload, dict):
                raise ValueError("snapshot data must be a dictionary")

            return payload

        return snapshot

    @staticmethod
    def _sanitize_mapping(
        value: dict[str, Any],
        *,
        field_name: str,
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError(
                f"{field_name} must be a dictionary, "
                f"got {type(value).__name__}"
            )

        safe_value = copy.deepcopy(value)

        HealthState._validate_nesting_depth(safe_value)

        try:
            encoded = json.dumps(
                safe_value,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{field_name} must be JSON serializable"
            ) from exc

        if len(encoded) > MAX_SECTION_BYTES:
            raise ValueError(
                f"{field_name} exceeds maximum size of {MAX_SECTION_BYTES} bytes"
            )

        return safe_value

    @staticmethod
    def _validate_nesting_depth(
        value: Any,
        *,
        depth: int = 0,
    ) -> None:
        if depth > MAX_NESTING_DEPTH:
            raise ValueError(
                f"payload exceeds maximum nesting depth of {MAX_NESTING_DEPTH}"
            )

        if isinstance(value, dict):
            for key, nested_value in value.items():
                if not isinstance(key, str):
                    raise ValueError("payload dictionary keys must be strings")

                HealthState._validate_nesting_depth(
                    nested_value,
                    depth=depth + 1,
                )

        elif isinstance(value, list):
            for nested_value in value:
                HealthState._validate_nesting_depth(
                    nested_value,
                    depth=depth + 1,
                )

    @staticmethod
    def _infer_ok(value: dict[str, Any]) -> bool:
        explicit_ok = value.get("ok")

        if isinstance(explicit_ok, bool):
            return explicit_ok

        status = value.get("status")

        if isinstance(status, str):
            return status.lower().strip() in {
                "ok",
                "healthy",
                "ready",
                "online",
                "active",
            }

        return False

    @staticmethod
    def _validate_section_name(section: str) -> str:
        if not isinstance(section, str):
            raise TypeError("section must be a string")

        cleaned = section.lower().strip()

        if cleaned not in SECTION_NAMES:
            raise ValueError(f"Invalid health-state section: {section!r}")

        return cleaned

    @staticmethod
    def _validate_loading_source(source: str) -> str:
        if not isinstance(source, str):
            raise TypeError("loading source must be a string")

        cleaned = source.strip()

        if not cleaned:
            raise ValueError("loading source must not be empty")

        if len(cleaned) > 64:
            raise ValueError("loading source must not exceed 64 characters")

        if not all(
            character.isalnum()
            or character in {"_", "-", "."}
            for character in cleaned
        ):
            raise ValueError(
                "loading source may contain only alphanumeric, dash, underscore, or dot characters"
            )

        return cleaned
    


health_state = HealthState()
