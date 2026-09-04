"""
Sentinel-43 Dashboard State
Remote Gateway State

Shared gateway telemetry and optional per-session operator UI state.
"""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Iterable

from dashboard.components.remote_event_form import VALID_EVENT_TYPES


DEFAULT_STALE_THRESHOLD = timedelta(minutes=5)
DEFAULT_OPERATION_DISPLAY_TTL = timedelta(minutes=5)

MAX_TARGETS = 500
MAX_SECTION_BYTES = 256 * 1024
MAX_NESTING_DEPTH = 12

TARGET_ID_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")
LOADING_SOURCE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


class RemoteState:
    """
    Shared Remote Gateway telemetry state.

    This class may be shared by the dashboard application because it stores
    system-level information only:
    - Gateway health
    - Available remote targets
    - Loading state
    - Retrieval errors
    - Freshness timestamps

    Operator-specific selections and operation banners do NOT belong here.
    Store those in frontend state or a session-scoped RemoteSessionState.
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

        self._gateway_health: dict[str, Any] = {}
        self._targets: list[dict[str, Any]] = []

        self._gateway_health_ok: bool | None = None
        self._gateway_health_error: str | None = None
        self._targets_error: str | None = None

        self._gateway_health_updated_at: datetime | None = None
        self._targets_updated_at: datetime | None = None

        self._pending_loads: dict[str, int] = {}

        self._error: str | None = None
        self._last_updated: datetime | None = None
        self._last_successful_update: datetime | None = None
        self._last_error_at: datetime | None = None
        self._last_clear_reason: str | None = None

    @property
    def gateway_health(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._gateway_health)

    @property
    def targets(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._targets)

    @property
    def target_count(self) -> int:
        with self._lock:
            return len(self._targets)

    @property
    def loading(self) -> bool:
        with self._lock:
            return bool(self._pending_loads)

    @property
    def error(self) -> str | None:
        with self._lock:
            if self._error:
                return self._error

            errors = [
                message
                for message in (
                    self._gateway_health_error,
                    self._targets_error,
                )
                if message
            ]

            return "; ".join(errors) if errors else None

    @property
    def last_updated(self) -> datetime | None:
        with self._lock:
            return self._last_updated

    @property
    def last_successful_update(self) -> datetime | None:
        with self._lock:
            return self._last_successful_update

    @property
    def last_error_at(self) -> datetime | None:
        with self._lock:
            return self._last_error_at

    @property
    def is_gateway_online(self) -> bool:
        with self._lock:
            if isinstance(self._gateway_health_ok, bool):
                return self._gateway_health_ok

            return self._infer_ok(self._gateway_health)

    @property
    def degraded(self) -> bool:
        """
        Gateway liveness and target-list completeness are separate concerns.

        A healthy gateway with an unavailable or stale target list is degraded,
        not offline.
        """
        return (
            self.is_gateway_online
            and (
                self._targets_error is not None
                or self.is_stale(section="targets")
            )
        )

    def set_gateway_health(self, value: dict[str, Any]) -> None:
        sanitized = self._sanitize_mapping(
            value,
            field_name="gateway_health",
        )
        now = datetime.now(timezone.utc)

        with self._lock:
            self._gateway_health = sanitized
            self._gateway_health_ok = self._infer_ok(sanitized)
            self._gateway_health_error = None
            self._gateway_health_updated_at = now
            self._last_updated = now
            self._last_successful_update = now

    def set_targets(self, value: list[dict[str, Any]]) -> None:
        sanitized = self._sanitize_targets(value)
        now = datetime.now(timezone.utc)

        with self._lock:
            self._targets = sanitized
            self._targets_error = None
            self._targets_updated_at = now
            self._last_updated = now
            self._last_successful_update = now

    def apply_snapshot(self, snapshot: dict[str, Any]) -> None:
        """
        Apply the Remote Gateway client snapshot atomically.

        Expected input:
        - The ApiResponse dictionary returned by get_remote_gateway_snapshot(),
          or
        - Its inner data dictionary.

        Successful sections replace stored data.
        Failed sections preserve their previous last-known-good values.
        """
        payload = self._unwrap_snapshot(snapshot)
        raw_results = payload.get("raw", {})

        if raw_results is None:
            raw_results = {}

        if not isinstance(raw_results, dict):
            raise TypeError("snapshot raw field must be a dictionary")

        health_payload = payload.get("health")
        targets_payload = payload.get("targets")

        health_result = raw_results.get("health", {})
        targets_result = raw_results.get("targets", {})

        staged_health: dict[str, Any] | None = None
        staged_targets: list[dict[str, Any]] | None = None

        health_error = self._extract_result_error(
            health_result,
            fallback="remote gateway health endpoint failed",
        )
        targets_error = self._extract_result_error(
            targets_result,
            fallback="remote target endpoint failed",
        )

        health_ok = self._extract_result_ok(health_result)
        targets_ok = self._extract_result_ok(targets_result)

        if health_ok is not False:
            if health_payload is None:
                health_error = "remote gateway health endpoint returned no data"
            else:
                try:
                    staged_health = self._sanitize_mapping(
                        health_payload,
                        field_name="gateway_health",
                    )
                    health_error = None
                except (TypeError, ValueError) as exc:
                    health_error = str(exc)

        if targets_ok is not False:
            if targets_payload is None:
                targets_error = "remote target endpoint returned no data"
            else:
                try:
                    extracted_targets = self._extract_target_list(
                        targets_payload
                    )
                    staged_targets = self._sanitize_targets(
                        extracted_targets
                    )
                    targets_error = None
                except (TypeError, ValueError) as exc:
                    targets_error = str(exc)

        now = datetime.now(timezone.utc)

        with self._lock:
            if staged_health is not None:
                self._gateway_health = staged_health
                self._gateway_health_ok = (
                    health_ok
                    if isinstance(health_ok, bool)
                    else self._infer_ok(staged_health)
                )
                self._gateway_health_updated_at = now

            if staged_targets is not None:
                self._targets = staged_targets
                self._targets_updated_at = now

            self._gateway_health_error = health_error
            self._targets_error = targets_error

            top_level_error = snapshot.get("error")

            if isinstance(top_level_error, str) and top_level_error.strip():
                self._error = top_level_error.strip()
            else:
                self._error = None

            self._last_updated = now

            if staged_health is not None or staged_targets is not None:
                self._last_successful_update = now

            if health_error or targets_error or self._error:
                self._last_error_at = now
            else:
                self._last_error_at = None

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        cleaned = self._validate_target_id(target_id)

        with self._lock:
            for target in self._targets:
                if target["target_id"] == cleaned:
                    return copy.deepcopy(target)

        return None

    def has_target(self, target_id: str) -> bool:
        return self.get_target(target_id) is not None

    def begin_loading(self, source: str) -> None:
        cleaned = self._validate_loading_source(source)

        with self._lock:
            self._pending_loads[cleaned] = (
                self._pending_loads.get(cleaned, 0) + 1
            )
            self._touch()

    def finish_loading(self, source: str) -> None:
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
        source: str = "remote_gateway",
    ) -> None:
        """
        Compatibility helper for older wiring.

        New code should use begin_loading() and finish_loading().
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
        with self._lock:
            self._error = None
            self._gateway_health_error = None
            self._targets_error = None
            self._last_error_at = None
            self._touch()

    def is_stale(
        self,
        *,
        section: str | None = None,
        threshold: timedelta | None = None,
        now: datetime | None = None,
    ) -> bool:
        current_time = now or datetime.now(timezone.utc)
        effective_threshold = threshold or self._stale_threshold

        if current_time.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        if effective_threshold <= timedelta(seconds=0):
            raise ValueError("threshold must be greater than 0")

        with self._lock:
            if section is None:
                timestamps = (
                    self._gateway_health_updated_at,
                    self._targets_updated_at,
                )
            elif section == "gateway_health":
                timestamps = (self._gateway_health_updated_at,)
            elif section == "targets":
                timestamps = (self._targets_updated_at,)
            else:
                raise ValueError(f"Invalid remote-state section: {section!r}")

        return any(
            timestamp is None
            or current_time - timestamp > effective_threshold
            for timestamp in timestamps
        )

    def clear(self, *, reason: str) -> None:
        """
        Reset shared gateway telemetry.

        The application layer should send the reason to the external audit sink.
        """
        if not isinstance(reason, str):
            raise TypeError("clear reason must be a string")

        cleaned_reason = reason.strip()

        if not cleaned_reason:
            raise ValueError("clear reason must not be empty")

        now = datetime.now(timezone.utc)

        with self._lock:
            self._gateway_health = {}
            self._targets = []

            self._gateway_health_ok = None
            self._gateway_health_error = None
            self._targets_error = None

            self._gateway_health_updated_at = None
            self._targets_updated_at = None

            self._pending_loads = {}

            self._error = None
            self._last_updated = now
            self._last_successful_update = None
            self._last_error_at = None
            self._last_clear_reason = cleaned_reason

    def to_dict(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)

        with self._lock:
            gateway_health = copy.deepcopy(self._gateway_health)
            targets = copy.deepcopy(self._targets)
            pending_loads = dict(self._pending_loads)

            gateway_health_ok = self._gateway_health_ok
            gateway_health_error = self._gateway_health_error
            targets_error = self._targets_error

            gateway_health_updated_at = self._gateway_health_updated_at
            targets_updated_at = self._targets_updated_at

            error = self._error
            last_updated = self._last_updated
            last_successful_update = self._last_successful_update
            last_error_at = self._last_error_at
            last_clear_reason = self._last_clear_reason

        gateway_stale = (
            gateway_health_updated_at is None
            or now - gateway_health_updated_at > self._stale_threshold
        )

        targets_stale = (
            targets_updated_at is None
            or now - targets_updated_at > self._stale_threshold
        )

        effective_gateway_online = (
            gateway_health_ok
            if isinstance(gateway_health_ok, bool)
            else self._infer_ok(gateway_health)
        )

        aggregated_errors = [
            message
            for message in (
                error,
                gateway_health_error,
                targets_error,
            )
            if message
        ]

        return {
            "gateway_health": gateway_health,
            "targets": targets,
            "target_count": len(targets),
            "is_gateway_online": effective_gateway_online,
            "degraded": (
                effective_gateway_online
                and (
                    targets_error is not None
                    or targets_stale
                )
            ),
            "loading": bool(pending_loads),
            "pending_loads": pending_loads,
            "error": "; ".join(aggregated_errors) if aggregated_errors else None,
            "is_stale": gateway_stale or targets_stale,
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
                "gateway_health": {
                    "ok": effective_gateway_online,
                    "error": gateway_health_error,
                    "is_stale": gateway_stale,
                    "last_updated": (
                        gateway_health_updated_at.isoformat()
                        if gateway_health_updated_at is not None
                        else None
                    ),
                },
                "targets": {
                    "ok": targets_error is None,
                    "error": targets_error,
                    "is_stale": targets_stale,
                    "last_updated": (
                        targets_updated_at.isoformat()
                        if targets_updated_at is not None
                        else None
                    ),
                },
            },
        }

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
    def _extract_target_list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return value

        if isinstance(value, dict):
            targets = value.get("targets")

            if isinstance(targets, list):
                return targets

        raise TypeError(
            "targets payload must be a list or a dictionary containing a targets list"
        )

    @staticmethod
    def _sanitize_targets(
        targets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not isinstance(targets, list):
            raise TypeError(
                f"targets must be a list, got {type(targets).__name__}"
            )

        if len(targets) > MAX_TARGETS:
            raise ValueError(
                f"targets must not exceed {MAX_TARGETS} entries"
            )

        sanitized: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for index, target in enumerate(targets):
            if not isinstance(target, dict):
                raise TypeError(
                    f"targets[{index}] must be a dictionary, "
                    f"got {type(target).__name__}"
                )

            safe_target = copy.deepcopy(target)

            target_id = safe_target.get("target_id")
            name = safe_target.get("name")

            safe_target_id = RemoteState._validate_target_id(target_id)

            if safe_target_id in seen_ids:
                raise ValueError(
                    f"Duplicate target_id: {safe_target_id!r}"
                )

            if not isinstance(name, str) or not name.strip():
                raise ValueError(
                    f"targets[{index}].name must be a non-empty string"
                )

            safe_target["target_id"] = safe_target_id
            safe_target["name"] = name.strip()

            RemoteState._validate_nesting_depth(safe_target)
            sanitized.append(safe_target)
            seen_ids.add(safe_target_id)

        RemoteState._validate_json_size(
            sanitized,
            field_name="targets",
        )

        return sanitized

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

        RemoteState._validate_nesting_depth(safe_value)
        RemoteState._validate_json_size(
            safe_value,
            field_name=field_name,
        )

        return safe_value

    @staticmethod
    def _validate_json_size(
        value: Any,
        *,
        field_name: str,
    ) -> None:
        try:
            encoded = json.dumps(
                value,
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
                    raise ValueError("dictionary keys must be strings")

                RemoteState._validate_nesting_depth(
                    nested_value,
                    depth=depth + 1,
                )

        elif isinstance(value, list):
            for nested_value in value:
                RemoteState._validate_nesting_depth(
                    nested_value,
                    depth=depth + 1,
                )

    @staticmethod
    def _extract_result_ok(result: Any) -> bool | None:
        if not isinstance(result, dict):
            return None

        ok = result.get("ok")

        return ok if isinstance(ok, bool) else None

    @staticmethod
    def _extract_result_error(
        result: Any,
        *,
        fallback: str,
    ) -> str | None:
        if not isinstance(result, dict):
            return None

        if result.get("ok") is not False:
            return None

        error = result.get("error")

        if isinstance(error, str) and error.strip():
            return error.strip()

        return fallback

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
                "online",
                "active",
                "ready",
            }

        return False

    @staticmethod
    def _validate_target_id(target_id: Any) -> str:
        if not isinstance(target_id, str):
            raise TypeError("target_id must be a string")

        cleaned = target_id.strip()

        if not TARGET_ID_RE.fullmatch(cleaned):
            raise ValueError(
                "target_id must be 1-64 alphanumeric, dash, underscore, dot, or colon characters"
            )

        return cleaned

    @staticmethod
    def _validate_loading_source(source: str) -> str:
        if not isinstance(source, str):
            raise TypeError("loading source must be a string")

        cleaned = source.strip()

        if not LOADING_SOURCE_RE.fullmatch(cleaned):
            raise ValueError(
                "loading source must be 1-64 alphanumeric, dash, underscore, or dot characters"
            )

        return cleaned


remote_state = RemoteState()
