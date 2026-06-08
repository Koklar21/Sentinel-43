"""
Sentinel-43 Dashboard State
Watchtower State
"""

from __future__ import annotations

import copy
import json
import re
from collections import deque
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any


DEFAULT_STALE_THRESHOLD = timedelta(minutes=5)

DEFAULT_MAX_NODES = 500
DEFAULT_MAX_ALERTS = 500

MAX_SECTION_BYTES = 256 * 1024
MAX_NESTING_DEPTH = 12

MAX_NODE_NAME_LENGTH = 128
MAX_ALERT_TITLE_LENGTH = 256
MAX_ALERT_MESSAGE_LENGTH = 2048

IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")
LOADING_SOURCE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")

VALID_NODE_STATUSES = frozenset({
    "initializing",
    "active",
    "online",
    "degraded",
    "failed",
    "error",
    "offline",
    "unknown",
})

VALID_ALERT_SEVERITIES = frozenset({
    "critical",
    "high",
    "warning",
    "info",
})

SECTION_NAMES = frozenset({
    "health",
    "status",
    "nodes",
    "alerts",
    "metrics",
})

SNAPSHOT_SECTION_MAP = {
    "health": "health",
    "status": "status",
    "nodes": "nodes",
    "alerts": "alerts",
    "metrics": "metrics",
}


class WatchtowerState:
    """
    Shared Watchtower telemetry state.

    Stores:
    - Watchtower health
    - Watchtower status
    - Current nodes
    - Recent bounded alerts
    - Watchtower metrics
    - Per-section freshness and error information
    - Concurrent loading sources

    REST refresh:
    - apply_snapshot() replaces successful sections atomically.

    WebSocket updates:
    - upsert_node() updates one node.
    - append_alert() stores one recent alert without unbounded growth.

    Authorization note:
    - Metrics are stored internally.
    - Metrics are omitted from to_dict() unless include_metrics=True.
    - The route layer must authorize telemetry access before opting in.
    """

    def __init__(
        self,
        *,
        stale_threshold: timedelta = DEFAULT_STALE_THRESHOLD,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_alerts: int = DEFAULT_MAX_ALERTS,
    ) -> None:
        if not isinstance(stale_threshold, timedelta):
            raise TypeError("stale_threshold must be a timedelta")

        if stale_threshold <= timedelta(seconds=0):
            raise ValueError("stale_threshold must be greater than 0")

        if not isinstance(max_nodes, int):
            raise TypeError("max_nodes must be an integer")

        if max_nodes <= 0:
            raise ValueError("max_nodes must be greater than 0")

        if not isinstance(max_alerts, int):
            raise TypeError("max_alerts must be an integer")

        if max_alerts <= 0:
            raise ValueError("max_alerts must be greater than 0")

        self._lock = RLock()

        self._stale_threshold = stale_threshold
        self._max_nodes = max_nodes
        self._max_alerts = max_alerts

        self._health: dict[str, Any] = {}
        self._status: dict[str, Any] = {}
        self._metrics: dict[str, Any] = {}

        self._nodes: dict[str, dict[str, Any]] = {}

        self._alerts: deque[dict[str, Any]] = deque(
            maxlen=max_alerts,
        )
        self._alert_ids: set[str] = set()

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
    def health(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._health)

    @property
    def status(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._status)

    @property
    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._metrics)

    @property
    def nodes(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(list(self._nodes.values()))

    @property
    def alerts(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(list(self._alerts))

    @property
    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    @property
    def alert_count(self) -> int:
        with self._lock:
            return len(self._alerts)

    @property
    def loading(self) -> bool:
        with self._lock:
            return bool(self._pending_loads)

    @property
    def error(self) -> str | None:
        with self._lock:
            return self._aggregate_errors_locked()

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
    def is_watchtower_healthy(self) -> bool:
        return (
            self._section_is_ok("health")
            and not self.is_stale(section="health")
        )

    @property
    def is_watchtower_ready(self) -> bool:
        return (
            self._section_is_ok("status")
            and not self.is_stale(section="status")
        )

    @property
    def liveness_ok(self) -> bool:
        return (
            self.is_watchtower_healthy
            and self.is_watchtower_ready
        )

    @property
    def data_complete(self) -> bool:
        data_sections = {
            "nodes",
            "alerts",
            "metrics",
        }

        return all(
            self._section_is_ok(section)
            and not self.is_stale(section=section)
            for section in data_sections
        )

    @property
    def degraded(self) -> bool:
        return self.liveness_ok and not self.data_complete

    def set_health(self, value: dict[str, Any]) -> None:
        self._set_mapping_section(
            "health",
            value,
        )

    def set_status(self, value: dict[str, Any]) -> None:
        self._set_mapping_section(
            "status",
            value,
        )

    def set_metrics(self, value: dict[str, Any]) -> None:
        self._set_mapping_section(
            "metrics",
            value,
        )

    def set_nodes(
        self,
        value: list[dict[str, Any]],
    ) -> None:
        """
        Replace the complete node list.

        Pass the actual node list, not an ApiResponse envelope.
        Use apply_snapshot() when handling a Watchtower client snapshot.
        """
        sanitized = self._sanitize_nodes(value)
        now = datetime.now(timezone.utc)

        with self._lock:
            self._nodes = {
                node["node_id"]: node
                for node in sanitized
            }

            self._mark_section_success_locked(
                section="nodes",
                now=now,
                ok=True,
            )

    def set_alerts(
        self,
        value: list[dict[str, Any]],
    ) -> None:
        """
        Replace the bounded recent-alert list.

        Pass the actual alert list, not an ApiResponse envelope.
        Use append_alert() for individual WebSocket alerts.
        """
        sanitized = self._sanitize_alerts(value)
        now = datetime.now(timezone.utc)

        with self._lock:
            self._replace_alerts_locked(sanitized)

            self._mark_section_success_locked(
                section="alerts",
                now=now,
                ok=True,
            )

    def upsert_node(
        self,
        node: dict[str, Any],
    ) -> None:
        """
        Add or replace one node from an incremental WebSocket event.
        """
        sanitized = self._sanitize_node(
            node,
            field_name="node",
        )
        now = datetime.now(timezone.utc)

        with self._lock:
            node_id = sanitized["node_id"]

            if (
                node_id not in self._nodes
                and len(self._nodes) >= self._max_nodes
            ):
                raise ValueError(
                    f"node limit reached: {self._max_nodes}"
                )

            self._nodes[node_id] = sanitized

            self._mark_section_success_locked(
                section="nodes",
                now=now,
                ok=True,
            )

    def remove_node(
        self,
        node_id: str,
        *,
        reason: str,
    ) -> bool:
        """
        Remove one node explicitly.

        The application layer should send the reason to the audit sink.
        """
        cleaned_node_id = self._validate_identifier(
            node_id,
            field_name="node_id",
        )
        self._validate_reason(reason)

        with self._lock:
            if cleaned_node_id not in self._nodes:
                return False

            del self._nodes[cleaned_node_id]
            self._touch()
            return True

    def append_alert(
        self,
        alert: dict[str, Any],
    ) -> bool:
        """
        Add one recent Watchtower alert.

        Returns False when an alert with the same alert_id has already been
        stored. Duplicate WebSocket deliveries are ignored safely.
        """
        sanitized = self._sanitize_alert(
            alert,
            field_name="alert",
        )
        now = datetime.now(timezone.utc)

        with self._lock:
            alert_id = sanitized["alert_id"]

            if alert_id in self._alert_ids:
                return False

            if len(self._alerts) == self._max_alerts:
                oldest = self._alerts[-1]
                self._alert_ids.discard(oldest["alert_id"])

            self._alerts.appendleft(sanitized)
            self._alert_ids.add(alert_id)

            self._mark_section_success_locked(
                section="alerts",
                now=now,
                ok=True,
            )

            return True

    def apply_snapshot(
        self,
        snapshot: dict[str, Any],
    ) -> None:
        """
        Apply a Watchtower client snapshot atomically.

        Expected input:
        - The ApiResponse dictionary returned by get_watchtower_snapshot(), or
        - Its inner data dictionary.

        Successful sections replace stored values.
        Failed sections preserve previous last-known-good values while recording
        localized errors.
        """
        payload = self._unwrap_snapshot(snapshot)
        raw_results = payload.get("raw", {})

        if raw_results is None:
            raw_results = {}

        if not isinstance(raw_results, dict):
            raise TypeError("snapshot raw field must be a dictionary")

        staged_updates: dict[str, Any] = {}
        staged_errors: dict[str, str | None] = {}
        staged_ok: dict[str, bool | None] = {}

        for snapshot_key, section_name in SNAPSHOT_SECTION_MAP.items():
            section_payload = payload.get(snapshot_key)
            raw_result = raw_results.get(snapshot_key)

            raw_ok = self._extract_result_ok(raw_result)
            raw_error = self._extract_result_error(
                raw_result,
                fallback=f"{snapshot_key} endpoint returned an unsuccessful response",
            )

            if raw_ok is False:
                staged_errors[section_name] = raw_error
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
                if section_name in {"health", "status", "metrics"}:
                    sanitized = self._sanitize_mapping(
                        section_payload,
                        field_name=section_name,
                    )

                elif section_name == "nodes":
                    sanitized = self._sanitize_nodes(
                        self._extract_list_payload(
                            section_payload,
                            collection_key="nodes",
                        )
                    )

                elif section_name == "alerts":
                    sanitized = self._sanitize_alerts(
                        self._extract_list_payload(
                            section_payload,
                            collection_key="alerts",
                        )
                    )

                else:
                    raise ValueError(
                        f"Unsupported Watchtower section: {section_name!r}"
                    )

            except (TypeError, ValueError) as exc:
                staged_errors[section_name] = str(exc)
                staged_ok[section_name] = False
                continue

            staged_updates[section_name] = sanitized
            staged_errors[section_name] = None

            if isinstance(raw_ok, bool):
                staged_ok[section_name] = raw_ok
            elif section_name in {"health", "status"}:
                staged_ok[section_name] = self._infer_ok(sanitized)
            else:
                staged_ok[section_name] = True

        now = datetime.now(timezone.utc)

        with self._lock:
            for section_name, sanitized in staged_updates.items():
                if section_name == "health":
                    self._health = sanitized

                elif section_name == "status":
                    self._status = sanitized

                elif section_name == "metrics":
                    self._metrics = sanitized

                elif section_name == "nodes":
                    self._nodes = {
                        node["node_id"]: node
                        for node in sanitized
                    }

                elif section_name == "alerts":
                    self._replace_alerts_locked(sanitized)

                self._section_updated_at[section_name] = now

            for section_name, section_error in staged_errors.items():
                self._section_errors[section_name] = section_error

            for section_name, section_ok in staged_ok.items():
                self._section_ok[section_name] = section_ok

            top_level_error = snapshot.get("error")

            if isinstance(top_level_error, str) and top_level_error.strip():
                self._error = top_level_error.strip()
            else:
                self._error = None

            self._last_updated = now

            if staged_updates:
                self._last_successful_update = now

            if self._error or any(staged_errors.values()):
                self._last_error_at = now
            else:
                self._last_error_at = None

    def begin_loading(self, source: str) -> None:
        """
        Register one pending Watchtower state load.
        """
        cleaned = self._validate_loading_source(source)

        with self._lock:
            self._pending_loads[cleaned] = (
                self._pending_loads.get(cleaned, 0) + 1
            )
            self._touch()

    def finish_loading(self, source: str) -> None:
        """
        Complete one pending Watchtower state load.
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
        source: str = "watchtower",
    ) -> None:
        """
        Compatibility helper for older callers.

        New wiring should use begin_loading() and finish_loading().
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
        Set or clear a top-level Watchtower state error.
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
        Clear top-level and localized Watchtower state errors.
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
        Return True when stored Watchtower information is too old to trust.

        When no section is supplied, every section is checked.
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
                timestamp = self._section_updated_at[cleaned]

                return (
                    timestamp is None
                    or current_time - timestamp > effective_threshold
                )

            timestamps = list(self._section_updated_at.values())

        return any(
            timestamp is None
            or current_time - timestamp > effective_threshold
            for timestamp in timestamps
        )

    def clear(self, *, reason: str) -> None:
        """
        Reset Watchtower state explicitly.

        The application layer should send the reason to the audit sink.
        """
        cleaned_reason = self._validate_reason(reason)
        now = datetime.now(timezone.utc)

        with self._lock:
            self._health = {}
            self._status = {}
            self._metrics = {}

            self._nodes = {}

            self._alerts = deque(
                maxlen=self._max_alerts,
            )
            self._alert_ids = set()

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
        Return a serialization-safe point-in-time snapshot.

        Metrics are omitted unless the route layer explicitly opts in after
        authorizing the caller.
        """
        if not isinstance(include_metrics, bool):
            raise TypeError("include_metrics must be a boolean")

        now = datetime.now(timezone.utc)

        with self._lock:
            health = copy.deepcopy(self._health)
            status = copy.deepcopy(self._status)
            metrics = copy.deepcopy(self._metrics)

            nodes = copy.deepcopy(list(self._nodes.values()))
            alerts = copy.deepcopy(list(self._alerts))

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
                timestamp is None
                or now - timestamp > self._stale_threshold
            )
            for section, timestamp in section_updated_at.items()
        }

        health_ok = (
            section_ok["health"]
            if isinstance(section_ok["health"], bool)
            else self._infer_ok(health)
        )

        status_ok = (
            section_ok["status"]
            if isinstance(section_ok["status"], bool)
            else self._infer_ok(status)
        )

        liveness_ok = (
            health_ok
            and status_ok
            and not stale_by_section["health"]
            and not stale_by_section["status"]
        )

        data_complete = all(
            section_errors[section] is None
            and not stale_by_section[section]
            for section in {
                "nodes",
                "alerts",
                "metrics",
            }
        )

        aggregated_errors = self._aggregate_errors(
            error=error,
            section_errors=section_errors,
        )

        return {
            "health": health,
            "status": status,
            "nodes": nodes,
            "alerts": alerts,
            "metrics": metrics if include_metrics else {},
            "metrics_included": include_metrics,
            "node_count": len(nodes),
            "alert_count": len(alerts),
            "unacknowledged_alert_count": sum(
                1
                for alert in alerts
                if not alert.get("acknowledged", False)
            ),
            "liveness_ok": liveness_ok,
            "data_complete": data_complete,
            "degraded": liveness_ok and not data_complete,
            "loading": bool(pending_loads),
            "pending_loads": pending_loads,
            "error": aggregated_errors,
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

    def _set_mapping_section(
        self,
        section: str,
        value: dict[str, Any],
    ) -> None:
        cleaned_section = self._validate_section_name(section)

        if cleaned_section not in {
            "health",
            "status",
            "metrics",
        }:
            raise ValueError(
                f"{cleaned_section!r} is not a mapping section"
            )

        sanitized = self._sanitize_mapping(
            value,
            field_name=cleaned_section,
        )
        now = datetime.now(timezone.utc)

        with self._lock:
            if cleaned_section == "health":
                self._health = sanitized

            elif cleaned_section == "status":
                self._status = sanitized

            elif cleaned_section == "metrics":
                self._metrics = sanitized

            self._mark_section_success_locked(
                section=cleaned_section,
                now=now,
                ok=(
                    self._infer_ok(sanitized)
                    if cleaned_section in {"health", "status"}
                    else True
                ),
            )

    def _mark_section_success_locked(
        self,
        *,
        section: str,
        now: datetime,
        ok: bool,
    ) -> None:
        self._section_updated_at[section] = now
        self._section_errors[section] = None
        self._section_ok[section] = ok

        self._last_updated = now
        self._last_successful_update = now

    def _replace_alerts_locked(
        self,
        alerts: list[dict[str, Any]],
    ) -> None:
        bounded = alerts[: self._max_alerts]

        self._alerts = deque(
            bounded,
            maxlen=self._max_alerts,
        )

        self._alert_ids = {
            alert["alert_id"]
            for alert in bounded
        }

    def _section_is_ok(self, section: str) -> bool:
        cleaned = self._validate_section_name(section)

        with self._lock:
            stored_ok = self._section_ok[cleaned]

            if isinstance(stored_ok, bool):
                return stored_ok

            if cleaned == "health":
                return self._infer_ok(self._health)

            if cleaned == "status":
                return self._infer_ok(self._status)

            return bool(self._section_updated_at[cleaned])

    def _aggregate_errors_locked(self) -> str | None:
        return self._aggregate_errors(
            error=self._error,
            section_errors=self._section_errors,
        )

    def _touch(self) -> None:
        self._last_updated = datetime.now(timezone.utc)

    def _sanitize_nodes(
        self,
        nodes: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not isinstance(nodes, list):
            raise TypeError(
                f"nodes must be a list, got {type(nodes).__name__}"
            )

        if len(nodes) > self._max_nodes:
            raise ValueError(
                f"nodes must not exceed {self._max_nodes} entries"
            )

        sanitized: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for index, node in enumerate(nodes):
            safe_node = self._sanitize_node(
                node,
                field_name=f"nodes[{index}]",
            )

            node_id = safe_node["node_id"]

            if node_id in seen_ids:
                raise ValueError(
                    f"Duplicate node_id: {node_id!r}"
                )

            sanitized.append(safe_node)
            seen_ids.add(node_id)

        self._validate_json_size(
            sanitized,
            field_name="nodes",
        )

        return sanitized

    def _sanitize_node(
        self,
        node: dict[str, Any],
        *,
        field_name: str,
    ) -> dict[str, Any]:
        if not isinstance(node, dict):
            raise TypeError(
                f"{field_name} must be a dictionary, "
                f"got {type(node).__name__}"
            )

        safe_node = copy.deepcopy(node)

        node_id = self._validate_identifier(
            safe_node.get("node_id"),
            field_name=f"{field_name}.node_id",
        )

        name = self._validate_text(
            safe_node.get("name"),
            field_name=f"{field_name}.name",
            max_length=MAX_NODE_NAME_LENGTH,
        )

        status = safe_node.get("status")

        if not isinstance(status, str):
            raise TypeError(
                f"{field_name}.status must be a string"
            )

        normalized_status = status.lower().strip()

        if normalized_status not in VALID_NODE_STATUSES:
            raise ValueError(
                f"Invalid {field_name}.status: {status!r}"
            )

        safe_node["node_id"] = node_id
        safe_node["name"] = name
        safe_node["status"] = normalized_status

        self._validate_nesting_depth(safe_node)

        return safe_node

    def _sanitize_alerts(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not isinstance(alerts, list):
            raise TypeError(
                f"alerts must be a list, got {type(alerts).__name__}"
            )

        sanitized: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for index, alert in enumerate(alerts[: self._max_alerts]):
            safe_alert = self._sanitize_alert(
                alert,
                field_name=f"alerts[{index}]",
            )

            alert_id = safe_alert["alert_id"]

            if alert_id in seen_ids:
                raise ValueError(
                    f"Duplicate alert_id: {alert_id!r}"
                )

            sanitized.append(safe_alert)
            seen_ids.add(alert_id)

        self._validate_json_size(
            sanitized,
            field_name="alerts",
        )

        return sanitized

    def _sanitize_alert(
        self,
        alert: dict[str, Any],
        *,
        field_name: str,
    ) -> dict[str, Any]:
        if not isinstance(alert, dict):
            raise TypeError(
                f"{field_name} must be a dictionary, "
                f"got {type(alert).__name__}"
            )

        safe_alert = copy.deepcopy(alert)

        alert_id = self._validate_identifier(
            safe_alert.get("alert_id"),
            field_name=f"{field_name}.alert_id",
        )

        title = self._validate_text(
            safe_alert.get("title"),
            field_name=f"{field_name}.title",
            max_length=MAX_ALERT_TITLE_LENGTH,
        )

        message = self._validate_text(
            safe_alert.get("message"),
            field_name=f"{field_name}.message",
            max_length=MAX_ALERT_MESSAGE_LENGTH,
        )

        severity = safe_alert.get("severity")

        if not isinstance(severity, str):
            raise TypeError(
                f"{field_name}.severity must be a string"
            )

        normalized_severity = severity.lower().strip()

        if normalized_severity not in VALID_ALERT_SEVERITIES:
            raise ValueError(
                f"Invalid {field_name}.severity: {severity!r}"
            )

        acknowledged = safe_alert.get("acknowledged", False)

        if not isinstance(acknowledged, bool):
            raise TypeError(
                f"{field_name}.acknowledged must be a boolean"
            )

        safe_alert["alert_id"] = alert_id
        safe_alert["title"] = title
        safe_alert["message"] = message
        safe_alert["severity"] = normalized_severity
        safe_alert["acknowledged"] = acknowledged

        self._validate_nesting_depth(safe_alert)

        return safe_alert

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

        WatchtowerState._validate_nesting_depth(safe_value)
        WatchtowerState._validate_json_size(
            safe_value,
            field_name=field_name,
        )

        return safe_value

    @staticmethod
    def _extract_list_payload(
        value: Any,
        *,
        collection_key: str,
    ) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return value

        if isinstance(value, dict):
            collection = value.get(collection_key)

            if isinstance(collection, list):
                return collection

        raise TypeError(
            f"{collection_key} payload must be a list or a dictionary "
            f"containing a {collection_key!r} list"
        )

    @staticmethod
    def _unwrap_snapshot(
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(snapshot, dict):
            raise TypeError("snapshot must be a dictionary")

        if "data" in snapshot and "ok" in snapshot:
            payload = snapshot.get("data")

            if not isinstance(payload, dict):
                raise ValueError("snapshot data must be a dictionary")

            return payload

        return snapshot

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
                "ready",
                "online",
                "active",
            }

        return False

    @staticmethod
    def _aggregate_errors(
        *,
        error: str | None,
        section_errors: dict[str, str | None],
    ) -> str | None:
        messages: list[str] = []

        if error:
            messages.append(error)

        for section, message in section_errors.items():
            if message:
                entry = f"{section}: {message}"

                if entry not in messages:
                    messages.append(entry)

        return "; ".join(messages) if messages else None

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
                f"{field_name} exceeds maximum size of "
                f"{MAX_SECTION_BYTES} bytes"
            )

    @staticmethod
    def _validate_nesting_depth(
        value: Any,
        *,
        depth: int = 0,
    ) -> None:
        if depth > MAX_NESTING_DEPTH:
            raise ValueError(
                f"payload exceeds maximum nesting depth of "
                f"{MAX_NESTING_DEPTH}"
            )

        if isinstance(value, dict):
            for key, nested_value in value.items():
                if not isinstance(key, str):
                    raise ValueError(
                        "dictionary keys must be strings"
                    )

                WatchtowerState._validate_nesting_depth(
                    nested_value,
                    depth=depth + 1,
                )

        elif isinstance(value, list):
            for nested_value in value:
                WatchtowerState._validate_nesting_depth(
                    nested_value,
                    depth=depth + 1,
                )

    @staticmethod
    def _validate_identifier(
        value: Any,
        *,
        field_name: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string"
            )

        cleaned = value.strip()

        if not IDENTIFIER_RE.fullmatch(cleaned):
            raise ValueError(
                f"{field_name} must be 1-64 alphanumeric, dash, "
                f"underscore, dot, or colon characters"
            )

        return cleaned

    @staticmethod
    def _validate_text(
        value: Any,
        *,
        field_name: str,
        max_length: int,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string"
            )

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                f"{field_name} must not be empty"
            )

        if len(cleaned) > max_length:
            raise ValueError(
                f"{field_name} must not exceed {max_length} characters"
            )

        return cleaned

    @staticmethod
    def _validate_reason(reason: str) -> str:
        if not isinstance(reason, str):
            raise TypeError("reason must be a string")

        cleaned = reason.strip()

        if not cleaned:
            raise ValueError("reason must not be empty")

        return cleaned

    @staticmethod
    def _validate_loading_source(source: str) -> str:
        if not isinstance(source, str):
            raise TypeError("loading source must be a string")

        cleaned = source.strip()

        if not LOADING_SOURCE_RE.fullmatch(cleaned):
            raise ValueError(
                "loading source must be 1-64 alphanumeric, dash, "
                "underscore, or dot characters"
            )

        return cleaned

    @staticmethod
    def _validate_section_name(section: str) -> str:
        if not isinstance(section, str):
            raise TypeError("section must be a string")

        cleaned = section.lower().strip()

        if cleaned not in SECTION_NAMES:
            raise ValueError(
                f"Invalid Watchtower state section: {section!r}"
            )

        return cleaned
