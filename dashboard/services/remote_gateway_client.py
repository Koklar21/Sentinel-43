"""
Sentinel-43 Dashboard Service
Remote Gateway Client

Calls the authorized Remote Gateway API endpoints.
"""

from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from dashboard.components.remote_event_form import (
    RemoteEventForm,
    RemoteEventFormData,
)
from dashboard.services.api_client import ApiClient, ApiResponse


CORRELATION_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")

DEFAULT_TARGET_LIMIT = 100
MAX_TARGET_LIMIT = 500


def _error(message: str) -> dict[str, Any]:
    return ApiResponse(
        ok=False,
        status_code=None,
        data=None,
        error=message,
        headers={},
        is_json=True,
    ).to_dict()


def _validate_correlation_id(correlation_id: Any) -> str | None:
    if not isinstance(correlation_id, str):
        return None

    cleaned = correlation_id.strip()

    if not CORRELATION_ID_RE.fullmatch(cleaned):
        return None

    return cleaned


def _validate_limit_offset(*, limit: int, offset: int) -> tuple[int, int]:
    if not isinstance(limit, int):
        raise ValueError("limit must be an integer")

    if not isinstance(offset, int):
        raise ValueError("offset must be an integer")

    if limit <= 0:
        raise ValueError("limit must be greater than 0")

    if limit > MAX_TARGET_LIMIT:
        raise ValueError(f"limit must not exceed {MAX_TARGET_LIMIT}")

    if offset < 0:
        raise ValueError("offset must not be negative")

    return limit, offset


def get_remote_gateway_health(client: ApiClient) -> dict[str, Any]:
    return client.get("/remote/health").to_dict()


def get_remote_targets(
    client: ApiClient,
    *,
    limit: int = DEFAULT_TARGET_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    try:
        safe_limit, safe_offset = _validate_limit_offset(
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        return _error(str(exc))

    query = urllib.parse.urlencode({
        "limit": safe_limit,
        "offset": safe_offset,
    })

    return client.get(f"/remote/targets?{query}").to_dict()


def activate_remote_event(
    client: ApiClient,
    *,
    operator_id: str,
    operator_role: str,
    target_id: str,
    event_type: str,
    reason: str,
    correlation_id: str,
    dry_run: bool,
    payload: dict[str, Any] | None = None,
    form: RemoteEventForm | None = None,
) -> dict[str, Any]:
    validator = form or RemoteEventForm()

    form_data = RemoteEventFormData(
        operator_id=operator_id,
        operator_role=operator_role,
        target_id=target_id,
        event_type=event_type,
        reason=reason,
        correlation_id=correlation_id,
        dry_run=dry_run,
        payload=payload or {},
    )

    validated = validator.to_payload(form_data)

    if not validated.get("ok", False):
        errors = validated.get("errors") or ["remote event validation failed"]
        return _error("; ".join(str(error) for error in errors))

    return client.post(
        "/remote/events/activate",
        payload=validated["payload"],
    ).to_dict()


def get_remote_audit_records(
    client: ApiClient,
    correlation_id: Any,
) -> dict[str, Any]:
    cleaned = _validate_correlation_id(correlation_id)

    if cleaned is None:
        return _error(
            "correlation_id must be 8-64 alphanumeric, dash, or underscore characters"
        )

    return client.get(f"/remote/audit/{cleaned}").to_dict()


def get_remote_event_status(
    client: ApiClient,
    correlation_id: Any,
) -> dict[str, Any]:
    cleaned = _validate_correlation_id(correlation_id)

    if cleaned is None:
        return _error(
            "correlation_id must be 8-64 alphanumeric, dash, or underscore characters"
        )

    return client.get(f"/remote/events/{cleaned}/status").to_dict()


def get_remote_gateway_snapshot(
    client: ApiClient,
    *,
    target_limit: int = DEFAULT_TARGET_LIMIT,
    target_offset: int = 0,
) -> dict[str, Any]:
    calls = {
        "health": lambda: get_remote_gateway_health(client),
        "targets": lambda: get_remote_targets(
            client,
            limit=target_limit,
            offset=target_offset,
        ),
    }

    results: dict[str, dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        futures = {
            pool.submit(call): key
            for key, call in calls.items()
        }

        for future in as_completed(futures):
            key = futures[future]

            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = _error(
                    f"{key} failed: {exc.__class__.__name__}"
                )

    for key in calls:
        results.setdefault(key, _error(f"{key} did not return a result"))

    health_ok = results["health"].get("ok", False)
    degraded = not results["targets"].get("ok", False)

    errors = [
        f"{key}: {result.get('error')}"
        for key, result in results.items()
        if not result.get("ok", False) and result.get("error")
    ]

    return ApiResponse(
        ok=health_ok,
        status_code=200 if health_ok else None,
        data={
            "health_ok": health_ok,
            "degraded": degraded,
            "non_atomic": True,
            "health": results["health"].get("data"),
            "targets": results["targets"].get("data"),
            "raw": results,
        },
        error="; ".join(errors) if errors else None,
        headers={},
        is_json=True,
    ).to_dict()
