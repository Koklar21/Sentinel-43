"""
Sentinel-43 Dashboard Service
Watchtower Client

Provides dashboard access to Watchtower endpoints.
"""

from __future__ import annotations

import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from dashboard.services.api_client import ApiClient, ApiResponse, api_client


LIVENESS_KEYS = frozenset({"health", "status"})
DATA_KEYS = frozenset({"nodes", "alerts", "metrics"})

DEFAULT_LIMIT = 100
MAX_LIMIT = 500

VALID_NODE_STATUSES = frozenset({
    "online",
    "offline",
    "degraded",
    "unknown",
    "error",
})

VALID_ALERT_SEVERITIES = frozenset({
    "critical",
    "high",
    "warning",
    "info",
})


def _error(message: str) -> dict[str, Any]:
    return ApiResponse(
        ok=False,
        status_code=None,
        data=None,
        error=message,
        headers={},
        is_json=True,
    ).to_dict()


def _validate_limit(limit: int) -> int:
    if not isinstance(limit, int):
        raise ValueError("limit must be an integer")

    if limit <= 0:
        raise ValueError("limit must be greater than 0")

    if limit > MAX_LIMIT:
        raise ValueError(f"limit must not exceed {MAX_LIMIT}")

    return limit


def _validate_optional_enum(
    value: str | None,
    *,
    allowed: frozenset[str],
    field_name: str,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    cleaned = value.lower().strip()

    if not cleaned:
        return None

    if cleaned not in allowed:
        raise ValueError(f"Invalid {field_name}: {value!r}")

    return cleaned


def _get_with_retry(
    client: ApiClient,
    path: str,
    *,
    retries: int = 1,
    backoff_seconds: float = 0.15,
) -> dict[str, Any]:
    last_result: dict[str, Any] | None = None

    for attempt in range(retries + 1):
        result = client.get(path).to_dict()
        last_result = result

        if result.get("ok", False):
            return result

        if result.get("status_code") is not None:
            return result

        if attempt < retries:
            time.sleep(backoff_seconds * (attempt + 1))

    return last_result or _error("request failed")


def get_watchtower_health(client: ApiClient | None = None) -> dict[str, Any]:
    if client is None:
        client = api_client

    return _get_with_retry(client, "/watchtower/health")


def get_watchtower_status(client: ApiClient | None = None) -> dict[str, Any]:
    if client is None:
        client = api_client

    return _get_with_retry(client, "/watchtower/status")


def get_watchtower_nodes(
    client: ApiClient | None = None,
    *,
    limit: int = DEFAULT_LIMIT,
    status: str | None = None,
) -> dict[str, Any]:
    if client is None:
        client = api_client

    try:
        safe_limit = _validate_limit(limit)
        safe_status = _validate_optional_enum(
            status,
            allowed=VALID_NODE_STATUSES,
            field_name="status",
        )
    except ValueError as exc:
        return _error(str(exc))

    params: dict[str, Any] = {"limit": safe_limit}

    if safe_status:
        params["status"] = safe_status

    query = urllib.parse.urlencode(params)

    return client.get(f"/watchtower/nodes?{query}").to_dict()


def get_watchtower_alerts(
    client: ApiClient | None = None,
    *,
    limit: int = DEFAULT_LIMIT,
    severity: str | None = None,
    since: str | None = None,
) -> dict[str, Any]:
    if client is None:
        client = api_client

    try:
        safe_limit = _validate_limit(limit)
        safe_severity = _validate_optional_enum(
            severity,
            allowed=VALID_ALERT_SEVERITIES,
            field_name="severity",
        )
    except ValueError as exc:
        return _error(str(exc))

    params: dict[str, Any] = {"limit": safe_limit}

    if safe_severity:
        params["severity"] = safe_severity

    if since:
        if not isinstance(since, str) or not since.strip():
            return _error("since must be a non-empty string")
        params["since"] = since.strip()

    query = urllib.parse.urlencode(params)

    return client.get(f"/watchtower/alerts?{query}").to_dict()


def get_watchtower_metrics(
    client: ApiClient | None = None,
    *,
    include_sensitive: bool = False,
) -> dict[str, Any]:
    if client is None:
        client = api_client

    result = client.get("/watchtower/metrics").to_dict()

    if include_sensitive or not result.get("ok", False):
        return result

    data = result.get("data")

    if isinstance(data, dict):
        result["data"] = {
            key: value
            for key, value in data.items()
            if key not in {
                "env",
                "environment",
                "secrets",
                "tokens",
                "internal_ips",
                "process",
                "threads",
                "tracebacks",
            }
        }

    return result


def get_watchtower_snapshot(
    client: ApiClient | None = None,
    *,
    node_limit: int = DEFAULT_LIMIT,
    node_status: str | None = None,
    alert_limit: int = DEFAULT_LIMIT,
    alert_severity: str | None = None,
    alert_since: str | None = None,
    include_sensitive_metrics: bool = False,
) -> dict[str, Any]:
    if client is None:
        client = api_client

    calls = {
        "health": lambda: get_watchtower_health(client),
        "status": lambda: get_watchtower_status(client),
        "nodes": lambda: get_watchtower_nodes(
            client,
            limit=node_limit,
            status=node_status,
        ),
        "alerts": lambda: get_watchtower_alerts(
            client,
            limit=alert_limit,
            severity=alert_severity,
            since=alert_since,
        ),
        "metrics": lambda: get_watchtower_metrics(
            client,
            include_sensitive=include_sensitive_metrics,
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

    liveness_ok = all(
        results[key].get("ok", False)
        for key in LIVENESS_KEYS
    )

    data_complete = all(
        results[key].get("ok", False)
        for key in DATA_KEYS
    )

    degraded = not data_complete

    errors = [
        f"{key}: {result.get('error')}"
        for key, result in results.items()
        if not result.get("ok", False) and result.get("error")
    ]

    return ApiResponse(
        ok=liveness_ok,
        status_code=200 if liveness_ok else None,
        data={
            "liveness_ok": liveness_ok,
            "data_complete": data_complete,
            "degraded": degraded,
            "non_atomic": True,
            "health": results["health"].get("data"),
            "status": results["status"].get("data"),
            "nodes": results["nodes"].get("data"),
            "alerts": results["alerts"].get("data"),
            "metrics": results["metrics"].get("data"),
            "raw": results,
        },
        error="; ".join(errors) if errors else None,
        headers={},
        is_json=True,
    ).to_dict()


# ---------------------------------------------------------------------------
# Factory / alias functions expected by dashboard/services/__init__.py
# ---------------------------------------------------------------------------

def fetch_watchtower_status(client: ApiClient | None = None) -> dict[str, Any]:
    return get_watchtower_status(client)


def get_watchtower_dashboard_status(client: ApiClient | None = None) -> dict[str, Any]:
    return get_watchtower_snapshot(client)


def normalize_watchtower_status(raw: dict[str, Any]) -> dict[str, Any]:
    data = raw.get("data")

    if isinstance(data, dict):
        return data

    return {}
