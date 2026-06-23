"""
Sentinel-43 Dashboard Service
Health Client

Calls API health, readiness, status, metrics, and route endpoints.
"""

from __future__ import annotations

import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from dashboard.services.api_client import ApiClient, ApiResponse, api_client


CRITICAL_KEYS = frozenset({"health", "ready"})

SNAPSHOT_ENDPOINTS = {
    "health": "/health",
    "ready": "/ready",
    "status": "/status",
    "metrics": "/metrics",
    "routes": "/system/routes",
    "routes_status": "/system/routes/status",
}

DEFAULT_ROUTE_LIMIT = 100
MAX_ROUTE_LIMIT = 500


def _error(message: str) -> dict[str, Any]:
    return ApiResponse(
        ok=False,
        status_code=None,
        data=None,
        error=message,
        headers={},
        is_json=True,
    ).to_dict()


def _validate_limit_offset(*, limit: int, offset: int) -> tuple[int, int]:
    if not isinstance(limit, int):
        raise ValueError("limit must be an integer")

    if not isinstance(offset, int):
        raise ValueError("offset must be an integer")

    if limit <= 0:
        raise ValueError("limit must be greater than 0")

    if limit > MAX_ROUTE_LIMIT:
        raise ValueError(f"limit must not exceed {MAX_ROUTE_LIMIT}")

    if offset < 0:
        raise ValueError("offset must not be negative")

    return limit, offset


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


def get_api_health(client: ApiClient | None = None) -> dict[str, Any]:
    if client is None:
        client = api_client

    return _get_with_retry(client, "/health")


def get_api_ready(client: ApiClient | None = None) -> dict[str, Any]:
    if client is None:
        client = api_client

    return _get_with_retry(client, "/ready")


def get_api_status(client: ApiClient | None = None) -> dict[str, Any]:
    if client is None:
        client = api_client

    return client.get("/status").to_dict()


def get_api_metrics(
    client: ApiClient | None = None,
    *,
    include_sensitive: bool = False,
) -> dict[str, Any]:
    if client is None:
        client = api_client

    result = client.get("/metrics").to_dict()

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


def get_system_routes(
    client: ApiClient | None = None,
    *,
    limit: int = DEFAULT_ROUTE_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    if client is None:
        client = api_client

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

    return client.get(f"/system/routes?{query}").to_dict()


def get_routes_status(client: ApiClient | None = None) -> dict[str, Any]:
    if client is None:
        client = api_client

    return client.get("/system/routes/status").to_dict()


def get_health_snapshot(
    client: ApiClient | None = None,
    *,
    include_sensitive_metrics: bool = False,
    route_limit: int = DEFAULT_ROUTE_LIMIT,
    route_offset: int = 0,
) -> dict[str, Any]:
    """
    Combined health snapshot for dashboard panels.

    The snapshot is non-atomic. Each section may represent a slightly different
    moment in time because the underlying API endpoints are queried separately.
    Yes, time remains rude.
    """
    if client is None:
        client = api_client

    def call_endpoint(key: str, path: str) -> dict[str, Any]:
        if key == "health":
            return get_api_health(client)

        if key == "ready":
            return get_api_ready(client)

        if key == "status":
            return get_api_status(client)

        if key == "metrics":
            return get_api_metrics(
                client,
                include_sensitive=include_sensitive_metrics,
            )

        if key == "routes":
            return get_system_routes(
                client,
                limit=route_limit,
                offset=route_offset,
            )

        if key == "routes_status":
            return get_routes_status(client)

        return client.get(path).to_dict()

    results: dict[str, dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=len(SNAPSHOT_ENDPOINTS)) as pool:
        futures = {
            pool.submit(call_endpoint, key, path): key
            for key, path in SNAPSHOT_ENDPOINTS.items()
        }

        for future in as_completed(futures):
            key = futures[future]

            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = _error(
                    f"{key} failed: {exc.__class__.__name__}"
                )

    for key in SNAPSHOT_ENDPOINTS:
        results.setdefault(key, _error(f"{key} did not return a result"))

    critical_ok = all(
        results[key].get("ok", False)
        for key in CRITICAL_KEYS
    )

    degraded = any(
        not result.get("ok", False)
        for key, result in results.items()
        if key not in CRITICAL_KEYS
    )

    errors = [
        f"{key}: {result.get('error')}"
        for key, result in results.items()
        if not result.get("ok", False) and result.get("error")
    ]

    return ApiResponse(
        ok=critical_ok,
        status_code=200 if critical_ok else None,
        data={
            "critical_ok": critical_ok,
            "degraded": degraded,
            "non_atomic": True,
            "health": results["health"].get("data"),
            "ready": results["ready"].get("data"),
            "status": results["status"].get("data"),
            "metrics": results["metrics"].get("data"),
            "routes": results["routes"].get("data"),
            "routes_status": results["routes_status"].get("data"),
            "raw": results,
        },
        error="; ".join(errors) if errors else None,
        headers={},
        is_json=True,
    ).to_dict()
