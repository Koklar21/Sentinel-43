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
    # The canonical subsystem lifecycle surface. "/status" is the coarse
    # anonymous one and reports only "online" -- it cannot distinguish a
    # disabled subsystem from a failed one.
    "system_status": "/system/status",
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


# ---------------------------------------------------------------------------
# Canonical subsystem lifecycle
#
# The runtime reports each subsystem in one of eight states. Collapsing those
# into online/offline destroys the distinction an operator actually needs:
# "turned off on purpose" is not "broken", and "enabled but never configured"
# is not "it crashed".
# ---------------------------------------------------------------------------

#: Mirrors core.lifecycle.SubsystemState.
SUBSYSTEM_STATES: frozenset[str] = frozenset({
    "DISABLED", "STARTING", "ACTIVE", "DEGRADED",
    "UNAVAILABLE", "FAILED", "STOPPING", "STOPPED",
})

#: States that are not faults: behaving exactly as configured.
NON_FAULT_STATES: frozenset[str] = frozenset({"DISABLED", "ACTIVE", "STOPPED"})


def get_system_status(client: ApiClient | None = None) -> dict[str, Any]:
    """Authoritative subsystem lifecycle snapshot (operator-authenticated)."""
    return _get_with_retry(client, SNAPSHOT_ENDPOINTS["system_status"])


def summarize_subsystems(system_status: dict[str, Any]) -> dict[str, Any]:
    """Reduce a /system/status body to a display-ready subsystem summary.

    Preserves each subsystem's real state and never infers health from an
    object merely existing. An unrecognised state is reported as-is and
    treated as a fault rather than being silently mapped to healthy.
    """
    data = system_status.get("data") if isinstance(system_status, dict) else None
    if not isinstance(data, dict):
        data = system_status if isinstance(system_status, dict) else {}

    subsystems = data.get("subsystems")
    if not isinstance(subsystems, dict):
        return {
            "available": False,
            "subsystems": {},
            "degraded": [],
            "failed": [],
            "disabled": [],
        }

    summary: dict[str, dict[str, Any]] = {}
    degraded: list[str] = []
    failed: list[str] = []
    disabled: list[str] = []

    for name, record in sorted(subsystems.items()):
        if not isinstance(record, dict):
            continue

        state = str(record.get("state") or "").strip().upper()
        known = state in SUBSYSTEM_STATES
        summary[name] = {
            "state": state or "UNKNOWN",
            "known_state": known,
            "required": bool(record.get("required")),
            "configured": bool(record.get("configured")),
            "reason": str(record.get("reason") or ""),
            "detail": str(record.get("detail") or ""),
            "missing": list(record.get("missing") or []),
            # An unrecognised state is NOT evidence of health.
            "faulted": (not known) or state not in NON_FAULT_STATES,
        }

        if state == "DISABLED":
            disabled.append(name)
        elif state in ("FAILED", "UNAVAILABLE"):
            failed.append(name)
        elif summary[name]["faulted"]:
            degraded.append(name)

    return {
        "available": True,
        "subsystems": summary,
        "degraded": degraded,
        "failed": failed,
        "disabled": disabled,
    }


def summarize_authority(system_status: dict[str, Any]) -> dict[str, Any]:
    """Normalize the read-only Sentinel-43 authority provenance snapshot."""
    data = system_status.get("data") if isinstance(system_status, dict) else None
    if not isinstance(data, dict):
        data = system_status if isinstance(system_status, dict) else {}

    raw = data.get("sentinel43_authority")
    if not isinstance(raw, dict):
        return {
            "available": False,
            "authority": "Sentinel43RuntimeAuthority",
            "mode": "",
            "owner_engine": {},
            "owner_components": {},
            "component_count": 0,
            "recommendation_store_attached": False,
            "runtime_reporting_available": False,
            "external_execution_supported": False,
        }

    components = raw.get("owner_components")
    if not isinstance(components, dict):
        components = {}

    engine = raw.get("owner_engine")
    if not isinstance(engine, dict):
        engine = {}

    unavailable = str(raw.get("state") or "").strip().lower() == "unavailable"

    return {
        "available": not unavailable,
        "authority": str(raw.get("authority") or "Sentinel43RuntimeAuthority"),
        "mode": str(raw.get("mode") or "").strip().upper(),
        "owner_engine": dict(engine),
        "owner_components": dict(components),
        "component_count": len(components),
        "recommendation_store_attached": bool(raw.get("recommendation_store_attached")),
        "runtime_reporting_available": bool(raw.get("runtime_reporting_available")),
        "external_execution_supported": raw.get("external_execution_supported") is True,
    }

def classify_runtime(
    health: dict[str, Any],
    ready: dict[str, Any],
) -> dict[str, Any]:
    """Distinguish HEALTH from READINESS from DEGRADED.

    They answer different questions and must not be merged:
      health    -- is the process alive?
      readiness -- can it actually do its job right now?
      degraded  -- it is serving, but something optional is not well.
    """
    alive = bool(health.get("ok"))
    ready_ok = bool(ready.get("ok"))

    body = ready.get("data") if isinstance(ready.get("data"), dict) else {}
    degraded = list(body.get("degraded") or [])
    blocking = list(body.get("blocking") or [])

    if not alive:
        state = "UNAVAILABLE"
    elif not ready_ok:
        state = "NOT_READY"
    elif degraded:
        state = "DEGRADED"
    else:
        state = "READY"

    return {
        "state": state,
        "alive": alive,
        "ready": ready_ok,
        "degraded": degraded,
        "blocking": blocking,
    }
