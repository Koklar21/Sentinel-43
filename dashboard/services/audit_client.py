"""
Sentinel-43 Dashboard Service
Audit Client

Provides dashboard access to audit-related API endpoints.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from dashboard.services.api_client import ApiClient, ApiResponse


AUDIT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
DEFAULT_LIMIT = 100
MAX_LIMIT = 500


def _error(message: str) -> dict[str, Any]:
    return ApiResponse(
        ok=False,
        status_code=None,
        data=None,
        error=message,
        headers={},
        is_json=True,
    ).to_dict()


def _validate_audit_id(audit_id: Any) -> str | None:
    if not isinstance(audit_id, str):
        return None

    cleaned = audit_id.strip()

    if not cleaned:
        return None

    if not AUDIT_ID_RE.fullmatch(cleaned):
        return None

    return cleaned


def _validate_pagination(*, limit: int, offset: int) -> tuple[int, int]:
    if not isinstance(limit, int):
        raise ValueError("limit must be an integer")

    if not isinstance(offset, int):
        raise ValueError("offset must be an integer")

    if limit <= 0:
        raise ValueError("limit must be greater than 0")

    if limit > MAX_LIMIT:
        raise ValueError(f"limit must not exceed {MAX_LIMIT}")

    if offset < 0:
        raise ValueError("offset must not be negative")

    return limit, offset


def get_audit_records(
    client: ApiClient,
    *,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    try:
        safe_limit, safe_offset = _validate_pagination(
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        return _error(str(exc))

    query = urllib.parse.urlencode({
        "limit": safe_limit,
        "offset": safe_offset,
    })

    return client.get(f"/audit?{query}").to_dict()


def get_audit_status(client: ApiClient) -> dict[str, Any]:
    return client.get("/audit/status").to_dict()


def get_audit_record(
    client: ApiClient,
    audit_id: Any,
) -> dict[str, Any]:
    cleaned = _validate_audit_id(audit_id)

    if cleaned is None:
        return _error(
            "audit_id must be 1-64 alphanumeric, dash, or underscore characters"
        )

    return client.get(f"/audit/{cleaned}").to_dict()


def get_audit_snapshot(
    client: ApiClient,
    *,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    records = get_audit_records(
        client,
        limit=limit,
        offset=offset,
    )
    status = get_audit_status(client)

    errors = [
        result.get("error")
        for result in (records, status)
        if not result.get("ok", False) and result.get("error")
    ]

    ok = records.get("ok", False) and status.get("ok", False)

    return ApiResponse(
        ok=ok,
        status_code=200 if ok else None,
        data={
            "records": records.get("data"),
            "status": status.get("data"),
            "raw": {
                "records": records,
                "status": status,
            },
            "non_atomic": True,
        },
        error="; ".join(errors) if errors else None,
        headers={},
        is_json=True,
    ).to_dict()
def fetch_audit_logs(
    client: ApiClient,
    *,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    return get_audit_records(client, limit=limit, offset=offset)


def normalize_audit_logs(raw: dict[str, Any]) -> list[dict[str, Any]]:
    data = raw.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("records") or []
    return []
