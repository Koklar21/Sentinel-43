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

"""Dashboard client for the operator findings surface.

Read-only view into MonitoringManager's own recent-event state (Fenrir
detections, SpartaCore integrity events/alerts, and anything else routed
through analyze_event()) -- GET /operator/findings on the API. This is a
client of the runtime, not part of it: it calls the authenticated API like
any other consumer and holds no state of its own. It is visibility only --
it never stages, approves, or executes anything.

AUTHORIZATION
    /operator/findings is operator-authenticated on the server. A dashboard
    service credential is not an operator credential, and this module cannot
    change that: it presents whatever token the ApiClient carries, and the
    API decides.
"""

from __future__ import annotations

from typing import Any

from dashboard.services.api_client import ApiClient, ApiResponse, api_client

#: Canonical route exposed by the API's operator-findings router.
ENDPOINTS: dict[str, str] = {
    "findings": "/operator/findings",
}

DEFAULT_LIMIT = 50
MAX_LIMIT = 500

#: Fields a finding is allowed to surface in the dashboard. The API already
#: sanitizes (core.api.main._FINDING_ALLOWED_FIELDS), but the dashboard
#: re-projects rather than rendering whatever it happens to receive -- a new
#: server field cannot leak into the UI unreviewed.
_DISPLAY_FIELDS: tuple[str, ...] = (
    "id",
    "event_id",
    "kind",
    "event_type",
    "source",
    "source_identity",
    "subsystem",
    "correlation_id",
    "parent_event_id",
    "created_at",
    "ingested_at",
    "severity",
    "threat_kind",
    "source_ip",
    "indicators",
    "confidence",
    "integrity_status",
)


def _error(message: str) -> dict[str, Any]:
    return ApiResponse(
        ok=False,
        status_code=None,
        data=None,
        error=message,
        headers={},
        is_json=True,
    ).to_dict()


def _client(client: ApiClient | None) -> ApiClient:
    return client if client is not None else api_client


def describe_failure(response: dict[str, Any]) -> str:
    """Turn an API failure into an operator-meaningful sentence.

    "Server offline" for every failure is actively misleading: an expired
    session and an unreachable monitoring subsystem need different operator
    responses. No raw body or stack trace is surfaced.
    """
    if response.get("ok"):
        return ""

    status = response.get("status_code")
    return {
        400: "The request was malformed.",
        401: "Not signed in, or the operator session expired.",
        403: "This operator is not authorized to view findings.",
        422: "The request filters were rejected as invalid.",
        429: "Rate limited. Slow down and retry shortly.",
        503: "The monitoring subsystem is unavailable on the server.",
    }.get(
        status,
        "The API is unreachable."
        if status is None
        else f"Unexpected API response ({status}).",
    )


def get_findings(
    client: ApiClient | None = None,
    *,
    limit: int = DEFAULT_LIMIT,
    source: str | None = None,
    severity: str | None = None,
    event_type: str | None = None,
    subsystem: str | None = None,
    since: str | None = None,
) -> dict[str, Any]:
    """Bounded, sanitized recent findings from Fenrir, SpartaCore, and
    anything else the embedded MonitoringManager has scored."""
    try:
        bounded = int(limit)
    except (TypeError, ValueError):
        return _error("limit must be an integer")

    if bounded < 1 or bounded > MAX_LIMIT:
        return _error(f"limit must be between 1 and {MAX_LIMIT}")

    params: dict[str, str] = {"limit": str(bounded)}
    if source is not None:
        params["source"] = source
    if severity is not None:
        params["severity"] = severity
    if event_type is not None:
        params["event_type"] = event_type
    if subsystem is not None:
        params["subsystem"] = subsystem
    if since is not None:
        params["since"] = since

    query = "&".join(f"{key}={value}" for key, value in params.items())
    path = f"{ENDPOINTS['findings']}?{query}"

    return _client(client).get(path).to_dict()


def summarize_findings(response: dict[str, Any]) -> dict[str, Any]:
    """Reduce a findings response to display-ready rows.

    Re-projects onto an explicit field allowlist. Fails closed: any
    non-ok/malformed response reports unavailable with zero findings, never
    a partial or best-guess render.
    """
    if not response.get("ok"):
        return {
            "available": False,
            "error": describe_failure(response),
            "total": 0,
            "findings": [],
        }

    data = response.get("data")
    if not isinstance(data, dict):
        return {
            "available": False,
            "error": "Malformed findings response.",
            "total": 0,
            "findings": [],
        }

    raw_findings = data.get("findings")
    findings: list[dict[str, Any]] = []

    if isinstance(raw_findings, list):
        for record in raw_findings:
            if not isinstance(record, dict):
                continue
            findings.append(
                {field: record.get(field, "") for field in _DISPLAY_FIELDS}
            )

    return {
        "available": True,
        "error": "",
        "total": int(data.get("count") or len(findings)),
        "findings": findings,
    }


__all__ = [
    "DEFAULT_LIMIT",
    "ENDPOINTS",
    "MAX_LIMIT",
    "describe_failure",
    "get_findings",
    "summarize_findings",
]
