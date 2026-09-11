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

"""Dashboard client for the event reliability / dead-letter surface.

Read-only status plus ONE control action: an operator-initiated replay of a
single failed event.

This is a client of the runtime, not part of it. It calls the authenticated
API like any other consumer -- it does not import EventReliabilityManager,
DeadLetterStore, or any runtime object, and it holds no state of its own. The
API remains the source of truth.

AUTHORIZATION
    Every route here is operator-authenticated on the server. A dashboard
    service credential is not an operator credential, and this module cannot
    change that: it simply presents whatever token the ApiClient carries, and
    the API decides. Replay in particular is a human decision -- nothing in
    this module retries, schedules, or escalates it.
"""

from __future__ import annotations

import re
from typing import Any

from dashboard.services.api_client import ApiClient, ApiResponse, api_client

#: Canonical routes exposed by the API's reliability router.
ENDPOINTS: dict[str, str] = {
    "status": "/reliability/status",
    "failed_events": "/reliability/failed-events",
    "replay": "/reliability/replay",
}

DEFAULT_LIMIT = 50
MAX_LIMIT = 500

#: Replay statuses the API reports. "replay_in_progress" marks a record
#: claimed for a delivery attempt whose outcome has not yet been confirmed
#: persisted -- see core/reliability.py's ReplayStatus docstring.
REPLAY_STATUSES: frozenset[str] = frozenset(
    {"pending", "replayed_ok", "replay_failed", "replay_in_progress"}
)

#: Event ids are echoed into a URL path, so they are constrained to a boring
#: charset here rather than trusted from arbitrary UI input.
_EVENT_ID_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")

#: Fields a dead-letter record is allowed to surface. The API already
#: sanitizes, but the dashboard re-projects rather than rendering whatever it
#: happens to receive -- a new server field cannot leak into the UI unreviewed.
_DISPLAY_FIELDS: tuple[str, ...] = (
    "event_id",
    "correlation_id",
    "parent_event_id",
    "event_type",
    "schema_version",
    "source",
    "source_identity",
    "failure_stage",
    "failure_classification",
    "failure_reason",
    "attempts",
    "first_failed_at",
    "last_attempt_at",
    "replay_status",
    "replay_attempts",
    # Whether a faithfully replayable body was persisted -- NOT the body
    # itself. The API never returns that; see core/reliability.py's
    # DeadLetterStore.get_replay_payload docstring.
    "replay_available",
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
    session, a missing permission and an unreachable dependency need
    different operator responses. No raw body or stack trace is surfaced.
    """
    if response.get("ok"):
        return ""

    status = response.get("status_code")
    return {
        400: "The request was malformed.",
        401: "Not signed in, or the operator session expired.",
        403: "This operator is not authorized for that action.",
        404: "No such failed event.",
        409: "That event is not in a replayable state.",
        413: "The request was too large.",
        422: "The request was rejected as invalid.",
        429: "Rate limited. Slow down and retry shortly.",
        503: "The reliability subsystem is unavailable on the server.",
    }.get(
        status,
        "The API is unreachable."
        if status is None
        else f"Unexpected API response ({status}).",
    )


def get_reliability_status(client: ApiClient | None = None) -> dict[str, Any]:
    """Counters, dead-letter totals and the active retry policy."""
    return _client(client).get(ENDPOINTS["status"]).to_dict()


def get_failed_events(
    client: ApiClient | None = None,
    *,
    limit: int = DEFAULT_LIMIT,
    replay_status: str | None = None,
) -> dict[str, Any]:
    """Sanitized metadata for dead-lettered events."""
    try:
        bounded = int(limit)
    except (TypeError, ValueError):
        return _error("limit must be an integer")

    if bounded < 1 or bounded > MAX_LIMIT:
        return _error(f"limit must be between 1 and {MAX_LIMIT}")

    path = f"{ENDPOINTS['failed_events']}?limit={bounded}"

    if replay_status is not None:
        normalized = str(replay_status).strip().lower()
        if normalized not in REPLAY_STATUSES:
            return _error(
                "replay_status must be one of "
                f"{sorted(REPLAY_STATUSES)}"
            )
        path = f"{path}&replay_status={normalized}"

    return _client(client).get(path).to_dict()


def request_replay(
    event_id: str,
    client: ApiClient | None = None,
) -> dict[str, Any]:
    """Ask the API to replay ONE failed event. Operator-authenticated.

    One call, one replay attempt. This function never retries and never
    loops: if the replay fails, the event stays dead-lettered and a human
    decides what to do next. Replay re-delivers an event -- it does not
    approve anything or execute any remediation.
    """
    safe_id = str(event_id or "").strip()
    if not _EVENT_ID_RE.fullmatch(safe_id):
        return _error("event_id has an invalid format")

    return _client(client).post(
        f"{ENDPOINTS['replay']}/{safe_id}"
    ).to_dict()


def summarize_failed_events(response: dict[str, Any]) -> dict[str, Any]:
    """Reduce a failed-events response to display-ready rows.

    Re-projects onto an explicit field allowlist and preserves the identity
    an operator needs to correlate a failure with the rest of the system.
    """
    if not response.get("ok"):
        return {
            "available": False,
            "error": describe_failure(response),
            "total": 0,
            "events": [],
            "counts": {},
        }

    data = response.get("data")
    if not isinstance(data, dict):
        return {
            "available": False,
            "error": "Malformed reliability response.",
            "total": 0,
            "events": [],
            "counts": {},
        }

    raw_events = data.get("events")
    events: list[dict[str, Any]] = []

    if isinstance(raw_events, list):
        for record in raw_events:
            if not isinstance(record, dict):
                continue
            row = {field: record.get(field, "") for field in _DISPLAY_FIELDS}
            row["retryable"] = (
                str(record.get("failure_classification", "")).lower()
                == "retryable"
            )
            row["replayed"] = (
                str(record.get("replay_status", "")).lower() == "replayed_ok"
            )
            events.append(row)

    counts = data.get("counts")
    return {
        "available": True,
        "error": "",
        "total": int(data.get("count") or len(events)),
        "events": events,
        "counts": counts if isinstance(counts, dict) else {},
    }


__all__ = [
    "DEFAULT_LIMIT",
    "ENDPOINTS",
    "MAX_LIMIT",
    "REPLAY_STATUSES",
    "describe_failure",
    "get_failed_events",
    "get_reliability_status",
    "request_replay",
    "summarize_failed_events",
]
