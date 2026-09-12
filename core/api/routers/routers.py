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

"""Sentinel-43 "/v1" Watchgate compatibility routes.

DISPOSITION (post-merge baseline remediation, Section D): this router used
to delegate to a generic Engine/Store dependency-injection abstraction
(core.api.deps.get_engine / get_store) that was never wired to a real
backend anywhere in the deployed stack -- SENTINEL_ENGINE_FACTORY and
SENTINEL_STORE_FACTORY are declared nowhere in docker-compose.yml or
.env.example, and no second implementation of EngineProtocol/StoreProtocol
exists anywhere in the tree besides the dev-only in-memory ones, which
refuse to run outside S43_ENABLE_DEV_ENGINE/S43_ENABLE_DEV_STORE=true. Live
baseline verification confirmed every route in this router 500s
unconditionally in a standard deployment.

Rather than inventing a new production Store/Engine (explicitly out of
scope -- see S43_BASELINE_VERIFICATION_REPORT.md Section I, Defect 4), each
route below is honestly dispositioned against the modern, working,
canonical backend that superseded it:

    /v1/actions               REPLACE -> wired directly to the same
                               in-memory action ledger + _list_actions()
                               core.api.main's own GET /actions already uses
    /v1/actions/{id}/approve  REPLACE -> wired to
                               _resolve_governance_and_commit_action(), the
                               same human-gated commit path
                               POST /actions/{id}/approve uses
    /v1/actions/{id}/veto     REPLACE -> same, approved=False
    /v1/assess                DEPRECATE -> explicit 501 Not Implemented;
                               no modern equivalent exists (assessment now
                               happens automatically through the canonical
                               event pipeline, not via a posted payload),
                               and no real caller depends on this route
                               succeeding

No route here fabricates a successful ledger state, autonomously executes
anything, or bypasses operator/governance gating: every mutation still goes
through the same human-gated core.api.main commit path the modern
non-legacy routes use, with the same audit trail.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Final

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from core.api.deps import require_operator
from core.api.models import (
    ActionDecision,
    ActionListResponse,
    ActionRequest,
    ActionResponse,
    ActionStatus,
    ApiStatus,
    ThreatAssessmentIn,
    utc_now_iso,
)

logger = logging.getLogger("sentinel43.watchgate.api")


S43_API_NAME: Final[str] = "Sentinel-43 Watchgate API"
S43_API_VERSION: Final[str] = "v1"
S43_CORE_PRINCIPLE: Final[str] = (
    "Advisory-first. Human-gated. Audit-backed. "
    "No autonomous enforcement in core."
)

S43_ERR_APPROVAL_PIPELINE_FAILURE: Final[str] = (
    "S43_APPROVAL_PIPELINE_FAILURE"
)
S43_ERR_VETO_PIPELINE_FAILURE: Final[str] = (
    "S43_VETO_PIPELINE_FAILURE"
)
S43_ERR_ACTION_LEDGER_QUERY_FAILURE: Final[str] = (
    "S43_ACTION_LEDGER_QUERY_FAILURE"
)
S43_ERR_ACTION_ID_MISMATCH: Final[str] = (
    "S43_ACTION_ID_MISMATCH"
)
S43_ERR_V1_ASSESS_DEPRECATED: Final[str] = "S43_V1_ASSESS_DEPRECATED"

_REQUEST_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_.:-]{1,64}$"
)

router = APIRouter()
v1 = APIRouter(
    prefix="/v1",
    dependencies=[Depends(require_operator)],
)


def dep_request_id(
    x_request_id: str | None = Header(
        default=None,
        alias="X-Request-ID",
    ),
) -> str:
    if x_request_id:
        candidate = x_request_id.strip()

        if _REQUEST_ID_RE.fullmatch(candidate):
            return candidate

        logger.warning(
            "Rejected unsafe X-Request-ID header"
        )

    return str(uuid.uuid4())


# =============================================================================
# Error helpers
# =============================================================================

def _http_error(
    status_code: int,
    code: str,
    message: str,
    *,
    request_id: str | None = None,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "status": ApiStatus.ERROR.value,
            "request_id": request_id,
            "ts": utc_now_iso(),
            "service": S43_API_NAME,
            "version": S43_API_VERSION,
            "error": {
                "code": code,
                "message": message,
            },
        },
    )


def _http_500(
    code: str,
    *,
    request_id: str | None = None,
) -> HTTPException:
    return _http_error(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        code,
        "Sentinel-43 Watchgate pipeline failure.",
        request_id=request_id,
    )


# =============================================================================
# Normalization helpers
# =============================================================================
#
# core.api.main's canonical action dicts use their own status vocabulary
# (STAGED/PENDING/APPROVED/VETOED, uppercase) rather than v1's ActionDecision
# enum (approved/vetoed/pending/unknown, lowercase) -- STAGED in particular
# has no literal match. This maps the real, current ledger onto the v1
# response contract rather than pretending the two vocabularies are the
# same thing.

_MODERN_STATUS_TO_DECISION: Final[dict[str, ActionDecision]] = {
    "staged": ActionDecision.PENDING,
    "pending": ActionDecision.PENDING,
    "approved": ActionDecision.APPROVED,
    "vetoed": ActionDecision.VETOED,
}


def _blank_to_none(value: Any) -> Any:
    """A not-yet-decided action carries "" for operator/reason/timestamp,
    not None (see core.api.main._create_synthetic_action /
    _commit_action_status). ActionStatus's fields reject an empty-but-set
    string, so "" must become None here rather than passing it through."""
    if isinstance(value, str) and not value.strip():
        return None
    return value


def _modern_action_to_status(action: dict[str, Any]) -> ActionStatus:
    decision = _MODERN_STATUS_TO_DECISION.get(
        str(action.get("status") or "").strip().lower(),
        ActionDecision.UNKNOWN,
    )
    return ActionStatus(
        action_id=str(action.get("id") or ""),
        decision=decision,
        decided_by=_blank_to_none(action.get("operator")),
        decided_ts=_blank_to_none(action.get("decision_at")),
        reason=_blank_to_none(action.get("decision_reason")),
    )


# =============================================================================
# Health
# =============================================================================
#
# The canonical GET /health lives in core/api/main.py. This router must not
# register its own — main.py fails at import time on a duplicate /health.


# =============================================================================
# Assessment -- DEPRECATED (see module docstring, disposition D)
# =============================================================================

@v1.post(
    "/assess",
    tags=["assessment"],
)
def assess(
    payload: ThreatAssessmentIn,
    request_id: str = Depends(dep_request_id),
) -> None:
    """Deprecated: no supported backend, and none will be built here.

    Threat assessment happens automatically through the canonical event
    pipeline (Fenrir/SpartaCore -> MonitoringManager -> GET
    /operator/findings); there was never a real backend behind "POST an
    arbitrary payload for assessment" in the deployed stack, and inventing
    one now would be a new production Store/Engine built solely to silence
    this route -- exactly what this disposition pass was told not to do.
    Payload shape is still validated (ThreatAssessmentIn) so a malformed
    caller gets 422 before this deprecation notice, unchanged from before.
    """
    raise _http_error(
        status.HTTP_501_NOT_IMPLEMENTED,
        S43_ERR_V1_ASSESS_DEPRECATED,
        "This legacy Watchgate assessment endpoint is deprecated and has "
        "no supported backend. There is no direct replacement for posting "
        "an arbitrary assessment payload -- assessment now happens "
        "automatically through the canonical event pipeline.",
        request_id=request_id,
    )


# =============================================================================
# Actions
# =============================================================================

def _validate_action_id_match(
    *,
    path_action_id: str,
    body_action_id: str | None,
    request_id: str,
) -> None:
    if (
        body_action_id is not None
        and body_action_id != path_action_id
    ):
        raise _http_error(
            status.HTTP_400_BAD_REQUEST,
            S43_ERR_ACTION_ID_MISMATCH,
            "Body action_id does not match path.",
            request_id=request_id,
        )


@v1.post(
    "/actions/{action_id}/approve",
    response_model=ActionResponse,
    tags=["actions"],
)
async def approve_action(
    action_id: str,
    body: ActionRequest,
    request_id: str = Depends(dep_request_id),
) -> ActionResponse:
    """REPLACE disposition: wired to the same human-gated commit path
    POST /actions/{action_id}/approve uses (core.api.main
    _resolve_governance_and_commit_action), not the dead Engine/Store
    abstraction. v1's ActionRequest has no decision_id field; passing None
    falls back to the decision_id already recorded on the staged action's
    own payload -- exactly what the modern route does when its caller omits
    one too.
    """
    _validate_action_id_match(
        path_action_id=action_id,
        body_action_id=body.action_id,
        request_id=request_id,
    )

    from core.api import main as _core_main

    try:
        action = await _core_main._resolve_governance_and_commit_action(
            action_id=action_id,
            decision_id=None,
            approved=True,
            allowed_statuses={"STAGED"},
            new_status="APPROVED",
            reason=body.reason,
            operator=body.operator_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "Approval failed. action_id=%s request_id=%s",
            action_id,
            request_id,
        )
        raise _http_500(
            S43_ERR_APPROVAL_PIPELINE_FAILURE,
            request_id=request_id,
        ) from exc

    return ActionResponse(
        status=ApiStatus.OK,
        request_id=request_id,
        result=True,
        action=_modern_action_to_status(action),
    )


@v1.post(
    "/actions/{action_id}/veto",
    response_model=ActionResponse,
    tags=["actions"],
)
async def veto_action(
    action_id: str,
    body: ActionRequest,
    request_id: str = Depends(dep_request_id),
) -> ActionResponse:
    """REPLACE disposition: same as approve_action, approved=False."""
    _validate_action_id_match(
        path_action_id=action_id,
        body_action_id=body.action_id,
        request_id=request_id,
    )

    from core.api import main as _core_main

    try:
        action = await _core_main._resolve_governance_and_commit_action(
            action_id=action_id,
            decision_id=None,
            approved=False,
            allowed_statuses={"PENDING", "STAGED"},
            new_status="VETOED",
            reason=body.reason,
            operator=body.operator_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "Veto failed. action_id=%s request_id=%s",
            action_id,
            request_id,
        )
        raise _http_500(
            S43_ERR_VETO_PIPELINE_FAILURE,
            request_id=request_id,
        ) from exc

    return ActionResponse(
        status=ApiStatus.OK,
        request_id=request_id,
        result=True,
        action=_modern_action_to_status(action),
    )


@v1.get(
    "/actions",
    response_model=ActionListResponse,
    tags=["actions"],
)
async def list_actions(
    decision: ActionDecision | None = Query(
        default=None,
        alias="status",
        description="Filter by Sentinel-43 decision/status",
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
    ),
    cursor: str | None = Query(
        default=None,
        max_length=512,
    ),
    request_id: str = Depends(dep_request_id),
) -> ActionListResponse:
    """REPLACE disposition: wired to the same in-memory action ledger
    GET /actions already reads via core.api.main._list_actions(), not the
    dead Store abstraction. The ledger has no cursor-based pagination (a
    flat, bounded, most-recent-first list); cursor is accepted for contract
    compatibility and echoed back as None, unchanged from how this route
    already behaved when the old Store returned a bare list.
    """
    from core.api import main as _core_main

    try:
        raw_actions = await _core_main._list_actions(limit)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "Action ledger query failed. request_id=%s",
            request_id,
        )
        raise _http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            S43_ERR_ACTION_LEDGER_QUERY_FAILURE,
            "Action ledger is unavailable.",
            request_id=request_id,
        ) from exc

    items = [_modern_action_to_status(action) for action in raw_actions]
    if decision is not None:
        items = [item for item in items if item.decision == decision]

    return ActionListResponse(
        status=ApiStatus.OK,
        request_id=request_id,
        items=items,
        next_cursor=None,
    )


router.include_router(v1)


__all__ = ["router"]
