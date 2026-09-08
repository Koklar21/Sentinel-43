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

"""Sentinel-43 Watchgate API routes.

The router is intentionally thin:
    - request validation is owned by Pydantic models
    - authentication is owned by dependency wiring
    - business behavior is delegated to engine/store interfaces
    - authoritative action state comes from the store
    - route code never fabricates a successful ledger state when the store is
      unavailable or returns malformed data
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Final

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from core.api.deps import (
    EngineProtocol,
    StoreProtocol,
    get_engine,
    get_store,
    require_operator,
)
from core.api.models import (
    ActionDecision,
    ActionListResponse,
    ActionRequest,
    ActionResponse,
    ActionStatus,
    ApiStatus,
    ErrorDetail,
    HealthResponse,
    ThreatAssessmentIn,
    ThreatAssessmentOut,
    utc_now_iso,
)

logger = logging.getLogger("sentinel43.watchgate.api")


S43_API_NAME: Final[str] = "Sentinel-43 Watchgate API"
S43_API_VERSION: Final[str] = "v1"
S43_CORE_PRINCIPLE: Final[str] = (
    "Advisory-first. Human-gated. Audit-backed. "
    "No autonomous enforcement in core."
)

S43_ERR_ASSESSMENT_PIPELINE_FAILURE: Final[str] = (
    "S43_ASSESSMENT_PIPELINE_FAILURE"
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
S43_ERR_ACTION_LEDGER_UNAVAILABLE: Final[str] = (
    "S43_ACTION_LEDGER_UNAVAILABLE"
)
S43_ERR_ACTION_STATUS_INVALID: Final[str] = (
    "S43_ACTION_STATUS_INVALID"
)
S43_ERR_ASSESSMENT_RESULT_INVALID: Final[str] = (
    "S43_ASSESSMENT_RESULT_INVALID"
)

_REQUEST_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_.:-]{1,64}$"
)

router = APIRouter()
v1 = APIRouter(
    prefix="/v1",
    dependencies=[Depends(require_operator)],
)


# =============================================================================
# Dependency adapters
# =============================================================================

def dep_engine(
    engine: EngineProtocol = Depends(get_engine),
) -> EngineProtocol:
    return engine


def dep_store(
    store: StoreProtocol = Depends(get_store),
) -> StoreProtocol:
    return store


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

def _model_to_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return dict(model.model_dump())

    if isinstance(model, dict):
        return dict(model)

    raise TypeError(
        f"Unsupported model payload type: {type(model).__name__}"
    )


def _normalize_decision(value: Any) -> ActionDecision:
    if isinstance(value, ActionDecision):
        return value

    normalized = str(value or "").strip().lower()

    try:
        return ActionDecision(normalized)
    except ValueError as exc:
        raise ValueError(
            f"Unrecognized action decision {value!r}"
        ) from exc


def _as_action_status(raw: Any) -> ActionStatus:
    if isinstance(raw, ActionStatus):
        return raw

    if not isinstance(raw, dict):
        raise ValueError(
            f"Unsupported action status payload type: "
            f"{type(raw).__name__}"
        )

    action_id = str(
        raw.get("action_id")
        or raw.get("id")
        or ""
    ).strip()

    if not action_id:
        raise ValueError(
            "Action status payload is missing action_id"
        )

    decision = _normalize_decision(
        raw.get("decision")
        or raw.get("status")
        or ActionDecision.UNKNOWN.value
    )

    return ActionStatus(
        action_id=action_id,
        decision=decision,
        decided_by=raw.get("decided_by"),
        decided_ts=(
            raw.get("decided_ts")
            or raw.get("ts")
        ),
        reason=raw.get("reason"),
    )


def _safe_score(
    value: Any,
    *,
    field_name: str,
) -> int:
    if isinstance(value, bool):
        raise ValueError(
            f"{field_name} must be numeric"
        )

    try:
        score = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{field_name} must be numeric"
        ) from exc

    if not 0 <= score <= 100:
        raise ValueError(
            f"{field_name} must be between 0 and 100"
        )

    return score


def _as_assessment_out(
    result: Any,
    *,
    request_id: str,
) -> ThreatAssessmentOut:
    if isinstance(result, ThreatAssessmentOut):
        return result.model_copy(
            update={"request_id": request_id}
        )

    if not isinstance(result, dict):
        raise ValueError(
            "Assessment engine returned unsupported payload type"
        )

    assessment_id = str(
        result.get("assessment_id")
        or result.get("id")
        or ""
    ).strip()

    summary = str(
        result.get("summary")
        or result.get("message")
        or ""
    ).strip()

    if not assessment_id:
        raise ValueError(
            "Assessment result missing assessment_id"
        )

    if not summary:
        raise ValueError(
            "Assessment result missing summary"
        )

    tags_raw = result.get("tags") or []

    if not isinstance(tags_raw, list):
        raise ValueError(
            "Assessment result tags must be a list"
        )

    metadata: dict[str, Any] = {}

    for key, value in result.items():
        if key not in {
            "assessment_id",
            "id",
            "severity",
            "confidence",
            "summary",
            "message",
            "tags",
        }:
            metadata[key] = value

    return ThreatAssessmentOut(
        status=ApiStatus.OK,
        request_id=request_id,
        assessment_id=assessment_id,
        severity=_safe_score(
            result.get("severity"),
            field_name="severity",
        ),
        confidence=_safe_score(
            result.get("confidence"),
            field_name="confidence",
        ),
        summary=summary,
        tags=tags_raw,
        metadata=metadata or None,
    )


def _read_authoritative_action_status(
    *,
    store: StoreProtocol,
    action_id: str,
    request_id: str,
) -> ActionStatus:
    try:
        raw = store.get_status(action_id)
    except Exception as exc:
        logger.exception(
            "Sentinel-43 action ledger read failed. "
            "action_id=%s request_id=%s",
            action_id,
            request_id,
        )
        raise _http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            S43_ERR_ACTION_LEDGER_UNAVAILABLE,
            "Authoritative action state is unavailable.",
            request_id=request_id,
        ) from exc

    if raw is None:
        raise _http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            S43_ERR_ACTION_LEDGER_UNAVAILABLE,
            "Authoritative action state is unavailable.",
            request_id=request_id,
        )

    try:
        action = _as_action_status(raw)
    except Exception as exc:
        logger.exception(
            "Sentinel-43 action ledger returned invalid state. "
            "action_id=%s request_id=%s",
            action_id,
            request_id,
        )
        raise _http_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            S43_ERR_ACTION_STATUS_INVALID,
            "Authoritative action state is invalid.",
            request_id=request_id,
        ) from exc

    if action.action_id != action_id:
        raise _http_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            S43_ERR_ACTION_STATUS_INVALID,
            "Authoritative action state does not match requested action.",
            request_id=request_id,
        )

    return action


# =============================================================================
# Health
# =============================================================================

@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["system"],
)
def health(
    request_id: str = Depends(dep_request_id),
) -> HealthResponse:
    return HealthResponse(
        status=ApiStatus.OK,
        request_id=request_id,
        service=S43_API_NAME,
        version=S43_API_VERSION,
        principle=S43_CORE_PRINCIPLE,
    )


# =============================================================================
# Assessment
# =============================================================================

@v1.post(
    "/assess",
    response_model=ThreatAssessmentOut,
    tags=["assessment"],
)
def assess(
    payload: ThreatAssessmentIn,
    request_id: str = Depends(dep_request_id),
    engine: EngineProtocol = Depends(dep_engine),
) -> ThreatAssessmentOut:
    try:
        payload_dict = _model_to_dict(payload)

        result = engine.handle_assessment(
            payload.mode.value,
            payload_dict,
        )

        return _as_assessment_out(
            result,
            request_id=request_id,
        )

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning(
            "Assessment engine returned invalid result. "
            "request_id=%s error=%s",
            request_id,
            type(exc).__name__,
        )
        raise _http_error(
            status.HTTP_502_BAD_GATEWAY,
            S43_ERR_ASSESSMENT_RESULT_INVALID,
            "Assessment engine returned an invalid result.",
            request_id=request_id,
        ) from exc

    except Exception as exc:
        logger.exception(
            "Assessment failed. request_id=%s",
            request_id,
        )
        raise _http_500(
            S43_ERR_ASSESSMENT_PIPELINE_FAILURE,
            request_id=request_id,
        ) from exc


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
def approve_action(
    action_id: str,
    body: ActionRequest,
    request_id: str = Depends(dep_request_id),
    engine: EngineProtocol = Depends(dep_engine),
    store: StoreProtocol = Depends(dep_store),
) -> ActionResponse:
    _validate_action_id_match(
        path_action_id=action_id,
        body_action_id=body.action_id,
        request_id=request_id,
    )

    try:
        ok = bool(
            engine.approve_action(
                action_id,
                body.operator_id,
                reason=body.reason,
            )
        )

        if not ok:
            raise _http_error(
                status.HTTP_409_CONFLICT,
                S43_ERR_APPROVAL_PIPELINE_FAILURE,
                "Approval was not accepted.",
                request_id=request_id,
            )

        action = _read_authoritative_action_status(
            store=store,
            action_id=action_id,
            request_id=request_id,
        )

        if action.decision is not ActionDecision.APPROVED:
            raise _http_error(
                status.HTTP_409_CONFLICT,
                S43_ERR_ACTION_STATUS_INVALID,
                "Approval did not produce an approved ledger state.",
                request_id=request_id,
            )

        return ActionResponse(
            status=ApiStatus.OK,
            request_id=request_id,
            result=True,
            action=action,
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


@v1.post(
    "/actions/{action_id}/veto",
    response_model=ActionResponse,
    tags=["actions"],
)
def veto_action(
    action_id: str,
    body: ActionRequest,
    request_id: str = Depends(dep_request_id),
    engine: EngineProtocol = Depends(dep_engine),
    store: StoreProtocol = Depends(dep_store),
) -> ActionResponse:
    _validate_action_id_match(
        path_action_id=action_id,
        body_action_id=body.action_id,
        request_id=request_id,
    )

    try:
        ok = bool(
            engine.veto_action(
                action_id,
                body.operator_id,
                reason=body.reason,
            )
        )

        if not ok:
            raise _http_error(
                status.HTTP_409_CONFLICT,
                S43_ERR_VETO_PIPELINE_FAILURE,
                "Veto was not accepted.",
                request_id=request_id,
            )

        action = _read_authoritative_action_status(
            store=store,
            action_id=action_id,
            request_id=request_id,
        )

        if action.decision is not ActionDecision.VETOED:
            raise _http_error(
                status.HTTP_409_CONFLICT,
                S43_ERR_ACTION_STATUS_INVALID,
                "Veto did not produce a vetoed ledger state.",
                request_id=request_id,
            )

        return ActionResponse(
            status=ApiStatus.OK,
            request_id=request_id,
            result=True,
            action=action,
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


@v1.get(
    "/actions",
    response_model=ActionListResponse,
    tags=["actions"],
)
def list_actions(
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
    store: StoreProtocol = Depends(dep_store),
) -> ActionListResponse:
    try:
        items_raw = store.list_actions(
            status=(
                decision.value
                if decision is not None
                else None
            ),
            limit=limit,
            cursor=cursor,
        )

        if isinstance(items_raw, dict):
            raw_items = items_raw.get("items") or []
            next_cursor = items_raw.get("next_cursor")
        else:
            raw_items = items_raw or []
            next_cursor = None

        if not isinstance(raw_items, list):
            raise ValueError(
                "Action ledger items must be a list"
            )

        items = [
            _as_action_status(item)
            for item in raw_items
        ]

        return ActionListResponse(
            status=ApiStatus.OK,
            request_id=request_id,
            items=items,
            next_cursor=next_cursor,
        )

    except HTTPException:
        raise

    except ValueError as exc:
        logger.exception(
            "Action ledger returned invalid data. "
            "request_id=%s",
            request_id,
        )
        raise _http_error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            S43_ERR_ACTION_STATUS_INVALID,
            "Action ledger returned invalid data.",
            request_id=request_id,
        ) from exc

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


router.include_router(v1)


__all__ = ["router"]
