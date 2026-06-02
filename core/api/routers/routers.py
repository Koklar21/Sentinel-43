# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 Watchgate API routes."""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from core.api.deps import get_engine, get_store
from core.api.models import (
    ActionDecision,
    ActionListResponse,
    ActionRequest,
    ActionResponse,
    ActionStatus,
    ApiStatus,
    HealthResponse,
    ThreatAssessmentIn,
    ThreatAssessmentOut,
    utc_now_iso,
)

S43_API_NAME = "Sentinel-43 Watchgate API"
S43_API_VERSION = "v1"
S43_CORE_PRINCIPLE = (
    "Advisory-first. Human-gated. Audit-backed. "
    "No autonomous enforcement in core."
)

S43_ERR_ASSESSMENT_PIPELINE_FAILURE = "S43_ASSESSMENT_PIPELINE_FAILURE"
S43_ERR_APPROVAL_PIPELINE_FAILURE = "S43_APPROVAL_PIPELINE_FAILURE"
S43_ERR_VETO_PIPELINE_FAILURE = "S43_VETO_PIPELINE_FAILURE"
S43_ERR_ACTION_LEDGER_QUERY_FAILURE = "S43_ACTION_LEDGER_QUERY_FAILURE"
S43_ERR_ACTION_ID_MISMATCH = "S43_ACTION_ID_MISMATCH"
S43_ERR_VETO_REASON_REQUIRED = "S43_VETO_REASON_REQUIRED"
S43_ERR_ACTION_LEDGER_UNAVAILABLE = "S43_ACTION_LEDGER_UNAVAILABLE"

logger = logging.getLogger("sentinel43.watchgate.api")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

router = APIRouter()
v1 = APIRouter(prefix="/v1")


def dep_engine(engine: Any = Depends(get_engine)) -> Any:
    return engine


def dep_store(store: Any = Depends(get_store)) -> Any:
    return store


def dep_request_id(
    x_request_id: str | None = Header(default=None, alias="X-Request-ID"),
) -> str:
    if x_request_id:
        candidate = str(x_request_id).strip()
        if _REQUEST_ID_RE.fullmatch(candidate):
            return candidate
        logger.warning("Rejected unsafe X-Request-ID header.")

    return str(uuid.uuid4())


def _api_status_value(status: Any) -> Any:
    return status.value if hasattr(status, "value") else status


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
            "status": _api_status_value(ApiStatus.error),
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


def _http_500(code: str, *, request_id: str | None = None) -> HTTPException:
    return _http_error(
        500,
        code,
        "Sentinel-43 Watchgate pipeline failure.",
        request_id=request_id,
    )


def _safe_int(value: Any, default: int = 0, *, field_name: str = "value") -> int:
    if value is None:
        return default

    if isinstance(value, bool):
        logger.warning("Invalid bool for numeric field %s=%r; using %d", field_name, value, default)
        return default

    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning("Invalid integer for %s=%r; using %d", field_name, value, default)
        return default


def _model_to_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return dict(model.model_dump())
    if hasattr(model, "dict"):
        return dict(model.dict())
    if isinstance(model, dict):
        return dict(model)
    return dict(vars(model))


def _with_request_id(model: Any, request_id: str | None) -> Any:
    if not request_id:
        return model

    if hasattr(model, "model_copy"):
        return model.model_copy(update={"request_id": request_id})

    if hasattr(model, "copy"):
        return model.copy(update={"request_id": request_id})

    logger.warning(
        "Could not attach request_id to unsupported model type: %s",
        type(model).__name__,
    )
    return model


def _as_action_status(raw: Any) -> ActionStatus:
    if isinstance(raw, ActionStatus):
        return raw

    if isinstance(raw, dict):
        decision = raw.get("decision") or raw.get("status") or "unknown"

        try:
            decision_enum = ActionDecision(decision)
        except Exception:
            logger.warning("Unrecognized Sentinel-43 action decision: %r", decision)
            decision_enum = ActionDecision.unknown

        return ActionStatus(
            action_id=str(raw.get("action_id") or raw.get("id") or ""),
            decision=decision_enum,
            decided_by=raw.get("decided_by"),
            decided_ts=raw.get("decided_ts") or raw.get("ts"),
            reason=raw.get("reason"),
        )

    logger.warning("Unexpected action status payload type: %s", type(raw).__name__)
    return ActionStatus(action_id=str(raw), decision=ActionDecision.unknown)


def _as_assessment_out(
    result: Any,
    *,
    request_id: str | None = None,
) -> ThreatAssessmentOut:
    if isinstance(result, ThreatAssessmentOut):
        return _with_request_id(result, request_id)

    if isinstance(result, dict):
        return ThreatAssessmentOut(
            status=ApiStatus.ok,
            request_id=request_id,
            assessment_id=str(result.get("assessment_id") or result.get("id") or ""),
            severity=_safe_int(result.get("severity", 0), field_name="severity"),
            confidence=_safe_int(result.get("confidence", 0), field_name="confidence"),
            summary=str(result.get("summary") or result.get("message") or ""),
            tags=list(result.get("tags") or []),
            raw=result,
        )

    return ThreatAssessmentOut(
        status=ApiStatus.ok,
        request_id=request_id,
        assessment_id="",
        severity=0,
        confidence=0,
        summary=str(result),
        tags=[],
        raw=None,
    )


def _store_status_or_default(
    *,
    store: Any,
    action_id: str,
    fallback_decision: ActionDecision,
    operator_id: str,
    reason: str,
) -> ActionStatus:
    try:
        status_raw = store.get_status(action_id)
    except Exception:
        logger.exception("Sentinel-43 action ledger status read failed.")
        status_raw = None

    if status_raw is not None:
        return _as_action_status(status_raw)

    return ActionStatus(
        action_id=action_id,
        decision=fallback_decision,
        decided_by=operator_id,
        decided_ts=utc_now_iso(),
        reason=reason,
    )


def _health_response(request_id: str) -> HealthResponse:
    base = {
        "status": ApiStatus.ok,
        "request_id": request_id,
    }

    extended = {
        **base,
        "service": S43_API_NAME,
        "version": S43_API_VERSION,
        "principle": S43_CORE_PRINCIPLE,
    }

    try:
        return HealthResponse(**extended)
    except Exception:
        return HealthResponse(**base)


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health(request_id: str = Depends(dep_request_id)) -> HealthResponse:
    return _health_response(request_id)


@v1.post("/assess", response_model=ThreatAssessmentOut, tags=["assessment"])
def assess(
    payload: ThreatAssessmentIn,
    request_id: str = Depends(dep_request_id),
    engine: Any = Depends(dep_engine),
) -> ThreatAssessmentOut:
    try:
        payload_dict = _model_to_dict(payload)
        mode = payload.mode.value if hasattr(payload.mode, "value") else str(payload.mode)

        result = engine.handle_assessment(mode, payload_dict)
        return _as_assessment_out(result, request_id=request_id)

    except HTTPException:
        raise
    except Exception:
        logger.exception("Assessment failed. request_id=%s", request_id)
        raise _http_500(S43_ERR_ASSESSMENT_PIPELINE_FAILURE, request_id=request_id)


@v1.post("/actions/{action_id}/approve", response_model=ActionResponse, tags=["actions"])
def approve_action(
    action_id: str,
    body: ActionRequest,
    request_id: str = Depends(dep_request_id),
    engine: Any = Depends(dep_engine),
    store: Any = Depends(dep_store),
) -> ActionResponse:
    if body.action_id and body.action_id != action_id:
        raise _http_error(
            400,
            S43_ERR_ACTION_ID_MISMATCH,
            "Body action_id does not match path.",
            request_id=request_id,
        )

    try:
        reason = body.reason or ""
        ok = bool(engine.approve_action(action_id, body.operator_id, reason=reason))

        action = _store_status_or_default(
            store=store,
            action_id=action_id,
            fallback_decision=ActionDecision.approved,
            operator_id=body.operator_id,
            reason=reason,
        )

        return ActionResponse(
            status=ApiStatus.ok,
            request_id=request_id,
            result=ok,
            action=action,
        )

    except HTTPException:
        raise
    except Exception:
        logger.exception("Approval failed. action_id=%s request_id=%s", action_id, request_id)
        raise _http_500(S43_ERR_APPROVAL_PIPELINE_FAILURE, request_id=request_id)


@v1.post("/actions/{action_id}/veto", response_model=ActionResponse, tags=["actions"])
def veto_action(
    action_id: str,
    body: ActionRequest,
    request_id: str = Depends(dep_request_id),
    engine: Any = Depends(dep_engine),
    store: Any = Depends(dep_store),
) -> ActionResponse:
    if body.action_id and body.action_id != action_id:
        raise _http_error(
            400,
            S43_ERR_ACTION_ID_MISMATCH,
            "Body action_id does not match path.",
            request_id=request_id,
        )

    reason = (body.reason or "").strip()
    if not reason:
        raise _http_error(
            400,
            S43_ERR_VETO_REASON_REQUIRED,
            "Sentinel-43 veto requires a human-readable reason.",
            request_id=request_id,
        )

    try:
        ok = bool(engine.veto_action(action_id, body.operator_id, reason=reason))

        action = _store_status_or_default(
            store=store,
            action_id=action_id,
            fallback_decision=ActionDecision.vetoed,
            operator_id=body.operator_id,
            reason=reason,
        )

        return ActionResponse(
            status=ApiStatus.ok,
            request_id=request_id,
            result=ok,
            action=action,
        )

    except HTTPException:
        raise
    except Exception:
        logger.exception("Veto failed. action_id=%s request_id=%s", action_id, request_id)
        raise _http_500(S43_ERR_VETO_PIPELINE_FAILURE, request_id=request_id)


@v1.get("/actions", response_model=ActionListResponse, tags=["actions"])
def list_actions(
    status: str | None = Query(default=None, description="Filter by Sentinel-43 decision/status"),
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = Query(default=None),
    request_id: str = Depends(dep_request_id),
    store: Any = Depends(dep_store),
) -> ActionListResponse:
    try:
        if not hasattr(store, "list_actions"):
            raise _http_error(
                501,
                S43_ERR_ACTION_LEDGER_UNAVAILABLE,
                "Sentinel-43 action ledger does not implement list_actions().",
                request_id=request_id,
            )

        items_raw = store.list_actions(status=status, limit=limit, cursor=cursor)

        next_cursor = None
        if isinstance(items_raw, dict):
            next_cursor = items_raw.get("next_cursor")
            raw_items = items_raw.get("items") or []
        else:
            raw_items = items_raw or []

        items = [_as_action_status(item) for item in raw_items]

        return ActionListResponse(
            status=ApiStatus.ok,
            request_id=request_id,
            items=items,
            next_cursor=next_cursor,
        )

    except HTTPException:
        raise
    except Exception:
        logger.exception("Action ledger query failed. request_id=%s", request_id)
        raise _http_500(S43_ERR_ACTION_LEDGER_QUERY_FAILURE, request_id=request_id)


router.include_router(v1)
