# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 Watchgate API routes.

This module is the HTTP boundary for Sentinel-43.

Rules:
- Advisory-first by default.
- Human-gated for approval/veto paths.
- Audit-backed decision visibility.
- No autonomous enforcement in the API core.
- No hidden side effects.
- No database initialization here.
- No global mutable runtime state here.

The route layer translates HTTP payloads into deterministic Sentinel-43
engine/store calls and returns clean, request-correlated API responses.
"""

from __future__ import annotations

import inspect
import logging
import re
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional

try:
    from .models import (
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
except ImportError:  # pragma: no cover
    try:
        from api.models import (  # type: ignore
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
    except ImportError:
        from models import (  # type: ignore
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

try:
    from fastapi import APIRouter, Depends, Header, HTTPException, Query
except Exception as e:  # pragma: no cover
    raise RuntimeError("FastAPI is required to use Sentinel-43 Watchgate routes.") from e


# -----------------------------------------------------------------------------
# Sentinel-43 identity
# -----------------------------------------------------------------------------

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


# -----------------------------------------------------------------------------
# Dependency import cache
# -----------------------------------------------------------------------------

def _import_get_engine():
    """Import get_engine with relative-first fallback strategy."""
    try:
        from .deps import get_engine  # type: ignore
        return get_engine
    except ImportError:  # pragma: no cover
        try:
            from api.deps import get_engine  # type: ignore
            return get_engine
        except ImportError:
            from deps import get_engine  # type: ignore
            return get_engine


def _import_get_store():
    """Import get_store with relative-first fallback strategy."""
    try:
        from .deps import get_store  # type: ignore
        return get_store
    except ImportError:  # pragma: no cover
        try:
            from api.deps import get_store  # type: ignore
            return get_store
        except ImportError:
            from deps import get_store  # type: ignore
            return get_store


_GET_ENGINE = _import_get_engine()
_GET_STORE = _import_get_store()


@contextmanager
def _resolve_dependency(factory: Any) -> Generator[Any, None, None]:
    """Resolve plain callable or generator-style dependency safely."""
    value = factory()

    if inspect.isgenerator(value):
        try:
            resolved = next(value)
        except StopIteration as exc:
            raise RuntimeError("Sentinel-43 dependency generator yielded no value.") from exc

        try:
            yield resolved
        finally:
            try:
                next(value)
            except StopIteration:
                pass
            else:
                raise RuntimeError("Sentinel-43 dependency generator yielded more than once.")
        return

    yield value


def dep_engine() -> Generator[Any, None, None]:
    """FastAPI dependency: resolve Sentinel-43 engine with teardown support."""
    with _resolve_dependency(_GET_ENGINE) as engine:
        yield engine


def dep_store() -> Generator[Any, None, None]:
    """FastAPI dependency: resolve Sentinel-43 action ledger/store."""
    with _resolve_dependency(_GET_STORE) as store:
        yield store


def dep_request_id(
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
) -> str:
    """Return safe Sentinel-43 request correlation ID."""
    if x_request_id:
        candidate = str(x_request_id).strip()
        if _REQUEST_ID_RE.fullmatch(candidate):
            return candidate

        logger.warning("Rejected unsafe X-Request-ID header.")

    return str(uuid.uuid4())


# -----------------------------------------------------------------------------
# Routers
# -----------------------------------------------------------------------------

router = APIRouter()
v1 = APIRouter(prefix="/v1")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _api_status_value(status: Any) -> Any:
    return status.value if hasattr(status, "value") else status


def _http_error(
    status_code: int,
    code: str,
    message: str,
    *,
    request_id: Optional[str] = None,
) -> HTTPException:
    detail: Dict[str, Any] = {
        "status": _api_status_value(ApiStatus.error),
        "request_id": request_id,
        "ts": utc_now_iso(),
        "service": S43_API_NAME,
        "version": S43_API_VERSION,
        "error": {
            "code": code,
            "message": message,
        },
    }
    return HTTPException(status_code=status_code, detail=detail)


def _http_500(code: str, *, request_id: Optional[str] = None) -> HTTPException:
    return _http_error(
        500,
        code,
        "Sentinel-43 Watchgate pipeline failure.",
        request_id=request_id,
    )


def _model_to_dict(model: Any) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return dict(model.model_dump())
    if hasattr(model, "dict"):
        return dict(model.dict())
    if isinstance(model, dict):
        return dict(model)
    return dict(vars(model))


def _with_request_id(model: Any, request_id: Optional[str]) -> Any:
    """Return a new model with request_id when possible."""
    if not request_id:
        return model

    if hasattr(model, "model_copy"):
        return model.model_copy(update={"request_id": request_id})

    if hasattr(model, "copy"):
        return model.copy(update={"request_id": request_id})

    raise TypeError(f"Unsupported Sentinel-43 response model type: {type(model)!r}")


def _as_action_status(raw: Any) -> ActionStatus:
    """Normalize store payload into Sentinel-43 ActionStatus."""
    if isinstance(raw, ActionStatus):
        return raw

    if isinstance(raw, dict):
        decision = raw.get("decision") or raw.get("status") or "unknown"

        try:
            decision_enum = ActionDecision(decision)
        except Exception:
            logger.warning("Unrecognized Sentinel-43 action decision from store: %r", decision)
            decision_enum = ActionDecision.unknown

        return ActionStatus(
            action_id=str(raw.get("action_id") or raw.get("id") or ""),
            decision=decision_enum,
            decided_by=raw.get("decided_by"),
            decided_ts=raw.get("decided_ts") or raw.get("ts"),
            reason=raw.get("reason"),
        )

    logger.warning("Unexpected Sentinel-43 action status payload type: %s", type(raw).__name__)
    return ActionStatus(action_id=str(raw), decision=ActionDecision.unknown)


def _as_assessment_out(
    result: Any,
    *,
    request_id: Optional[str] = None,
) -> ThreatAssessmentOut:
    """Normalize engine output into Sentinel-43 ThreatAssessmentOut."""
    if isinstance(result, ThreatAssessmentOut):
        return _with_request_id(result, request_id)

    if isinstance(result, dict):
        return ThreatAssessmentOut(
            status=ApiStatus.ok,
            request_id=request_id,
            assessment_id=str(result.get("assessment_id") or result.get("id") or ""),
            severity=int(result.get("severity", 0)),
            confidence=int(result.get("confidence", 0)),
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
    """Build health response with optional Sentinel-43 identity fields."""
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


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

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
        logger.exception("Sentinel-43 assessment failed. request_id=%s", request_id)
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
        logger.exception(
            "Sentinel-43 approval failed. action_id=%s request_id=%s",
            action_id,
            request_id,
        )
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
        logger.exception(
            "Sentinel-43 veto failed. action_id=%s request_id=%s",
            action_id,
            request_id,
        )
        raise _http_500(S43_ERR_VETO_PIPELINE_FAILURE, request_id=request_id)


@v1.get("/actions", response_model=ActionListResponse, tags=["actions"])
def list_actions(
    status: Optional[str] = Query(default=None, description="Filter by Sentinel-43 decision/status"),
    limit: int = Query(default=50, ge=1, le=500),
    cursor: Optional[str] = Query(default=None),
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
        logger.exception("Sentinel-43 action ledger query failed. request_id=%s", request_id)
        raise _http_500(S43_ERR_ACTION_LEDGER_QUERY_FAILURE, request_id=request_id)


router.include_router(v1)


# -----------------------------------------------------------------------------
# Minimal self-tests
# -----------------------------------------------------------------------------

def _run_self_tests() -> None:  # pragma: no cover
    import unittest

    class DummyEngine:
        def handle_assessment(self, mode: str, assessment: Any) -> Any:
            return {
                "assessment_id": "s43-a1",
                "severity": 10,
                "confidence": 20,
                "summary": f"Sentinel-43 mode={mode}",
                "tags": ["watchgate", "shadow"],
            }

        def approve_action(self, action_id: str, operator_id: str, *, reason: str = "") -> bool:
            return True

        def veto_action(self, action_id: str, operator_id: str, *, reason: str) -> bool:
            return True

    class DummyStore:
        def get_status(self, action_id: str) -> Any:
            return {
                "action_id": action_id,
                "decision": "approved",
                "decided_by": "op",
                "decided_ts": "2026-01-01T00:00:00Z",
                "reason": "approved by Sentinel-43 test operator",
            }

        def list_actions(
            self,
            *,
            status: Optional[str] = None,
            limit: int = 50,
            cursor: Optional[str] = None,
        ) -> Any:
            return {
                "items": [
                    {"action_id": "s43-x", "decision": "approved"},
                    {"action_id": "s43-y", "decision": "vetoed"},
                ],
                "next_cursor": "s43-next-1" if cursor is None else None,
            }

    class StoreNoList:
        def get_status(self, action_id: str) -> Any:
            return {"action_id": action_id, "decision": "approved"}

    class RoutesTests(unittest.TestCase):
        def test_dep_request_id_uses_safe_header(self):
            self.assertEqual(dep_request_id("s43-req-123"), "s43-req-123")

        def test_dep_request_id_rejects_newline(self):
            rid = dep_request_id("bad\nid")
            self.assertNotEqual(rid, "bad\nid")
            self.assertTrue(len(rid) >= 32)

        def test_dep_request_id_rejects_oversized(self):
            rid = dep_request_id("x" * 100)
            self.assertNotEqual(rid, "x" * 100)

        def test_http_error_serializes_enum_value(self):
            exc = _http_error(
                400,
                S43_ERR_ACTION_ID_MISMATCH,
                "bad",
                request_id="r",
            )
            self.assertEqual(exc.detail["status"], _api_status_value(ApiStatus.error))
            self.assertEqual(exc.detail["service"], S43_API_NAME)

        def test_as_action_status_dict(self):
            s = _as_action_status({"action_id": "x", "decision": "approved"})
            self.assertEqual(s.action_id, "x")
            self.assertEqual(s.decision, ActionDecision.approved)

        def test_as_action_status_unknown_value(self):
            s = _as_action_status({"action_id": "x", "decision": "feral-nonsense"})
            self.assertEqual(s.decision, ActionDecision.unknown)

        def test_as_assessment_out_no_mutation(self):
            out1 = ThreatAssessmentOut(
                status=ApiStatus.ok,
                request_id=None,
                assessment_id="a",
                severity=1,
                confidence=2,
                summary="s",
                tags=[],
            )
            out2 = _as_assessment_out(out1, request_id="req-1")
            self.assertIsNone(out1.request_id)
            self.assertEqual(out2.request_id, "req-1")

        def test_assess_normalizes_dict(self):
            eng = DummyEngine()
            payload = ThreatAssessmentIn(mode="shadow", signals=[], context={})  # type: ignore[arg-type]
            out = assess(payload, request_id="s43-r", engine=eng)  # type: ignore[misc]
            self.assertEqual(out.assessment_id, "s43-a1")
            self.assertEqual(out.severity, 10)
            self.assertEqual(out.request_id, "s43-r")

        def test_veto_requires_reason(self):
            with self.assertRaises(HTTPException) as ctx:
                veto_action(
                    "x",
                    ActionRequest(action_id="x", operator_id="op", reason=""),
                    request_id="r",
                    engine=DummyEngine(),
                    store=DummyStore(),
                )  # type: ignore[misc]
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(ctx.exception.detail["error"]["code"], S43_ERR_VETO_REASON_REQUIRED)

        def test_approve_mismatch(self):
            with self.assertRaises(HTTPException) as ctx:
                approve_action(
                    "x",
                    ActionRequest(action_id="y", operator_id="op", reason="r"),
                    request_id="r",
                    engine=DummyEngine(),
                    store=DummyStore(),
                )  # type: ignore[misc]
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(ctx.exception.detail["error"]["code"], S43_ERR_ACTION_ID_MISMATCH)

        def test_list_actions_missing_method_501(self):
            with self.assertRaises(HTTPException) as ctx:
                list_actions(
                    status=None,
                    limit=50,
                    cursor=None,
                    request_id="r",
                    store=StoreNoList(),
                )  # type: ignore[misc]
            self.assertEqual(ctx.exception.status_code, 501)
            self.assertEqual(ctx.exception.detail["error"]["code"], S43_ERR_ACTION_LEDGER_UNAVAILABLE)

        def test_list_actions_pagination_path(self):
            out = list_actions(
                status=None,
                limit=2,
                cursor=None,
                request_id="r",
                store=DummyStore(),
            )  # type: ignore[misc]
            self.assertEqual(len(out.items), 2)
            self.assertEqual(out.next_cursor, "s43-next-1")

    unittest.main(argv=["routes.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
