# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
#
# See LICENSE.md and COMMERCIAL_LICENSE.md at the repository root.
# =============================================================================

"""Sentinel-43 API layer: FastAPI routes.

File: api/routes.py

This is the HTTP surface.
- No database setup here.
- No global singletons here.
- Convert API schemas <-> core inputs/outputs here.

Wiring expectations:
- api/deps.py provides get_engine() and get_store() dependencies.

Notes on execution:
- If you run this file directly ("python api/routes.py"), Python will *not* treat
  it as part of the `api` package, and relative imports will fail.
- Preferred: run your app entrypoint (e.g., `python -m api.main`) or import
  `api.routes` from inside the package.

This module includes import fallbacks for dev/test environments.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import uuid

# -----------------------------------------------------------------------------
# Imports (robust against "no parent package" situations)
# -----------------------------------------------------------------------------

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
    raise RuntimeError(
        "FastAPI is required to use api/routes.py. Install fastapi + pydantic."  # noqa: EM101
    ) from e


# -----------------------------------------------------------------------------
# Dependency import helpers (do NOT use these directly with Depends)
# -----------------------------------------------------------------------------


def _import_get_engine():
    """Import get_engine with a relative-first, absolute-fallback strategy."""
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
    """Import get_store with a relative-first, absolute-fallback strategy."""
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


# -----------------------------------------------------------------------------
# FastAPI dependency callables (safe to pass into Depends)
# -----------------------------------------------------------------------------


def dep_engine():
    """FastAPI dependency: resolves and calls get_engine at request time."""
    get_engine = _import_get_engine()
    return get_engine()


def dep_store():
    """FastAPI dependency: resolves and calls get_store at request time."""
    get_store = _import_get_store()
    return get_store()


def dep_request_id(x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID")) -> str:
    """FastAPI dependency: request correlation id.

    Behavior:
    - If client provides X-Request-ID, we trust it.
    - Otherwise we generate a UUID4.

    (If you want strict validation or length caps, do it here.)
    """
    if x_request_id and str(x_request_id).strip():
        return str(x_request_id).strip()
    return str(uuid.uuid4())


# -----------------------------------------------------------------------------
# Routers
# -----------------------------------------------------------------------------

router = APIRouter()

v1 = APIRouter(prefix="/v1")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _http_error(status_code: int, code: str, message: str, *, request_id: Optional[str] = None) -> HTTPException:
    detail: Dict[str, Any] = {
        "status": ApiStatus.error,
        "request_id": request_id,
        "ts": utc_now_iso(),
        "error": {"code": code, "message": message},
    }
    return HTTPException(status_code=status_code, detail=detail)


def _http_500(msg: str, *, request_id: Optional[str] = None) -> HTTPException:
    return _http_error(500, "internal_error", msg, request_id=request_id)


def _as_action_status(raw: Any) -> ActionStatus:
    """Best-effort conversion from store payload to ActionStatus."""
    if isinstance(raw, ActionStatus):
        return raw

    if isinstance(raw, dict):
        decision = raw.get("decision") or raw.get("status") or "unknown"
        try:
            decision_enum = ActionDecision(decision)
        except Exception:
            decision_enum = ActionDecision.unknown

        return ActionStatus(
            action_id=str(raw.get("action_id") or raw.get("id") or ""),
            decision=decision_enum,
            decided_by=raw.get("decided_by"),
            decided_ts=raw.get("decided_ts") or raw.get("ts"),
            reason=raw.get("reason"),
        )

    return ActionStatus(action_id=str(raw), decision=ActionDecision.unknown)


def _with_request_id(model: Any, request_id: Optional[str]) -> Any:
    """Return a *new* object updated with request_id, avoiding mutation."""
    if not request_id:
        return model

    # Pydantic v2
    if hasattr(model, "model_copy"):
        try:
            return model.model_copy(update={"request_id": request_id})
        except Exception:
            return model

    # Pydantic v1
    if hasattr(model, "copy"):
        try:
            return model.copy(update={"request_id": request_id})
        except Exception:
            return model

    # Fallback: best effort shallow copy via dict
    try:
        d = dict(model.__dict__)
        d["request_id"] = request_id
        return model.__class__(**d)
    except Exception:
        return model


def _as_assessment_out(result: Any, *, request_id: Optional[str] = None) -> ThreatAssessmentOut:
    """Normalize whatever the engine returns into ThreatAssessmentOut."""
    if isinstance(result, ThreatAssessmentOut):
        return _with_request_id(result, request_id)

    if isinstance(result, dict):
        assessment_id = str(result.get("assessment_id") or result.get("id") or "")
        severity = int(result.get("severity", 0))
        confidence = int(result.get("confidence", 0))
        summary = str(result.get("summary") or result.get("message") or "")
        tags = list(result.get("tags") or [])

        return ThreatAssessmentOut(
            status=ApiStatus.ok,
            request_id=request_id,
            assessment_id=assessment_id,
            severity=severity,
            confidence=confidence,
            summary=summary,
            tags=tags,
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


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health(request_id: str = Depends(dep_request_id)) -> HealthResponse:
    # Uptime can be wired later once you add an app-state timer.
    return HealthResponse(status=ApiStatus.ok, request_id=request_id)


@v1.post("/assess", response_model=ThreatAssessmentOut, tags=["assessment"])
def assess(
    payload: ThreatAssessmentIn,
    request_id: str = Depends(dep_request_id),
    engine=Depends(dep_engine),
) -> ThreatAssessmentOut:
    try:
        # Keep contract simple: pass dict payload to engine.
        if hasattr(payload, "model_dump"):
            payload_dict = payload.model_dump()  # pydantic v2
        else:
            payload_dict = payload.__dict__

        # mode is enum in models.py; if payload.mode is a str in fallback mode,
        # this will still behave.
        mode = payload.mode.value if hasattr(payload.mode, "value") else str(payload.mode)

        result = engine.handle_assessment(mode, payload_dict)
        return _as_assessment_out(result, request_id=request_id)
    except HTTPException:
        raise
    except Exception as e:
        raise _http_500(f"assessment_failed: {e}", request_id=request_id)


@v1.post("/actions/{action_id}/approve", response_model=ActionResponse, tags=["actions"])
def approve_action(
    action_id: str,
    body: ActionRequest,
    request_id: str = Depends(dep_request_id),
    engine=Depends(dep_engine),
    store=Depends(dep_store),
) -> ActionResponse:
    if body.action_id and body.action_id != action_id:
        raise _http_error(400, "action_id_mismatch", "Body action_id does not match path.", request_id=request_id)

    try:
        ok = bool(engine.approve_action(action_id, body.operator_id, reason=body.reason or ""))

        # Prefer store status when available.
        status_raw = None
        try:
            status_raw = store.get_status(action_id)
        except Exception:
            status_raw = None

        action = (
            _as_action_status(status_raw)
            if status_raw is not None
            else ActionStatus(
                action_id=action_id,
                decision=ActionDecision.approved,
                decided_by=body.operator_id,
                decided_ts=utc_now_iso(),
                reason=body.reason or "",
            )
        )

        return ActionResponse(status=ApiStatus.ok, request_id=request_id, result=ok, action=action)
    except HTTPException:
        raise
    except Exception as e:
        raise _http_500(f"approve_failed: {e}", request_id=request_id)


@v1.post("/actions/{action_id}/veto", response_model=ActionResponse, tags=["actions"])
def veto_action(
    action_id: str,
    body: ActionRequest,
    request_id: str = Depends(dep_request_id),
    engine=Depends(dep_engine),
    store=Depends(dep_store),
) -> ActionResponse:
    if body.action_id and body.action_id != action_id:
        raise _http_error(400, "action_id_mismatch", "Body action_id does not match path.", request_id=request_id)

    if not (body.reason or "").strip():
        raise _http_error(400, "reason_required", "Veto requires a reason.", request_id=request_id)

    try:
        ok = bool(engine.veto_action(action_id, body.operator_id, reason=body.reason or ""))

        status_raw = None
        try:
            status_raw = store.get_status(action_id)
        except Exception:
            status_raw = None

        action = (
            _as_action_status(status_raw)
            if status_raw is not None
            else ActionStatus(
                action_id=action_id,
                decision=ActionDecision.vetoed,
                decided_by=body.operator_id,
                decided_ts=utc_now_iso(),
                reason=body.reason or "",
            )
        )

        return ActionResponse(status=ApiStatus.ok, request_id=request_id, result=ok, action=action)
    except HTTPException:
        raise
    except Exception as e:
        raise _http_500(f"veto_failed: {e}", request_id=request_id)


@v1.get("/actions", response_model=ActionListResponse, tags=["actions"])
def list_actions(
    status: Optional[str] = Query(default=None, description="Filter by decision/status"),
    limit: int = Query(default=50, ge=1, le=500),
    cursor: Optional[str] = Query(default=None),
    request_id: str = Depends(dep_request_id),
    store=Depends(dep_store),
) -> ActionListResponse:
    try:
        if not hasattr(store, "list_actions"):
            # Returning an empty list here hides a wiring bug.
            raise _http_error(
                501,
                "not_implemented",
                "Store does not implement list_actions().",
                request_id=request_id,
            )

        items_raw = store.list_actions(status=status, limit=limit, cursor=cursor)  # type: ignore[arg-type]

        next_cursor = None
        items = []

        if isinstance(items_raw, dict):
            next_cursor = items_raw.get("next_cursor")
            raw_list = items_raw.get("items") or []
            items = [_as_action_status(x) for x in raw_list]
        else:
            items = [_as_action_status(x) for x in (items_raw or [])]

        return ActionListResponse(status=ApiStatus.ok, request_id=request_id, items=items, next_cursor=next_cursor)
    except HTTPException:
        raise
    except Exception as e:
        raise _http_500(f"list_actions_failed: {e}", request_id=request_id)


router.include_router(v1)


# -----------------------------------------------------------------------------
# Minimal tests (no pytest required)
# -----------------------------------------------------------------------------


def _run_self_tests() -> None:  # pragma: no cover
    import unittest

    class DummyEngine:
        def handle_assessment(self, mode: str, assessment: Any) -> Any:
            return {
                "assessment_id": "a1",
                "severity": 10,
                "confidence": 20,
                "summary": f"mode={mode}",
                "tags": ["t1"],
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
                "reason": "because",
            }

        def list_actions(self, *, status: Optional[str] = None, limit: int = 50, cursor: Optional[str] = None) -> Any:
            return {
                "items": [
                    {"action_id": "x", "decision": "approved"},
                    {"action_id": "y", "decision": "vetoed"},
                ],
                "next_cursor": None,
            }

    class StoreNoList:
        def get_status(self, action_id: str) -> Any:
            return {"action_id": action_id, "decision": "approved"}

    class RoutesTests(unittest.TestCase):
        def test_dep_request_id_uses_header(self):
            rid = dep_request_id("abc-123")
            self.assertEqual(rid, "abc-123")

        def test_dep_request_id_generates_uuid(self):
            rid = dep_request_id(None)
            self.assertTrue(isinstance(rid, str) and len(rid) >= 32)

        def test_as_action_status_dict(self):
            s = _as_action_status({"action_id": "x", "decision": "approved"})
            self.assertEqual(s.action_id, "x")
            self.assertEqual(s.decision, ActionDecision.approved)

        def test_as_assessment_out_no_mutation(self):
            rid = "req-1"
            out1 = ThreatAssessmentOut(
                status=ApiStatus.ok,
                request_id=None,
                assessment_id="a",
                severity=1,
                confidence=2,
                summary="s",
                tags=[],
            )
            out2 = _as_assessment_out(out1, request_id=rid)
            # out1 should remain unchanged
            self.assertIsNone(out1.request_id)
            # out2 should have request id
            self.assertEqual(out2.request_id, rid)

        def test_assess_normalizes_dict(self):
            eng = DummyEngine()
            payload = ThreatAssessmentIn(mode="shadow", signals=[], context={})  # type: ignore[arg-type]
            out = assess(payload, request_id="r", engine=eng)  # type: ignore[misc]
            self.assertEqual(out.assessment_id, "a1")
            self.assertEqual(out.severity, 10)
            self.assertEqual(out.request_id, "r")

        def test_veto_requires_reason(self):
            eng = DummyEngine()
            st = DummyStore()
            with self.assertRaises(HTTPException):
                veto_action(
                    "x",
                    ActionRequest(action_id="x", operator_id="op", reason=""),
                    request_id="r",
                    engine=eng,
                    store=st,
                )  # type: ignore[misc]

        def test_approve_mismatch(self):
            eng = DummyEngine()
            st = DummyStore()
            with self.assertRaises(HTTPException):
                approve_action(
                    "x",
                    ActionRequest(action_id="y", operator_id="op", reason="r"),
                    request_id="r",
                    engine=eng,
                    store=st,
                )  # type: ignore[misc]

        def test_list_actions_missing_method_501(self):
            st = StoreNoList()
            with self.assertRaises(HTTPException) as ctx:
                list_actions(request_id="r", store=st)  # type: ignore[misc]
            self.assertEqual(ctx.exception.status_code, 501)

    unittest.main(argv=["routes.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
