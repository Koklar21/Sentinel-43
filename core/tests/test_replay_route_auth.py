# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_replay_route_auth.py
#
# PR #276 integration repair -- Part A.
#
# Contract coverage for the OPERATOR SURFACE of replay (POST
# /reliability/replay/{event_id} in core/api/main.py): authorization and
# HTTP status mapping. The replay STATE MACHINE itself (eligibility,
# payload fidelity, crash safety) is covered at the core/reliability.py
# level in core/tests/test_event_reliability.py; this file proves the route
# enforces the same guard every other operator route uses, and that the
# manager's refusal reasons reach the operator as the right HTTP status --
# not as a silent 200 with ok: false, and not as an opaque 500.
#
# Follows the same direct-handler-invocation pattern as
# test_watchtower_bridge_auth.py: no TestClient, no app boot. Route
# functions are called directly and _require_operator / _watchtower_request
# are patched, so this isolates "does the route call the guard, in the
# right order, and turn each manager outcome into the right response" from
# JWT/session mechanics (owned by test_jwt_auth.py) and from Watchtower
# transport (owned by test_watchtower_bridge_auth.py).
# =============================================================================

from __future__ import annotations

import asyncio
import os
import pathlib
import tempfile

import pytest
from fastapi import HTTPException
from starlette.requests import Request

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault(
    "S43_JWT_SECRET", "test-secret-for-replay-route-auth-tests"
)
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.main as main_module  # noqa: E402
from core.reliability import (  # noqa: E402
    DeadLetterStore,
    EventReliabilityManager,
    FailureStage,
    Retryability,
)


def _run(coro):
    return asyncio.run(coro)


def _request(*, authorization: str | None = None) -> Request:
    headers = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/reliability/replay/ev-1",
        "headers": headers,
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


@pytest.fixture
def reliability_manager(monkeypatch):
    """A real manager + store, wired in as the runtime singleton.

    Real, not mocked: the point of this file is that the route's HTTP
    mapping matches what the manager actually returns, not what a stub was
    told to return.
    """
    store = DeadLetterStore(
        sqlite_path=pathlib.Path(tempfile.mkdtemp()) / "dl.sqlite3"
    )
    store.initialize()
    manager = EventReliabilityManager(dead_letter_store=store, sleep=lambda _d: None)
    monkeypatch.setattr(main_module.runtime, "reliability", manager)
    return manager, store


@pytest.fixture
def deny_operator(monkeypatch):
    """_require_operator rejects every caller -- the same guard a machine
    (Fenrir/Watchtower service) token fails, and the same one an invalid or
    missing human session fails."""

    async def _deny(request):  # noqa: ANN001, ANN202
        raise HTTPException(status_code=401, detail="Authentication required")

    monkeypatch.setattr(main_module, "_require_operator", _deny)


@pytest.fixture
def allow_operator(monkeypatch):
    async def _allow(request):  # noqa: ANN001, ANN202
        return "alice"

    monkeypatch.setattr(main_module, "_require_operator", _allow)


def _dead_letter(store: DeadLetterStore, event_id: str = "ev-1", *, payload=None) -> None:
    store.record_failure(
        envelope={
            "event_id": event_id,
            "correlation_id": "corr-1",
            "payload": payload,
        },
        failure_stage=FailureStage.WATCHTOWER_DELIVERY,
        classification=Retryability.TERMINAL,
        reason="watchtower_unreachable",
        attempts=3,
    )


# --------------------------------------------------------------------------- #
# authorization: replay requires a human operator, never a machine token
# --------------------------------------------------------------------------- #

def test_replay_rejects_a_caller_that_fails_the_operator_guard(
    reliability_manager, deny_operator
):
    """A Fenrir/Watchtower service token cannot satisfy _require_operator,
    the same guard every other operator-only route uses -- so it is
    rejected exactly like an anonymous or invalid caller, before the
    manager is ever consulted."""
    _, store = reliability_manager
    _dead_letter(store, payload={"score": 9})

    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("ev-1", _request()))
    assert exc.value.status_code == 401

    # Refused before the manager acted: the record is untouched.
    assert store.get("ev-1").replay_status == "pending"


def test_authorized_operator_can_replay(
    reliability_manager, allow_operator, monkeypatch
):
    _, store = reliability_manager
    _dead_letter(store, payload={"score": 9})
    monkeypatch.setattr(
        main_module, "_watchtower_request", lambda *a, **k: {"status_code": 200}
    )

    result = _run(main_module.reliability_replay("ev-1", _request()))

    assert result["ok"] is True
    assert result["operator"] == "alice"
    assert store.get("ev-1").replay_status == "replayed_ok"


# --------------------------------------------------------------------------- #
# HTTP status mapping for every refusal reason the manager can return
# --------------------------------------------------------------------------- #

def test_unknown_event_is_404(reliability_manager, allow_operator):
    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("does-not-exist", _request()))
    assert exc.value.status_code == 404


def test_invalid_event_id_is_422(reliability_manager, allow_operator):
    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("x" * 300, _request()))
    assert exc.value.status_code == 422


def test_reliability_layer_unavailable_is_503(monkeypatch, allow_operator):
    monkeypatch.setattr(main_module.runtime, "reliability", None)
    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("ev-1", _request()))
    assert exc.value.status_code == 503


def test_legacy_event_with_no_replay_body_is_409_not_a_partial_replay(
    reliability_manager, allow_operator, monkeypatch
):
    """A record with no persisted replay payload must be refused, never
    redelivered as a payload-less approximation of the original event."""
    _, store = reliability_manager
    _dead_letter(store, payload=None)
    calls = {"n": 0}

    def _traced(*a, **k):  # noqa: ANN001, ANN002
        calls["n"] += 1
        return {"status_code": 200}

    monkeypatch.setattr(main_module, "_watchtower_request", _traced)

    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("ev-1", _request()))

    assert exc.value.status_code == 409
    assert calls["n"] == 0, "a non-replayable record must cause zero delivery attempts"


def test_already_replayed_event_is_409_and_never_redelivered(
    reliability_manager, allow_operator, monkeypatch
):
    _, store = reliability_manager
    _dead_letter(store, payload={"score": 9})
    calls = {"n": 0}

    def _traced(*a, **k):  # noqa: ANN001, ANN002
        calls["n"] += 1
        return {"status_code": 200}

    monkeypatch.setattr(main_module, "_watchtower_request", _traced)

    first = _run(main_module.reliability_replay("ev-1", _request()))
    assert first["ok"] is True
    assert calls["n"] == 1

    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("ev-1", _request()))

    assert exc.value.status_code == 409
    assert calls["n"] == 1, "a conflicting replay must cause zero additional deliveries"


def test_in_progress_event_is_409_and_never_redelivered(
    reliability_manager, allow_operator, monkeypatch
):
    """Simulates a crashed or concurrent prior attempt: the record is
    claimed (REPLAY_IN_PROGRESS) without ever being resolved."""
    _, store = reliability_manager
    _dead_letter(store, payload={"score": 9})
    store.begin_replay_attempt("ev-1")

    calls = {"n": 0}

    def _traced(*a, **k):  # noqa: ANN001, ANN002
        calls["n"] += 1
        return {"status_code": 200}

    monkeypatch.setattr(main_module, "_watchtower_request", _traced)

    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("ev-1", _request()))

    assert exc.value.status_code == 409
    assert calls["n"] == 0


def test_reconciliation_required_is_409_and_not_a_silent_500(
    reliability_manager, allow_operator, monkeypatch
):
    """Delivery succeeds, then persisting that outcome raises. The operator
    must see an explicit conflict describing the uncertain state, not an
    unhandled exception or a false clean result."""
    manager, store = reliability_manager
    _dead_letter(store, payload={"score": 9})
    monkeypatch.setattr(
        main_module, "_watchtower_request", lambda *a, **k: {"status_code": 200}
    )

    def _boom(*a, **k):  # noqa: ANN001, ANN002
        raise RuntimeError("disk full")

    monkeypatch.setattr(store, "mark_replay_result", _boom)

    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("ev-1", _request()))

    assert exc.value.status_code == 409
    assert store.get("ev-1").replay_status == "replay_in_progress"


# --------------------------------------------------------------------------- #
# defect: a failed replay delivery must not return HTTP 200
#
# outcome.delivered is false when Watchtower rejects or cannot receive a
# replay, but the route used to return that outcome as a plain dict, so
# FastAPI answered 200 regardless. The dashboard's ApiClient derives its
# own "ok" purely from HTTP status (200 <= status < 300), so a 200 here
# reported success to the UI for a replay that did not happen.
# --------------------------------------------------------------------------- #

def test_watchtower_rejecting_the_replay_is_non_2xx_not_200(
    reliability_manager, allow_operator, monkeypatch
):
    _, store = reliability_manager
    _dead_letter(store, payload={"score": 9})
    monkeypatch.setattr(
        main_module,
        "_watchtower_request",
        lambda *a, **k: {"status_code": 400, "error": "bad_request"},
    )

    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("ev-1", _request()))

    assert exc.value.status_code == 503
    assert exc.value.status_code not in (200, 201, 204)
    # The record returns to the dead-letter state, never claims success.
    assert store.get("ev-1").replay_status == "replay_failed"


def test_watchtower_unavailable_during_replay_is_non_2xx_not_200(
    reliability_manager, allow_operator, monkeypatch
):
    _, store = reliability_manager
    _dead_letter(store, payload={"score": 9})

    def _unreachable(*a, **k):  # noqa: ANN001, ANN002
        raise ConnectionError("watchtower unreachable")

    monkeypatch.setattr(main_module, "_watchtower_request", _unreachable)

    with pytest.raises(HTTPException) as exc:
        _run(main_module.reliability_replay("ev-1", _request()))

    assert exc.value.status_code == 503
    assert store.get("ev-1").replay_status == "replay_failed"


def test_successful_replay_is_200(reliability_manager, allow_operator, monkeypatch):
    _, store = reliability_manager
    _dead_letter(store, payload={"score": 9})
    monkeypatch.setattr(
        main_module, "_watchtower_request", lambda *a, **k: {"status_code": 200}
    )

    # No HTTPException raised == the route returns a plain dict == FastAPI
    # answers 200 -- the direct-call equivalent of asserting the status.
    result = _run(main_module.reliability_replay("ev-1", _request()))
    assert result["ok"] is True


__all__: list[str] = []
