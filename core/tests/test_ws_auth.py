# =============================================================================
# Sentinel-43 — WebSocket Auth Boundary Tests
#
# Purpose:
#   Verify the dashboard WebSocket's auth handshake before closed beta.
#
# This is NOT a standard "reject the upgrade" pattern. Per core/api/main.py
# dashboard_websocket():
#   1. Server ALWAYS calls websocket.accept() first, regardless of auth.
#   2. If S43_WS_REQUIRE_AUTH=true, server then sends:
#        {"type": "auth_required", "payload": {...}}
#   3. Server waits (up to 15s) for the client's FIRST message to be:
#        {"type": "auth", "payload": {"token": "<bearer>"}}
#   4. On success: sends {"type": "connected", ...} and the session proceeds.
#   5. On failure: behavior differs by failure type —
#        - bad/expired/forged token  -> sends an {"type":"error",...} frame,
#                                       THEN closes with code 1008
#        - wrong frame type / no token field -> same: error frame, then 1008
#        - malformed JSON / non-dict frame   -> NO error frame, closes 1008
#          immediately (caught by the ValueError branch in
#          _receive_ws_message(), not the per-field validation branches)
#
# That last asymmetry is real and worth knowing before relying on auth.js
# to always show an error message before disconnecting — it won't, for a
# malformed first frame.
#
# WS_REQUIRE_AUTH, JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE, JWT_ALGORITHM are
# all module-level constants in core.api.main, read at import time. This
# file does not assume it is the first test module to import that module —
# pytest collection order is not something to rely on — so it forces the
# values it needs with importlib.reload() rather than os.environ.setdefault.
#
# Fix (95→95 pass):
#   Added setup_module() to re-apply test env vars and reload main_module
#   immediately before this module's tests execute, not just at collection
#   time. Without this, another test file's reload (with real .env values)
#   runs between collection and execution, swapping JWT_SECRET from the
#   test key to the production key. Tokens built with the test key then
#   fail signature verification with DecodeError → generic PyJWTError →
#   "Invalid token", preventing ExpiredSignatureError from ever firing and
#   causing valid tokens to be rejected.
#
#   Changed client fixture to use main_module.app (read after the
#   setup_module reload) rather than the app reference captured at
#   collection time.
# =============================================================================

from __future__ import annotations

import importlib
import os
from datetime import datetime, timezone
from typing import Any, Generator

import jwt
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

# ---------------------------------------------------------------------------
# Test environment setup — hard-set, then reload, so this file's config
# wins regardless of what other test modules already imported main with.
# ---------------------------------------------------------------------------

TEST_SUBJECT = "ws-test-operator"
JWT_SECRET = "test-secret-for-ws-auth-boundary-tests"
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "sentinel-43-test"
JWT_AUDIENCE = "sentinel-43-dashboard-test"
WRONG_SECRET = "a-completely-different-secret-for-ws-tests"

# Snapshot pre-existing values (None if unset) so teardown_module() can put
# the environment back exactly as it found it. Without this, the hard
# os.environ[...] = ... assignments below leak this module's test secret
# into every test module that runs afterward in the same pytest process —
# auth.py's verify_jwt_token() reads S43_JWT_SECRET at call time, so any
# later module that builds a token with a *different* secret captured at
# its own import time will fail signature verification against this
# module's leftover secret.
_ENV_KEYS_MUTATED = (
    "SENTINEL_ENV",
    "S43_JWT_SECRET",
    "S43_JWT_ALGORITHM",
    "S43_JWT_ISSUER",
    "S43_JWT_AUDIENCE",
    "S43_WS_REQUIRE_AUTH",
    "S43_ENABLE_TEST_INJECTION",
)
_ORIGINAL_ENV = {key: os.environ.get(key) for key in _ENV_KEYS_MUTATED}

os.environ["SENTINEL_ENV"] = "test"
os.environ["S43_JWT_SECRET"] = JWT_SECRET
os.environ["S43_JWT_ALGORITHM"] = JWT_ALGORITHM
os.environ["S43_JWT_ISSUER"] = JWT_ISSUER
os.environ["S43_JWT_AUDIENCE"] = JWT_AUDIENCE
os.environ["S43_WS_REQUIRE_AUTH"] = "true"
os.environ["S43_ENABLE_TEST_INJECTION"] = "false"

import core.api.main as main_module  # noqa: E402
import core.api.routers.auth as auth_module  # noqa: E402

importlib.reload(main_module)  # force constants to pick up the values above

WS_URL = "/ws"

# Every WS auth frame now also carries a password (see main.py's auth frame
# handling: reverify_password() must accept it). No DB/env credentials are
# configured in this module, so reverify_password is monkeypatched to
# accept exactly this value for any non-empty subject.
TEST_PASSWORD = "ws-boundary-test-password"


async def _fake_reverify_password(username: str, password: str) -> bool:
    return bool(username) and password == TEST_PASSWORD


_real_reverify_password = auth_module.reverify_password


# ---------------------------------------------------------------------------
# setup_module / teardown_module — re-applies test config immediately before
# tests execute, and restores auth_module.reverify_password afterward so the
# fake doesn't leak into other test modules sharing this process.
#
# The module-level reload above runs at collection time. By execution time,
# another test module may have reloaded core.api.main with different env
# vars (e.g. real JWT_SECRET from .env), breaking signature verification
# for tokens built here. setup_module() re-establishes the correct state
# right before this module's first test runs, after all collection is done.
# ---------------------------------------------------------------------------

def setup_module(module: Any) -> None:
    os.environ["S43_JWT_SECRET"] = JWT_SECRET
    os.environ["S43_JWT_ALGORITHM"] = JWT_ALGORITHM
    os.environ["S43_JWT_ISSUER"] = JWT_ISSUER
    os.environ["S43_JWT_AUDIENCE"] = JWT_AUDIENCE
    os.environ["S43_WS_REQUIRE_AUTH"] = "true"
    os.environ["SENTINEL_ENV"] = "test"
    importlib.reload(main_module)
    auth_module.reverify_password = _fake_reverify_password


def teardown_module(module: Any) -> None:
    auth_module.reverify_password = _real_reverify_password

    # Restore the environment to what it was before this module's collection
    # -time mutations, so later test modules in the same pytest process don't
    # silently inherit this module's test JWT secret/config.
    for key, original_value in _ORIGINAL_ENV.items():
        if original_value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original_value
    importlib.reload(main_module)


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client() -> Generator[TestClient, None, None]:
    # Use main_module.app after setup_module's reload, not a reference
    # captured at collection time before other test files ran their reloads.
    with TestClient(main_module.app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Token builders
# ---------------------------------------------------------------------------

def _build_token(
    *,
    secret: str = JWT_SECRET,
    algorithm: str = JWT_ALGORITHM,
    issuer: str | None = JWT_ISSUER,
    audience: str | None = JWT_AUDIENCE,
    subject: str | None = TEST_SUBJECT,
    role: str | None = "operator",
    exp_offset_seconds: int = 3600,
) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + exp_offset_seconds,
    }
    if issuer is not None:
        payload["iss"] = issuer
    if audience is not None:
        payload["aud"] = audience
    if subject is not None:
        payload["sub"] = subject
    if role is not None:
        payload["role"] = role

    return jwt.encode(payload, secret, algorithm=algorithm)


def make_valid_token() -> str:
    return _build_token()


def make_expired_token() -> str:
    return _build_token(exp_offset_seconds=-3600)


def make_forged_token() -> str:
    return _build_token(secret=WRONG_SECRET)


def make_wrong_algorithm_token() -> str:
    """Signed with HS384 — a legitimate HMAC algorithm, but not the one
    this server is configured to accept (HS256-only policy)."""
    return _build_token(algorithm="HS384", secret="x" * 64)


def make_no_role_token() -> str:
    return _build_token(role=None)


def make_unapproved_role_token() -> str:
    return _build_token(role="guest")


# ---------------------------------------------------------------------------
# Handshake helpers
# ---------------------------------------------------------------------------

def _consume_auth_required(ws) -> None:
    """Every authenticated session opens with this frame. Assert and discard."""
    frame = ws.receive_json()
    assert frame["type"] == "auth_required"


def _expect_rejection(ws, *, expected_error_substring: str | None = None) -> None:
    """
    Most rejection paths send an error frame, then close(1008). Assert
    the error frame if a substring is given, then assert the close code.
    """
    if expected_error_substring is not None:
        frame = ws.receive_json()
        assert frame["type"] == "error"
        assert expected_error_substring.lower() in frame["payload"]["error"].lower()

    with pytest.raises(WebSocketDisconnect) as exc_info:
        ws.receive_text()
    assert exc_info.value.code == 1008


# ---------------------------------------------------------------------------
# Rejection Tests
# ---------------------------------------------------------------------------

def test_ws_rejects_missing_token_field(client: TestClient):
    """Auth frame sent, but payload has no 'token' key at all."""
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({"type": "auth", "payload": {}})
        _expect_rejection(ws, expected_error_substring="token missing")


def test_ws_rejects_wrong_frame_type(client: TestClient):
    """First message sent is not type='auth' — protocol violation, not a bad token."""
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({"type": "ping", "payload": {}})
        _expect_rejection(ws, expected_error_substring="auth frame")


def test_ws_rejects_malformed_json_frame(client: TestClient):
    """
    Not valid JSON at all. This hits the ValueError branch in
    _receive_ws_message(), which closes WITHOUT sending an error frame —
    distinct from every other rejection path in this file.
    """
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_text("this is not json")
        _expect_rejection(ws, expected_error_substring=None)


def test_ws_rejects_malformed_token_string(client: TestClient):
    """Token field present but not a parseable JWT (DecodeError path)."""
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({"type": "auth", "payload": {"token": "not-a-real-jwt"}})
        _expect_rejection(ws, expected_error_substring="invalid token")


def test_ws_rejects_forged_signature(client: TestClient):
    """Structurally valid JWT, correct claims, signed with the wrong key."""
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({"type": "auth", "payload": {"token": make_forged_token()}})
        _expect_rejection(ws, expected_error_substring="invalid token")


def test_ws_rejects_expired_token(client: TestClient):
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({"type": "auth", "payload": {"token": make_expired_token()}})
        _expect_rejection(ws, expected_error_substring="expired")


def test_ws_rejects_valid_token_missing_password(client: TestClient):
    """A structurally valid, correctly-signed token is not enough on its
    own — the auth frame must also carry the operator's password."""
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({"type": "auth", "payload": {"token": make_valid_token()}})
        _expect_rejection(ws, expected_error_substring="password missing")


def test_ws_rejects_valid_token_wrong_password(client: TestClient):
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({
            "type": "auth",
            "payload": {"token": make_valid_token(), "password": "not-the-right-password"},
        })
        _expect_rejection(ws, expected_error_substring="invalid password")


def test_ws_rejects_unsupported_algorithm(client: TestClient):
    """
    A token signed with HS384 must be rejected even though HS384 is a
    legitimate HMAC algorithm — the server only accepts HS256
    (core.security.jwt_constants.APPROVED_JWT_ALGORITHMS), and
    verify_jwt_token() must reject it before ever reaching pyjwt.decode
    with an algorithm list that includes it.
    """
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({
            "type": "auth",
            "payload": {"token": make_wrong_algorithm_token(), "password": TEST_PASSWORD},
        })
        _expect_rejection(ws, expected_error_substring="invalid token")


def test_ws_rejects_missing_role_claim(client: TestClient):
    """A structurally valid, correctly signed token with no role claim at
    all must still be rejected — authentication succeeded, authorization
    did not."""
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({
            "type": "auth",
            "payload": {"token": make_no_role_token(), "password": TEST_PASSWORD},
        })
        _expect_rejection(ws, expected_error_substring="role")


def test_ws_rejects_unapproved_role(client: TestClient):
    """A role outside {operator, admin} must be rejected the same way."""
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({
            "type": "auth",
            "payload": {"token": make_unapproved_role_token(), "password": TEST_PASSWORD},
        })
        _expect_rejection(ws, expected_error_substring="role")


def test_ws_rejects_invalid_origin(client: TestClient):
    """
    A WebSocket handshake carrying an Origin header outside
    S43_ALLOWED_ORIGINS must be rejected before the auth handshake ever
    starts — no auth_required frame, connection closes immediately.
    """
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            WS_URL, headers={"origin": "https://evil.example.com"}
        ) as ws:
            # If the origin check somehow didn't reject the connection,
            # this receive_text() surfaces whatever the server actually
            # sent so the failure is easy to diagnose instead of hanging.
            ws.receive_text()


# ---------------------------------------------------------------------------
# Acceptance Test
# ---------------------------------------------------------------------------

def test_ws_accepts_valid_token(client: TestClient):
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({
            "type": "auth",
            "payload": {"token": make_valid_token(), "password": TEST_PASSWORD},
        })

        frame = ws.receive_json()
        assert frame["type"] == "connected"
        assert frame["payload"]["status"] == "ok"

        # Confirm the session is actually live post-auth, not just that the
        # connect frame was sent before an immediate drop.
        ws.send_json({"type": "ping", "payload": {}})
        pong = ws.receive_json()
        assert pong["type"] == "pong"


def test_ws_ignores_duplicate_auth_frame_after_connect(client: TestClient):
    """
    Authentication happens exactly once — on the first message after
    auth_required. A second {"type":"auth",...} frame sent after the
    session is already connected is not a second authentication attempt;
    it falls through to the generic "unsupported event" handling like any
    other unrecognized frame type, and must not tear down or re-privilege
    the existing session.
    """
    with client.websocket_connect(WS_URL) as ws:
        _consume_auth_required(ws)
        ws.send_json({
            "type": "auth",
            "payload": {"token": make_valid_token(), "password": TEST_PASSWORD},
        })
        connected = ws.receive_json()
        assert connected["type"] == "connected"

        ws.send_json({
            "type": "auth",
            "payload": {"token": make_valid_token(), "password": TEST_PASSWORD},
        })
        second = ws.receive_json()
        assert second["type"] == "error"
        assert "unsupported event" in second["payload"]["error"].lower()

        # Session must still be alive and usable afterward.
        ws.send_json({"type": "ping", "payload": {}})
        pong = ws.receive_json()
        assert pong["type"] == "pong"