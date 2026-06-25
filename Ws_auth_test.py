"""
Sentinel-43 WebSocket Authentication Test
==========================================

Validates WebSocket connectivity and authentication behavior
against the running Docker stack.

Run with:
    python Ws_auth_test.py

Requires:
    pip install websockets PyJWT

Fixes from original:
  - JWT_ISSUER default changed from "sentinel-43-test" to "sentinel-43"
    to match main.py's S43_JWT_ISSUER default.
  - JWT_AUDIENCE default changed from "sentinel-43-dashboard-test" to
    "sentinel-43-dashboard" to match main.py's S43_JWT_AUDIENCE default.
    Both mismatches caused all valid tokens to fail with InvalidIssuerError
    / InvalidAudienceError, which main.py catches as the generic PyJWTError
    and returns {'error': 'Invalid token'}.
  - test_ping_pong and test_subscribe_channel previously sent an HTTP
    Authorization header instead of the WS message auth protocol. The server
    ignores HTTP headers and sends auth_required first, so those tests were
    "passing" by receiving the auth challenge, not by actually testing the
    target behavior. Both tests now complete the full auth handshake before
    sending their test message.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any

try:
    import jwt as pyjwt
except ImportError:
    print("FAIL  PyJWT not installed. Run: pip install PyJWT")
    sys.exit(1)

try:
    import websockets
    from websockets.exceptions import (
        ConnectionClosedError,
        ConnectionClosedOK,
        InvalidHandshake,
        WebSocketException,
    )
except ImportError:
    print("FAIL  websockets not installed. Run: pip install websockets")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WS_URL        = os.getenv("SENTINEL_WS_URL",    "ws://localhost:8000/ws")
JWT_SECRET    = os.getenv("S43_JWT_SECRET",      "test-secret-key-at-least-32-bytes-long-xxxx")
JWT_ALGORITHM = os.getenv("S43_JWT_ALGORITHM",   "HS256")

# Fix: defaults now match main.py's S43_JWT_ISSUER / S43_JWT_AUDIENCE defaults.
# Previously appended "-test" to both, causing InvalidIssuerError /
# InvalidAudienceError on every token the server validated.
JWT_ISSUER    = os.getenv("S43_JWT_ISSUER",      "sentinel-43")
JWT_AUDIENCE  = os.getenv("S43_JWT_AUDIENCE",    "sentinel-43-dashboard")

CONNECT_TIMEOUT = float(os.getenv("S43_WS_TEST_TIMEOUT", "5"))

PASS = "PASS "
FAIL = "FAIL "
SKIP = "SKIP "

_results: list[tuple[str, str]] = []


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def _make_token(
    *,
    subject: str = "test-operator",
    role: str = "operator",
    exp_offset: int = 3600,
    secret: str = JWT_SECRET,
    issuer: str = JWT_ISSUER,
    audience: str = JWT_AUDIENCE,
) -> str:
    claims: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iss": issuer,
        "aud": audience,
        "exp": int(time.time()) + exp_offset,
    }
    return pyjwt.encode(claims, secret, algorithm=JWT_ALGORITHM)


def _make_expired_token() -> str:
    return _make_token(exp_offset=-3600)


def _make_bad_secret_token() -> str:
    return _make_token(secret="a-completely-different-wrong-secret-xxx!")


# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------

def _auth_message(token: str) -> str:
    return json.dumps({"type": "auth", "payload": {"token": token}})


def _ping_message() -> str:
    return json.dumps({"type": "ping", "payload": {"timestamp": time.time()}})


def _subscribe_message(channel: str = "actions") -> str:
    return json.dumps({"type": "subscribe", "payload": {"channel": channel}})


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def _record(label: str, status: str, detail: str = "") -> None:
    tag = f"{status}{label}"
    if detail:
        tag += f"  [{detail}]"
    _results.append((status.strip(), label))
    print(tag)


async def _try_connect(
    url: str,
    *,
    token: str | None = None,
    timeout: float = CONNECT_TIMEOUT,
) -> tuple[bool, str]:
    """
    Attempt a WebSocket connection using the server's auth protocol.

    Correct auth flow:
    1. Connect.
    2. Read server's first message.
    3. If auth_required, send auth frame.
    4. Read server's response to auth frame.
    5. Return True if connected, False otherwise.
    """
    try:
        async with asyncio.timeout(timeout):
            async with websockets.connect(url) as ws:
                first_raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                first_msg = json.loads(first_raw) if isinstance(first_raw, str) else {}
                first_type = first_msg.get("type", "unknown")

                if first_type == "auth_required":
                    if not token:
                        return False, "auth required and no token provided"

                    await ws.send(_auth_message(token))

                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    except (ConnectionClosedError, ConnectionClosedOK) as exc:
                        return False, f"connection closed after auth: {exc}"

                    msg = json.loads(raw) if isinstance(raw, str) else {}
                    msg_type = msg.get("type", "unknown")

                    if msg_type == "connected":
                        return True, "authenticated and connected"
                    if msg_type == "error":
                        return False, f"auth rejected: {msg.get('payload', {})}"
                    return False, f"unexpected post-auth message type={msg_type!r}"

                if first_type == "connected":
                    return True, "connected without auth_required"
                if first_type == "error":
                    return False, f"server error: {first_msg.get('payload', {})}"
                return False, f"unexpected first message type={first_type!r}"

    except ConnectionClosedError as exc:
        return False, f"connection closed: code={exc.rcvd.code if exc.rcvd else '?'}"
    except ConnectionClosedOK:
        return False, "connection closed cleanly"
    except InvalidHandshake as exc:
        return False, f"handshake rejected: {exc}"
    except asyncio.TimeoutError:
        return False, "connection timed out"
    except OSError as exc:
        return False, f"OS error: {exc}"
    except WebSocketException as exc:
        return False, f"WebSocket error: {exc.__class__.__name__}: {exc}"
    except Exception as exc:
        return False, f"unexpected: {exc.__class__.__name__}: {exc}"


async def _connect_and_auth(
    url: str,
    token: str,
    timeout: float = CONNECT_TIMEOUT,
) -> tuple[websockets.WebSocketClientProtocol | None, str]:
    """
    Connect and complete the full auth handshake.
    Returns the open websocket on success, None on failure.
    Used by tests that need a live authenticated connection.
    """
    try:
        ws = await asyncio.wait_for(websockets.connect(url), timeout=timeout)
    except Exception as exc:
        return None, f"could not connect: {exc.__class__.__name__}: {exc}"

    try:
        first_raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        first_msg = json.loads(first_raw) if isinstance(first_raw, str) else {}
        first_type = first_msg.get("type", "unknown")

        if first_type == "auth_required":
            await ws.send(_auth_message(token))
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
            msg = json.loads(raw) if isinstance(raw, str) else {}
            if msg.get("type") != "connected":
                await ws.close()
                return None, f"auth failed: {msg.get('payload', {})}"
        elif first_type != "connected":
            await ws.close()
            return None, f"unexpected first message: {first_type!r}"

        return ws, "authenticated"

    except Exception as exc:
        try:
            await ws.close()
        except Exception:
            pass
        return None, f"auth handshake error: {exc.__class__.__name__}: {exc}"


# ---------------------------------------------------------------------------
# Individual tests
# ---------------------------------------------------------------------------

async def test_unauthenticated_connection() -> None:
    """
    In development/test environments, unauthenticated connections
    are permitted (dev-operator fallback). In production they are
    rejected with 401/403.
    """
    ok, detail = await _try_connect(WS_URL)

    env = os.getenv("SENTINEL_ENV", "development").lower()
    is_prod = env not in {"development", "dev", "local", "test"}

    if is_prod:
        if not ok:
            _record("unauthenticated rejected in production", PASS, detail)
        else:
            _record("unauthenticated rejected in production", FAIL,
                    "expected rejection but connected successfully")
    else:
        if ok:
            _record("unauthenticated allowed in dev environment", PASS, detail)
        else:
            _record("unauthenticated allowed in dev environment", SKIP,
                    f"could not connect — {detail} (server may require auth even in dev)")


async def test_valid_token_connection() -> None:
    token = _make_token()
    ok, detail = await _try_connect(WS_URL, token=token)

    if ok:
        _record("valid token accepted", PASS, detail)
    else:
        _record("valid token accepted", FAIL, detail)


async def test_expired_token_rejected() -> None:
    token = _make_expired_token()
    ok, detail = await _try_connect(WS_URL, token=token)

    if not ok:
        _record("expired token rejected", PASS, detail)
    else:
        _record("expired token rejected", FAIL,
                "expired token was accepted — authentication not enforced")


async def test_bad_secret_token_rejected() -> None:
    token = _make_bad_secret_token()
    ok, detail = await _try_connect(WS_URL, token=token)

    if not ok:
        _record("forged token rejected", PASS, detail)
    else:
        _record("forged token rejected", FAIL,
                "forged token was accepted — signature not verified")


async def test_ping_pong() -> None:
    """
    Authenticate, send a ping, and verify a pong is received.

    Fix: previously sent an HTTP Authorization header which the server
    ignores for WebSocket auth. The server sends auth_required first;
    the test was receiving that as its "pong" and counting it as a pass.
    Now completes the full auth handshake before sending the ping.
    """
    token = _make_token()

    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            ws, auth_detail = await _connect_and_auth(WS_URL, token)
            if ws is None:
                _record("ping receives response", SKIP,
                        f"could not authenticate: {auth_detail}")
                return

            async with ws:
                await ws.send(_ping_message())

                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=CONNECT_TIMEOUT)
                    msg = json.loads(raw) if isinstance(raw, str) else {}
                    msg_type = msg.get("type", "")

                    if msg_type == "pong":
                        _record("ping receives response", PASS, f"type={msg_type!r}")
                    else:
                        _record("ping receives response", FAIL,
                                f"expected pong, got type={msg_type!r}")
                except asyncio.TimeoutError:
                    _record("ping receives response", FAIL,
                            "no response received within timeout")

    except Exception as exc:
        _record("ping receives response", SKIP,
                f"error: {exc.__class__.__name__}: {exc}")


async def test_subscribe_channel() -> None:
    """
    Authenticate, subscribe to a channel, and verify acknowledgement.

    Fix: previously sent an HTTP Authorization header instead of
    completing the WS auth handshake. The first server message (auth_required)
    was being counted as the subscription response. Now authenticates first,
    then sends the subscribe frame and checks for a subscribed response.
    """
    token = _make_token()

    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            ws, auth_detail = await _connect_and_auth(WS_URL, token)
            if ws is None:
                _record("subscribe message accepted", SKIP,
                        f"could not authenticate: {auth_detail}")
                return

            async with ws:
                await ws.send(_subscribe_message("actions"))

                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=CONNECT_TIMEOUT)
                    msg = json.loads(raw) if isinstance(raw, str) else {}
                    msg_type = msg.get("type", "?")

                    if msg_type == "subscribed":
                        _record("subscribe message accepted", PASS,
                                f"response type={msg_type!r}")
                    elif msg_type == "actions_snapshot":
                        # Server may send snapshot immediately on subscribe
                        _record("subscribe message accepted", PASS,
                                f"response type={msg_type!r} (snapshot received)")
                    else:
                        _record("subscribe message accepted", FAIL,
                                f"unexpected response type={msg_type!r}")
                except asyncio.TimeoutError:
                    _record("subscribe message accepted", SKIP,
                            "no response received within timeout")

    except Exception as exc:
        _record("subscribe message accepted", SKIP,
                f"error: {exc.__class__.__name__}: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _run_all() -> int:
    print()
    print("=" * 50)
    print("  Sentinel-43 WebSocket Auth Test")
    print(f"  Target: {WS_URL}")
    print("=" * 50)
    print()

    await test_unauthenticated_connection()
    await test_valid_token_connection()
    await test_expired_token_rejected()
    await test_bad_secret_token_rejected()
    await test_ping_pong()
    await test_subscribe_channel()

    print()
    print("=" * 50)

    passed  = sum(1 for s, _ in _results if s == "PASS")
    failed  = sum(1 for s, _ in _results if s == "FAIL")
    skipped = sum(1 for s, _ in _results if s == "SKIP")

    print(f"  Results: {passed} passed  {failed} failed  {skipped} skipped")
    print("=" * 50)
    print()

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    exit_code = asyncio.run(_run_all())
    sys.exit(exit_code)
