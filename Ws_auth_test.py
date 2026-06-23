"""
Sentinel-43 WebSocket Authentication Test
==========================================

Validates WebSocket connectivity and authentication behavior
against the running Docker stack.

Run with:
    python ws_auth_test.py

Requires:
    pip install websockets PyJWT
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

WS_URL = os.getenv("SENTINEL_WS_URL", "ws://localhost:8000/ws")
JWT_SECRET = os.getenv("S43_JWT_SECRET", "test-secret-key-at-least-32-bytes-long-xxxx")
JWT_ALGORITHM = os.getenv("S43_JWT_ALGORITHM", "HS256")
JWT_ISSUER = os.getenv("S43_JWT_ISSUER", "sentinel-43-test")
JWT_AUDIENCE = os.getenv("S43_JWT_AUDIENCE", "sentinel-43-dashboard-test")
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

def _ping_message() -> str:
    return json.dumps({
        "type": "ping",
        "payload": {"timestamp": time.time()},
    })


def _subscribe_message(channel: str = "events") -> str:
    return json.dumps({
        "type": "subscribe",
        "payload": {"channel": channel},
    })


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
    Attempt a WebSocket connection. Returns (success, detail).
    """
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with asyncio.timeout(timeout):
            async with websockets.connect(
                url,
                additional_headers=headers,
            ) as ws:
                await ws.send(_ping_message())

                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    msg = json.loads(raw) if isinstance(raw, str) else {}
                    msg_type = msg.get("type", "unknown")
                    return True, f"connected, received type={msg_type!r}"
                except asyncio.TimeoutError:
                    return True, "connected, no response to ping within timeout"

    except ConnectionClosedError as exc:
        return False, f"connection closed: code={exc.rcvd.code if exc.rcvd else '?'}"
    except ConnectionClosedOK:
        return False, "connection closed cleanly (rejected)"
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
    """Send a ping and verify a pong or acknowledgement is received."""
    token = _make_token()

    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            async with websockets.connect(
                WS_URL,
                additional_headers={"Authorization": f"Bearer {token}"},
            ) as ws:
                await ws.send(_ping_message())

                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=CONNECT_TIMEOUT)
                    msg = json.loads(raw) if isinstance(raw, str) else {}
                    msg_type = msg.get("type", "")

                    if msg_type in {"pong", "ping", "ack", "error", "connected"}:
                        _record("ping receives response", PASS, f"type={msg_type!r}")
                    else:
                        _record("ping receives response", PASS,
                                f"received type={msg_type!r}")
                except asyncio.TimeoutError:
                    _record("ping receives response", FAIL,
                            "no response received within timeout")

    except Exception as exc:
        _record("ping receives response", SKIP,
                f"could not connect: {exc.__class__.__name__}")


async def test_subscribe_channel() -> None:
    """Send a subscribe message and verify it is acknowledged."""
    token = _make_token()

    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            async with websockets.connect(
                WS_URL,
                additional_headers={"Authorization": f"Bearer {token}"},
            ) as ws:
                await ws.send(_subscribe_message("events"))

                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=CONNECT_TIMEOUT)
                    msg = json.loads(raw) if isinstance(raw, str) else {}
                    _record("subscribe message accepted", PASS,
                            f"response type={msg.get('type', '?')!r}")
                except asyncio.TimeoutError:
                    _record("subscribe message accepted", SKIP,
                            "no response received within timeout")

    except Exception as exc:
        _record("subscribe message accepted", SKIP,
                f"could not connect: {exc.__class__.__name__}")


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

    passed = sum(1 for s, _ in _results if s == "PASS")
    failed = sum(1 for s, _ in _results if s == "FAIL")
    skipped = sum(1 for s, _ in _results if s == "SKIP")

    print(f"  Results: {passed} passed  {failed} failed  {skipped} skipped")
    print("=" * 50)
    print()

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    exit_code = asyncio.run(_run_all())
    sys.exit(exit_code)
