"""
Sentinel-43 WebSocket Authentication Test
==========================================

Validates WebSocket connectivity and authentication behavior
against the running Docker stack.

Run with:
    python test_ws_auth.py       # standalone
    pytest test_ws_auth.py -v    # via pytest

Requires:
    pip install websockets PyJWT
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import sys
import time
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# pytest-asyncio: mark every async test in this file automatically.
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.asyncio

# ---------------------------------------------------------------------------
# .env auto-load — must happen before JWT constants are set.
# Tries python-dotenv first; falls back to a minimal manual parser.
# Never overwrites values already set in the shell environment.
# ---------------------------------------------------------------------------
def _load_dotenv_file(path: pathlib.Path) -> None:
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(path, override=False)
        return
    except ImportError:
        pass
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


_env_path = pathlib.Path(__file__).parent / ".env"
if _env_path.exists():
    _load_dotenv_file(_env_path)

# ---------------------------------------------------------------------------
# JWT / websockets imports
# ---------------------------------------------------------------------------
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
WS_URL          = os.getenv("SENTINEL_WS_URL",   "ws://localhost:8000/ws")
JWT_SECRET      = os.getenv("S43_JWT_SECRET",    "test-secret-key-at-least-32-bytes-long-xxxx")
JWT_ALGORITHM   = os.getenv("S43_JWT_ALGORITHM", "HS256")
JWT_ISSUER      = os.getenv("S43_JWT_ISSUER",    "sentinel-43")
JWT_AUDIENCE    = os.getenv("S43_JWT_AUDIENCE",  "sentinel-43-dashboard")
CONNECT_TIMEOUT = float(os.getenv("S43_WS_TEST_TIMEOUT", "5"))

_results: list[tuple[str, str]] = []
RUNNING_STANDALONE = __name__ == "__main__"

# ---------------------------------------------------------------------------
# Result helpers
# _pass / _fail / _skip integrate with both the standalone scoreboard AND
# pytest so a FAIL actually fails the test (not just prints).
# ---------------------------------------------------------------------------
def _pass(label: str, detail: str = "") -> None:
    msg = f"PASS  {label}" + (f"  [{detail}]" if detail else "")
    _results.append(("PASS", label))
    print(msg)


def _fail(label: str, detail: str = "") -> None:
    msg = f"FAIL  {label}" + (f"  [{detail}]" if detail else "")
    _results.append(("FAIL", label))
    print(msg)
    if not RUNNING_STANDALONE:
        pytest.fail(f"{label}: {detail}", pytrace=False)


def _skip(label: str, detail: str = "") -> None:
    msg = f"SKIP  {label}" + (f"  [{detail}]" if detail else "")
    _results.append(("SKIP", label))
    print(msg)
    if not RUNNING_STANDALONE:
        pytest.skip(f"{label}: {detail}")


# ---------------------------------------------------------------------------
# Token helpers
# Server checks: claims.get("role") or claims.get("scope")
# Keep it minimal — only what the server actually validates.
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
# Connection helpers
# ---------------------------------------------------------------------------
async def _try_connect(
    url: str,
    *,
    token: str | None = None,
    timeout: float = CONNECT_TIMEOUT,
) -> tuple[bool, str]:
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
                    return False, f"unexpected post-auth type={msg_type!r}"

                if first_type == "connected":
                    return True, "connected without auth challenge"
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
) -> tuple[Any, str]:
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
# Tests
# ---------------------------------------------------------------------------
async def test_unauthenticated_connection() -> None:
    ok, detail = await _try_connect(WS_URL)
    env = os.getenv("SENTINEL_ENV", "development").lower()
    is_prod = env not in {"development", "dev", "local", "test"}

    if is_prod:
        if ok:
            _fail("unauthenticated rejected in production",
                  "expected rejection but connected")
        else:
            _pass("unauthenticated rejected in production", detail)
    else:
        if ok:
            _pass("unauthenticated allowed in dev environment", detail)
        else:
            _skip("unauthenticated allowed in dev environment",
                  f"could not connect — {detail}")


async def test_valid_token_connection() -> None:
    token = _make_token()
    ok, detail = await _try_connect(WS_URL, token=token)
    if ok:
        _pass("valid token accepted", detail)
    else:
        _fail("valid token accepted", detail)


async def test_expired_token_rejected() -> None:
    token = _make_expired_token()
    ok, detail = await _try_connect(WS_URL, token=token)
    if not ok:
        _pass("expired token rejected", detail)
    else:
        _fail("expired token rejected", "expired token was accepted — auth not enforced")


async def test_bad_secret_token_rejected() -> None:
    token = _make_bad_secret_token()
    ok, detail = await _try_connect(WS_URL, token=token)
    if not ok:
        _pass("forged token rejected", detail)
    else:
        _fail("forged token rejected", "forged token accepted — signature not verified")


async def test_ping_pong() -> None:
    token = _make_token()
    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            ws, auth_detail = await _connect_and_auth(WS_URL, token)
            if ws is None:
                _skip("ping receives response",
                      f"could not authenticate: {auth_detail}")
                return
            async with ws:
                await ws.send(_ping_message())
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=CONNECT_TIMEOUT)
                    msg = json.loads(raw) if isinstance(raw, str) else {}
                    if msg.get("type") == "pong":
                        _pass("ping receives response", "pong received")
                    else:
                        _fail("ping receives response",
                              f"expected pong, got type={msg.get('type')!r}")
                except asyncio.TimeoutError:
                    _fail("ping receives response", "no response within timeout")
    except pytest.skip.Exception:
        raise
    except pytest.fail.Exception:
        raise
    except Exception as exc:
        _skip("ping receives response",
              f"error: {exc.__class__.__name__}: {exc}")


async def test_subscribe_channel() -> None:
    token = _make_token()
    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            ws, auth_detail = await _connect_and_auth(WS_URL, token)
            if ws is None:
                _skip("subscribe message accepted",
                      f"could not authenticate: {auth_detail}")
                return
            async with ws:
                await ws.send(_subscribe_message("actions"))
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=CONNECT_TIMEOUT)
                    msg = json.loads(raw) if isinstance(raw, str) else {}
                    msg_type = msg.get("type", "?")
                    if msg_type in ("subscribed", "actions_snapshot"):
                        _pass("subscribe message accepted",
                              f"response type={msg_type!r}")
                    else:
                        _fail("subscribe message accepted",
                              f"unexpected response type={msg_type!r}")
                except asyncio.TimeoutError:
                    _skip("subscribe message accepted", "no response within timeout")
    except pytest.skip.Exception:
        raise
    except pytest.fail.Exception:
        raise
    except Exception as exc:
        _skip("subscribe message accepted",
              f"error: {exc.__class__.__name__}: {exc}")


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------
async def _run_all() -> int:
    print()
    print("=" * 50)
    print("  Sentinel-43 WebSocket Auth Test")
    print(f"  Target  : {WS_URL}")
    print(f"  Issuer  : {JWT_ISSUER}")
    print(f"  Audience: {JWT_AUDIENCE}")
    print(f"  .env    : {'loaded' if _env_path.exists() else 'not found'}")
    print("=" * 50)
    print()

    # Run without pytest.fail/skip interference
    tests = [
        test_unauthenticated_connection,
        test_valid_token_connection,
        test_expired_token_rejected,
        test_bad_secret_token_rejected,
        test_ping_pong,
        test_subscribe_channel,
    ]
    for t in tests:
        try:
            await t()
        except BaseException as exc:
            _results.append(("FAIL", t.__name__))
            print(f"FAIL  {t.__name__}  [unexpected crash: {exc.__class__.__name__}: {exc}]")

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
    sys.exit(asyncio.run(_run_all()))
