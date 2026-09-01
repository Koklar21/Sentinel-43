# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is distributed under a dual-license model:
#   1. GNU Affero General Public License (AGPL v3.0)
#   2. Commercial License
# =============================================================================
#
# core/tests/test_firewall_proxy_trust.py
#
# Pass 2 — trusted-proxy / X-Forwarded-For handling in SentinelFirewall
# (core/api/middleware/sentinel_firewall_middleware.py::_resolve_client_ip).
#
# Exercises the middleware as a real ASGI app (crafted http scope ->
# await fw(scope, receive, send)) and reads back scope["state"]["s43_client_ip"]
# (set by _attach_state via _resolve_client_ip), plus the actual allow/block
# decision, rather than unit-testing a parser in isolation.
#
# Invariant under test (was RELEASE_FINDINGS #7, only partially closed by
# 3f65ca1 which fixed the env->field plumbing but not the resolution logic):
#
#   trusted_proxy_cidrs == ()   =>   NO forwarded header is believed;
#                                    every request is its direct TCP peer.
#
# An empty trusted-proxy list must mean "trust nobody", not "trust everybody".
# =============================================================================

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# Import the concrete implementation directly. Going through the
# `core.middleware` package __init__ before core.api.main is imported can hit
# an import-order cycle; these tests don't need from_env().
from core.api.middleware.sentinel_firewall_middleware import (
    FirewallConfig,
    SentinelFirewall,
)


async def _ok_app(scope: dict, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok", "more_body": False})


def _scope(client_ip: str, headers: list[tuple[str, str]] | None = None,
           *, path: str = "/", method: str = "GET") -> dict:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1"))
                   for k, v in (headers or [])]
    return {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": raw_headers,
        "client": (client_ip, 44444),
        "server": ("testserver", 8000),
        "scheme": "http",
        "state": {},
    }


def _run(fw: SentinelFirewall, scope: dict) -> tuple[str | None, int | None]:
    sent: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(fw(scope, receive, send))
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    return scope["state"].get("s43_client_ip"), status


@pytest.fixture
def no_trusted() -> SentinelFirewall:
    # Default posture: no trusted proxies, no allow/block lists.
    return SentinelFirewall(app=_ok_app, config=FirewallConfig())


@pytest.fixture
def trust_10() -> SentinelFirewall:
    return SentinelFirewall(
        app=_ok_app,
        config=FirewallConfig(trusted_proxy_cidrs=("10.0.0.0/8",)),
    )


# ---------------------------------------------------------------------------
# Empty trusted-proxy list => trust nobody
# ---------------------------------------------------------------------------

def test_direct_no_forwarding_header(no_trusted):
    ip, status = _run(no_trusted, _scope("203.0.113.7"))
    assert ip == "203.0.113.7"
    assert status == 200


def test_xff_from_untrusted_peer_is_ignored(no_trusted):
    # THE regression: with trusted_proxy_cidrs==() this used to return 9.9.9.9.
    ip, _ = _run(no_trusted, _scope("203.0.113.7", [("x-forwarded-for", "9.9.9.9")]))
    assert ip == "203.0.113.7"


def test_forwarded_rfc7239_header_is_ignored(no_trusted):
    ip, _ = _run(no_trusted, _scope("203.0.113.7", [("forwarded", "for=9.9.9.9")]))
    assert ip == "203.0.113.7"


def test_xff_present_but_peer_not_in_trusted_list(trust_10):
    ip, _ = _run(trust_10, _scope("203.0.113.7", [("x-forwarded-for", "9.9.9.9")]))
    assert ip == "203.0.113.7"


# ---------------------------------------------------------------------------
# Spoof cannot defeat IP allow / block once the resolver is honest
# ---------------------------------------------------------------------------

def test_spoofed_xff_cannot_evade_ip_block():
    fw = SentinelFirewall(
        app=_ok_app,
        config=FirewallConfig(blocked_ip_cidrs=("203.0.113.7/32",)),
    )
    # Blocked peer tries to look like someone else.
    ip, status = _run(fw, _scope("203.0.113.7", [("x-forwarded-for", "8.8.8.8")]))
    assert ip == "203.0.113.7"
    assert status == 403


def test_spoofed_xff_cannot_forge_allowlist_membership():
    fw = SentinelFirewall(
        app=_ok_app,
        config=FirewallConfig(allowed_ip_cidrs=("10.0.0.0/8",)),
    )
    ip, status = _run(fw, _scope("203.0.113.7", [("x-forwarded-for", "10.0.0.5")]))
    assert ip == "203.0.113.7"
    assert status == 403  # IP_NOT_ALLOWED


# ---------------------------------------------------------------------------
# Trusted proxy: single hop, multi hop, mixed chain
# ---------------------------------------------------------------------------

def test_trusted_single_hop(trust_10):
    ip, _ = _run(trust_10, _scope("10.0.0.9", [("x-forwarded-for", "203.0.113.7")]))
    assert ip == "203.0.113.7"


def test_trusted_multi_hop_peels_trusted_proxies(trust_10):
    ip, _ = _run(trust_10, _scope("10.0.0.9",
                                  [("x-forwarded-for", "203.0.113.7, 10.0.0.2")]))
    assert ip == "203.0.113.7"


def test_mixed_chain_drops_client_prepended_entries(trust_10):
    # Client prepended 1.2.3.4; only the right-hand trusted segment is real.
    ip, _ = _run(trust_10, _scope("10.0.0.9",
                                  [("x-forwarded-for", "1.2.3.4, 203.0.113.7, 10.0.0.2")]))
    assert ip == "203.0.113.7"


def test_whole_chain_trusted_falls_back_to_direct(trust_10):
    ip, _ = _run(trust_10, _scope("10.0.0.9",
                                  [("x-forwarded-for", "10.0.0.2, 10.0.0.3")]))
    assert ip == "10.0.0.9"


def test_malformed_rightmost_entry_bails_to_direct(trust_10):
    ip, _ = _run(trust_10, _scope("10.0.0.9",
                                  [("x-forwarded-for", "203.0.113.7, garbage")]))
    assert ip == "10.0.0.9"


def test_malformed_only_entry_bails_to_direct(trust_10):
    ip, _ = _run(trust_10, _scope("10.0.0.9", [("x-forwarded-for", "not-an-ip")]))
    assert ip == "10.0.0.9"


def test_empty_xff_from_trusted_peer(trust_10):
    ip, _ = _run(trust_10, _scope("10.0.0.9", [("x-forwarded-for", "   ,  ")]))
    assert ip == "10.0.0.9"


# ---------------------------------------------------------------------------
# respect_x_forwarded_for master switch
# ---------------------------------------------------------------------------

def test_respect_disabled_ignores_xff_even_from_trusted_peer():
    fw = SentinelFirewall(
        app=_ok_app,
        config=FirewallConfig(trusted_proxy_cidrs=("10.0.0.0/8",),
                              respect_x_forwarded_for=False),
    )
    ip, _ = _run(fw, _scope("10.0.0.9", [("x-forwarded-for", "203.0.113.7")]))
    assert ip == "10.0.0.9"


# ---------------------------------------------------------------------------
# IPv4 / IPv6 / IPv4-mapped-IPv6
# ---------------------------------------------------------------------------

def test_ipv6_direct_peer(no_trusted):
    ip, _ = _run(no_trusted, _scope("2001:db8::1",
                                    [("x-forwarded-for", "9.9.9.9")]))
    assert ip == "2001:db8::1"


def test_ipv6_trusted_proxy_forwards_ipv4_client():
    fw = SentinelFirewall(
        app=_ok_app,
        config=FirewallConfig(trusted_proxy_cidrs=("2001:db8::/32",)),
    )
    ip, _ = _run(fw, _scope("2001:db8::5", [("x-forwarded-for", "203.0.113.7")]))
    assert ip == "203.0.113.7"


def test_ipv4_mapped_ipv6_client_from_trusted_proxy(trust_10):
    ip, _ = _run(trust_10, _scope("10.0.0.9",
                                  [("x-forwarded-for", "::ffff:203.0.113.7")]))
    # normalized textual form
    assert ip in ("::ffff:203.0.113.7", "::ffff:cb00:7107")


# ---------------------------------------------------------------------------
# Duplicate / multi X-Forwarded-For headers
# ---------------------------------------------------------------------------

def test_multiple_xff_headers_first_wins_and_only_from_trusted(trust_10):
    # _first_header takes the first occurrence; still only honored because the
    # direct peer is trusted.
    scope = _scope("10.0.0.9", [
        ("x-forwarded-for", "203.0.113.7"),
        ("x-forwarded-for", "6.6.6.6"),
    ])
    ip, _ = _run(trust_10, scope)
    assert ip == "203.0.113.7"


def test_multiple_xff_headers_ignored_when_untrusted(no_trusted):
    scope = _scope("203.0.113.7", [
        ("x-forwarded-for", "1.1.1.1"),
        ("x-forwarded-for", "6.6.6.6"),
    ])
    ip, _ = _run(no_trusted, scope)
    assert ip == "203.0.113.7"


# ---------------------------------------------------------------------------
# Header casing / whitespace
# ---------------------------------------------------------------------------

def test_header_casing_and_whitespace(trust_10):
    ip, _ = _run(trust_10, _scope("10.0.0.9",
                                  [("X-Forwarded-For", "  203.0.113.7  , 10.0.0.2 ")]))
    assert ip == "203.0.113.7"


__all__: list[str] = []
