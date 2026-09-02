# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================

"""
File: core/api/middleware/security_headers.py

Transport / response security headers (beta-execution Phase 2, F-TLS-1).

The reverse proxy / ingress in front of the API terminates TLS, redirects
HTTP -> HTTPS, and is the primary place `Strict-Transport-Security` is set
(deploy/proxy/nginx.conf, deploy/kubernetes/overlays/beta/ingress.yaml). This
middleware is **defence in depth** inside the app:

  * `Strict-Transport-Security` -- emitted only when the request actually
    reached the app over HTTPS (or via a trusted proxy that says so with
    `X-Forwarded-Proto: https`), and never in a local environment. A browser
    ignores HSTS received over plain HTTP anyway; gating it means a
    misconfigured plaintext production listener does not pin clients to a
    scheme it cannot serve.
  * `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` -- also
    set by SentinelFirewall; harmless to re-assert and covers responses the
    firewall's wrapped-send path does not touch.
  * `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
    `Permissions-Policy` -- static, safe hardening.
  * `Content-Security-Policy` -- opt-in via `S43_CONTENT_SECURITY_POLICY`
    (the dashboard uses dynamically-injected `<style>` elements, so a
    default-deny CSP would need `style-src 'unsafe-inline'`; left to the
    operator rather than guessed).

`X-Forwarded-Proto` is trusted ONLY when the immediate peer is inside
`S43_TRUSTED_PROXIES` (the same CIDR list SentinelFirewall uses for
`X-Forwarded-For`). With no trusted proxies configured the header is ignored
-- fail safe.

Cookies are always issued `Secure` regardless of the detected scheme
(AUTH_TLS_POSTURE_PASS5A §4/§8) -- the deployment guarantees HTTPS, the app
does not infer it.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Iterable, Optional

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_LOCAL_ENVIRONMENTS = frozenset({"development", "dev", "local", "test"})

_DEFAULT_HSTS_MAX_AGE = 15552000  # 180 days
_STATIC_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-site"),
    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
)


def _is_local_environment() -> bool:
    return os.getenv("SENTINEL_ENV", "production").strip().lower() in _LOCAL_ENVIRONMENTS


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return max(0, int(raw.strip()))
    except ValueError:
        return default


def _env_bool(name: str) -> Optional[bool]:
    raw = os.getenv(name)
    if raw is None:
        return None
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _trusted_proxy_networks() -> list[ipaddress._BaseNetwork]:
    raw = os.getenv("S43_TRUSTED_PROXIES", "")
    nets: list[ipaddress._BaseNetwork] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return nets


def _peer_is_trusted_proxy(scope: Scope) -> bool:
    nets = _trusted_proxy_networks()
    if not nets:
        return False
    client = scope.get("client")
    if not (isinstance(client, (list, tuple)) and client):
        return False
    try:
        addr = ipaddress.ip_address(str(client[0]))
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _header_value(headers: Iterable[tuple[bytes, bytes]], name: bytes) -> Optional[bytes]:
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def _effective_scheme(scope: Scope) -> str:
    scheme = str(scope.get("scheme") or "http").lower()
    if _peer_is_trusted_proxy(scope):
        xfp = _header_value(scope.get("headers") or [], b"x-forwarded-proto")
        if xfp:
            first = xfp.decode("latin-1").split(",")[0].strip().lower()
            if first in {"http", "https"}:
                return first
    return scheme


class SecurityHeadersMiddleware:
    """Adds transport-security response headers. Read config at call time so a
    test / restart picks up env changes without a reload."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        secure = _effective_scheme(scope) == "https"
        local = _is_local_environment()

        force_hsts = _env_bool("S43_HSTS_FORCE")
        disable_hsts = _env_bool("S43_HSTS_DISABLE")
        emit_hsts = (
            not disable_hsts
            and not local
            and (secure or force_hsts is True)
        )
        max_age = _env_int("S43_HSTS_MAX_AGE", _DEFAULT_HSTS_MAX_AGE)
        csp = os.getenv("S43_CONTENT_SECURITY_POLICY", "").strip()

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {k.lower() for k, _ in headers}
                for name, value in _STATIC_HEADERS:
                    if name not in present:
                        headers.append((name, value))
                if emit_hsts and b"strict-transport-security" not in present:
                    headers.append((
                        b"strict-transport-security",
                        f"max-age={max_age}; includeSubDomains".encode("ascii"),
                    ))
                if csp and b"content-security-policy" not in present:
                    headers.append((b"content-security-policy", csp.encode("latin-1")))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, _send)


__all__ = ["SecurityHeadersMiddleware"]
