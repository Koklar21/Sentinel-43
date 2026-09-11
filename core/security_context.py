# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""The canonical per-request security context.

SentinelFirewall establishes exactly one :class:`SecurityContext` per request,
after it has decided whether the request may proceed. Everything downstream
reads that trusted context instead of re-deriving the same facts from raw
headers.

Before this existed, three modules each re-implemented client-IP resolution
with subtly different fallbacks (``core.api.routers.auth``,
``core.api.routers.remote_gateway``, ``core.monitoring.sparta_core``): one
returned ``None`` when the peer was unknown, the others ``"unknown"``. Any
handler could also have read ``X-Forwarded-For`` directly and reached a
different answer than the firewall did -- the classic way a proxy-trust
boundary silently develops two opinions.

This module is a leaf on purpose:
    - no imports from ``core.api`` or ``core.monitoring`` (monitoring consumes
      it, so the dependency must point this way)
    - no environment reads, no I/O, no logging, no globals
    - the request object is duck-typed; nothing here depends on FastAPI

TRUST MODEL
    ``client_ip`` and ``via_trusted_proxy`` are the firewall's decision and are
    authoritative. A handler that disagrees is wrong. ``identity_type`` and
    ``principal_id`` start out anonymous and are narrowed by the authenticating
    verifier via :meth:`SecurityContext.authenticated_as`, which returns a new
    frozen instance -- provenance is never mutated in place.

SECRET SAFETY
    No field may hold credential material. ``principal_id`` is an identifier or
    a truncated digest, never a bearer token, password, or key. Nothing here
    redacts for you.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Final

#: Key under which the context is stored in the ASGI ``scope["state"]`` dict.
STATE_KEY: Final[str] = "s43_security"

#: Retained for compatibility: the firewall also publishes the resolved IP
#: under this key, which existing code and tests already read.
CLIENT_IP_STATE_KEY: Final[str] = "s43_client_ip"

#: Used when the peer address cannot be determined at all. A single sentinel,
#: rather than the three different answers the old resolvers gave.
UNKNOWN_CLIENT: Final[str] = "unknown"

#: Correlation/request identifiers are echoed into logs and audit records, so
#: an inbound value is accepted only if it is short and boring. Anything else
#: is replaced with a generated id rather than trusted.
_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex


def sanitize_correlation_id(value: str | None) -> str:
    """Accept a caller-supplied correlation id only if it is safe to log.

    A correlation id is a tracing aid, never a credential and never an
    authorization input, so accepting one from the client is fine -- but it
    lands in logs and audit records, so an unbounded or control-character
    value would be a log-injection vector. Anything failing the charset is
    discarded and a fresh id generated.
    """
    if not value:
        return new_id()
    candidate = value.strip()
    if not _ID_RE.fullmatch(candidate):
        return new_id()
    return candidate


class IdentityType(StrEnum):
    """Which class of caller authenticated this request.

    Human and service identities are deliberately distinct values: nothing in
    Sentinel-43 may treat a service token as an operator session or vice
    versa, and keeping them separate here makes a conflation visible.
    """

    ANONYMOUS = "anonymous"
    OPERATOR = "operator"
    SERVICE_API = "service:sentinel-api"
    SERVICE_WATCHTOWER = "service:watchtower"
    SERVICE_FENRIR = "service:fenrir"
    SERVICE_SPARTA_NODE = "service:sparta-node"
    SERVICE_REMOTE_GATEWAY = "service:remote-gateway"

    @property
    def is_service(self) -> bool:
        return self.value.startswith("service:")

    @property
    def is_human(self) -> bool:
        return self is IdentityType.OPERATOR


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Immutable, trusted facts about one request."""

    request_id: str
    correlation_id: str
    #: Firewall-resolved peer address, or ``UNKNOWN_CLIENT``.
    client_ip: str = UNKNOWN_CLIENT
    #: True only when the peer was inside a configured trusted-proxy CIDR and
    #: a forwarded header was therefore honoured.
    via_trusted_proxy: bool = False
    identity_type: IdentityType = IdentityType.ANONYMOUS
    #: Identifier or truncated digest. NEVER a credential.
    principal_id: str = ""
    firewall_allowed: bool = True
    firewall_reason: str = ""
    received_at: str = ""

    def __post_init__(self) -> None:
        if not self.request_id:
            object.__setattr__(self, "request_id", new_id())
        if not self.correlation_id:
            object.__setattr__(self, "correlation_id", self.request_id)
        if not str(self.client_ip).strip():
            object.__setattr__(self, "client_ip", UNKNOWN_CLIENT)
        if not self.received_at:
            object.__setattr__(self, "received_at", _utc_now())

    @property
    def authenticated(self) -> bool:
        return self.identity_type is not IdentityType.ANONYMOUS

    def authenticated_as(
        self,
        identity_type: IdentityType,
        principal_id: str = "",
    ) -> "SecurityContext":
        """Return a narrowed copy once a verifier has established identity.

        Returns a new instance: the firewall's findings (client_ip,
        via_trusted_proxy, the firewall decision) are carried forward
        unchanged and cannot be rewritten by a downstream handler.
        """
        return replace(
            self,
            identity_type=identity_type,
            principal_id=str(principal_id),
        )

    def to_dict(self) -> dict[str, Any]:
        """Log/audit-safe projection. Contains no credential material."""
        return {
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "client_ip": self.client_ip,
            "via_trusted_proxy": self.via_trusted_proxy,
            "identity_type": self.identity_type.value,
            "principal_id": self.principal_id,
            "firewall_allowed": self.firewall_allowed,
            "firewall_reason": self.firewall_reason,
            "received_at": self.received_at,
        }


def _state_of(request: Any) -> Any:
    return getattr(request, "state", None)


def get_security_context(request: Any) -> SecurityContext | None:
    """Return the context the firewall attached, or None if absent.

    Absent means the request did not traverse SentinelFirewall (a directly
    constructed test client, or an ASGI path that bypasses middleware).
    Callers must treat that as "no trusted context", never as "trusted".
    """
    state = _state_of(request)
    if state is None:
        return None
    context = getattr(state, STATE_KEY, None)
    return context if isinstance(context, SecurityContext) else None


def client_ip_of(request: Any) -> str:
    """The canonical client identity for rate limiting and audit.

    Resolution order, single definition for the whole codebase:
      1. the firewall's SecurityContext
      2. the firewall's legacy ``s43_client_ip`` state key
      3. the raw ASGI peer
      4. ``UNKNOWN_CLIENT``

    Never consults forwarded headers itself -- honouring those is the
    firewall's decision alone, and duplicating it here is exactly how a
    second, weaker proxy-trust boundary gets created.
    """
    context = get_security_context(request)
    if context is not None:
        return context.client_ip

    state = _state_of(request)
    if state is not None:
        legacy = getattr(state, CLIENT_IP_STATE_KEY, None)
        if isinstance(legacy, str) and legacy.strip():
            return legacy.strip()

    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client is not None else None
    if isinstance(host, str) and host.strip():
        return host.strip()

    return UNKNOWN_CLIENT


def correlation_id_of(request: Any) -> str:
    """Correlation id for this request, generating one if unavailable."""
    context = get_security_context(request)
    return context.correlation_id if context is not None else new_id()


def identity_of(request: Any) -> IdentityType:
    context = get_security_context(request)
    return context.identity_type if context is not None else IdentityType.ANONYMOUS


def attach_security_context(
    state: dict[str, Any],
    context: SecurityContext,
) -> None:
    """Publish the context into an ASGI ``scope["state"]`` mapping."""
    state[STATE_KEY] = context
    state[CLIENT_IP_STATE_KEY] = (
        None if context.client_ip == UNKNOWN_CLIENT else context.client_ip
    )


def set_identity(
    request: Any,
    identity_type: IdentityType,
    principal_id: str = "",
) -> SecurityContext | None:
    """Narrow the stored context after a verifier authenticated the caller.

    No-ops when the request carries no context (it did not pass the
    firewall), rather than fabricating a trusted one.
    """
    context = get_security_context(request)
    if context is None:
        return None

    updated = context.authenticated_as(identity_type, principal_id)
    state = _state_of(request)
    try:
        setattr(state, STATE_KEY, updated)
    except Exception:
        return context
    return updated


__all__ = [
    "CLIENT_IP_STATE_KEY",
    "IdentityType",
    "STATE_KEY",
    "SecurityContext",
    "UNKNOWN_CLIENT",
    "attach_security_context",
    "client_ip_of",
    "correlation_id_of",
    "get_security_context",
    "identity_of",
    "new_id",
    "sanitize_correlation_id",
    "set_identity",
]
