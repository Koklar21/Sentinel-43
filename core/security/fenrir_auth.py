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

"""Fenrir authorization helpers.

Fenrir does not own authentication or JWT issuance.

Authentication must be completed by the canonical Sentinel-43 auth/session
layer before these helpers are called. This module only evaluates an already
authenticated identity and its granted scopes/roles for Fenrir operations.

No environment reads.
No JWT creation.
No JWT decoding.
No pseudo-subjects.
No auth-disabled bypass.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


class FenrirAuthorizationError(RuntimeError):
    """Raised when an authenticated identity lacks Fenrir authorization."""


@dataclass(frozen=True, slots=True)
class FenrirPrincipal:
    subject: str
    scopes: frozenset[str]
    roles: frozenset[str]
    claims: Mapping[str, Any]

    def __post_init__(self) -> None:
        subject = str(
            self.subject
        ).strip()

        if not subject:
            raise ValueError(
                "subject must not be empty"
            )

        scopes = frozenset(
            str(scope).strip()
            for scope in self.scopes
            if str(scope).strip()
        )

        roles = frozenset(
            str(role).strip()
            for role in self.roles
            if str(role).strip()
        )

        object.__setattr__(
            self,
            "subject",
            subject,
        )

        object.__setattr__(
            self,
            "scopes",
            scopes,
        )

        object.__setattr__(
            self,
            "roles",
            roles,
        )

        object.__setattr__(
            self,
            "claims",
            MappingProxyType(
                dict(
                    self.claims
                )
            ),
        )

    def has_scope(
        self,
        scope: str,
    ) -> bool:
        normalized = str(
            scope
        ).strip()

        if not normalized:
            raise ValueError(
                "scope must not be empty"
            )

        return (
            normalized in self.scopes
            or "*" in self.scopes
        )

    def has_role(
        self,
        role: str,
    ) -> bool:
        normalized = str(
            role
        ).strip()

        if not normalized:
            raise ValueError(
                "role must not be empty"
            )

        return normalized in self.roles


def principal_from_authenticated_claims(
    claims: Mapping[str, Any],
    *,
    roles: frozenset[str] | set[str] | tuple[str, ...] = (),
) -> FenrirPrincipal:
    """Build a Fenrir principal from already-validated canonical auth claims."""
    if not isinstance(
        claims,
        Mapping,
    ):
        raise TypeError(
            "claims must be a mapping"
        )

    subject = claims.get(
        "sub"
    )

    if not isinstance(
        subject,
        str,
    ) or not subject.strip():
        raise FenrirAuthorizationError(
            "authenticated claims are missing a valid subject"
        )

    raw_scope = claims.get(
        "scope",
        "",
    )

    scopes: frozenset[str]

    if isinstance(
        raw_scope,
        str,
    ):
        scopes = frozenset(
            part
            for part in raw_scope.split()
            if part
        )

    elif isinstance(
        raw_scope,
        (
            list,
            tuple,
            set,
            frozenset,
        ),
    ):
        scopes = frozenset(
            str(
                part
            ).strip()
            for part in raw_scope
            if str(
                part
            ).strip()
        )

    else:
        raise FenrirAuthorizationError(
            "authenticated claims contain an invalid scope value"
        )

    return FenrirPrincipal(
        subject=subject,
        scopes=scopes,
        roles=frozenset(
            roles
        ),
        claims=claims,
    )


def require_fenrir_scope(
    principal: FenrirPrincipal,
    required_scope: str,
) -> None:
    if not isinstance(
        principal,
        FenrirPrincipal,
    ):
        raise TypeError(
            "principal must be FenrirPrincipal"
        )

    if not principal.has_scope(
        required_scope
    ):
        raise FenrirAuthorizationError(
            "authenticated principal lacks required Fenrir scope"
        )


def require_fenrir_role(
    principal: FenrirPrincipal,
    required_role: str,
) -> None:
    if not isinstance(
        principal,
        FenrirPrincipal,
    ):
        raise TypeError(
            "principal must be FenrirPrincipal"
        )

    if not principal.has_role(
        required_role
    ):
        raise FenrirAuthorizationError(
            "authenticated principal lacks required Fenrir role"
        )


def extract_bearer_token(
    header_value: str | None,
) -> str | None:
    """Extract a raw bearer token for forwarding to canonical auth verification."""
    if not isinstance(
        header_value,
        str,
    ):
        return None

    scheme, separator, token = header_value.partition(
        " "
    )

    if (
        not separator
        or scheme.lower()
        != "bearer"
    ):
        return None

    cleaned = token.strip()

    return cleaned or None


__all__ = [
    "FenrirAuthorizationError",
    "FenrirPrincipal",
    "extract_bearer_token",
    "principal_from_authenticated_claims",
    "require_fenrir_role",
    "require_fenrir_scope",
]
