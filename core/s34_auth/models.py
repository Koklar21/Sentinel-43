# =============================================================================
# Sentinel-43 Security Platform
# =============================================================================
#
# Copyright (c) 2026 Justin
# All rights reserved.
#
# This file is part of the Sentinel-43 security, audit, and orchestration system.
#
# =============================================================================
# LICENSE (DUAL LICENSE MODEL)
# =============================================================================
#
# OPEN SOURCE LICENSE OPTION (AGPLv3):
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See the GNU Affero General Public License for more details:
#
# https://www.gnu.org/licenses/agpl-3.0.html
#
#
# COMMERCIAL LICENSE OPTION:
#
# This file may alternatively be used under the terms of a commercial license
# issued by the copyright holder.
#
# Commercial licenses allow private use, modification, and distribution
# without the copyleft requirements of the AGPL.
#
# For commercial licensing inquiries, contact:
#
# licensing@sentinel43.io
#
#
# =============================================================================
# FILE INFORMATION
# =============================================================================
#
# Project: Sentinel-43
# Component: <COMPONENT_NAME>
# File: <FILE_NAME>
#
# Description:
# <SHORT_DESCRIPTION_OF_FILE_PURPOSE>
#
# Author: Justin
# Created: 2026
# Last Modified: <YYYY-MM-DD>
#
# =============================================================================
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import FrozenSet, Optional, Literal
import re
import uuid


# -----------------------------
# Helpers
# -----------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def require_tz_aware(dt: datetime, field_name: str) -> None:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{field_name} must be timezone-aware (UTC recommended)")

def normalize_roles(roles) -> FrozenSet[str]:
    # Accept set/frozenset/iterable, normalize, strip, dedupe, drop empties.
    frozen = frozenset(r.strip() for r in roles if isinstance(r, str) and r.strip())
    return frozen

# A simple “token hash must look like a hash digest” check.
# Not perfect, but it blocks the classic “oops I stored the raw token” footgun.
_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")  # md5..sha512 range


# -----------------------------
# Auth Identity
# -----------------------------

@dataclass(frozen=True, slots=True)
class AuthContext:
    """
    Represents authenticated identity (immutable, safe to share)
    """
    subject_id: str
    device_id: Optional[str]
    roles: FrozenSet[str]
    issued_at: datetime
    expires_at: datetime
    issuer: str

    def __post_init__(self) -> None:
        if not self.subject_id.strip():
            raise ValueError("subject_id is required")
        if not self.issuer.strip():
            raise ValueError("issuer is required")

        require_tz_aware(self.issued_at, "issued_at")
        require_tz_aware(self.expires_at, "expires_at")

        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")

        # Roles must be frozen, non-empty strings. Normalize defensively.
        object.__setattr__(self, "roles", normalize_roles(self.roles))


@dataclass(frozen=True, slots=True)
class AuthResult:
    """
    Result of auth verification. Enforces coherent states:
    - success=True => context present, reason empty/None
    - success=False => context None, reason present
    """
    success: bool
    context: Optional[AuthContext] = None
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.success:
            if self.context is None:
                raise ValueError("success=True requires context")
            # If you succeeded, a reason is noise (and a security leak risk)
            if self.reason:
                raise ValueError("success=True must not include reason")
        else:
            if self.context is not None:
                raise ValueError("success=False must not include context")
            if not (self.reason and self.reason.strip()):
                raise ValueError("success=False requires a non-empty reason")


# -----------------------------
# Token/Key Usage Audit
# -----------------------------

@dataclass(frozen=True, slots=True)
class TokenHash:
    """
    Structured token hash descriptor to prevent raw token logging mistakes.
    Example:
        TokenHash(alg="sha256", digest="ab12...ff")
    """
    alg: Literal["sha256", "sha384", "sha512"]
    digest: str  # hex digest

    def __post_init__(self) -> None:
        if not _HEX_RE.match(self.digest):
            raise ValueError("TokenHash.digest must be a hex digest (32-128 hex chars)")


@dataclass(slots=True)
class KeyUsageRecord:
    """
    Immutable-ish audit record of key usage.
    Defaults are safe: validity is NOT assumed.
    """
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # WHO
    subject_id: str = field(default="")
    device_id: Optional[str] = None
    issuer: str = field(default="")

    # WHAT
    key_id: str = field(default="")
    token_hash: TokenHash = field(default=None)  # required, validated
    auth_method: str = field(default="HMAC")

    # WHEN
    issued_at: datetime = field(default_factory=utc_now)
    used_at: datetime = field(default_factory=utc_now)
    expires_at: Optional[datetime] = None

    # WHERE
    source_ip: Optional[str] = None
    node_id: Optional[str] = None
    service: Optional[str] = None

    # STATE
    valid: bool = False
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        # Required identity fields
        if not self.subject_id.strip():
            raise ValueError("subject_id is required")
        if not self.issuer.strip():
            raise ValueError("issuer is required")
        if not self.key_id.strip():
            raise ValueError("key_id is required")

        if self.token_hash is None:
            raise ValueError("token_hash is required (TokenHash)")
        if not isinstance(self.token_hash, TokenHash):
            raise TypeError("token_hash must be a TokenHash instance")

        # Time sanity
        require_tz_aware(self.issued_at, "issued_at")
        require_tz_aware(self.used_at, "used_at")

        if self.expires_at is not None:
            require_tz_aware(self.expires_at, "expires_at")
            if self.expires_at <= self.issued_at:
                raise ValueError("expires_at must be after issued_at")
            if self.used_at > self.expires_at and self.valid:
                raise ValueError("used_at after expires_at cannot be valid=True")

        # Valid/reason coherence
        if self.valid:
            # If valid, reason should be empty (keeps logs clean, avoids confusion)
            if self.reason:
                raise ValueError("valid=True must not include reason")
        else:
            # If invalid and no reason, you just created an audit record with zero forensic value.
            if not (self.reason and self.reason.strip()):
                raise ValueError("valid=False requires a non-empty reason")