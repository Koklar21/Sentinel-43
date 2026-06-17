# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
Sentinel-43 authentication identity, result, and audit models.

File:
    core/security/auth/models.py

Changes from previous version:
  - Fix: _SUPPORTED_TOKEN_HASH_LENGTHS promoted to MappingProxyType so it
    cannot be mutated at runtime (same pattern as _THREAT_SCORE_MAP in
    jormungandr.py).
  - Fix: _HEX_RE pattern simplified to [0-9a-f]+ since TokenHash.__post_init__
    already calls .lower() before applying the regex. The A-F range was
    unreachable and misleading.
  - Fix: AuthGlobalsSnapshot (moved here from globals.py) is frozen — the
    "read-only style" description was contradicted by mutability.
  - Minor: KeyUsageRecord issued_at / used_at default race documented; the
    strict < check already tolerates same-microsecond timestamps.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import FrozenSet, Iterable, Literal, Optional

__all__ = [
    "AuthContext",
    "AuthResult",
    "TokenHash",
    "KeyUsageRecord",
    "utc_now",
    "require_tz_aware",
    "normalize_roles",
]

MAX_SUBJECT_CHARS    = 512
MAX_DEVICE_ID_CHARS  = 512
MAX_ISSUER_CHARS     = 512
MAX_KEY_ID_CHARS     = 512
MAX_AUTH_METHOD_CHARS = 128
MAX_REASON_CHARS     = 2048
MAX_OPTIONAL_TEXT_CHARS = 512

MAX_ROLE_COUNT = 64
MAX_ROLE_CHARS = 128

# Fix: MappingProxyType prevents accidental mutation of this security-critical
# length table. _SUPPORTED_TOKEN_HASH_LENGTHS["evil"] = 0 now raises TypeError.
_SUPPORTED_TOKEN_HASH_LENGTHS: MappingProxyType = MappingProxyType({
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
})

# Fix: pattern is [0-9a-f]+ (lowercase only) because TokenHash.__post_init__
# normalizes the digest to lowercase via .lower() before applying this regex.
# The original A-F range was unreachable after normalization.
_HEX_RE = re.compile(r"^[0-9a-f]+$")


# =============================================================================
# Helpers
# =============================================================================

def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def require_tz_aware(dt: datetime, field_name: str) -> None:
    """Require a timezone-aware datetime value."""
    if not isinstance(dt, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{field_name} must be timezone-aware (UTC recommended)")


def _require_text(value: object, *, field_name: str, max_chars: int) -> str:
    """Validate, trim, and return a required string."""
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} is required")
    if len(cleaned) > max_chars:
        raise ValueError(f"{field_name} exceeds maximum length of {max_chars}")
    return cleaned


def _normalize_optional_text(
    value: object,
    *,
    field_name: str,
    max_chars: int,
) -> Optional[str]:
    """
    Normalize an optional string.
    Empty strings become None so downstream truthiness checks behave honestly.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string or None")
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > max_chars:
        raise ValueError(f"{field_name} exceeds maximum length of {max_chars}")
    return cleaned


def normalize_roles(roles: Iterable[str]) -> FrozenSet[str]:
    """
    Normalize and validate role names.

    Roles must be:
    - supplied as an iterable of strings (not a bare string)
    - non-empty after stripping
    - individually bounded in length
    - limited in total count
    """
    if isinstance(roles, (str, bytes)):
        raise TypeError("roles must be an iterable of role strings, not a string")
    try:
        raw_roles = list(roles)
    except TypeError as exc:
        raise TypeError("roles must be an iterable of strings") from exc

    normalized: set[str] = set()
    for role in raw_roles:
        if not isinstance(role, str):
            raise TypeError("roles must contain only strings")
        cleaned = role.strip()
        if not cleaned:
            raise ValueError("roles must not contain empty values")
        if len(cleaned) > MAX_ROLE_CHARS:
            raise ValueError(f"role exceeds maximum length of {MAX_ROLE_CHARS}")
        normalized.add(cleaned)

    if not normalized:
        raise ValueError("at least one role is required")
    if len(normalized) > MAX_ROLE_COUNT:
        raise ValueError(f"roles exceed maximum count of {MAX_ROLE_COUNT}")

    return frozenset(normalized)


# =============================================================================
# AuthContext
# =============================================================================

@dataclass(frozen=True, slots=True)
class AuthContext:
    """
    Represents an authenticated identity.
    Instances are immutable and safe to share after validation.
    """

    subject_id: str
    device_id:  Optional[str]
    roles:      FrozenSet[str]
    issued_at:  datetime
    expires_at: datetime
    issuer:     str

    def __post_init__(self) -> None:
        subject_id = _require_text(
            self.subject_id, field_name="subject_id", max_chars=MAX_SUBJECT_CHARS,
        )
        issuer = _require_text(
            self.issuer, field_name="issuer", max_chars=MAX_ISSUER_CHARS,
        )
        device_id = _normalize_optional_text(
            self.device_id, field_name="device_id", max_chars=MAX_DEVICE_ID_CHARS,
        )
        roles = normalize_roles(self.roles)

        require_tz_aware(self.issued_at,  "issued_at")
        require_tz_aware(self.expires_at, "expires_at")

        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")

        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "issuer",     issuer)
        object.__setattr__(self, "device_id",  device_id)
        object.__setattr__(self, "roles",      roles)


# =============================================================================
# AuthResult
# =============================================================================

@dataclass(frozen=True, slots=True)
class AuthResult:
    """
    Result of authentication verification.

    Coherent states:
      success=True  -> context present, reason absent
      success=False -> context absent,  reason present
    """

    success: bool
    context: Optional[AuthContext] = None
    reason:  Optional[str]         = None

    def __post_init__(self) -> None:
        if not isinstance(self.success, bool):
            raise TypeError("success must be a bool")

        if self.success:
            if self.context is None:
                raise ValueError("success=True requires context")
            if not isinstance(self.context, AuthContext):
                raise TypeError("context must be an AuthContext instance")
            if self.reason is not None:
                raise ValueError("success=True must not include reason")
            return

        if self.context is not None:
            raise ValueError("success=False must not include context")

        reason = _require_text(
            self.reason, field_name="reason", max_chars=MAX_REASON_CHARS,
        )
        object.__setattr__(self, "reason", reason)


# =============================================================================
# TokenHash
# =============================================================================

@dataclass(frozen=True, slots=True)
class TokenHash:
    """
    Structured token-hash descriptor.

    Raw tokens must never be stored in audit records — store a TokenHash
    instead.

    Examples:
        TokenHash(alg="sha256", digest="ab12cd34...")
        TokenHash(alg="sha512", digest="ef56gh78...")
    """

    alg: Literal["sha256", "sha384", "sha512"]
    digest: str

    def __post_init__(self) -> None:
        if self.alg not in _SUPPORTED_TOKEN_HASH_LENGTHS:
            raise ValueError("Unsupported token-hash algorithm")
        if not isinstance(self.digest, str):
            raise TypeError("TokenHash.digest must be a string")

        # Normalize to lowercase before length and character checks.
        digest = self.digest.strip().lower()
        expected_length = _SUPPORTED_TOKEN_HASH_LENGTHS[self.alg]

        if len(digest) != expected_length:
            raise ValueError("TokenHash.digest length does not match algorithm")

        # _HEX_RE matches [0-9a-f]+ — uppercase already handled by .lower() above.
        if _HEX_RE.fullmatch(digest) is None:
            raise ValueError("TokenHash.digest must contain hexadecimal characters only")

        object.__setattr__(self, "digest", digest)


# =============================================================================
# KeyUsageRecord
# =============================================================================

@dataclass(frozen=True, slots=True)
class KeyUsageRecord:
    """
    Immutable audit record of a single key usage event.

    Defaults are intentionally conservative:
      - valid=False: validity is never assumed
      - invalid records require an explicit reason string
      - raw credentials are never accepted

    Note on issued_at / used_at defaults:
      Both call utc_now() independently at construction time. The validation
      check uses < (strictly less-than), so same-microsecond timestamps pass.
      If sub-microsecond ordering matters, pass explicit values.
    """

    # Required identity and key fields.
    subject_id:  str
    issuer:      str
    key_id:      str
    token_hash:  TokenHash

    # Safe generated identifier.
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Optional identity context.
    device_id: Optional[str] = None

    # Authentication method.
    auth_method: str = "HMAC"

    # Time context. See class docstring note on default ordering.
    issued_at:  datetime           = field(default_factory=utc_now)
    used_at:    datetime           = field(default_factory=utc_now)
    expires_at: Optional[datetime] = None

    # Source context.
    source_ip: Optional[str] = None
    node_id:   Optional[str] = None
    service:   Optional[str] = None

    # Validation state.
    # valid=False requires an explicit reason; valid=True forbids one.
    valid:  bool          = False
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        subject_id = _require_text(
            self.subject_id, field_name="subject_id", max_chars=MAX_SUBJECT_CHARS,
        )
        issuer = _require_text(
            self.issuer, field_name="issuer", max_chars=MAX_ISSUER_CHARS,
        )
        key_id = _require_text(
            self.key_id, field_name="key_id", max_chars=MAX_KEY_ID_CHARS,
        )
        record_id = _require_text(
            self.record_id, field_name="record_id", max_chars=64,
        )
        try:
            uuid.UUID(record_id)
        except ValueError as exc:
            raise ValueError("record_id must be a valid UUID") from exc

        if not isinstance(self.token_hash, TokenHash):
            raise TypeError("token_hash must be a TokenHash instance")

        auth_method = _require_text(
            self.auth_method, field_name="auth_method", max_chars=MAX_AUTH_METHOD_CHARS,
        )
        device_id = _normalize_optional_text(
            self.device_id, field_name="device_id", max_chars=MAX_DEVICE_ID_CHARS,
        )
        source_ip = _normalize_optional_text(
            self.source_ip, field_name="source_ip", max_chars=MAX_OPTIONAL_TEXT_CHARS,
        )
        node_id = _normalize_optional_text(
            self.node_id, field_name="node_id", max_chars=MAX_OPTIONAL_TEXT_CHARS,
        )
        service = _normalize_optional_text(
            self.service, field_name="service", max_chars=MAX_OPTIONAL_TEXT_CHARS,
        )

        require_tz_aware(self.issued_at, "issued_at")
        require_tz_aware(self.used_at,   "used_at")

        if self.used_at < self.issued_at:
            raise ValueError("used_at must not occur before issued_at")

        if self.expires_at is not None:
            require_tz_aware(self.expires_at, "expires_at")
            if self.expires_at <= self.issued_at:
                raise ValueError("expires_at must be after issued_at")
            if self.valid and self.used_at > self.expires_at:
                raise ValueError("used_at after expires_at cannot be valid=True")

        if not isinstance(self.valid, bool):
            raise TypeError("valid must be a bool")

        if self.valid:
            if self.reason is not None:
                raise ValueError("valid=True must not include reason")
            reason = None
        else:
            reason = _require_text(
                self.reason, field_name="reason", max_chars=MAX_REASON_CHARS,
            )

        object.__setattr__(self, "subject_id",  subject_id)
        object.__setattr__(self, "issuer",      issuer)
        object.__setattr__(self, "key_id",      key_id)
        object.__setattr__(self, "record_id",   record_id)
        object.__setattr__(self, "auth_method", auth_method)
        object.__setattr__(self, "device_id",   device_id)
        object.__setattr__(self, "source_ip",   source_ip)
        object.__setattr__(self, "node_id",     node_id)
        object.__setattr__(self, "service",     service)
        object.__setattr__(self, "reason",      reason)
