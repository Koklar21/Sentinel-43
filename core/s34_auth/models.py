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
# [licensing@sentinel43.io](mailto:licensing@sentinel43.io)
#
#
# =============================================================================
# FILE INFORMATION
# =============================================================================
#
# Project: Sentinel-43
# Component: Identity Core
# File: models.py
#
# Description:
# Immutable authentication identity, verification-result, and key-usage
# audit models.
#
# Author: Justin
# Created: 2026
# Last Modified: 2026-06-09
#
# =============================================================================

from **future** import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import FrozenSet, Iterable, Literal, Optional

**all** = [
"AuthContext",
"AuthResult",
"TokenHash",
"KeyUsageRecord",
"utc_now",
"require_tz_aware",
"normalize_roles",
]

MAX_SUBJECT_CHARS = 512
MAX_DEVICE_ID_CHARS = 512
MAX_ISSUER_CHARS = 512
MAX_KEY_ID_CHARS = 512
MAX_AUTH_METHOD_CHARS = 128
MAX_REASON_CHARS = 2048
MAX_OPTIONAL_TEXT_CHARS = 512

MAX_ROLE_COUNT = 64
MAX_ROLE_CHARS = 128

_SUPPORTED_TOKEN_HASH_LENGTHS: dict[str, int] = {
"sha256": 64,
"sha384": 96,
"sha512": 128,
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def utc_now() -> datetime:
"""
Return the current timezone-aware UTC timestamp.
"""

```
return datetime.now(timezone.utc)
```

def require_tz_aware(
dt: datetime,
field_name: str,
) -> None:
"""
Require a timezone-aware datetime value.
"""

```
if not isinstance(dt, datetime):
    raise TypeError(
        f"{field_name} must be a datetime"
    )

if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
    raise ValueError(
        f"{field_name} must be timezone-aware (UTC recommended)"
    )
```

def _require_text(
value: object,
*,
field_name: str,
max_chars: int,
) -> str:
"""
Validate, trim, and return a required string.
"""

```
if not isinstance(value, str):
    raise TypeError(
        f"{field_name} must be a string"
    )

cleaned = value.strip()

if not cleaned:
    raise ValueError(
        f"{field_name} is required"
    )

if len(cleaned) > max_chars:
    raise ValueError(
        f"{field_name} exceeds maximum length of {max_chars}"
    )

return cleaned
```

def _normalize_optional_text(
value: object,
*,
field_name: str,
max_chars: int,
) -> Optional[str]:
"""
Normalize an optional string.

```
Empty strings become None so downstream truthiness checks behave honestly.
"""

if value is None:
    return None

if not isinstance(value, str):
    raise TypeError(
        f"{field_name} must be a string or None"
    )

cleaned = value.strip()

if not cleaned:
    return None

if len(cleaned) > max_chars:
    raise ValueError(
        f"{field_name} exceeds maximum length of {max_chars}"
    )

return cleaned
```

def normalize_roles(
roles: Iterable[str],
) -> FrozenSet[str]:
"""
Normalize and validate role names.

```
Roles must be:
- supplied as an iterable of strings
- non-empty after normalization
- individually bounded in length
- limited in total count
"""

if isinstance(roles, (str, bytes)):
    raise TypeError(
        "roles must be an iterable of role strings, not a string"
    )

try:
    raw_roles = list(roles)
except TypeError as exc:
    raise TypeError(
        "roles must be an iterable of strings"
    ) from exc

normalized: set[str] = set()

for role in raw_roles:
    if not isinstance(role, str):
        raise TypeError(
            "roles must contain only strings"
        )

    cleaned = role.strip()

    if not cleaned:
        raise ValueError(
            "roles must not contain empty values"
        )

    if len(cleaned) > MAX_ROLE_CHARS:
        raise ValueError(
            f"role exceeds maximum length of {MAX_ROLE_CHARS}"
        )

    normalized.add(cleaned)

if not normalized:
    raise ValueError(
        "at least one role is required"
    )

if len(normalized) > MAX_ROLE_COUNT:
    raise ValueError(
        f"roles exceed maximum count of {MAX_ROLE_COUNT}"
    )

return frozenset(normalized)
```

@dataclass(frozen=True, slots=True)
class AuthContext:
"""
Represents an authenticated identity.

```
Instances are immutable and safe to share after validation.
"""

subject_id: str
device_id: Optional[str]
roles: FrozenSet[str]
issued_at: datetime
expires_at: datetime
issuer: str

def __post_init__(self) -> None:
    subject_id = _require_text(
        self.subject_id,
        field_name="subject_id",
        max_chars=MAX_SUBJECT_CHARS,
    )

    issuer = _require_text(
        self.issuer,
        field_name="issuer",
        max_chars=MAX_ISSUER_CHARS,
    )

    device_id = _normalize_optional_text(
        self.device_id,
        field_name="device_id",
        max_chars=MAX_DEVICE_ID_CHARS,
    )

    roles = normalize_roles(
        self.roles
    )

    require_tz_aware(
        self.issued_at,
        "issued_at",
    )

    require_tz_aware(
        self.expires_at,
        "expires_at",
    )

    if self.expires_at <= self.issued_at:
        raise ValueError(
            "expires_at must be after issued_at"
        )

    object.__setattr__(
        self,
        "subject_id",
        subject_id,
    )

    object.__setattr__(
        self,
        "issuer",
        issuer,
    )

    object.__setattr__(
        self,
        "device_id",
        device_id,
    )

    object.__setattr__(
        self,
        "roles",
        roles,
    )
```

@dataclass(frozen=True, slots=True)
class AuthResult:
"""
Result of authentication verification.

```
Coherent states:
- success=True  => context present, reason absent
- success=False => context absent, reason present
"""

success: bool
context: Optional[AuthContext] = None
reason: Optional[str] = None

def __post_init__(self) -> None:
    if not isinstance(self.success, bool):
        raise TypeError(
            "success must be a bool"
        )

    if self.success:
        if self.context is None:
            raise ValueError(
                "success=True requires context"
            )

        if not isinstance(self.context, AuthContext):
            raise TypeError(
                "context must be an AuthContext instance"
            )

        if self.reason is not None:
            raise ValueError(
                "success=True must not include reason"
            )

        return

    if self.context is not None:
        raise ValueError(
            "success=False must not include context"
        )

    reason = _require_text(
        self.reason,
        field_name="reason",
        max_chars=MAX_REASON_CHARS,
    )

    object.__setattr__(
        self,
        "reason",
        reason,
    )
```

@dataclass(frozen=True, slots=True)
class TokenHash:
"""
Structured token-hash descriptor.

```
Raw tokens must never be stored in audit records.

Examples:
    TokenHash(alg="sha256", digest="ab12...")
    TokenHash(alg="sha512", digest="cd34...")
"""

alg: Literal[
    "sha256",
    "sha384",
    "sha512",
]

digest: str

def __post_init__(self) -> None:
    if self.alg not in _SUPPORTED_TOKEN_HASH_LENGTHS:
        raise ValueError(
            "Unsupported token-hash algorithm"
        )

    if not isinstance(self.digest, str):
        raise TypeError(
            "TokenHash.digest must be a string"
        )

    digest = self.digest.strip().lower()

    expected_length = _SUPPORTED_TOKEN_HASH_LENGTHS[
        self.alg
    ]

    if len(digest) != expected_length:
        raise ValueError(
            "TokenHash.digest length does not match algorithm"
        )

    if _HEX_RE.fullmatch(digest) is None:
        raise ValueError(
            "TokenHash.digest must contain hexadecimal characters only"
        )

    object.__setattr__(
        self,
        "digest",
        digest,
    )
```

@dataclass(frozen=True, slots=True)
class KeyUsageRecord:
"""
Immutable audit record of key usage.

```
Defaults are intentionally conservative:
- validity is never assumed
- invalid records require a reason
- raw credentials are never accepted
"""

# Required identity and key fields.
subject_id: str
issuer: str
key_id: str
token_hash: TokenHash

# Safe generated identifier.
record_id: str = field(
    default_factory=lambda: str(
        uuid.uuid4()
    )
)

# Optional identity context.
device_id: Optional[str] = None

# Authentication method.
auth_method: str = "HMAC"

# Time context.
issued_at: datetime = field(
    default_factory=utc_now
)

used_at: datetime = field(
    default_factory=utc_now
)

expires_at: Optional[datetime] = None

# Source context.
source_ip: Optional[str] = None
node_id: Optional[str] = None
service: Optional[str] = None

# Validation state.
valid: bool = False
reason: Optional[str] = None

def __post_init__(self) -> None:
    subject_id = _require_text(
        self.subject_id,
        field_name="subject_id",
        max_chars=MAX_SUBJECT_CHARS,
    )

    issuer = _require_text(
        self.issuer,
        field_name="issuer",
        max_chars=MAX_ISSUER_CHARS,
    )

    key_id = _require_text(
        self.key_id,
        field_name="key_id",
        max_chars=MAX_KEY_ID_CHARS,
    )

    record_id = _require_text(
        self.record_id,
        field_name="record_id",
        max_chars=64,
    )

    try:
        uuid.UUID(record_id)
    except ValueError as exc:
        raise ValueError(
            "record_id must be a valid UUID"
        ) from exc

    if not isinstance(
        self.token_hash,
        TokenHash,
    ):
        raise TypeError(
            "token_hash must be a TokenHash instance"
        )

    auth_method = _require_text(
        self.auth_method,
        field_name="auth_method",
        max_chars=MAX_AUTH_METHOD_CHARS,
    )

    device_id = _normalize_optional_text(
        self.device_id,
        field_name="device_id",
        max_chars=MAX_DEVICE_ID_CHARS,
    )

    source_ip = _normalize_optional_text(
        self.source_ip,
        field_name="source_ip",
        max_chars=MAX_OPTIONAL_TEXT_CHARS,
    )

    node_id = _normalize_optional_text(
        self.node_id,
        field_name="node_id",
        max_chars=MAX_OPTIONAL_TEXT_CHARS,
    )

    service = _normalize_optional_text(
        self.service,
        field_name="service",
        max_chars=MAX_OPTIONAL_TEXT_CHARS,
    )

    require_tz_aware(
        self.issued_at,
        "issued_at",
    )

    require_tz_aware(
        self.used_at,
        "used_at",
    )

    if self.used_at < self.issued_at:
        raise ValueError(
            "used_at must not occur before issued_at"
        )

    if self.expires_at is not None:
        require_tz_aware(
            self.expires_at,
            "expires_at",
        )

        if self.expires_at <= self.issued_at:
            raise ValueError(
                "expires_at must be after issued_at"
            )

        if (
            self.valid
            and self.used_at > self.expires_at
        ):
            raise ValueError(
                "used_at after expires_at cannot be valid=True"
            )

    if not isinstance(self.valid, bool):
        raise TypeError(
            "valid must be a bool"
        )

    if self.valid:
        if self.reason is not None:
            raise ValueError(
                "valid=True must not include reason"
            )

        reason = None
    else:
        reason = _require_text(
            self.reason,
            field_name="reason",
            max_chars=MAX_REASON_CHARS,
        )

    object.__setattr__(
        self,
        "subject_id",
        subject_id,
    )

    object.__setattr__(
        self,
        "issuer",
        issuer,
    )

    object.__setattr__(
        self,
        "key_id",
        key_id,
    )

    object.__setattr__(
        self,
        "record_id",
        record_id,
    )

    object.__setattr__(
        self,
        "auth_method",
        auth_method,
    )

    object.__setattr__(
        self,
        "device_id",
        device_id,
    )

    object.__setattr__(
        self,
        "source_ip",
        source_ip,
    )

    object.__setattr__(
        self,
        "node_id",
        node_id,
    )

    object.__setattr__(
        self,
        "service",
        service,
    )

    object.__setattr__(
        self,
        "reason",
        reason,
    )
```
