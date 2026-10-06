# =============================================================================
# Sentinel-43
# Copyright (c) 2026 Justin Armstrong
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Shared validation for security-sensitive secret values."""

from __future__ import annotations

import re
from typing import Final

MIN_GENERATED_SECRET_CHARS: Final[int] = 32

_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(
    r"CHANGE[_-]?ME|<[^>]+>|\byour[-_.]|example\.(?:invalid|com|org|net)\b|"
    r"(?:^|[^0-9A-Za-z.])(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(?:$|[^0-9A-Za-z.])",
    re.IGNORECASE,
)


def is_placeholder_secret(value: str) -> bool:
    """Return true when a value is visibly a template/default stand-in."""
    text = str(value or "").strip()
    return bool(text) and bool(_PLACEHOLDER_RE.search(text))


def require_generated_secret(
    name: str,
    value: str,
    *,
    minimum_chars: int = MIN_GENERATED_SECRET_CHARS,
) -> str:
    """Return a validated secret or fail closed.

    This deliberately checks deploy-time properties that runtime can prove:
    presence, known/template placeholder patterns, and a minimum encoded
    length. It does not pretend to measure entropy from a finished string.
    """
    text = str(value or "").strip()
    if not text:
        raise RuntimeError(f"{name} must be configured with a generated secret")
    if is_placeholder_secret(text):
        raise RuntimeError(f"{name} must not use a placeholder value")
    if len(text) < int(minimum_chars):
        raise RuntimeError(
            f"{name} must be at least {int(minimum_chars)} characters"
        )
    return text


__all__ = [
    "MIN_GENERATED_SECRET_CHARS",
    "is_placeholder_secret",
    "require_generated_secret",
]
