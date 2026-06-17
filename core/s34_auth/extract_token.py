from pathlib import Path

content = '''# =============================================================================
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
Sentinel-43 authorization token extraction helper.

File:
    core/security/extract_token.py

Purpose:
    Extract a Bearer token from HTTP-style headers safely and predictably.

Design:
    - Accepts normal dict-like mappings.
    - Handles case-insensitive Authorization header lookup.
    - Accepts str or bytes header values.
    - Rejects malformed Authorization values.
    - Never raises for bad input.
    - Returns None when no valid Bearer token is present.

Typical usage:
    token = extract_token(request.headers)
    if token is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional


AUTHORIZATION_HEADER = "authorization"
BEARER_SCHEME = "bearer"


def _to_text(value: Any) -> Optional[str]:
    """
    Convert a header key/value to text when safe.

    Returns None for unsupported values. This keeps extract_token() fail-closed
    without making every caller wrap it in try/except, because apparently even
    header parsing needs a seatbelt.
    """
    if isinstance(value, str):
        return value

    if isinstance(value, bytes):
        try:
            return value.decode("latin-1")
        except Exception:
            return None

    return None


def _get_header_case_insensitive(
    headers: Mapping[Any, Any],
    header_name: str,
) -> Optional[str]:
    """
    Fetch a header value from a mapping using case-insensitive key matching.

    Starlette/FastAPI Headers already support case-insensitive .get(), but
    plain dicts do not. This handles both without caring which tiny kingdom
    the headers object came from.
    """
    direct_value = headers.get(header_name)
    direct_text = _to_text(direct_value)
    if direct_text is not None:
        return direct_text

    wanted = header_name.lower()

    for raw_key, raw_value in headers.items():
        key = _to_text(raw_key)
        if key is None:
            continue

        if key.lower() == wanted:
            return _to_text(raw_value)

    return None


def extract_token(headers: Optional[Mapping[Any, Any]]) -> Optional[str]:
    """
    Extract a Bearer token from request headers.

    Returns None when:
        - headers is None
        - headers is empty
        - Authorization header is missing
        - Authorization header is not text/bytes
        - scheme is not Bearer
        - token is missing
        - token contains internal whitespace
        - Authorization header contains extra parts

    Accepted examples:
        Authorization: Bearer abc.def.ghi
        authorization: bearer local-dev-token

    Rejected examples:
        Authorization: Basic abc
        Authorization: Bearer
        Authorization: Bearer token extra
        Authorization: Bearer bad token
    """
    if not headers:
        return None

    auth_header = _get_header_case_insensitive(headers, AUTHORIZATION_HEADER)
    if not auth_header:
        return None

    parts = auth_header.strip().split()

    if len(parts) != 2:
        return None

    scheme, token = parts

    if scheme.lower() != BEARER_SCHEME:
        return None

    token = token.strip()
    if not token:
        return None

    # split() above already rejects internal whitespace by producing >2 parts.
    # This second guard keeps the intent obvious for future maintainers, who are
    # statistically likely to be sleep-deprived and holding coffee.
    if any(char.isspace() for char in token):
        return None

    return token


__all__ = [
    "AUTHORIZATION_HEADER",
    "BEARER_SCHEME",
    "extract_token",
]


# =============================================================================
# Minimal self-tests
# =============================================================================

def _run_self_tests() -> None:  # pragma: no cover
    import unittest

    class ExtractTokenTests(unittest.TestCase):
        def test_none_headers(self) -> None:
            self.assertIsNone(extract_token(None))

        def test_empty_headers(self) -> None:
            self.assertIsNone(extract_token({}))

        def test_missing_authorization(self) -> None:
            self.assertIsNone(extract_token({"X-Test": "value"}))

        def test_valid_bearer(self) -> None:
            self.assertEqual(
                extract_token({"Authorization": "Bearer abc.def.ghi"}),
                "abc.def.ghi",
            )

        def test_valid_lowercase_header_and_scheme(self) -> None:
            self.assertEqual(
                extract_token({"authorization": "bearer local-dev-token"}),
                "local-dev-token",
            )

        def test_bytes_header_value(self) -> None:
            self.assertEqual(
                extract_token({"Authorization": b"Bearer byte-token"}),
                "byte-token",
            )

        def test_reject_basic(self) -> None:
            self.assertIsNone(extract_token({"Authorization": "Basic abc"}))

        def test_reject_missing_token(self) -> None:
            self.assertIsNone(extract_token({"Authorization": "Bearer"}))

        def test_reject_extra_parts(self) -> None:
            self.assertIsNone(extract_token({"Authorization": "Bearer token extra"}))

        def test_reject_non_string_value(self) -> None:
            self.assertIsNone(extract_token({"Authorization": 123}))

    unittest.main(argv=["extract_token.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
'''

path = Path("/mnt/data/extract_token.py")
path.write_text(content, encoding="utf-8")
print(f"created {path}")
print(path.stat().st_size)
