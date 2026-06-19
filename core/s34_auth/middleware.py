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
# 1. GNU Affero General Public License (AGPL v3.0)
# for open-source use, modification, and distribution.
#
# 2. Commercial License
# for proprietary, enterprise, government, or other commercial use
# not permitted under the AGPL v3.0.
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

from **future** import annotations

import re
from typing import Mapping, Optional

from .constants import AUTH_HEADER, BEARER_SCHEME

**all** = [
"extract_token",
]

# This extractor rejects oversized credentials before they reach JWT parsing,

# signature verification, or any other downstream cryptographic work.

#

# The hardened AuthManager currently rejects tokens above 4096 characters, so

# this perimeter check uses the same ceiling.

MAX_BEARER_TOKEN_CHARS = 4096

# Allow reasonable formatting room for the scheme and separating spaces while

# still rejecting absurd Authorization headers before regex evaluation.

MAX_AUTH_HEADER_CHARS = MAX_BEARER_TOKEN_CHARS + 64

_AUTH_HEADER_CASEFOLDED = AUTH_HEADER.casefold()

# HTTP authentication schemes are case-insensitive.

#

# RFC-style parsing permits one or more ordinary spaces between the scheme and

# credentials. Tabs and other whitespace are deliberately rejected.

_BEARER_PATTERN = re.compile(
rf"^{re.escape(BEARER_SCHEME)} +(\S+)$",
flags=re.IGNORECASE | re.ASCII,
)

def extract_token(
headers: Optional[Mapping[str, str]],
) -> Optional[str]:
"""
Extract a Bearer token from request headers.

```
Returns None when:
- headers is None or empty
- Authorization header is missing
- multiple case-variant Authorization headers are present
- Authorization header is not a string
- Authorization header exceeds the configured size limit
- authentication scheme is not Bearer
- token is missing, malformed, or oversized

Notes:
- HTTP header names are matched case-insensitively.
- Bearer scheme matching is case-insensitive.
- This function performs perimeter parsing only. Cryptographic token
  validation remains the responsibility of AuthManager.
"""

if not headers:
    return None

auth_header = _find_authorization_header(headers)

if auth_header is None:
    return None

if len(auth_header) > MAX_AUTH_HEADER_CHARS:
    return None

match = _BEARER_PATTERN.fullmatch(
    auth_header.strip()
)

if match is None:
    return None

token = match.group(1)

if len(token) > MAX_BEARER_TOKEN_CHARS:
    return None

return token
```

def _find_authorization_header(
headers: Mapping[str, str],
) -> Optional[str]:
"""
Return the single Authorization header value using case-insensitive
matching.

```
Reject ambiguous mappings that contain multiple case variants such as:

    Authorization
    authorization

Real HTTP frameworks normally normalize headers, but this helper also
supports raw dictionaries used by tests, middleware adapters, and CLI
tooling.
"""

matches: list[object] = []

for name, value in headers.items():
    if (
        isinstance(name, str)
        and name.casefold() == _AUTH_HEADER_CASEFOLDED
    ):
        matches.append(value)

if len(matches) != 1:
    return None

value = matches[0]

if not isinstance(value, str):
    return None

return value
```
