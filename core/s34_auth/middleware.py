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

from typing import Mapping, Optional

from .constants import AUTH_HEADER, BEARER_PREFIX


def extract_token(headers: Optional[Mapping[str, str]]) -> Optional[str]:
    """
    Extract a Bearer token from request headers.

    Returns None when:
    - headers is None or empty
    - Authorization header is missing
    - Authorization header is not a string
    - scheme is not Bearer
    - token is missing or malformed
    """
    if not headers:
        return None

    auth_header = headers.get(AUTH_HEADER)
    if not isinstance(auth_header, str):
        return None

    parts = auth_header.strip().split()

    expected_scheme = BEARER_PREFIX.strip().lower()

    if len(parts) != 2:
        return None

    scheme, token = parts

    if scheme.lower() != expected_scheme:
        return None

    token = token.strip()
    if not token:
        return None

    return token
