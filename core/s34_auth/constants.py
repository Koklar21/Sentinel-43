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
from __future__ import annotations


AUTH_HEADER = "Authorization"

BEARER_SCHEME = "Bearer"
BEARER_PREFIX = f"{BEARER_SCHEME} "

DEFAULT_ALGORITHM = "HS256"

ALLOWED_ALGORITHMS: frozenset[str] = frozenset(
    {
        "HS256",
        "HS384",
        "HS512",
    }
)


def is_allowed_algorithm(algorithm: str) -> bool:
    """
    Return True if the requested signing algorithm is explicitly allowed.
    """

    return algorithm in ALLOWED_ALGORITHMS
