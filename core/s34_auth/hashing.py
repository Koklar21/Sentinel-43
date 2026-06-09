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

import hashlib
import hmac
from typing import Union


BytesLike = Union[bytes, bytearray, memoryview]


def hmac_sha256(secret: BytesLike, message: BytesLike) -> str:
    """
    Generate an HMAC-SHA256 hex digest.

    Args:
        secret:
            Secret signing key.

        message:
            Message payload to authenticate.

    Returns:
        Hex-encoded SHA256 HMAC digest.
    """

    if not secret:
        raise ValueError("secret must not be empty")

    digest = hmac.new(
        bytes(secret),
        bytes(message),
        hashlib.sha256,
    )

    return digest.hexdigest()


def hmac_sha256_bytes(secret: BytesLike, message: BytesLike) -> bytes:
    """
    Generate a raw HMAC-SHA256 digest.

    Useful for internal cryptographic operations where raw bytes
    are preferred over hex strings.
    """

    if not secret:
        raise ValueError("secret must not be empty")

    digest = hmac.new(
        bytes(secret),
        bytes(message),
        hashlib.sha256,
    )

    return digest.digest()


def constant_time_compare(a: str | bytes, b: str | bytes) -> bool:
    """
    Perform constant-time comparison.

    Prevents timing attacks during MAC/signature verification.
    """

    if type(a) is not type(b):
        return False

    return hmac.compare_digest(a, b)
