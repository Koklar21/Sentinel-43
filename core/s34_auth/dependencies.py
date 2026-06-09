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

import threading

from .manager import AuthManager


_lock = threading.Lock()
_auth_manager: AuthManager | None = None


def configure_auth(manager: AuthManager) -> None:
    """
    Configure the global AuthManager instance.

    This function may only be called once during application startup.
    """

    if not isinstance(manager, AuthManager):
        raise TypeError(
            f"manager must be AuthManager, got {type(manager).__name__}"
        )

    global _auth_manager

    with _lock:
        if _auth_manager is not None:
            raise RuntimeError(
                "AuthManager is already configured"
            )

        _auth_manager = manager


def get_auth_manager() -> AuthManager:
    """
    Return the configured global AuthManager instance.
    """

    manager = _auth_manager

    if manager is None:
        raise RuntimeError(
            "AuthManager has not been configured"
        )

    return manager


def is_auth_configured() -> bool:
    """
    Return True if the global AuthManager is configured.
    """

    return _auth_manager is not None


def _reset_auth_for_tests() -> None:
    """
    Reset global auth state.

    Intended for test environments only.
    """

    global _auth_manager

    with _lock:
        _auth_manager = None
