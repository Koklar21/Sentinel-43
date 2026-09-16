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
Sentinel-43 Middleware Package

Re-exports SentinelFirewall / FirewallConfig / BlockReason so existing
imports of the form

    from core.middleware import SentinelFirewall, FirewallConfig

continue to work regardless of which physical file currently backs them.

Current structure (no longer two independently-editable copies)
------------------------------------------------------------------
core/api/middleware/sentinel_firewall_middleware.py is the implementation.
core/middleware/sentinel_firewall.py is a thin canonical wrapper: it
imports FirewallConfig/SentinelFirewall/BlockReason FROM that
implementation module and adds environment parsing (FirewallConfig.
from_env()) on top. This is intentional layering, not duplication -- the
implementation lives in exactly one file.

History, for context: this shim once tried the implementation module
FIRST and core/middleware/sentinel_firewall.py SECOND, back when both were
genuinely independent, divergence-prone copies. That ordering caused a
real, reproduced production outage (a stale copy missing from_env(), the
app silently loading it on every boot, and a confusing "FirewallConfig has
no attribute from_env" three layers deep in main.py's middleware
registration). Since core/middleware/sentinel_firewall.py now wraps rather
than duplicates the implementation, that specific divergence class can no
longer occur -- but the defensive ordering (prefer the wrapper, which
always succeeds if the implementation module is intact), the warning on
the fallback branch, and the from_env() presence check below are kept as
cheap, still-correct insurance against a future accidental re-duplication.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("SentinelMiddleware")

_source: str | None = None

try:
    # Fix: the verified-correct location now goes first. This used to be
    # the fallback branch -- see module docstring for why the order
    # changed.
    from .sentinel_firewall import (
        BlockReason,
        FirewallConfig,
        SentinelFirewall,
    )

    _source = "core.middleware.sentinel_firewall"

except ImportError:
    try:
        # Only reached if the wrapper module itself is unimportable (e.g.
        # a syntax error, or it was deleted). Falls back to importing the
        # implementation directly -- see module docstring for the history
        # of why this fallback exists and is still kept as insurance.
        from core.api.middleware.sentinel_firewall_middleware import (  # type: ignore[no-redef]
            BlockReason,
            FirewallConfig,
            SentinelFirewall,
        )

        _source = "core.api.middleware.sentinel_firewall_middleware"

        logger.warning(
            "core.middleware: loaded SentinelFirewall/FirewallConfig "
            "directly from the implementation module (core.api.middleware."
            "sentinel_firewall_middleware) because the canonical wrapper "
            "(core.middleware.sentinel_firewall) was not importable. "
            "FirewallConfig.from_env() is normally added by that wrapper, "
            "so this path is missing it unless the implementation module "
            "has since grown its own -- see the check below."
        )

    except ImportError:
        raise ImportError(
            "SentinelFirewall not found at "
            "core.middleware.sentinel_firewall or "
            "core.api.middleware.sentinel_firewall_middleware. "
            "Check that one of these files exists and is importable."
        ) from None

# Fix: fail loudly and specifically at import time if whichever copy got
# loaded is missing the expected interface, instead of letting it surface
# later as a generic, hard-to-trace AttributeError inside main.py's
# middleware registration -- exactly what happened with this bug.
if not hasattr(FirewallConfig, "from_env"):
    raise ImportError(
        f"core.middleware: FirewallConfig loaded from {_source!r} has no "
        "from_env() classmethod. The canonical wrapper (core.middleware."
        "sentinel_firewall) normally adds this; either it was bypassed "
        "(see this module's docstring for the fallback path) or "
        "from_env() was removed from it. Fix core/middleware/"
        "sentinel_firewall.py before continuing."
    )


__all__ = [
    "SentinelFirewall",
    "FirewallConfig",
    "BlockReason",
]
