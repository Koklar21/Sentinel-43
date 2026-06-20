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

Fix (public-beta hardening) — what changed and why
----------------------------------------------------
This shim previously tried core.api.middleware.sentinel_firewall_middleware
FIRST, falling back to core/middleware/sentinel_firewall.py (the original
location) SECOND. That ordering caused a real, reproduced production
outage: the "new" relocated copy was an older snapshot that predated
FirewallConfig.from_env() being added to the original file, and the two
were never synced. The app silently loaded the broken copy on every boot.
The resulting error -- "FirewallConfig has no attribute from_env" -- gave
no indication that a second, correct copy of the same class existed one
import path away. Tracking that down cost real debugging time.

This shim now does three things differently:

  1. Prefers the original, verified-correct location first. The relocated
     path is only used as a fallback if the original is missing entirely
     (e.g. once a relocation is actually completed and the original file
     is deleted for real).
  2. Logs a warning whenever the fallback path is used, since that path
     is known to have been stale at least once already. Silent precedence
     between two near-duplicate files is what turned this into a
     debugging session in the first place -- this makes it visible
     instead.
  3. Validates the loaded FirewallConfig actually has from_env() at
     import time, regardless of which path supplied it, and raises a
     specific, actionable ImportError immediately if not. This is the
     real fix: it converts "confusing AttributeError three layers deep
     inside main.py's middleware registration, with zero clue which of
     two files is at fault" into "clear failure at the moment the wrong
     file gets loaded, naming the file and the missing attribute."

TODO (not blocking, but should happen): reconcile the two physical files.
Either bring core/api/middleware/sentinel_firewall_middleware.py up to
date with core/middleware/sentinel_firewall.py and finish the relocation
properly -- delete the old file and remove the fallback branch below
entirely -- or abandon the relocation and delete the new file. Keeping
two independently-editable copies of the same class indefinitely is what
caused this bug, and the consistency check below only catches drift in
from_env() specifically; it won't catch every way these two files could
diverge.
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
        # Relocated copy. Known stale as of the fix described above
        # (missing from_env() at the time this bug was found) -- only
        # reached if the original location is unimportable, e.g. it has
        # since been deleted as part of finishing the relocation for
        # real.
        from core.api.middleware.sentinel_firewall_middleware import (  # type: ignore[no-redef]
            BlockReason,
            FirewallConfig,
            SentinelFirewall,
        )

        _source = "core.api.middleware.sentinel_firewall_middleware"

        logger.warning(
            "core.middleware: loaded SentinelFirewall/FirewallConfig from "
            "the relocated path (core.api.middleware."
            "sentinel_firewall_middleware) because core/middleware/"
            "sentinel_firewall.py was not importable. This path was found "
            "to be a stale, out-of-sync copy once already -- confirm it "
            "has been brought up to date before trusting it in production."
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
        "from_env() classmethod. This package has two candidate source "
        "files for FirewallConfig and they have drifted out of sync -- "
        "see this module's docstring. Reconcile core/middleware/"
        "sentinel_firewall.py and core/api/middleware/"
        "sentinel_firewall_middleware.py before continuing."
    )


__all__ = [
    "SentinelFirewall",
    "FirewallConfig",
    "BlockReason",
]
