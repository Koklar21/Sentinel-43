```python
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
Sentinel-43 middleware/security package.

This package exposes the primary middleware and security-node components used by
the S43 API layer:

    - SentinelFirewall:
        FastAPI / Starlette application-layer firewall middleware.

    - SpartaCore:
        File-integrity watchdog and hardened node API router.

    - JormungandrNode:
        Cryptographic audit/security node for tamper-resistant governance logs.

Preferred imports:

    from core.middleware import SentinelFirewall, FirewallConfig
    from core.middleware import SpartaCore, IntegrityConfig, create_node_router
    from core.middleware import JormungandrNode, JormungandrConfig, build_jormungandr
"""

from __future__ import annotations

try:
    from .sentinel_firewall import (
        BlockReason,
        FirewallConfig,
        SentinelFirewall,
    )
except ImportError:  # pragma: no cover
    BlockReason = None  # type: ignore[assignment]
    FirewallConfig = None  # type: ignore[assignment]
    SentinelFirewall = None  # type: ignore[assignment]

try:
    from .sparta_core import (
        IntegrityConfig,
        IntegrityEvent,
        NodeAuthRequest,
        NodeHeartbeatRequest,
        NodeRegisterRequest,
        SpartaCore,
        SpartaState,
        build_sparta_core,
        create_node_router,
        setup_signal_handlers,
    )
except ImportError:  # pragma: no cover
    IntegrityConfig = None  # type: ignore[assignment]
    IntegrityEvent = None  # type: ignore[assignment]
    NodeAuthRequest = None  # type: ignore[assignment]
    NodeHeartbeatRequest = None  # type: ignore[assignment]
    NodeRegisterRequest = None  # type: ignore[assignment]
    SpartaCore = None  # type: ignore[assignment]
    SpartaState = None  # type: ignore[assignment]
    build_sparta_core = None  # type: ignore[assignment]
    create_node_router = None  # type: ignore[assignment]
    setup_signal_handlers = None  # type: ignore[assignment]

try:
    from .jormungandr import (
        AuditRecord,
        JormungandrConfig,
        JormungandrConfigError,
        JormungandrCryptoError,
        JormungandrError,
        JormungandrNode,
        Mode,
        Posture,
        build_jormungandr,
    )
except ImportError:  # pragma: no cover
    AuditRecord = None  # type: ignore[assignment]
    JormungandrConfig = None  # type: ignore[assignment]
    JormungandrConfigError = None  # type: ignore[assignment]
    JormungandrCryptoError = None  # type: ignore[assignment]
    JormungandrError = None  # type: ignore[assignment]
    JormungandrNode = None  # type: ignore[assignment]
    Mode = None  # type: ignore[assignment]
    Posture = None  # type: ignore[assignment]
    build_jormungandr = None  # type: ignore[assignment]


__all__ = [
    # Firewall
    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",

    # SpartaCore
    "IntegrityConfig",
    "IntegrityEvent",
    "NodeAuthRequest",
    "NodeHeartbeatRequest",
    "NodeRegisterRequest",
    "SpartaCore",
    "SpartaState",
    "build_sparta_core",
    "create_node_router",
    "setup_signal_handlers",

    # Jormungandr
    "AuditRecord",
    "JormungandrConfig",
    "JormungandrConfigError",
    "JormungandrCryptoError",
    "JormungandrError",
    "JormungandrNode",
    "Mode",
    "Posture",
    "build_jormungandr",
]
```

