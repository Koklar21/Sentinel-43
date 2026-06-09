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

import logging
import os
import threading

from .manager import AuthManager

**all** = [
"configure_auth",
"get_auth_manager",
"is_auth_configured",
]

logger = logging.getLogger(**name**)

_lock = threading.Lock()
_auth_manager: AuthManager | None = None

def configure_auth(manager: AuthManager) -> None:
"""
Configure the process-local AuthManager instance.

```
This function may only be called once during application startup.

Each worker process must configure its own AuthManager during bootstrap.
A second configuration attempt is rejected rather than silently replacing
the active manager.
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

logger.info(
    "Sentinel-43 AuthManager configured successfully."
)
```

def get_auth_manager() -> AuthManager:
"""
Return the configured process-local AuthManager instance.

```
Raises:
    RuntimeError:
        If authentication bootstrap has not completed.
"""

with _lock:
    manager = _auth_manager

if manager is None:
    raise RuntimeError(
        "AuthManager has not been configured"
    )

return manager
```

def is_auth_configured() -> bool:
"""
Return True if the process-local AuthManager is currently configured.

```
This is an advisory status check only.

Do not use this function as a check-then-configure synchronization gate.
Call configure_auth() directly and allow its internal lock to enforce
single initialization safely.
"""

with _lock:
    return _auth_manager is not None
```

def _reset_auth_for_tests() -> None:
"""
Reset process-local authentication state for isolated test teardown.

```
This function is deliberately excluded from __all__ and must never be
callable in production environments.
"""

env = os.getenv("S43_ENV", "").strip().lower()

if env not in {
    "test",
    "testing",
    "development",
    "dev",
}:
    raise RuntimeError(
        "_reset_auth_for_tests() must not be called outside "
        "test or development environments"
    )

global _auth_manager

with _lock:
    _auth_manager = None

logger.warning(
    "Sentinel-43 AuthManager reset in %s environment.",
    env or "unspecified",
)
```
