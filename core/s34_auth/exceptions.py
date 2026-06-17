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

**all** = [
"SentinelSecurityError",
"AuthenticationError",
"AuthorizationError",
"InvalidTokenError",
"ExpiredTokenError",
"ReplayAttackError",
"InvalidSignatureError",
"MFARequiredError",
"PermissionDeniedError",
]

class SentinelSecurityError(Exception):
"""
Base exception for all Sentinel-43 security-related failures.

```
Constructor convention:
    SentinelSecurityError(code, message)

The machine-readable code is kept separate from the human-readable
message so Watchtower, audit logs, and API responses can classify
failures without exposing sensitive values.

Never include raw credentials, tokens, secrets, or authorization headers
inside exception messages.
"""

default_code = "SECURITY_ERROR"

def __init__(
    self,
    code: str,
    message: str,
) -> None:
    if not isinstance(code, str):
        raise TypeError("Security error code must be a string.")

    if not isinstance(message, str):
        raise TypeError("Security error message must be a string.")

    safe_code = code.strip() or self.default_code
    safe_message = message.strip() or "Security operation failed"

    # Store the readable message in Exception.args so str(exc), logs,
    # traceback rendering, and ordinary exception handling remain clear.
    super().__init__(safe_message)

    self.code = safe_code
    self.message = safe_message

def __reduce__(self) -> tuple[type[SentinelSecurityError], tuple[str, str]]:
    """
    Preserve both code and message when exceptions are serialized across
    process boundaries, such as multiprocessing workers or logging pipes.
    """

    return (
        self.__class__,
        (
            self.code,
            self.message,
        ),
    )
```

class AuthenticationError(SentinelSecurityError):
"""
Raised when authentication fails.
"""

```
default_code = "AUTHENTICATION_FAILED"
```

class AuthorizationError(SentinelSecurityError):
"""
Raised when authorization fails.
"""

```
default_code = "AUTHORIZATION_FAILED"
```

class InvalidTokenError(AuthenticationError):
"""
Raised when a token is malformed, unsupported, or otherwise invalid.
"""

```
default_code = "INVALID_TOKEN"
```

class ExpiredTokenError(AuthenticationError):
"""
Raised when a token has expired.
"""

```
default_code = "TOKEN_EXPIRED"
```

class ReplayAttackError(AuthenticationError):
"""
Reserved for replay-detection enforcement.

```
Raised when previously used credentials or signed requests are detected.
"""

default_code = "REPLAY_ATTACK_DETECTED"
```

class InvalidSignatureError(AuthenticationError):
"""
Raised when cryptographic signature verification fails.
"""

```
default_code = "INVALID_SIGNATURE"
```

class MFARequiredError(AuthenticationError):
"""
Reserved for MFA enforcement.

```
Raised when authentication is valid but MFA completion is still required.
"""

default_code = "MFA_REQUIRED"
```

class PermissionDeniedError(AuthorizationError):
"""
Raised when an authenticated subject lacks required permissions.
"""

```
default_code = "PERMISSION_DENIED"
```
