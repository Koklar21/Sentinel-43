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

import hashlib
import hmac
from typing import TypeAlias, Union

BytesLike: TypeAlias = Union[
bytes,
bytearray,
memoryview,
]

**all** = [
"BytesLike",
"hmac_sha256",
"hmac_sha256_bytes",
"constant_time_compare",
]

def _require_bytes_like(
name: str,
value: object,
) -> BytesLike:
"""
Validate that a cryptographic input supports the bytes buffer protocol.
"""

```
if not isinstance(
    value,
    (
        bytes,
        bytearray,
        memoryview,
    ),
):
    raise TypeError(
        f"{name} must be bytes, bytearray, or memoryview"
    )

return value
```

def _resolve_secret(secret: BytesLike) -> bytes:
"""
Validate and normalize an HMAC secret.

```
Secret keys are expected to be small, so resolving them to immutable
bytes is deliberate. Message payloads are passed through without copying.
"""

validated = _require_bytes_like(
    "secret",
    secret,
)

# bool(memoryview(b"")) is False because memoryview exposes its length.
# The same empty check therefore works for bytes, bytearray, and
# memoryview inputs.
if not validated:
    raise ValueError(
        "secret must not be empty"
    )

return bytes(validated)
```

def hmac_sha256_bytes(
secret: BytesLike,
message: BytesLike,
) -> bytes:
"""
Generate a raw HMAC-SHA256 digest.

```
The secret is normalized to immutable bytes. The message is passed
directly to hmac.HMAC.update() so large bytearray and memoryview payloads
do not incur an unnecessary full-size copy.
"""

resolved_secret = _resolve_secret(secret)

resolved_message = _require_bytes_like(
    "message",
    message,
)

digest = hmac.new(
    resolved_secret,
    digestmod=hashlib.sha256,
)

digest.update(resolved_message)

return digest.digest()
```

def hmac_sha256(
secret: BytesLike,
message: BytesLike,
) -> str:
"""
Generate a hexadecimal HMAC-SHA256 digest.

```
Delegates to hmac_sha256_bytes() so validation and cryptographic behavior
remain centralized in one implementation.
"""

return hmac_sha256_bytes(
    secret,
    message,
).hex()
```

def _normalize_compare_value(
name: str,
value: str | BytesLike,
) -> bytes:
"""
Normalize supported comparison inputs to immutable bytes.

```
This function is intended for digest-sized values such as signatures,
MACs, and token fragments. It is not intended for bulk payload comparison.
"""

if isinstance(value, str):
    return value.encode("utf-8")

validated = _require_bytes_like(
    name,
    value,
)

return bytes(validated)
```

def constant_time_compare(
a: str | BytesLike,
b: str | BytesLike,
) -> bool:
"""
Compare digest-sized values using the standard-library constant-time
primitive.

```
Inputs are normalized to bytes before comparison so mixed supported input
types do not take a separate early-return path.
"""

left = _normalize_compare_value(
    "a",
    a,
)

right = _normalize_compare_value(
    "b",
    b,
)

return hmac.compare_digest(
    left,
    right,
)
```
