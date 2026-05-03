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
