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
