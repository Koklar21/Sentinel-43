from typing import Mapping, Optional

from .constants import AUTH_HEADER, BEARER_PREFIX


def extract_token(headers: Optional[Mapping[str, str]]) -> Optional[str]:
    """
    Extract a Bearer token from request headers.

    Returns None when:
    - headers is None or empty
    - Authorization header is missing
    - Authorization header is not a string
    - scheme is not Bearer
    - token is missing or malformed
    """
    if not headers:
        return None

    auth_header = headers.get(AUTH_HEADER)
    if not isinstance(auth_header, str):
        return None

    parts = auth_header.strip().split()

    expected_scheme = BEARER_PREFIX.strip().lower()

    if len(parts) != 2:
        return None

    scheme, token = parts

    if scheme.lower() != expected_scheme:
        return None

    token = token.strip()
    if not token:
        return None

    return token