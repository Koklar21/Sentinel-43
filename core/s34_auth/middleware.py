from typing import Optional

from .constants import AUTH_HEADER, BEARER_PREFIX
from .manager import AuthManager


def extract_token(headers: dict) -> Optional[str]:

    auth_header = headers.get(AUTH_HEADER)

    if not auth_header:
        return None

    if not auth_header.startswith(BEARER_PREFIX):
        return None

    return auth_header[len(BEARER_PREFIX):]