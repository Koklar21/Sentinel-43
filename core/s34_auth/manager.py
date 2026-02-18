from datetime import datetime, timezone
from typing import Optional

from .models import AuthContext, AuthResult
from .exceptions import InvalidTokenError, ExpiredTokenError
from .hashing import constant_time_compare


class AuthManager:
    """
    Sentinel-43 unified authentication manager
    """

    def __init__(self, secret: bytes, issuer: str):
        self._secret = secret
        self._issuer = issuer

    def verify_token(self, token: str) -> AuthResult:
        """
        Verify token and return AuthResult
        """

        try:
            context = self._decode_token(token)

            if context.expires_at < datetime.now(timezone.utc):
                raise ExpiredTokenError("Token expired")

            return AuthResult(
                success=True,
                context=context,
            )

        except Exception as e:
            return AuthResult(
                success=False,
                context=None,
                reason=str(e),
            )

    def _decode_token(self, token: str) -> AuthContext:
        """
        Replace this with JWT decode or signed token decode
        """

        # placeholder logic — replace with real JWT or signed blob
        if not token:
            raise InvalidTokenError("Token missing")

        now = datetime.now(timezone.utc)

        return AuthContext(
            subject_id="system",
            device_id="local",
            roles={"core"},
            issued_at=now,
            expires_at=now.replace(year=now.year + 1),
            issuer=self._issuer,
        )