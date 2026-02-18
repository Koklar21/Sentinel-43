from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Set


@dataclass(frozen=True)
class AuthContext:
    """
    Represents authenticated identity
    """
    subject_id: str
    device_id: Optional[str]
    roles: Set[str]
    issued_at: datetime
    expires_at: datetime
    issuer: str


@dataclass(frozen=True)
class AuthResult:
    """
    Result of auth verification
    """
    success: bool
    context: Optional[AuthContext]
    reason: Optional[str] = None