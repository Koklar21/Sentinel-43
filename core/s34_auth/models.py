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

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import uuid


@dataclass
class KeyUsageRecord:

    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # WHO
    subject_id: str = ""
    device_id: Optional[str] = None
    issuer: str = ""

    # WHAT
    key_id: str = ""
    token_hash: str = ""
    auth_method: str = "HMAC"

    # WHEN
    issued_at: Optional[datetime] = None
    used_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    # WHERE
    source_ip: Optional[str] = None
    node_id: Optional[str] = None
    service: Optional[str] = None

    # STATE
    valid: bool = True
    reason: Optional[str] = None