# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Governed identity/account mutation service.

Credential verification and password hashing remain auth primitives. This
service owns the consequential account lifecycle operations that change
Sentinel-43 authority: first-admin claim, account creation, role/active
changes, password reset, and the session revocation coupled to those changes.

Every mutation is authorized/audited through the single runtime authority
before the account store is changed. Persistence remains in core.auth users
and sessions; those modules are storage/security primitives, not authorities.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from core.auth.sessions import revoke_all_user_sessions
from core.auth.users import (
    ADMIN_INVARIANT_LOCK_KEY,
    User,
    _pg_advisory_xact_lock,
    count_active_admins,
    create_first_admin,
    create_user,
    get_user_by_id,
    set_user_active,
    set_user_password,
    set_user_role,
)


logger = logging.getLogger("sentinel43.identity")


class IdentityGovernanceError(RuntimeError):
    """Base class for governed identity mutation refusals."""


class IdentityTargetNotFound(IdentityGovernanceError):
    """The requested account does not exist."""


class IdentitySelfDeactivationRefused(IdentityGovernanceError):
    """An administrator tried to deactivate their own account."""


class IdentityLastAdminRefused(IdentityGovernanceError):
    """The change would remove the final active administrator."""


class IdentityGovernanceService:
    """Own consequential account mutations beneath Sentinel-43 authority."""

    def __init__(
        self,
        *,
        audit_sink: Callable[[dict[str, Any]], None],
    ) -> None:
        if not callable(audit_sink):
            raise ValueError("identity governance requires an audit sink")
        self._audit_sink = audit_sink

    def _authorize(
        self,
        *,
        operation: str,
        actor: str,
        target: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        """Fail closed before a consequential account mutation."""
        self._audit_sink(
            {
                "subsystem": "sentinel43_identity",
                "component": "identity_governance",
                "decision": "IDENTITY_MUTATION_AUTHORIZED",
                "reason_code": operation,
                "actor": str(actor)[:200],
                "target": str(target)[:200],
                "metadata": dict(metadata or {}),
            }
        )

    @staticmethod
    async def _rollback_safely(session: AsyncSession) -> None:
        try:
            await session.rollback()
        except Exception:
            logger.exception("Identity-governance rollback failed")

    @staticmethod
    async def _revoke_sessions(
        session: AsyncSession,
        user_id: uuid.UUID,
        *,
        reason: str,
    ) -> None:
        await revoke_all_user_sessions(
            session,
            user_id,
            reason=reason,
        )

    @staticmethod
    async def _would_orphan_admins(
        session: AsyncSession,
        target: User,
        *,
        new_is_active: bool | None,
        new_role: str | None,
    ) -> bool:
        if not (
            bool(target.is_active)
            and str(target.role).lower() == "admin"
        ):
            return False

        effective_is_active = (
            bool(target.is_active)
            if new_is_active is None
            else bool(new_is_active)
        )
        effective_role = (
            str(target.role).lower()
            if new_role is None
            else str(new_role).lower()
        )
        if effective_is_active and effective_role == "admin":
            return False

        return await count_active_admins(session) <= 1

    async def bootstrap_first_admin(
        self,
        session: AsyncSession,
        *,
        username: str,
        password: str,
        email: str | None,
    ) -> User:
        self._authorize(
            operation="bootstrap_first_admin",
            actor="bootstrap:uninitialized",
            target=username,
            metadata={"role": "admin"},
        )
        try:
            user = await create_first_admin(
                session,
                username=username,
                password=password,
                email=email,
            )
            await session.commit()
            return user
        except Exception:
            await self._rollback_safely(session)
            raise

    async def create_account(
        self,
        session: AsyncSession,
        *,
        actor: str,
        username: str,
        password: str,
        role: str,
        email: str | None,
    ) -> User:
        self._authorize(
            operation="create_account",
            actor=actor,
            target=username,
            metadata={"role": role},
        )
        try:
            user = await create_user(
                session,
                username=username,
                password=password,
                role=role,
                email=email,
            )
            await session.commit()
            return user
        except Exception:
            await self._rollback_safely(session)
            raise

    async def update_account(
        self,
        session: AsyncSession,
        *,
        actor: str,
        user_id: uuid.UUID,
        new_is_active: bool | None,
        new_role: str | None,
    ) -> User:
        target = await get_user_by_id(session, user_id)
        if target is None:
            raise IdentityTargetNotFound(str(user_id))

        if target.username == actor and new_is_active is False:
            raise IdentitySelfDeactivationRefused(target.username)

        touches_admin_count = (
            (
                new_is_active is not None
                and str(target.role).lower() == "admin"
            )
            or (
                new_role is not None
                and (
                    str(target.role).lower() == "admin"
                    or str(new_role).lower() == "admin"
                )
            )
        )

        self._authorize(
            operation="update_account",
            actor=actor,
            target=target.username,
            metadata={
                "new_is_active": new_is_active,
                "new_role": new_role,
            },
        )

        try:
            if touches_admin_count:
                await _pg_advisory_xact_lock(
                    session,
                    ADMIN_INVARIANT_LOCK_KEY,
                )

            if await self._would_orphan_admins(
                session,
                target,
                new_is_active=new_is_active,
                new_role=new_role,
            ):
                raise IdentityLastAdminRefused(target.username)

            role_changed = (
                new_role is not None
                and str(new_role).lower() != str(target.role).lower()
            )
            deactivated = (
                new_is_active is False
                and bool(target.is_active)
            )

            if role_changed:
                target = await set_user_role(
                    session,
                    target,
                    role=str(new_role).lower(),
                )

            if (
                new_is_active is not None
                and bool(new_is_active) != bool(target.is_active)
            ):
                target = await set_user_active(
                    session,
                    target,
                    is_active=bool(new_is_active),
                )

            if deactivated:
                await self._revoke_sessions(
                    session,
                    target.user_id,
                    reason="account_disabled",
                )
            elif role_changed:
                await self._revoke_sessions(
                    session,
                    target.user_id,
                    reason="role_changed",
                )

            await session.commit()
            return target
        except Exception:
            await self._rollback_safely(session)
            raise

    async def create_login_session(
        self,
        session: AsyncSession,
        *,
        actor: str,
        user_id: uuid.UUID,
        refresh_secret: str,
        client_ip: str | None,
        user_agent: str | None,
    ) -> Any:
        """Create and commit one DB-backed login session through S43."""
        from core.auth.sessions import create_session

        self._authorize(
            operation="create_login_session",
            actor=actor,
            target=str(user_id),
        )
        try:
            row = await create_session(
                session,
                user_id=user_id,
                refresh_secret=refresh_secret,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            await session.commit()
            return row
        except Exception:
            await self._rollback_safely(session)
            raise

    async def rotate_session_refresh(
        self,
        session: AsyncSession,
        *,
        presented_secret: str,
        new_refresh_secret: str,
    ) -> tuple[Any, Any, User]:
        """Rotate refresh state while preserving revocation-on-abuse semantics."""
        from core.auth.sessions import (
            RefreshReuseError,
            SessionOwnerInactiveError,
            rotate_refresh,
        )

        self._authorize(
            operation="rotate_session_refresh",
            actor="session:refresh",
            target="presented_session",
        )
        try:
            row, outcome = await rotate_refresh(
                session,
                presented_secret=presented_secret,
                new_refresh_secret=new_refresh_secret,
            )
            owner = await get_user_by_id(session, row.user_id)
            if owner is None or not bool(owner.is_active):
                raise IdentityGovernanceError(
                    "rotated session owner is unavailable or inactive"
                )
            await session.commit()
            return row, outcome, owner

        except (RefreshReuseError, SessionOwnerInactiveError):
            # The primitive intentionally revokes the session before raising.
            # Persist that security state before propagating the refusal.
            await session.commit()
            raise

        except Exception:
            await self._rollback_safely(session)
            raise

    async def logout_session_by_refresh(
        self,
        session: AsyncSession,
        *,
        presented_secret: str,
    ) -> bool:
        """Revoke a server-side session through the S43 authority."""
        from core.auth.sessions import logout_by_refresh

        self._authorize(
            operation="logout_session",
            actor="session:logout",
            target="presented_session",
        )
        try:
            revoked = await logout_by_refresh(
                session,
                presented_secret=presented_secret,
            )
            await session.commit()
            return bool(revoked)
        except Exception:
            await self._rollback_safely(session)
            raise

    async def reset_password(
        self,
        session: AsyncSession,
        *,
        actor: str,
        user_id: uuid.UUID,
        new_password: str,
    ) -> User:
        target = await get_user_by_id(session, user_id)
        if target is None:
            raise IdentityTargetNotFound(str(user_id))

        self._authorize(
            operation="reset_password",
            actor=actor,
            target=target.username,
        )
        try:
            target = await set_user_password(
                session,
                target,
                password=new_password,
            )
            await self._revoke_sessions(
                session,
                target.user_id,
                reason="password_reset",
            )
            await session.commit()
            return target
        except Exception:
            await self._rollback_safely(session)
            raise


__all__ = [
    "IdentityGovernanceError",
    "IdentityGovernanceService",
    "IdentityLastAdminRefused",
    "IdentitySelfDeactivationRefused",
    "IdentityTargetNotFound",
]
