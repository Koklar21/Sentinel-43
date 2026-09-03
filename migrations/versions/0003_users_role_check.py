"""users.role CHECK constraint (RELEASE_FINDINGS P3-7)

Revision ID: 0003_users_role_check
Revises: 0002_sessions
Create Date: 2026-09-02

P3-7: ``User.role`` is validated at the application boundary
(``APPROVED_ROLES``) but had no database CHECK constraint, so a bad value
written by raw SQL / a future bug would sit undetected. This adds
``CHECK (role IN ('operator', 'admin'))``.

**Fail closed on adoption.** Before adding the constraint this migration
counts rows that would violate it. If any exist it raises and changes
nothing -- an operator must reconcile the data (the "live-data inventory"
the Pass 5AM authorization §9 asked for) and re-run. A fresh beta database
has no such rows.

downgrade() drops the constraint. It does not touch data.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_users_role_check"
down_revision: Union[str, None] = "0002_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ALLOWED = ("operator", "admin")


def upgrade() -> None:
    bind = op.get_bind()
    # The allowed set is a fixed constant — inline it (no bind params, so this
    # works identically under every driver).
    bad = bind.execute(
        sa.text("SELECT count(*) FROM users WHERE role NOT IN ('operator', 'admin')")
    ).scalar_one()
    if bad:
        raise RuntimeError(
            f"{bad} users row(s) have a role outside {_ALLOWED}. "
            "Reconcile them (UPDATE users SET role=... WHERE ...) before "
            "applying 0003_users_role_check. Nothing was changed."
        )
    # Pass the bare name "role"; the naming_convention on target_metadata
    # ("ck_%(table_name)s_%(constraint_name)s") renders it as ck_users_role,
    # matching core.auth.users.User.__table_args__.
    op.create_check_constraint("role", "users", "role IN ('operator', 'admin')")


def downgrade() -> None:
    # Bare name again — the convention renders it to ck_users_role.
    op.drop_constraint("role", "users", type_="check")
