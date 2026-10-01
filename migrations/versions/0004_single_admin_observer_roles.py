"""single administrator + observer account roles

Revision ID: 0004_single_admin_observer_roles
Revises: 0003_users_role_check
Create Date: 2026-10-01

Human-account model:
- exactly one administrator is created by first-run bootstrap
- every later human account is an observer
- observers may participate in human approval/veto decisions
- no normal account-management path may promote/demote administrator role

The database can enforce "at most one admin" with a partial unique index.
"At least one admin" is enforced by bootstrap/application invariants once a
store is initialized. For an existing populated database this migration fails
closed if zero or multiple administrators exist rather than choosing an owner
implicitly.

Existing operator rows are migrated to observer.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_single_admin_observer_roles"
down_revision: Union[str, None] = "0003_users_role_check"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SINGLE_ADMIN_INDEX = "uq_users_single_admin"


def upgrade() -> None:
    bind = op.get_bind()

    bad = bind.execute(
        sa.text(
            "SELECT count(*) FROM users "
            "WHERE role NOT IN ('operator', 'admin')"
        )
    ).scalar_one()
    if bad:
        raise RuntimeError(
            f"{bad} users row(s) have an unsupported pre-0004 role. "
            "Reconcile them before applying the single-admin migration."
        )

    total = bind.execute(sa.text("SELECT count(*) FROM users")).scalar_one()
    admins = bind.execute(
        sa.text("SELECT count(*) FROM users WHERE role = 'admin'")
    ).scalar_one()

    if admins > 1:
        raise RuntimeError(
            "single-admin migration refused: multiple administrator accounts "
            "exist. Select/reconcile the deployment administrator explicitly."
        )
    if total > 0 and admins == 0:
        raise RuntimeError(
            "single-admin migration refused: populated account store has no "
            "administrator. Restore/reconcile the administrator explicitly."
        )

    op.drop_constraint("role", "users", type_="check")
    bind.execute(sa.text("UPDATE users SET role = 'observer' WHERE role = 'operator'"))
    op.create_check_constraint(
        "role",
        "users",
        "role IN ('observer', 'admin')",
    )
    op.create_index(
        _SINGLE_ADMIN_INDEX,
        "users",
        ["role"],
        unique=True,
        postgresql_where=sa.text("role = 'admin'"),
        sqlite_where=sa.text("role = 'admin'"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_index(_SINGLE_ADMIN_INDEX, table_name="users")
    op.drop_constraint("role", "users", type_="check")
    bind.execute(sa.text("UPDATE users SET role = 'operator' WHERE role = 'observer'"))
    op.create_check_constraint(
        "role",
        "users",
        "role IN ('operator', 'admin')",
    )
