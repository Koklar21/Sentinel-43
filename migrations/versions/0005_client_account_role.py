"""add permanent client account role

Revision ID: 0005_client_account_role
Revises: 0004_single_admin_observer_roles
Create Date: 2026-10-03

Adds the non-governance client role without changing administrator or observer
authority. Existing accounts are not reclassified.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0005_client_account_role"
down_revision: Union[str, None] = "0004_single_admin_observer_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("role", "users", type_="check")
    op.create_check_constraint(
        "role",
        "users",
        "role IN ('client', 'observer', 'admin')",
    )


def downgrade() -> None:
    # Fail naturally if client rows still exist. Downgrade must never silently
    # promote or reinterpret an untrusted client as a governance observer.
    op.drop_constraint("role", "users", type_="check")
    op.create_check_constraint(
        "role",
        "users",
        "role IN ('observer', 'admin')",
    )
