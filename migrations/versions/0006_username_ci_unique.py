"""enforce case-insensitive username uniqueness

Revision ID: 0006_username_ci_unique
Revises: 0005_client_account_role
Create Date: 2026-10-04

Authentication throttling canonicalizes usernames case-insensitively. Account
identity must therefore use the same equivalence relation so a case-variant
account can never share and clear another account's throttle bucket.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_username_ci_unique"
down_revision: Union[str, None] = "0005_client_account_role"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    connection = op.get_bind()
    duplicates = connection.execute(
        sa.text(
            """
            SELECT lower(username) AS canonical, count(*) AS n
            FROM users
            GROUP BY lower(username)
            HAVING count(*) > 1
            LIMIT 1
            """
        )
    ).first()
    if duplicates is not None:
        raise RuntimeError(
            "cannot enforce case-insensitive username uniqueness: "
            "case-variant duplicate accounts already exist"
        )

    op.create_index(
        "uq_users_username_ci",
        "users",
        [sa.text("lower(username)")],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_users_username_ci",
        table_name="users",
    )
