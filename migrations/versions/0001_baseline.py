"""baseline — the pre-sessions Sentinel-43 schema (the `users` table)

Revision ID: 0001_baseline
Revises:
Create Date: 2026-09-01

Historical anchor for the schema that existed before Alembic (mission §8).
Two supported paths:

  FRESH database        `alembic upgrade head` runs upgrade() below, which
                        creates `users` with the naming_convention names
                        (pk_users, uq_users_email, ix_users_username).

  EXISTING pre-Alembic  `alembic stamp 0001_baseline` — env.py first runs the
  database              semantic compatibility check (migrations/baseline.py);
                        upgrade() is NOT executed, and the table keeps its
                        Postgres-default constraint names. See
                        MIGRATION_BASELINE_PASS5AM.md.

downgrade() is intentionally UNSUPPORTED (mission §12): dropping `users`
destroys every operator/admin account. Data safety over migration symmetry.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if inspect(bind).has_table("users"):
        # An existing pre-Alembic database must be ADOPTED with
        # `alembic stamp 0001_baseline` (after the baseline compatibility
        # check), never `alembic upgrade`. Refuse loudly rather than fail
        # halfway through a CREATE TABLE that already exists.
        raise RuntimeError(
            "0001_baseline.upgrade(): a 'users' table already exists. An "
            "existing Sentinel-43 database is adopted into Alembic with "
            "`alembic stamp 0001_baseline` (env.py runs the compatibility "
            "check first), NOT `alembic upgrade`. See "
            "MIGRATION_BASELINE_PASS5AM.md."
        )

    op.create_table(
        "users",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("user_id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    # username: model uses unique=True + index=True -> a single UNIQUE INDEX
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    raise RuntimeError(
        "0001_baseline downgrade is intentionally unsupported. Reversing it "
        "means DROP TABLE users, which permanently destroys every "
        "operator/admin account. If you truly intend to wipe the schema, do "
        "it explicitly and outside Alembic. (Mission §12: data safety over "
        "migration symmetry.)"
    )
