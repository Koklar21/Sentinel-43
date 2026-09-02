"""sessions — server-side refresh-session persistence (Pass 5A foundation)

Revision ID: 0002_sessions
Revises: 0001_baseline
Create Date: 2026-09-01

Implements exactly the persistence the validated Pass 5A foundation needs
(core/auth/sessions.py :: SessionRecord, SESSION_MODEL_PASS5A.md). No
speculative future-auth fields. No `role` column — role is read from `users`
at refresh time (Pass 5A design; mission §13).

Key decisions (see MIGRATION_ARCHITECTURE_PASS5AM.md):

  * refresh_hash uniqueness = SHAPE B (mission §14): a PARTIAL unique index
    over active (revoked_at IS NULL) rows only —
    `uq_sessions_active_refresh_hash`. Enforces "one parent generation -> at
    most one valid successor" while letting a revoked historical row keep a
    hash a later active row could also hold. An unconditional UNIQUE (shape
    A) would break legitimate rotation/replay history.

  * user_id FK = ON DELETE RESTRICT (mission §15, case 2): grep confirms NO
    user-deletion pathway exists anywhere in core/ (no @router.delete, no
    session.delete() of a User, no raw DELETE FROM users). RESTRICT is the
    least-surprising, least-destructive default; if user deletion is added
    later this decision must be explicitly revisited (cascade vs restrict vs
    set-null is a product call).

downgrade() DROPS the sessions table — **DESTROYS ALL ACTIVE SESSION STATE**.
It does not touch `users` or any unrelated schema (mission §18).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_sessions"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("sid", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("refresh_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_refresh_hash", sa.String(length=64), nullable=True),
        sa.Column("refresh_generation", sa.Integer(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=64), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.PrimaryKeyConstraint("sid", name="pk_sessions"),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"],
            name="fk_sessions_user_id_users",
            ondelete="RESTRICT",
        ),
    )
    # --- indexes (mission §16 — each justified) ---
    # user_id: revoke_all_user_sessions() + the operator's "my sessions" list
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    # prev_refresh_hash: the `OR prev_refresh_hash = :h` arm of
    # _lock_session_for_refresh() (single-step reuse detection)
    op.create_index("ix_sessions_prev_refresh_hash", "sessions", ["prev_refresh_hash"])
    # expires_at: purge_expired_sessions() housekeeping scan
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    # refresh_hash: the primary lookup in _lock_session_for_refresh()
    # (`WHERE refresh_hash = :h`) AND the shape-B uniqueness guard — one
    # partial unique index serves both.
    op.create_index(
        "uq_sessions_active_refresh_hash",
        "sessions",
        ["refresh_hash"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    # DESTROYS ALL ACTIVE SESSION STATE. Leaves `users` and everything else
    # untouched. drop_table drops the table's own indexes with it.
    op.drop_table("sessions")
