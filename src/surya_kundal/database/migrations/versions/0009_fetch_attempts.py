"""fetch attempts

Addresses the attacker's commands tried to fetch. Derived from command text, so the mapper
rebuilds them; sessions are mapped again once after this upgrade.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-10 07:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if "fetch_attempts" in existing:
        return
    op.create_table(
        "fetch_attempts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(64), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("tool", sa.String(16), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", "url", name="uq_fetch_attempt"),
    )
    op.create_index("ix_fetch_attempts_session_id", "fetch_attempts", ["session_id"])
    op.create_index("ix_fetch_attempts_url", "fetch_attempts", ["url"])


def downgrade() -> None:
    op.drop_table("fetch_attempts")
