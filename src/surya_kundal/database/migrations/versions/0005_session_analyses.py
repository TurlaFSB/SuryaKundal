"""session analyses

Optional machine-written summaries of sessions (local language model). Stored apart
from the facts so they can always be told apart and deleted without touching evidence.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-05 19:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if "session_analyses" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "session_analyses",
        sa.Column("session_id", sa.String(64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("intent", sa.String(32), nullable=False),
        sa.Column("sophistication", sa.String(24), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("model", sa.String(64), nullable=False),
        sa.Column("prompt_version", sa.String(8), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("session_id"),
    )


def downgrade() -> None:
    op.drop_table("session_analyses")
