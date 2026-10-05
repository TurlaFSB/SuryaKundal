"""ingest offsets

Remembers where the live watcher stopped in each log so a restart resumes there
instead of re-reading everything or skipping what arrived while it was down.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-05 13:10:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if "ingest_offsets" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "ingest_offsets",
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("inode", sa.BigInteger(), nullable=False),
        sa.Column("offset", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("path"),
    )


def downgrade() -> None:
    op.drop_table("ingest_offsets")
