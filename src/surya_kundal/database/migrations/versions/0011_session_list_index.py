"""index for the dashboard's session list

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-10 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NAME = "ix_sessions_internal_start"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {i["name"] for i in inspector.get_indexes("sessions")}
    columns = {c["name"] for c in inspector.get_columns("sessions")}
    if NAME not in existing and {"internal", "start_time"} <= columns:
        op.create_index(NAME, "sessions", ["internal", "start_time"])


def downgrade() -> None:
    op.drop_index(NAME, table_name="sessions")
