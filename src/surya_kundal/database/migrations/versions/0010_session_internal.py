"""mark internal sessions

Adds sessions.internal: traffic from non-public addresses (loopback, Docker bridges, LAN) or from
networks listed in INTERNAL_NETWORKS. Existing sessions are classified once here.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-10 09:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from surya_kundal.internal import is_internal

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("sessions")}
    if "internal" not in columns:
        op.add_column(
            "sessions",
            sa.Column("internal", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        )
        op.create_index("ix_sessions_internal", "sessions", ["internal"])
    if "src_ip" not in columns:
        return
    addresses = [row[0] for row in bind.execute(sa.text("SELECT DISTINCT src_ip FROM sessions"))]
    for address in addresses:
        if address and is_internal(address):
            bind.execute(
                sa.text("UPDATE sessions SET internal = 1 WHERE src_ip = :ip"), {"ip": address}
            )


def downgrade() -> None:
    op.drop_index("ix_sessions_internal", table_name="sessions")
    op.drop_column("sessions", "internal")
