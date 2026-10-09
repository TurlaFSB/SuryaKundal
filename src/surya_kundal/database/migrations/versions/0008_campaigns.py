"""campaigns

Groups of sessions that look like one operation, with the evidence that ties them together.
These tables are derived data and are rebuilt by `surya-kundal campaigns build`.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-09 07:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if "campaigns" not in existing:
        op.create_table(
            "campaigns",
            sa.Column("id", sa.String(16), nullable=False),
            sa.Column("first_seen", sa.DateTime(timezone=True)),
            sa.Column("last_seen", sa.DateTime(timezone=True)),
            sa.Column("session_count", sa.Integer(), nullable=False),
            sa.Column("ip_count", sa.Integer(), nullable=False),
            sa.Column("built_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_campaigns_first_seen", "campaigns", ["first_seen"])
        op.create_index("ix_campaigns_last_seen", "campaigns", ["last_seen"])
    if "campaign_sessions" not in existing:
        op.create_table(
            "campaign_sessions",
            sa.Column("session_id", sa.String(64), nullable=False),
            sa.Column("campaign_id", sa.String(16), nullable=False),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("session_id"),
        )
        op.create_index("ix_campaign_sessions_campaign_id", "campaign_sessions", ["campaign_id"])
    if "campaign_evidence" not in existing:
        op.create_table(
            "campaign_evidence",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("campaign_id", sa.String(16), nullable=False),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column("value", sa.String(300), nullable=False),
            sa.Column("sessions", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_campaign_evidence_campaign_id", "campaign_evidence", ["campaign_id"])


def downgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for table in ("campaign_evidence", "campaign_sessions", "campaigns"):
        if table in existing:
            op.drop_table(table)
