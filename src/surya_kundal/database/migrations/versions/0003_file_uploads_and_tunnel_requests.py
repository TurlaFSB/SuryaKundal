"""file uploads and tunnel requests

Adds the tables for files attackers upload (SFTP/SCP) and for port-forwarding requests,
and two columns that tell the ATT&CK mapper when a session gained either.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-05 03:38:58
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())
    mapping_columns = {c["name"] for c in inspector.get_columns("session_mappings")}

    if "tunnel_requests" not in existing:
        op.create_table(
            "tunnel_requests",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("dst_ip", sa.Text(), nullable=False),
            sa.Column("dst_port", sa.Integer(), nullable=False),
            sa.Column("orig_ip", sa.Text(), nullable=False),
            sa.Column("orig_port", sa.Integer(), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "session_id",
                "timestamp",
                "dst_ip",
                "dst_port",
                "orig_ip",
                "orig_port",
                name="uq_tunnel_event",
            ),
        )
        op.create_index("ix_tunnel_requests_session_id", "tunnel_requests", ["session_id"])

    if "uploads" not in existing:
        op.create_table(
            "uploads",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("filename", sa.Text(), nullable=False),
            sa.Column("destination", sa.Text(), nullable=True),
            sa.Column("sha256", sa.String(length=64), nullable=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "session_id", "timestamp", "filename", "sha256", name="uq_upload_event"
            ),
        )
        op.create_index("ix_uploads_session_id", "uploads", ["session_id"])
        op.create_index("ix_uploads_sha256", "uploads", ["sha256"])

    for column in ("transfer_count", "tunnel_count"):
        if column not in mapping_columns:
            with op.batch_alter_table("session_mappings") as batch_op:
                batch_op.add_column(
                    sa.Column(column, sa.Integer(), server_default="0", nullable=False)
                )


def downgrade() -> None:
    with op.batch_alter_table("session_mappings") as batch_op:
        batch_op.drop_column("tunnel_count")
        batch_op.drop_column("transfer_count")
    op.drop_table("uploads")
    op.drop_table("tunnel_requests")
