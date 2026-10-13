"""state or region of an IP address, for the dashboard map

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-13 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("ip_geo")}
    if "region" not in columns:
        # NULL means "not looked up since regions were added"; "" means "looked up, none".
        op.add_column("ip_geo", sa.Column("region", sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ip_geo") as batch:
        batch.drop_column("region")
