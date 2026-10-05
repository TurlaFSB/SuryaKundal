"""index technique_matches.command_id

Deleting or looking up a command's matches scanned the whole table without it.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-05 03:40:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEX = "ix_technique_matches_command_id"


def upgrade() -> None:
    indexes = {i["name"] for i in sa.inspect(op.get_bind()).get_indexes("technique_matches")}
    if INDEX not in indexes:
        op.create_index(INDEX, "technique_matches", ["command_id"])


def downgrade() -> None:
    op.drop_index(INDEX, table_name="technique_matches")
