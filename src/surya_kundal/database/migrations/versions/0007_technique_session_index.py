"""index technique matches by technique and session

Filtering sessions by technique ("show me every session that used T1082") looks up
matches by technique first and then collects their sessions; this composite index
serves exactly that, so the lookup stays fast on a database with millions of rows.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-05 21:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NAME = "ix_technique_matches_technique_session"


def _exists() -> bool:
    indexes = sa.inspect(op.get_bind()).get_indexes("technique_matches")
    return any(i["name"] == NAME for i in indexes)


def upgrade() -> None:
    if not _exists():
        op.create_index(NAME, "technique_matches", ["technique_id", "session_id"])


def downgrade() -> None:
    if _exists():
        op.drop_index(NAME, table_name="technique_matches")
