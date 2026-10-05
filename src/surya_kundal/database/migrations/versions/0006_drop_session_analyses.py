"""drop session analyses

The optional language-model summaries were removed from the project. Migration 0005
stays in the history because databases may already have applied it; this one removes
the table it created, so every database ends up with the same schema.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-05 20:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if "session_analyses" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("session_analyses")


def downgrade() -> None:
    pass  # the feature no longer exists; there is nothing to restore
