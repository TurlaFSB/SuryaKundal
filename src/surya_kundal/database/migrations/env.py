"""Alembic environment.

Used two ways: by ``init_db`` (which hands in a live connection) and by the ``alembic``
command for developers writing new revisions (which reads DATABASE_URL).
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from surya_kundal.config import Settings
from surya_kundal.database.models import Base

config = context.config
target_metadata = Base.metadata


def _configure(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=True,  # SQLite cannot ALTER most things in place
    )


def run_migrations() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = create_engine(Settings.from_env().database_url)
    with engine.connect() as connection:
        _configure(connection)
        with context.begin_transaction():
            context.run_migrations()


run_migrations()
