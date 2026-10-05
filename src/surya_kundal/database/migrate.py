"""Bring a database up to the current schema with Alembic.

``upgrade_database`` is safe in every situation:

- a new, empty database gets every table;
- a database from before migrations existed (it has our tables but no
  ``alembic_version``) gets any missing tables and is then marked as migrated;
- a database already under migration is upgraded to the latest revision.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

from surya_kundal.database.models import Base

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


class SchemaError(RuntimeError):
    """The database file has a shape this version of the code cannot write to."""


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


def upgrade_database(engine: Engine) -> None:
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    _check_compatible(engine)


def _check_compatible(engine: Engine) -> None:
    """Fail clearly if an old database has required columns the code does not fill in.

    Migrations only add missing tables, so a database created by a much older version
    can keep columns that were later removed. If one of them is NOT NULL with no
    default, every insert would fail, one traceback per session.
    """
    inspector = inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        known = {column.name for column in table.columns}
        for column in inspector.get_columns(table.name):
            if column["name"] in known or column["nullable"] or column.get("default") is not None:
                continue
            raise SchemaError(
                f"This database is from an older version: table '{table.name}' has a "
                f"required column '{column['name']}' that the current code does not "
                "fill in. Move the file aside and re-import the log, which rebuilds "
                "everything: mv <database file> <database file>.old && surya-kundal ingest"
            )
