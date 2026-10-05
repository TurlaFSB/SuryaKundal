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
from sqlalchemy import Engine

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


def upgrade_database(engine: Engine) -> None:
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
