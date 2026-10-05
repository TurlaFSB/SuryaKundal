"""Engine and session setup, including the SQLite settings we depend on."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from surya_kundal.database.models import Base

DEFAULT_DATABASE_URL = "sqlite:///data/surya_kundal.db"


def get_database_url() -> str:
    """Return DATABASE_URL from the environment, or the local default."""
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


def create_db_engine(url: str | None = None, *, echo: bool = False) -> Engine:
    """Create an engine. For SQLite files, the parent directory is created if needed."""
    url = url or get_database_url()
    parsed = make_url(url)
    is_sqlite = parsed.get_backend_name() == "sqlite"

    if is_sqlite and parsed.database not in (None, "", ":memory:"):
        Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(url, echo=echo)
    if is_sqlite:
        event.listen(engine, "connect", _configure_sqlite)
    return engine


def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    """Apply per-connection SQLite settings.

    - foreign_keys: SQLite ignores foreign keys unless this is switched on.
    - journal_mode=WAL: lets the dashboard read while the ingester writes.
    - busy_timeout: wait up to 5s on a locked database instead of failing at once.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def init_db(engine: Engine) -> None:
    """Create any missing tables. Existing tables are left untouched."""
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a factory for database sessions bound to ``engine``."""
    return sessionmaker(engine, expire_on_commit=False)
