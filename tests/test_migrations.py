"""Tests for schema migrations: fresh, legacy and partially built databases."""

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, select, text

from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.migrate import alembic_config, upgrade_database
from surya_kundal.database.models import Base, HoneypotSession


@pytest.fixture
def engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/m.db")
    yield engine
    engine.dispose()


def _head() -> str:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def _version(engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("select version_num from alembic_version")).scalar_one()


def test_there_is_exactly_one_migration_head():
    heads = ScriptDirectory.from_config(alembic_config()).get_heads()

    assert len(heads) == 1


def test_a_new_database_is_built_and_marked_current(engine):
    upgrade_database(engine)

    tables = set(inspect(engine).get_table_names())
    assert {"sessions", "logins", "commands", "downloads", "technique_matches"} <= tables
    assert _version(engine) == _head()


def test_migrations_and_models_describe_the_same_schema(engine):
    """Fails when someone changes a model without writing a migration."""
    upgrade_database(engine)

    with engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        differences = compare_metadata(context, Base.metadata)

    assert differences == []


def test_upgrading_twice_changes_nothing(engine):
    upgrade_database(engine)
    upgrade_database(engine)

    assert _version(engine) == _head()


def test_a_database_from_before_migrations_keeps_its_data(engine):
    # What the app built before Alembic: every table, no version table, no 0002 index.
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("drop index ix_technique_matches_command_id"))
        conn.execute(text("insert into sessions (id, src_ip) values ('legacy1', '45.33.32.156')"))

    upgrade_database(engine)

    assert _version(engine) == _head()
    names = {i["name"] for i in inspect(engine).get_indexes("technique_matches")}
    assert "ix_technique_matches_command_id" in names
    with engine.connect() as conn:
        assert conn.execute(text("select src_ip from sessions")).scalar_one() == "45.33.32.156"


def test_an_early_database_with_only_the_first_tables_gains_the_rest(engine):
    early = ["sessions", "logins", "commands", "downloads"]
    Base.metadata.create_all(engine, tables=[Base.metadata.tables[t] for t in early])
    with engine.begin() as conn:
        conn.execute(text("insert into sessions (id) values ('early1')"))

    upgrade_database(engine)

    tables = set(inspect(engine).get_table_names())
    assert {"ip_geo", "ip_intel", "file_intel", "technique_matches", "session_mappings"} <= tables
    with engine.connect() as conn:
        assert conn.execute(text("select id from sessions")).scalar_one() == "early1"


def test_downgrade_to_base_removes_everything(engine):
    upgrade_database(engine)
    config = alembic_config()
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.downgrade(config, "base")

    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}


def test_init_db_uses_migrations_and_works_in_memory():
    memory = create_db_engine("sqlite://")

    init_db(memory)

    with make_session_factory(memory)() as db:
        assert db.scalars(select(HoneypotSession)).all() == []
    assert _version(memory) == _head()


def test_a_database_from_an_older_version_is_refused_with_a_clear_message(tmp_path, capsys):
    from sqlalchemy import text

    from surya_kundal.cli import main
    from surya_kundal.database.migrate import SchemaError

    path = tmp_path / "old.db"
    engine = create_db_engine(f"sqlite:///{path}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE sessions (id VARCHAR(64) PRIMARY KEY)"))
        connection.execute(
            text(
                "CREATE TABLE commands (id INTEGER PRIMARY KEY, session_id VARCHAR(64) NOT NULL,"
                " seq INTEGER NOT NULL, command TEXT NOT NULL, timestamp DATETIME)"
            )
        )
    with pytest.raises(SchemaError, match=r"older version.*seq"):
        init_db(engine)
    engine.dispose()

    assert main(["list", "--db", f"sqlite:///{path}"]) == 2
    assert "older version" in capsys.readouterr().err


def test_upgrade_marks_existing_local_sessions_internal(engine):
    config = alembic_config()
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.upgrade(config, "0009")
        for sid, ip in (("a", "172.29.77.1"), ("b", "80.66.76.10"), ("c", None)):
            conn.execute(
                text("INSERT INTO sessions (id, src_ip) VALUES (:id, :ip)"), {"id": sid, "ip": ip}
            )
        command.upgrade(config, "head")
    with engine.connect() as conn:
        rows = dict(conn.execute(text("SELECT id, internal FROM sessions")).all())
    assert rows == {"a": 1, "b": 0, "c": 0}
