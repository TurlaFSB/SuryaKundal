"""Tests for the database layer: models, engine settings, and idempotent storage."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError

from sample_events import (
    HASSH,
    SESSION_A,
    SESSION_A_EVENTS,
    SHA,
    make_event,
)
from surya_kundal.database.engine import (
    DEFAULT_DATABASE_URL,
    create_db_engine,
    get_database_url,
    init_db,
    make_session_factory,
)
from surya_kundal.database.models import Command, HoneypotSession, Login, UTCDateTime
from surya_kundal.database.repository import parse_timestamp, save_session
from surya_kundal.parser.log_parser import summarize


@pytest.fixture
def engine():
    engine = create_db_engine("sqlite://")
    init_db(engine)
    return engine


@pytest.fixture
def db(engine):
    with make_session_factory(engine)() as session:
        yield session


def _count(db, model):
    return db.scalar(select(func.count()).select_from(model))


# --- engine ----------------------------------------------------------------


def test_init_db_creates_expected_tables(engine):
    assert set(inspect(engine).get_table_names()) == {
        "sessions",
        "logins",
        "commands",
        "downloads",
    }


def test_init_db_is_safe_to_run_twice(engine):
    init_db(engine)


def test_sqlite_file_uses_wal_and_creates_parent_directory(tmp_path):
    url = f"sqlite:///{tmp_path}/nested/dir/test.db"

    engine = create_db_engine(url)

    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_get_database_url_prefers_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///custom.db")
    assert get_database_url() == "sqlite:///custom.db"

    monkeypatch.delenv("DATABASE_URL")
    assert get_database_url() == DEFAULT_DATABASE_URL


# --- constraints -----------------------------------------------------------


def test_foreign_keys_are_enforced(db):
    db.add(Login(session_id="does-not-exist", username="root", password="x", success=False))

    with pytest.raises(IntegrityError):
        db.flush()


def test_command_sequence_is_unique_per_session(db):
    db.add(HoneypotSession(id=SESSION_A))
    db.add(Command(session_id=SESSION_A, seq=0, command="whoami"))
    db.add(Command(session_id=SESSION_A, seq=0, command="id"))

    with pytest.raises(IntegrityError):
        db.flush()


# --- timestamps ------------------------------------------------------------


def test_utc_datetime_rejects_naive_values():
    with pytest.raises(ValueError, match="Naive datetime"):
        UTCDateTime().process_bind_param(datetime(2026, 10, 5, 7, 11), None)


def test_parse_timestamp_handles_cowrie_format():
    assert parse_timestamp("2026-10-05T07:12:02.484294Z") == datetime(
        2026, 10, 5, 7, 12, 2, 484294, tzinfo=UTC
    )


@pytest.mark.parametrize("value", [None, "", "not a timestamp"])
def test_parse_timestamp_returns_none_for_missing_or_malformed(value):
    assert parse_timestamp(value) is None


# --- save_session ----------------------------------------------------------


def test_save_session_persists_all_fields(db):
    save_session(db, SESSION_A, summarize(SESSION_A_EVENTS))
    db.commit()
    db.expire_all()

    stored = db.get(HoneypotSession, SESSION_A)

    assert stored.src_ip == "203.0.113.7"
    assert stored.start_time == datetime(2026, 10, 5, 7, 11, 23, 959011, tzinfo=UTC)
    assert stored.end_time == datetime(2026, 10, 5, 7, 12, 36, 563805, tzinfo=UTC)
    assert stored.duration_ms == 72599
    assert stored.hassh == HASSH

    assert [(x.username, x.password, x.success) for x in stored.logins] == [
        ("root", "123456", False),
        ("root", "apple", True),
    ]
    assert [(c.seq, c.command) for c in stored.commands] == [
        (0, "whoami"),
        (1, "cat /etc/passwd"),
    ]
    assert [(d.url, d.sha256) for d in stored.downloads] == [("http://example.com/test/sh", SHA)]


def test_stored_timestamps_come_back_timezone_aware(db):
    save_session(db, SESSION_A, summarize(SESSION_A_EVENTS))
    db.commit()
    db.expire_all()

    stored = db.get(HoneypotSession, SESSION_A)

    assert stored.start_time.tzinfo is not None
    assert stored.commands[0].timestamp.utcoffset().total_seconds() == 0


def test_save_session_is_idempotent(db):
    summary = summarize(SESSION_A_EVENTS)

    save_session(db, SESSION_A, summary)
    db.commit()
    save_session(db, SESSION_A, summary)
    db.commit()

    assert _count(db, HoneypotSession) == 1
    assert _count(db, Login) == 2
    assert _count(db, Command) == 2


def test_save_session_completes_a_session_stored_while_in_progress(db):
    in_progress = [e for e in SESSION_A_EVENTS if e["eventid"] != "cowrie.session.closed"]
    in_progress = in_progress[:-2]  # drop the second command and the download too

    save_session(db, SESSION_A, summarize(in_progress))
    db.commit()
    assert db.get(HoneypotSession, SESSION_A).end_time is None
    assert _count(db, Command) == 1

    save_session(db, SESSION_A, summarize(SESSION_A_EVENTS))
    db.commit()

    stored = db.get(HoneypotSession, SESSION_A)
    assert stored.end_time is not None
    assert _count(db, Command) == 2
    assert len(stored.downloads) == 1


def test_save_session_tolerates_malformed_timestamp_and_missing_command(db):
    events = [
        make_event(SESSION_A, "cowrie.session.connect", "garbage"),
        make_event(SESSION_A, "cowrie.command.input", "2026-10-05T07:12:02Z", input=None),
        make_event(SESSION_A, "cowrie.command.input", "2026-10-05T07:12:03Z", input="ls"),
    ]

    save_session(db, SESSION_A, summarize(events))
    db.commit()

    stored = db.get(HoneypotSession, SESSION_A)
    assert stored.start_time is None
    assert [c.command for c in stored.commands] == ["ls"]
    assert stored.commands[0].seq == 0


def test_deleting_a_session_removes_its_children(db):
    save_session(db, SESSION_A, summarize(SESSION_A_EVENTS))
    db.commit()

    db.delete(db.get(HoneypotSession, SESSION_A))
    db.commit()

    assert _count(db, Login) == 0
    assert _count(db, Command) == 0
