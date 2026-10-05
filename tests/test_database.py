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
from surya_kundal.database.models import Command, Download, HoneypotSession, Login, UTCDateTime
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
        "ingest_offsets",
        "sessions",
        "logins",
        "commands",
        "downloads",
        "ip_geo",
        "ip_intel",
        "file_intel",
        "session_mappings",
        "technique_matches",
        "uploads",
        "tunnel_requests",
        "alembic_version",
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


def test_database_refuses_a_duplicate_command_event(db):
    ts = datetime(2026, 10, 5, 7, 12, 2, tzinfo=UTC)
    db.add(HoneypotSession(id=SESSION_A))
    db.add(Command(session_id=SESSION_A, timestamp=ts, command="whoami"))
    db.add(Command(session_id=SESSION_A, timestamp=ts, command="whoami"))

    with pytest.raises(IntegrityError):
        db.flush()


def test_database_refuses_a_duplicate_login_event(db):
    ts = datetime(2026, 10, 5, 7, 12, 2, tzinfo=UTC)
    db.add(HoneypotSession(id=SESSION_A))
    for _ in range(2):
        db.add(
            Login(session_id=SESSION_A, timestamp=ts, username="root", password="x", success=False)
        )

    with pytest.raises(IntegrityError):
        db.flush()


def test_database_refuses_a_duplicate_download_event(db):
    ts = datetime(2026, 10, 5, 7, 12, 2, tzinfo=UTC)
    db.add(HoneypotSession(id=SESSION_A))
    for _ in range(2):
        db.add(Download(session_id=SESSION_A, timestamp=ts, url="http://x/y", sha256=SHA))

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
    assert [c.command for c in stored.commands] == ["whoami", "cat /etc/passwd"]
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


# --- merge behaviour -------------------------------------------------------


def _ids(db):
    return {
        "commands": sorted(db.scalars(select(Command.id)).all()),
        "logins": sorted(db.scalars(select(Login.id)).all()),
        "downloads": sorted(db.scalars(select(Download.id)).all()),
    }


def test_resaving_leaves_existing_row_ids_untouched(db):
    summary = summarize(SESSION_A_EVENTS)
    save_session(db, SESSION_A, summary)
    db.commit()
    before = _ids(db)

    save_session(db, SESSION_A, summary)
    db.commit()

    assert _ids(db) == before


def test_pieces_of_one_session_are_merged_not_overwritten(db):
    first_half = SESSION_A_EVENTS[:6]  # up to and including the first command
    second_half = SESSION_A_EVENTS[6:]  # second command, download, close

    save_session(db, SESSION_A, summarize(first_half))
    db.commit()
    save_session(db, SESSION_A, summarize(second_half))
    db.commit()
    db.expire_all()

    stored = db.get(HoneypotSession, SESSION_A)
    assert [c.command for c in stored.commands] == ["whoami", "cat /etc/passwd"]
    assert len(stored.logins) == 2
    assert len(stored.downloads) == 1
    assert stored.end_time is not None
    assert stored.hassh == HASSH


def test_a_partial_view_never_destroys_what_is_already_stored(db):
    save_session(db, SESSION_A, summarize(SESSION_A_EVENTS))
    db.commit()
    before = _ids(db)

    only_the_close_event = [SESSION_A_EVENTS[-1]]
    save_session(db, SESSION_A, summarize(only_the_close_event))
    db.commit()
    db.expire_all()

    stored = db.get(HoneypotSession, SESSION_A)
    assert _ids(db) == before
    assert stored.hassh == HASSH
    assert stored.start_time == datetime(2026, 10, 5, 7, 11, 23, 959011, tzinfo=UTC)


def test_pieces_arriving_out_of_order_still_read_chronologically(db):
    later = [SESSION_A_EVENTS[6]]  # "cat /etc/passwd"
    earlier = [SESSION_A_EVENTS[5]]  # "whoami"

    save_session(db, SESSION_A, summarize(later))
    db.commit()
    save_session(db, SESSION_A, summarize(earlier))
    db.commit()
    db.expire_all()

    stored = db.get(HoneypotSession, SESSION_A)
    assert [c.command for c in stored.commands] == ["whoami", "cat /etc/passwd"]
    assert stored.start_time == datetime(2026, 10, 5, 7, 12, 2, 484294, tzinfo=UTC)


def test_deleting_a_session_removes_its_children(db):
    save_session(db, SESSION_A, summarize(SESSION_A_EVENTS))
    db.commit()

    db.delete(db.get(HoneypotSession, SESSION_A))
    db.commit()

    assert _count(db, Login) == 0
    assert _count(db, Command) == 0
