"""Hostile or odd log content must never stop ingestion or distort the data."""

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import Command, Download, HoneypotSession
from surya_kundal.database.repository import parse_timestamp
from surya_kundal.ingest import store_events
from surya_kundal.parser import log_parser as lp

T = "2026-10-01T12:00:00.000000Z"


@pytest.fixture
def db(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'h.db'}")
    init_db(engine)
    with make_session_factory(engine)() as session:
        yield session


def ev(session, eventid, **fields):
    return {
        "session": session,
        "eventid": eventid,
        "timestamp": T,
        "src_ip": "80.66.76.10",
        **fields,
    }


@pytest.mark.parametrize(
    "bad",
    [
        {"input": ["a"]},
        {"input": {"x": 1}},
        {"input": 5},
        {"input": "ok", "timestamp": 5},
        {"input": "ok", "src_ip": 5},
        {"input": "ok", "src_ip": {}},
        {"input": "\ud800 lone surrogate"},
        {"input": "nul\x00byte"},
    ],
)
def test_odd_field_types_never_stop_other_sessions(db, bad):
    events = [
        ev("bad", "cowrie.command.input", **bad),
        ev("good", "cowrie.command.input", input="id"),
    ]
    result = store_events(db, events)
    db.commit()
    assert (
        db.scalar(
            select(func.count()).select_from(HoneypotSession).where(HoneypotSession.id == "good")
        )
        == 1
    )
    assert result.failed == 0


def test_an_unexpected_error_in_one_session_is_contained(db, monkeypatch):
    from surya_kundal import ingest

    real = ingest.save_session

    def explode(session, session_id, summary):
        if session_id == "bad":
            raise TypeError("boom")
        return real(session, session_id, summary)

    monkeypatch.setattr(ingest, "save_session", explode)
    result = store_events(
        db, [ev("bad", "cowrie.session.connect"), ev("good", "cowrie.session.connect")]
    )
    db.commit()
    assert result.failed_ids == ("bad",) and result.saved == 1


@pytest.mark.parametrize("duration", [1e30, 10**30, -5, float("nan"), "7", True, None])
def test_absurd_durations_are_dropped(duration):
    summary = lp.summarize([ev("s", "cowrie.session.closed", duration_ms=duration)])
    assert summary["duration_ms"] is None


def test_extreme_timestamps_do_not_raise():
    assert parse_timestamp("0001-01-01T00:00:00+05:00") is None
    assert parse_timestamp("not a time") is None
    assert parse_timestamp(T) == datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def test_hostile_lines_are_skipped_not_fatal():
    assert lp.parse_event_line("[" * 100_000) is None  # deep nesting
    assert lp.parse_event_line("1" * 100_000) is None  # digit flood
    assert lp.parse_event_line("x" * (lp.MAX_LINE_LENGTH + 1)) is None
    assert lp.parse_event_line(json.dumps({"a": 1})) == {"a": 1}


def test_a_redirect_is_not_a_download():
    events = [
        ev("s", "cowrie.session.file_download", shasum="a" * 64, destfile="/etc/resolv.conf"),
        ev("s", "cowrie.session.file_download", url="http://45.33.32.156/x.sh", shasum="b" * 64),
    ]
    summary = lp.summarize(events)
    assert [d["url"] for d in summary["downloads"]] == ["http://45.33.32.156/x.sh"]


def test_sessions_are_bounded(db):
    flood = [
        ev("flood", "cowrie.command.input", input=f"echo {n}") for n in range(lp.MAX_COMMANDS + 500)
    ]
    flood.append(ev("flood", "cowrie.command.input", input="x" * (lp.MAX_COMMAND + 5000)))
    store_events(db, flood)
    db.commit()
    assert db.scalar(select(func.count()).select_from(Command)) == lp.MAX_COMMANDS
    assert db.scalar(select(func.max(func.length(Command.command)))) <= lp.MAX_COMMAND


@pytest.mark.parametrize(
    "value", ["fe80::1%eth0", "999.1.1.1", "not-an-ip", "", 7, None, "1.2.3.4 "]
)
def test_source_addresses_are_validated(value):
    summary = lp.summarize([ev("s", "cowrie.session.connect", src_ip=value)])
    assert summary["src_ip"] in (None, "1.2.3.4")


def test_odd_ports_and_text_become_none():
    summary = lp.summarize(
        [
            ev(
                "s",
                "cowrie.direct-tcpip.request",
                dst_ip=["x"],
                dst_port=[1],
                orig_ip="1.1.1.1",
                orig_port=70000,
            )
        ]
    )
    tunnel = summary["tunnels"][0]
    assert tunnel["dst_ip"] is None and tunnel["dst_port"] is None and tunnel["orig_port"] is None


def test_downloads_table_stays_empty_for_redirects(db):
    store_events(db, [ev("s", "cowrie.session.file_download", shasum="a" * 64)])
    db.commit()
    assert db.scalar(select(func.count()).select_from(Download)) == 0
