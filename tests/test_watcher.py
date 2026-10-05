"""Tests for the log tailer and the live watcher."""

import json
import signal
import threading
import time

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from sample_events import SESSION_A, SESSION_A_EVENTS, SESSION_B_EVENTS
from surya_kundal import cli, watcher
from surya_kundal.cli import main
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import Command, HoneypotSession
from surya_kundal.watcher import LogTailer, Watcher


def _line(event):
    return json.dumps(event)


def _append(path, *lines, newline=True):
    with path.open("a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + ("\n" if newline else ""))


# --- LogTailer -------------------------------------------------------------


def test_tailer_returns_nothing_while_the_log_does_not_exist(tmp_path):
    tailer = LogTailer(tmp_path / "cowrie.json")

    assert tailer.read_new_lines() == []


def test_tailer_picks_up_a_log_created_later_and_reads_it_from_the_start(tmp_path):
    log = tmp_path / "cowrie.json"
    tailer = LogTailer(log)
    assert tailer.read_new_lines() == []

    _append(log, "one", "two")

    assert tailer.read_new_lines() == ["one", "two"]


def test_tailer_returns_only_lines_added_since_the_last_call(tmp_path):
    log = tmp_path / "cowrie.json"
    _append(log, "one")
    tailer = LogTailer(log)
    assert tailer.read_new_lines() == ["one"]
    assert tailer.read_new_lines() == []

    _append(log, "two", "three")

    assert tailer.read_new_lines() == ["two", "three"]


def test_tailer_holds_back_a_half_written_line_until_it_is_complete(tmp_path):
    log = tmp_path / "cowrie.json"
    tailer = LogTailer(log)

    _append(log, '{"a": 1', newline=False)
    assert tailer.read_new_lines() == []

    _append(log, "}", newline=True)
    assert tailer.read_new_lines() == ['{"a": 1}']


def test_tailer_from_end_skips_existing_content(tmp_path):
    log = tmp_path / "cowrie.json"
    _append(log, "old")
    tailer = LogTailer(log, from_end=True)
    assert tailer.read_new_lines() == []

    _append(log, "new")

    assert tailer.read_new_lines() == ["new"]


def test_tailer_from_end_still_reads_everything_in_a_log_created_later(tmp_path):
    log = tmp_path / "cowrie.json"
    tailer = LogTailer(log, from_end=True)
    assert tailer.read_new_lines() == []

    _append(log, "first")

    assert tailer.read_new_lines() == ["first"]


def test_tailer_follows_a_rotated_log_without_losing_lines(tmp_path):
    log = tmp_path / "cowrie.json"
    _append(log, "one")
    tailer = LogTailer(log)
    assert tailer.read_new_lines() == ["one"]

    _append(log, "two")  # written to the old file but not yet read
    log.rename(tmp_path / "cowrie.json.2026-10-05")
    _append(log, "three")  # first line of the fresh file

    assert tailer.read_new_lines() == ["two", "three"]
    _append(log, "four")
    assert tailer.read_new_lines() == ["four"]


def test_tailer_survives_the_gap_between_rotation_and_the_new_file(tmp_path):
    log = tmp_path / "cowrie.json"
    _append(log, "one")
    tailer = LogTailer(log)
    tailer.read_new_lines()

    log.rename(tmp_path / "cowrie.json.1")
    assert tailer.read_new_lines() == []  # no new file yet, and no crash

    _append(log, "two")
    assert tailer.read_new_lines() == ["two"]


def test_tailer_restarts_from_the_top_after_truncation(tmp_path):
    log = tmp_path / "cowrie.json"
    _append(log, "aaaaaaaaaa", "bbbbbbbbbb")
    tailer = LogTailer(log)
    assert tailer.read_new_lines() == ["aaaaaaaaaa", "bbbbbbbbbb"]

    log.write_text("c\n", encoding="utf-8")  # same file, now much shorter

    assert tailer.read_new_lines() == ["c"]


def test_tailer_tolerates_invalid_utf8(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(b'\xff\xfe{"x": 1}\n')

    lines = LogTailer(log).read_new_lines()

    assert len(lines) == 1


# --- Watcher ---------------------------------------------------------------


@pytest.fixture
def factory(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path}/watch.db")
    init_db(engine)
    return make_session_factory(engine)


def _session_count(factory):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(HoneypotSession))


def test_poll_once_stores_new_events(tmp_path, factory):
    log = tmp_path / "cowrie.json"
    _append(log, *(_line(e) for e in SESSION_A_EVENTS))
    watch = Watcher(log, factory)

    assert watch.poll_once() == len(SESSION_A_EVENTS)

    with factory() as db:
        stored = db.get(HoneypotSession, SESSION_A)
        assert [c.command for c in stored.commands] == ["whoami", "cat /etc/passwd"]


def test_poll_once_with_nothing_new_does_nothing(tmp_path, factory):
    log = tmp_path / "cowrie.json"
    _append(log, *(_line(e) for e in SESSION_A_EVENTS))
    watch = Watcher(log, factory)
    watch.poll_once()

    assert watch.poll_once() == 0
    assert _session_count(factory) == 1


def test_a_session_is_built_up_across_polls(tmp_path, factory):
    log = tmp_path / "cowrie.json"
    watch = Watcher(log, factory)

    _append(log, *(_line(e) for e in SESSION_A_EVENTS[:6]))
    watch.poll_once()
    with factory() as db:
        assert db.get(HoneypotSession, SESSION_A).end_time is None

    _append(log, *(_line(e) for e in SESSION_A_EVENTS[6:]))
    watch.poll_once()

    with factory() as db:
        stored = db.get(HoneypotSession, SESSION_A)
        assert stored.end_time is not None
        assert len(stored.commands) == 2
        assert len(stored.downloads) == 1


def test_a_session_split_across_a_rotation_is_still_complete(tmp_path, factory):
    log = tmp_path / "cowrie.json"
    watch = Watcher(log, factory)

    _append(log, *(_line(e) for e in SESSION_A_EVENTS[:6]))
    watch.poll_once()
    log.rename(tmp_path / "cowrie.json.2026-10-05")
    _append(log, *(_line(e) for e in SESSION_A_EVENTS[6:]))
    watch.poll_once()

    with factory() as db:
        stored = db.get(HoneypotSession, SESSION_A)
        assert [c.command for c in stored.commands] == ["whoami", "cat /etc/passwd"]
        assert stored.end_time is not None
        assert db.scalar(select(func.count()).select_from(Command)) == 2


def test_blank_and_malformed_lines_are_ignored(tmp_path, factory):
    log = tmp_path / "cowrie.json"
    _append(log, "", "{broken", "[1, 2]", *(_line(e) for e in SESSION_B_EVENTS))
    watch = Watcher(log, factory)

    assert watch.poll_once() == len(SESSION_B_EVENTS)
    assert _session_count(factory) == 1


def test_restarting_replays_the_log_without_duplicating(tmp_path, factory):
    log = tmp_path / "cowrie.json"
    _append(log, *(_line(e) for e in SESSION_A_EVENTS))
    Watcher(log, factory).poll_once()

    Watcher(log, factory).poll_once()  # a fresh watcher starts from the top again

    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Command)) == 2
    assert _session_count(factory) == 1


def test_a_database_error_does_not_crash_the_watcher(tmp_path, factory, monkeypatch):
    log = tmp_path / "cowrie.json"
    _append(log, *(_line(e) for e in SESSION_A_EVENTS))

    def broken(*_args, **_kwargs):
        raise SQLAlchemyError("database is locked")

    monkeypatch.setattr(watcher, "store_events", broken)

    assert Watcher(log, factory).poll_once() == 0


def test_run_stores_events_live_and_stops_on_request(tmp_path, factory):
    log = tmp_path / "cowrie.json"
    stop = threading.Event()
    watch = Watcher(log, factory, interval=0.01)
    thread = threading.Thread(target=watch.run, args=(stop,), daemon=True)
    thread.start()

    _append(log, *(_line(e) for e in SESSION_A_EVENTS))
    deadline = time.monotonic() + 5
    while _session_count(factory) == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    stop.set()
    thread.join(timeout=5)

    assert _session_count(factory) == 1
    assert not thread.is_alive()


def test_run_survives_an_unexpected_error_in_one_cycle(tmp_path, factory, monkeypatch):
    stop = threading.Event()
    calls = []

    def flaky_poll(self):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        stop.set()
        return 0

    monkeypatch.setattr(Watcher, "poll_once", flaky_poll)

    Watcher(tmp_path / "cowrie.json", factory, interval=0.01).run(stop)

    assert len(calls) == 2


# --- CLI -------------------------------------------------------------------


@pytest.fixture
def restore_signal_handlers():
    saved = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    yield
    for signum, handler in saved.items():
        signal.signal(signum, handler)


def test_cli_watch_rejects_a_non_positive_interval(tmp_path, capsys):
    code = main(["watch", "--log", str(tmp_path / "x.json"), "--interval", "0"])

    assert code == 2
    assert "--interval" in capsys.readouterr().err


def test_cli_watch_starts_the_watcher_with_the_given_options(
    tmp_path, monkeypatch, restore_signal_handlers
):
    captured = {}

    class FakeWatcher:
        def __init__(self, log_path, session_factory, *, interval, from_end):
            captured.update(log_path=log_path, interval=interval, from_end=from_end)

        def run(self, stop):
            captured["stop_is_event"] = isinstance(stop, threading.Event)

    monkeypatch.setattr(cli, "Watcher", FakeWatcher)
    log = tmp_path / "cowrie.json"

    code = main(
        ["watch", "--log", str(log), "--db", f"sqlite:///{tmp_path}/w.db", "--from-end"]
        + ["--interval", "2.5"]
    )

    assert code == 0
    assert captured == {
        "log_path": log,
        "interval": 2.5,
        "from_end": True,
        "stop_is_event": True,
    }
