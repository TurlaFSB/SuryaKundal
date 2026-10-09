"""Tests for the robustness and safety fixes found in the audit."""

import json
import logging
import os
import threading
import time

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from sample_events import SESSION_A, SESSION_A_EVENTS, make_event
from surya_kundal import watcher as watcher_module
from surya_kundal.cli import main
from surya_kundal.config import Settings, load_env_file
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import Command, HoneypotSession, TechniqueMatch
from surya_kundal.ingest import store_events
from surya_kundal.mapping.engine import MAX_ANALYSED_CHARS, bound_command, map_command
from surya_kundal.pipeline import Providers
from surya_kundal.service import Service
from surya_kundal.textsafe import printable
from surya_kundal.watcher import LogTailer, Watcher

# --- terminal-safe text ------------------------------------------------------


def test_printable_escapes_terminal_control_sequences():
    attack = "\x1b[2J\x1b[Hnothing to see\x07\r"

    shown = printable(attack)

    assert "\x1b" not in shown and "\x07" not in shown and "\r" not in shown
    assert shown == r"\x1b[2J\x1b[Hnothing to see\x07\x0d"


def test_printable_escapes_bidi_overrides_and_invisible_characters():
    shown = printable("ls ‮ecnerucca​")

    assert "‮" not in shown and "​" not in shown
    assert "\\u202e" in shown


def test_printable_keeps_normal_text_including_unicode_and_backslashes():
    assert printable("echo -e '\\x41' café 日本") == "echo -e '\\x41' café 日本"
    assert printable(None) == ""
    assert printable(42) == "42"


def test_printable_can_truncate():
    assert printable("a" * 50, limit=10) == "a" * 9 + "…"


def test_show_never_prints_raw_escape_sequences(tmp_path, capsys):
    url = f"sqlite:///{tmp_path}/s.db"
    engine = create_db_engine(url)
    init_db(engine)
    events = [
        make_event(SESSION_A, "cowrie.session.connect", "2026-10-05T07:11:23.000000Z"),
        make_event(
            SESSION_A,
            "cowrie.command.input",
            "2026-10-05T07:11:24.000000Z",
            input="\x1b[2Jecho pwned\x1b]0;owned\x07",
        ),
    ]
    with make_session_factory(engine)() as db:
        store_events(db, events)
        db.commit()

    assert main(["show", SESSION_A[:6], "--db", url]) == 0

    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert r"\x1b[2Jecho pwned" in out


# --- mapping engine against hostile input ------------------------------------


def test_long_commands_are_bounded_but_keep_their_tail():
    command = "echo " + "A" * 100_000 + " | base64 -d | sh"

    bounded = bound_command(command)

    assert len(bounded) <= MAX_ANALYSED_CHARS + 1
    assert bounded.endswith("| base64 -d | sh")
    assert {"T1140", "T1059.004"} <= {m.technique for m in map_command(command)}


@pytest.mark.parametrize(
    "unit",
    ["rm ", ">", "tee ", "cp x ", "| sudo ", "chmod -R ", "\\x41", "/tmp/.", "history ", "curl a "],
)
def test_adversarial_input_is_analysed_in_bounded_time(unit):
    hostile = unit * (1_000_000 // len(unit))

    started = time.perf_counter()
    map_command(hostile)
    map_command(".bashrc /var/log/ authorized_keys " + hostile)

    assert time.perf_counter() - started < 2.0


# --- watcher robustness --------------------------------------------------------


def _factory(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path}/w.db")
    init_db(engine)
    return make_session_factory(engine)


def _append(path, events):
    with path.open("a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def test_events_are_kept_and_retried_when_the_database_write_fails(tmp_path, monkeypatch):
    factory = _factory(tmp_path)
    log = tmp_path / "cowrie.json"
    _append(log, SESSION_A_EVENTS)
    watch = Watcher(log, factory)

    real = watcher_module.store_events
    monkeypatch.setattr(
        watcher_module,
        "store_events",
        lambda *a, **k: (_ for _ in ()).throw(OperationalError("x", {}, Exception("locked"))),
    )
    assert watch.poll_once() == 0  # the write failed; nothing is stored yet

    monkeypatch.setattr(watcher_module, "store_events", real)
    assert watch.poll_once() == len(SESSION_A_EVENTS)  # the next cycle stores them

    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Command)) == 2


def test_retry_buffer_is_bounded(tmp_path, monkeypatch):
    factory = _factory(tmp_path)
    log = tmp_path / "cowrie.json"
    _append(log, SESSION_A_EVENTS)
    monkeypatch.setattr(watcher_module, "MAX_RETRY_EVENTS", 3)
    monkeypatch.setattr(
        watcher_module,
        "store_events",
        lambda *a, **k: (_ for _ in ()).throw(OperationalError("x", {}, Exception("locked"))),
    )
    watch = Watcher(log, factory)

    watch.poll_once()

    assert len(watch._unsaved) == 3


def test_a_line_without_a_newline_cannot_grow_without_bound(tmp_path, monkeypatch, caplog):
    log = tmp_path / "cowrie.json"
    monkeypatch.setattr(watcher_module, "MAX_PARTIAL_BYTES", 100)
    tailer = LogTailer(log)
    log.write_bytes(b"x" * 500)

    with caplog.at_level(logging.ERROR):
        assert tailer.read_new_lines() == []

    assert "Discarding" in caplog.text
    log.write_bytes(log.read_bytes() + b"\nnext\n")
    assert tailer.read_new_lines() == ["", "next"]


# --- settings ----------------------------------------------------------------


def test_settings_defaults_and_overrides():
    defaults = Settings.from_env({})
    assert str(defaults.database_url).startswith("sqlite:///")
    assert defaults.log_level == "INFO"
    assert defaults.abuseipdb_api_key == ""

    custom = Settings.from_env(
        {"DATABASE_URL": " sqlite:///x.db ", "LOG_LEVEL": "debug", "ABUSEIPDB_API_KEY": " k "}
    )
    assert custom.database_url == "sqlite:///x.db"
    assert custom.log_level == "DEBUG"
    assert custom.abuseipdb_api_key == "k"


def test_blank_values_fall_back_to_defaults():
    assert (
        Settings.from_env({"DATABASE_URL": "   "}).database_url
        == Settings.from_env({}).database_url
    )


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_a_world_readable_env_file_triggers_a_warning(tmp_path, caplog, monkeypatch):
    monkeypatch.delenv("SK_TEST_VALUE", raising=False)
    env = tmp_path / ".env"
    env.write_text("SK_TEST_VALUE=1\n")
    env.chmod(0o644)

    with caplog.at_level(logging.WARNING):
        load_env_file(env)

    assert "chmod 600" in caplog.text
    assert os.environ["SK_TEST_VALUE"] == "1"
    monkeypatch.delenv("SK_TEST_VALUE")


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_a_private_env_file_is_loaded_quietly(tmp_path, caplog, monkeypatch):
    monkeypatch.delenv("SK_TEST_VALUE2", raising=False)
    env = tmp_path / ".env"
    env.write_text("SK_TEST_VALUE2=ok\n")
    env.chmod(0o600)

    with caplog.at_level(logging.WARNING):
        load_env_file(env)

    assert caplog.text == ""
    monkeypatch.delenv("SK_TEST_VALUE2")


def test_missing_env_file_is_fine(tmp_path):
    load_env_file(tmp_path / "nope.env")


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert "surya-kundal" in capsys.readouterr().out


# --- the unified service ---------------------------------------------------


class _FakeAbuse:
    def __init__(self):
        self.calls = []

    def check(self, ip):
        self.calls.append(ip)
        return {"abuseConfidenceScore": 77}

    def close(self):
        pass


class _NoTor:
    def load(self):
        return False

    def __contains__(self, _ip):
        return False


def test_service_stores_maps_and_enriches_in_one_process(tmp_path):
    factory = _factory(tmp_path)
    log = tmp_path / "cowrie.json"
    events = [dict(e, src_ip="45.33.32.156") for e in SESSION_A_EVENTS]
    _append(log, events)
    abuse = _FakeAbuse()
    providers = Providers(geo=None, tor=_NoTor(), abuse=abuse, virustotal=None, notes=[])
    service = Service(
        log,
        factory,
        providers=providers,
        interval=0.01,
        map_interval=0.01,
        enrich_interval=0.05,
    )
    stop = threading.Event()
    thread = threading.Thread(target=service.run, args=(stop,))
    thread.start()

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with factory() as db:
            mapped = db.scalar(select(func.count()).select_from(TechniqueMatch))
        if mapped and abuse.calls:
            break
        time.sleep(0.05)
    stop.set()
    thread.join(timeout=10)

    assert not thread.is_alive()
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(HoneypotSession)) == 1
        assert db.scalar(select(func.count()).select_from(TechniqueMatch)) > 0
    assert abuse.calls == ["45.33.32.156"]


def test_service_without_providers_still_captures_and_maps(tmp_path):
    factory = _factory(tmp_path)
    log = tmp_path / "cowrie.json"
    _append(log, SESSION_A_EVENTS)
    service = Service(log, factory, providers=None, interval=0.01, map_interval=0.01)
    stop = threading.Event()
    thread = threading.Thread(target=service.run, args=(stop,))
    thread.start()
    time.sleep(0.5)
    stop.set()
    thread.join(timeout=10)

    with factory() as db:
        assert db.scalar(select(func.count()).select_from(TechniqueMatch)) > 0


def _two_sessions_sharing_a_payload():
    from sample_events import SHA, T0, T_DL, make_event

    second = [
        dict(make_event("bbbbbbbbbbbb", "cowrie.session.connect", T0), src_ip="198.51.100.9"),
        dict(
            make_event(
                "bbbbbbbbbbbb",
                "cowrie.session.file_download",
                T_DL,
                url="http://example.com/test/sh",
                shasum=SHA,
            ),
            src_ip="198.51.100.9",
        ),
    ]
    return SESSION_A_EVENTS + second


def _run_service_until(tmp_path, ready, **options):
    factory = _factory(tmp_path)
    log = tmp_path / "cowrie.json"
    _append(log, _two_sessions_sharing_a_payload())
    service = Service(log, factory, providers=None, interval=0.01, map_interval=0.01, **options)
    stop = threading.Event()
    thread = threading.Thread(target=service.run, args=(stop,))
    thread.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not ready(factory):
        time.sleep(0.05)
    stop.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    return factory


def test_service_groups_sessions_into_campaigns_by_itself(tmp_path):
    from surya_kundal.database.models import Campaign

    def ready(factory):
        with factory() as db:
            return bool(db.scalar(select(func.count()).select_from(Campaign)))

    factory = _run_service_until(tmp_path, ready, campaign_interval=0.05)
    with factory() as db:
        campaign = db.scalars(select(Campaign)).one()
        assert campaign.session_count == 2 and campaign.ip_count == 2


def test_service_retries_campaign_grouping_after_a_failure(tmp_path, monkeypatch, caplog):
    from surya_kundal import service as service_module
    from surya_kundal.database.models import Campaign

    real = service_module.build_campaigns
    calls = []

    def flaky(db, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return real(db, **kwargs)

    monkeypatch.setattr(service_module, "build_campaigns", flaky)

    def ready(factory):
        with factory() as db:
            return bool(db.scalar(select(func.count()).select_from(Campaign)))

    with caplog.at_level("ERROR"):
        _run_service_until(tmp_path, ready, campaign_interval=0.05)
    assert len(calls) >= 2
    assert "Campaign grouping failed" in caplog.text
