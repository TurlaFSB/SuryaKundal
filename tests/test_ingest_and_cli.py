"""Tests for log ingestion and the command-line interface."""

import json

import pytest
from sqlalchemy import func, select

from sample_events import SESSION_A, SESSION_A_EVENTS, SESSION_B, SESSION_B_EVENTS
from surya_kundal import ingest
from surya_kundal.cli import main
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import HoneypotSession
from surya_kundal.ingest import ingest_log


def _write_log(path, events, extra_lines=()):
    lines = [json.dumps(e) for e in events] + list(extra_lines)
    path.write_text("\n".join(lines) + "\n")
    return path


@pytest.fixture
def db():
    engine = create_db_engine("sqlite://")
    init_db(engine)
    with make_session_factory(engine)() as session:
        yield session


def _session_count(db):
    return db.scalar(select(func.count()).select_from(HoneypotSession))


# --- ingest_log ------------------------------------------------------------


def test_ingest_log_stores_every_session(db, tmp_path):
    log = _write_log(tmp_path / "cowrie.json", SESSION_A_EVENTS + SESSION_B_EVENTS)

    result = ingest_log(db, log)
    db.commit()

    assert (result.saved, result.failed) == (2, 0)
    assert _session_count(db) == 2


def test_ingest_log_twice_does_not_duplicate(db, tmp_path):
    log = _write_log(tmp_path / "cowrie.json", SESSION_A_EVENTS)

    ingest_log(db, log)
    db.commit()
    ingest_log(db, log)
    db.commit()

    assert _session_count(db) == 1


def test_ingest_log_survives_malformed_lines(db, tmp_path):
    log = _write_log(tmp_path / "cowrie.json", SESSION_A_EVENTS, extra_lines=["{broken"])

    result = ingest_log(db, log)

    assert result.saved == 1


def test_one_failing_session_does_not_block_the_others(db, tmp_path, monkeypatch):
    log = _write_log(tmp_path / "cowrie.json", SESSION_A_EVENTS + SESSION_B_EVENTS)
    real_save = ingest.save_session

    def flaky_save(session, session_id, summary):
        if session_id == SESSION_A:
            raise ValueError("boom")
        return real_save(session, session_id, summary)

    monkeypatch.setattr(ingest, "save_session", flaky_save)

    result = ingest_log(db, log)
    db.commit()

    assert (result.saved, result.failed) == (1, 1)
    assert db.get(HoneypotSession, SESSION_B) is not None
    assert db.get(HoneypotSession, SESSION_A) is None


# --- CLI -------------------------------------------------------------------


def test_cli_ingest_then_list(tmp_path, capsys):
    log = _write_log(tmp_path / "cowrie.json", SESSION_A_EVENTS + SESSION_B_EVENTS)
    db_url = f"sqlite:///{tmp_path}/test.db"

    assert main(["ingest", "--log", str(log), "--db", db_url]) == 0
    assert "Stored 2 session(s)" in capsys.readouterr().out

    assert main(["list", "--db", db_url]) == 0
    output = capsys.readouterr().out
    assert SESSION_A in output
    assert SESSION_B in output
    assert "203.0.113.7" in output


def test_cli_ingest_reports_missing_log(tmp_path, capsys):
    code = main(["ingest", "--log", str(tmp_path / "nope.json"), "--db", "sqlite://"])

    assert code == 2
    assert "log file not found" in capsys.readouterr().err


def test_cli_list_on_empty_database(tmp_path, capsys):
    assert main(["list", "--db", f"sqlite:///{tmp_path}/empty.db"]) == 0
    assert "No sessions stored yet" in capsys.readouterr().out


def test_cli_enrich_without_keys_still_runs_offline_providers(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("surya_kundal.cli.load_dotenv", lambda *a, **k: None)
    for name in ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TOR_EXIT_LIST_PATH", str(tmp_path / "tor.txt"))
    monkeypatch.setattr("surya_kundal.cli.TorExitList.load", lambda self, **k: False)
    log = _write_log(tmp_path / "cowrie.json", SESSION_A_EVENTS)
    db_url = f"sqlite:///{tmp_path}/e.db"
    main(["ingest", "--log", str(log), "--db", db_url])
    capsys.readouterr()

    code = main(["enrich", "--db", db_url, "--geoip-dir", str(tmp_path / "none")])

    captured = capsys.readouterr()
    assert code == 0
    assert "ABUSEIPDB_API_KEY not set" in captured.err
    assert "Enriched: 0 geo" in captured.out
