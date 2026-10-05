"""The dashboard: queries on seeded data, then the web layer (auth, CSP, escaping, read-only)."""

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import OperationalError

pytest.importorskip("flask")

from sample_events import SESSION_A, SESSION_A_EVENTS, SESSION_B_EVENTS, make_event
from surya_kundal.cli import main
from surya_kundal.dashboard import queries
from surya_kundal.dashboard.alerts import recent_alerts
from surya_kundal.dashboard.app import ago, create_app, project, stamp
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import HoneypotSession, IpGeo, IpIntel
from surya_kundal.ingest import store_events
from surya_kundal.mapping.store import map_pending

NOW = datetime.now(UTC)


@pytest.fixture
def factory(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'k.db'}")
    init_db(engine)
    sessions = make_session_factory(engine)
    with sessions() as db:
        store_events(db, SESSION_A_EVENTS + SESSION_B_EVENTS)
        db.commit()
        map_pending(db)
        db.add(
            IpGeo(
                ip="203.0.113.7",
                country_code="AU",
                city="Sydney",
                latitude=-33.9,
                longitude=151.2,
                looked_up_at=NOW,
            )
        )
        db.add(IpIntel(ip="203.0.113.7", provider="abuseipdb", fetched_at=NOW, score=88))
        db.add(IpIntel(ip="203.0.113.7", provider="tor", fetched_at=NOW, flagged=True))
        db.commit()
    return sessions


@pytest.fixture
def db(factory):
    with factory() as session:
        yield session


def _client(factory, **kwargs):
    return create_app(factory, **kwargs).test_client()


def _basic(password):
    return {"Authorization": "Basic " + base64.b64encode(f":{password}".encode()).decode()}


# --- queries ---------------------------------------------------------------


def test_totals_depth_and_pulse(db):
    t = queries.totals(db)
    assert t.sessions == 2 and t.sources >= 1 and t.commands > 0
    d = queries.depth(db)
    assert d.contact == 2 and d.contact >= d.access >= 0 and d.hands_on <= d.contact
    assert d.action <= d.contact
    count, last = queries.pulse(db)
    assert count == 2 and last is not None
    assert queries.has_data(db)


def test_map_points_countries_and_hourly(db):
    points = queries.map_points(db)
    assert [(p.ip, p.country, p.sessions) for p in points] == [("203.0.113.7", "AU", 2)]
    assert queries.top_countries(db)[0] == ("AU", 2)
    assert len(queries.hourly_activity(db, now=NOW)) == 24
    old = NOW - timedelta(days=400)
    assert sum(queries.hourly_activity(db, now=old)) == 0


def test_sessions_page_filters_and_clamps(db):
    everything = queries.sessions_page(db)
    assert everything.total == 2 and everything.rows[0].country == "AU"
    assert everything.rows[0].abuse == 88 and everything.rows[0].tor is True
    assert queries.sessions_page(db, query=SESSION_A[:4]).total == 1
    assert queries.sessions_page(db, query="198.51").total == 0
    assert queries.sessions_page(db, country="au").total == 2
    assert queries.sessions_page(db, country="us").total == 0
    assert queries.sessions_page(db, page=99, per_page=1).page == 2
    assert queries.sessions_page(db, query="%").total == 0  # LIKE wildcards are not special
    technique = queries.technique_counts(db)[0].technique_id
    assert queries.sessions_page(db, technique=technique).total >= 1


def test_techniques_matrix_and_probes(db):
    counts = queries.technique_counts(db)
    assert counts and counts[0].sessions >= counts[-1].sessions
    assert len(queries.technique_counts(db, limit=1)) == 1
    matrix = queries.attack_matrix(db)
    assert matrix and all(items for _, items in matrix)
    assert queries.probes(db) == [] and queries.probing_sessions(db) == 0


def test_session_detail_by_prefix(db):
    detail = queries.session_detail(db, SESSION_A[:6])
    assert detail is not None and detail.session.id == SESSION_A
    assert detail.geo.country_code == "AU" and detail.abuse == 88
    assert detail.commands and detail.login_total == len(detail.logins)
    assert queries.session_detail(db, "zzzz") is None
    assert queries.session_detail(db, "") is None  # empty prefix matches both: ambiguous


def test_empty_database(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'blank.db'}")
    with make_session_factory(engine)() as db:
        assert queries.has_data(db) is False


# --- helpers ---------------------------------------------------------------


def test_project_ago_stamp():
    assert project(-180, 90) == (0, 0) and project(180, -90) == (960, 480)
    assert project(0, 0) == (480, 240)
    assert ago(None) == "never" and ago(NOW + timedelta(hours=1), NOW) == "just now"
    assert ago(NOW - timedelta(seconds=5), NOW) == "5s ago"
    assert ago(NOW - timedelta(minutes=3), NOW) == "3m ago"
    assert ago(NOW - timedelta(hours=2), NOW) == "2h ago"
    assert ago(NOW - timedelta(days=4), NOW) == "4d ago"
    assert stamp(None) == "-" and stamp(datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02 03:04:05"


# --- alerts ----------------------------------------------------------------


def _alert(rule_id, desc="d", level=8):
    return json.dumps(
        {
            "timestamp": "2026-10-05T10:00:00Z",
            "rule": {
                "id": str(rule_id),
                "level": level,
                "description": desc,
                "mitre": {"id": ["T1082"]},
            },
            "data": {"src_ip": "1.2.3.4", "input": "uname -a"},
        }
    )


def test_recent_alerts_filters_and_survives_junk(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_text(
        "\n".join(
            [
                _alert(5710),
                "not json",
                "[]",
                '{"rule": {}}',
                _alert(100601, "x"),
                _alert(100602, "y"),
            ]
        )
        + "\n"
    )
    found = recent_alerts(path, limit=5)
    assert [a.description for a in found] == ["y", "x"]  # newest first, system rules dropped
    assert found[0].techniques == ("T1082",) and found[0].command == "uname -a"
    assert recent_alerts(path, limit=1)[0].description == "y"
    assert recent_alerts(tmp_path / "missing") == [] and recent_alerts(None) == []


def test_recent_alerts_reads_only_the_tail(tmp_path):
    path = tmp_path / "big.jsonl"
    filler = _alert(100601, "old") + "\n"
    path.write_text(filler * 20000 + _alert(100699, "newest") + "\n")
    assert path.stat().st_size > 512 * 1024
    assert recent_alerts(path, limit=1)[0].description == "newest"


# --- web layer -------------------------------------------------------------


def test_pages_render(factory, tmp_path):
    alerts = tmp_path / "a.jsonl"
    alerts.write_text(_alert(100601, "Cowrie: recon") + "\n")
    client = _client(factory, alerts_path=alerts)
    home = client.get("/")
    assert home.status_code == 200
    body = home.get_data(as_text=True)
    assert "Surya Kundal" in body and "Cowrie: recon" in body and "Sydney" in body
    assert client.get("/sessions").status_code == 200
    assert client.get("/sessions?page=abc&q=" + SESSION_A[:4]).status_code == 200
    detail = client.get(f"/sessions/{SESSION_A}")
    assert detail.status_code == 200 and SESSION_A in detail.get_data(as_text=True)
    assert client.get("/attack").status_code == 200
    assert client.get("/sessions/nope").status_code == 404
    assert client.get("/api/pulse").get_json()["sessions"] == 2
    assert client.get("/healthz").get_data(as_text=True) == "ok"


def test_security_headers(factory):
    response = _client(factory).get("/")
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "unsafe" not in csp and "http" not in csp
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert " style=" not in response.get_data(as_text=True)  # inline styles would break the CSP


def test_token_required_when_set(factory):
    client = _client(factory, token="s3cret")
    denied = client.get("/")
    assert denied.status_code == 401 and "Basic" in denied.headers["WWW-Authenticate"]
    assert client.get("/", headers=_basic("wrong")).status_code == 401
    assert client.get("/", headers=_basic("s3cret")).status_code == 200
    assert client.get("/api/pulse").status_code == 401
    assert client.get("/healthz").status_code == 200  # liveness probes carry no credentials


def test_attacker_text_is_escaped(factory):
    evil = "<script>alert(1)</script>\x1b[2J‮"
    with factory() as db:
        store_events(
            db,
            [
                make_event("evil1", "cowrie.session.connect", "2026-10-05T10:00:00.000000Z"),
                make_event(
                    "evil1", "cowrie.command.input", "2026-10-05T10:00:05.000000Z", input=evil
                ),
            ],
        )
        db.commit()
    body = _client(factory).get("/sessions/evil1").get_data(as_text=True)
    assert "<script>alert" not in body
    assert "&lt;script&gt;" in body
    assert "\x1b" not in body and "‮" not in body and "\\x1b" in body


def test_dashboard_cannot_write(factory):
    app = create_app(factory)
    with app.test_request_context("/healthz"):
        request_db = app.extensions["surya_db"]()
        with pytest.raises(OperationalError, match="readonly"):
            request_db.execute(text("DELETE FROM sessions"))
    # the setting does not leak into the shared pool: other users can still write
    with factory() as other:
        other.execute(text("DELETE FROM ip_intel"))
        other.commit()
    with factory() as check:
        assert check.scalar(select(func.count()).select_from(HoneypotSession)) == 2


def test_empty_database_shows_guidance(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'blank.db'}")
    client = _client(make_session_factory(engine))
    for path in ("/", "/sessions", "/attack", "/sessions/abc"):
        response = client.get(path)
        assert response.status_code == 200 and "No data yet" in response.get_data(as_text=True)
    assert client.get("/api/pulse").get_json() == {"sessions": 0, "last": None}


# --- CLI -------------------------------------------------------------------


def test_cli_refuses_public_listen_without_token(monkeypatch, capsys):
    monkeypatch.delenv("DASHBOARD_TOKEN", raising=False)
    monkeypatch.chdir("/")  # no .env to pick up
    assert main(["dashboard", "--host", "0.0.0.0"]) == 2  # noqa: S104
    assert "DASHBOARD_TOKEN" in capsys.readouterr().err


def test_cli_serves_with_waitress(monkeypatch, tmp_path, capsys):
    served = {}
    import waitress

    monkeypatch.setattr(waitress, "serve", lambda app, **kw: served.update(kw))
    monkeypatch.setenv("DASHBOARD_TOKEN", "")
    monkeypatch.chdir(tmp_path)
    assert main(["dashboard", "--db", f"sqlite:///{tmp_path / 'x.db'}", "--port", "9999"]) == 0
    assert served["host"] == "127.0.0.1" and served["port"] == 9999
    assert "http://127.0.0.1:9999" in capsys.readouterr().out
