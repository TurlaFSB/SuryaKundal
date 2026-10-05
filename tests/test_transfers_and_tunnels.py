"""Tests for file uploads and port-forwarding requests (events Cowrie also records)."""

import pytest
from sqlalchemy import create_engine, func, select, text

from sample_events import SESSION_A, make_event
from surya_kundal.cli import main
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.migrate import alembic_config
from surya_kundal.database.models import FileIntel, TechniqueMatch, TunnelRequest, Upload
from surya_kundal.enrichment.enrich import enrich_pending
from surya_kundal.ingest import store_events
from surya_kundal.mapping.engine import map_transfers, map_tunnels
from surya_kundal.mapping.store import map_pending
from surya_kundal.parser.log_parser import summarize

T = "2026-10-05T07:12:40.000000Z"
SHA_UP = "c" * 64

UPLOAD = make_event(
    SESSION_A,
    "cowrie.session.file_upload",
    T,
    filename="payload.bin",
    destfile="/tmp/payload.bin",
    shasum=SHA_UP,
)
TUNNEL = make_event(
    SESSION_A,
    "cowrie.direct-tcpip.request",
    "2026-10-05T07:12:41.000000Z",
    dst_ip="198.51.100.9",
    dst_port=25,
    orig_ip="127.0.0.1",
    orig_port=51514,
)


@pytest.fixture
def db():
    engine = create_db_engine("sqlite://")
    init_db(engine)
    with make_session_factory(engine)() as session:
        yield session


def test_summarize_collects_uploads_and_tunnels():
    summary = summarize([UPLOAD, TUNNEL])

    assert summary["uploads"] == [
        {
            "filename": "payload.bin",
            "destination": "/tmp/payload.bin",
            "sha256": SHA_UP,
            "timestamp": T,
        }
    ]
    assert summary["tunnels"] == [
        {
            "dst_ip": "198.51.100.9",
            "dst_port": 25,
            "orig_ip": "127.0.0.1",
            "orig_port": 51514,
            "timestamp": "2026-10-05T07:12:41.000000Z",
        }
    ]


def test_uploads_and_tunnels_are_stored_once_however_often_they_are_seen(db):
    for _ in range(3):
        store_events(db, [UPLOAD, TUNNEL])
        db.commit()

    upload = db.scalar(select(Upload))
    tunnel = db.scalar(select(TunnelRequest))
    assert db.scalar(select(func.count()).select_from(Upload)) == 1
    assert db.scalar(select(func.count()).select_from(TunnelRequest)) == 1
    assert (upload.filename, upload.destination, upload.sha256) == (
        "payload.bin",
        "/tmp/payload.bin",
        SHA_UP,
    )
    assert (tunnel.dst_ip, tunnel.dst_port, tunnel.orig_port) == ("198.51.100.9", 25, 51514)


def test_a_malformed_port_is_stored_as_zero_not_as_an_error(db):
    bad = dict(TUNNEL, dst_port="not-a-port", orig_port=999999)

    result = store_events(db, [bad])
    db.commit()

    assert result.failed == 0
    tunnel = db.scalar(select(TunnelRequest))
    assert (tunnel.dst_port, tunnel.orig_port) == (0, 0)


def test_an_upload_without_a_filename_is_still_stored(db):
    nameless = dict(UPLOAD)
    del nameless["filename"]

    store_events(db, [nameless])
    db.commit()

    assert db.scalar(select(Upload.filename)) == ""


def test_transfers_and_tunnels_map_to_attack_techniques():
    transfers = map_transfers([{"url": "http://x/a"}], [{"filename": "p.bin"}])
    tunnels = map_tunnels(
        [{"dst_ip": "198.51.100.9", "dst_port": 25}, {"dst_ip": "198.51.100.9", "dst_port": 25}]
    )

    assert [(m.rule_id, m.technique) for m in transfers] == [
        ("transfer-download", "T1105"),
        ("transfer-upload", "T1105"),
    ]
    assert [(m.rule_id, m.technique) for m in tunnels] == [("tunnel-request", "T1090")]
    assert "2 forwarding request(s) to 1 destination(s)" in tunnels[0].evidence
    assert map_tunnels([]) == []


def test_a_session_is_remapped_when_an_upload_or_tunnel_arrives(db):
    store_events(
        db, [make_event(SESSION_A, "cowrie.session.connect", "2026-10-05T07:11:00.000000Z")]
    )
    db.commit()
    map_pending(db)
    assert db.scalar(select(func.count()).select_from(TechniqueMatch)) == 0

    store_events(db, [UPLOAD, TUNNEL])
    db.commit()
    result = map_pending(db)

    assert result.sessions == 1
    rules = {m.rule_id for m in db.scalars(select(TechniqueMatch))}
    assert rules == {"transfer-upload", "tunnel-request"}


def test_uploaded_files_are_checked_with_virustotal_too(db):
    store_events(db, [UPLOAD])
    db.commit()

    class FakeVT:
        def __init__(self):
            self.calls: list[str] = []

        def lookup_file(self, sha):
            self.calls.append(sha)
            return None

    vt = FakeVT()
    enrich_pending(db, virustotal_client=vt)

    assert vt.calls == [SHA_UP]
    assert db.scalar(select(FileIntel.sha256)) == SHA_UP


def test_show_lists_uploads_and_tunnels(tmp_path, capsys):
    url = f"sqlite:///{tmp_path}/t.db"
    engine = create_db_engine(url)
    init_db(engine)
    with make_session_factory(engine)() as db:
        store_events(db, [UPLOAD, TUNNEL])
        db.commit()

    assert main(["show", SESSION_A[:6], "--db", url]) == 0

    out = capsys.readouterr().out
    assert "uploaded payload.bin" in out
    assert "tunnel request to 198.51.100.9:25" in out


def test_a_database_at_the_previous_revision_upgrades_and_keeps_its_data(tmp_path):
    from alembic import command

    engine = create_engine(f"sqlite:///{tmp_path}/old.db")
    config = alembic_config()
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.upgrade(config, "0002")
        conn.execute(text("insert into sessions (id, src_ip) values ('old1', '45.33.32.156')"))
        conn.execute(
            text(
                "insert into session_mappings (session_id, ruleset_version, attack_version,"
                " command_count, login_count, mapped_at)"
                " values ('old1', 'x', '19.2', 1, 1, '2026-10-05 00:00:00')"
            )
        )

    from surya_kundal.database.migrate import upgrade_database

    upgrade_database(engine)

    with engine.connect() as conn:
        assert conn.execute(text("select src_ip from sessions")).scalar_one() == "45.33.32.156"
        row = conn.execute(text("select transfer_count, tunnel_count from session_mappings")).one()
        assert tuple(row) == (0, 0)
        assert conn.execute(text("select count(*) from uploads")).scalar_one() == 0
    engine.dispose()
