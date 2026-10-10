"""Backup, restore and retention."""

import gzip
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from sample_events import SESSION_A_EVENTS, SESSION_B_EVENTS
from surya_kundal import maintenance
from surya_kundal.cli import main
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import (
    Command,
    HoneypotSession,
    IpGeo,
    IpIntel,
    Login,
    TechniqueMatch,
)
from surya_kundal.ingest import store_events
from surya_kundal.mapping.store import map_pending

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def _database(tmp_path, name="live.db", events=None):
    url = f"sqlite:///{tmp_path / name}"
    engine = create_db_engine(url)
    init_db(engine)
    factory = make_session_factory(engine)
    with factory() as db:
        store_events(db, events if events is not None else SESSION_A_EVENTS + SESSION_B_EVENTS)
        db.commit()
        map_pending(db)
        db.commit()
    return url, factory


def _count(factory, model):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(model))


# --- backup ------------------------------------------------------------------------------------


def test_backup_is_a_private_verified_copy(tmp_path):
    url, factory = _database(tmp_path)
    result = maintenance.backup_database(url, tmp_path / "bk", now=NOW)

    assert result.path.name == "surya-kundal-20261009-120000.db"
    assert result.sessions == _count(factory, HoneypotSession) > 0
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "bk").stat().st_mode) == 0o700
    assert maintenance.verify_backup(result.path).sessions == result.sessions
    assert [p.name for p in (tmp_path / "bk").iterdir()] == [result.path.name]  # no scratch left


def test_backup_is_consistent_while_a_writer_is_active(tmp_path):
    url, factory = _database(tmp_path)
    committed = _count(factory, HoneypotSession)
    with factory() as writer:
        writer.add(HoneypotSession(id="midflight", src_ip="203.0.113.50"))
        writer.flush()  # an open, uncommitted write transaction
        result = maintenance.backup_database(url, tmp_path / "bk", now=NOW)
    assert result.sessions == committed  # the half-written session is not in the copy
    check = sqlite3.connect(result.path)
    try:
        assert (
            check.execute("SELECT count(*) FROM sessions WHERE id='midflight'").fetchone()[0] == 0
        )
    finally:
        check.close()


def test_compressed_backup_round_trips(tmp_path):
    url, factory = _database(tmp_path)
    result = maintenance.backup_database(url, tmp_path / "bk", compress=True, now=NOW)

    assert result.path.name.endswith(".db.gz")
    assert maintenance.verify_backup(result.path).sessions == _count(factory, HoneypotSession)


def test_keep_removes_only_older_backups_and_never_the_new_one(tmp_path):
    url, _ = _database(tmp_path)
    directory = tmp_path / "bk"
    made = [
        maintenance.backup_database(url, directory, now=NOW + timedelta(minutes=i)).path
        for i in range(4)
    ]
    final = maintenance.backup_database(url, directory, keep=2, now=NOW + timedelta(minutes=10))

    names = [p.name for p in maintenance.list_backups(directory)]
    assert names == [made[3].name, final.path.name]
    assert {p.name for p in final.removed} == {made[0].name, made[1].name, made[2].name}


def test_keep_one_keeps_just_the_new_backup(tmp_path):
    url, _ = _database(tmp_path)
    directory = tmp_path / "bk"
    maintenance.backup_database(url, directory, now=NOW)
    new = maintenance.backup_database(url, directory, keep=1, now=NOW + timedelta(minutes=1))
    assert maintenance.list_backups(directory) == [new.path]


def test_backup_errors_are_clear(tmp_path):
    with pytest.raises(maintenance.MaintenanceError, match="not found"):
        maintenance.backup_database(f"sqlite:///{tmp_path / 'missing.db'}", tmp_path / "bk")
    with pytest.raises(maintenance.MaintenanceError, match="SQLite"):
        maintenance.backup_database("postgresql://u@h/db", tmp_path / "bk")
    url, _ = _database(tmp_path)
    with pytest.raises(maintenance.MaintenanceError, match="at least 1"):
        maintenance.backup_database(url, tmp_path / "bk", keep=0)
    maintenance.backup_database(url, tmp_path / "bk", now=NOW)
    with pytest.raises(maintenance.MaintenanceError, match="already exists"):
        maintenance.backup_database(url, tmp_path / "bk", now=NOW)


# --- restore -----------------------------------------------------------------------------------


def test_restore_brings_back_the_backed_up_data(tmp_path):
    url, factory = _database(tmp_path)
    backup = maintenance.backup_database(url, tmp_path / "bk", now=NOW).path
    expected = _count(factory, HoneypotSession)
    with factory() as db:
        db.query(HoneypotSession).delete()
        db.commit()
    assert _count(factory, HoneypotSession) == 0

    result = maintenance.restore_database(backup, url, force=True, now=NOW)

    assert result.sessions == expected and result.safety_copy is not None
    assert result.safety_copy.is_file()
    fresh = make_session_factory(create_db_engine(url))
    assert _count(fresh, HoneypotSession) == expected
    assert stat.S_IMODE(result.target.stat().st_mode) == 0o600


def test_restore_refuses_to_overwrite_without_force(tmp_path):
    url, _ = _database(tmp_path)
    backup = maintenance.backup_database(url, tmp_path / "bk", now=NOW).path
    with pytest.raises(maintenance.MaintenanceError, match="--force"):
        maintenance.restore_database(backup, url)


def test_restore_into_a_fresh_location_from_a_compressed_backup(tmp_path):
    url, factory = _database(tmp_path)
    backup = maintenance.backup_database(url, tmp_path / "bk", compress=True, now=NOW).path
    new_url = f"sqlite:///{tmp_path / 'new' / 'restored.db'}"

    result = maintenance.restore_database(backup, new_url)

    assert result.safety_copy is None
    assert _count(make_session_factory(create_db_engine(new_url)), HoneypotSession) == _count(
        factory, HoneypotSession
    )


def test_restore_removes_a_stale_write_ahead_log(tmp_path):
    url, _ = _database(tmp_path)
    backup = maintenance.backup_database(url, tmp_path / "bk", now=NOW).path
    live = tmp_path / "live.db"
    for extra in ("-wal", "-shm"):
        (tmp_path / f"live.db{extra}").write_bytes(b"stale")
    maintenance.restore_database(backup, url, force=True, now=NOW)
    assert not (tmp_path / "live.db-wal").exists() and not (tmp_path / "live.db-shm").exists()
    assert live.is_file()


def test_restore_rejects_damaged_or_foreign_files_and_leaves_the_target_alone(tmp_path):
    url, factory = _database(tmp_path)
    before = _count(factory, HoneypotSession)

    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"this is not a database" * 50)
    notours = tmp_path / "other.db"
    conn = sqlite3.connect(notours)
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    newer = tmp_path / "newer.db"
    good = maintenance.backup_database(url, tmp_path / "bk", now=NOW).path
    newer.write_bytes(good.read_bytes())
    conn = sqlite3.connect(newer)
    conn.execute("UPDATE alembic_version SET version_num = 'zzzz9999'")
    conn.commit()
    conn.close()
    badgz = tmp_path / "bad.db.gz"
    badgz.write_bytes(b"not gzip")

    for path, message in (
        (garbage, "not a readable|integrity"),
        (notours, "not a Surya Kundal database"),
        (newer, "newer version"),
        (badgz, "gzip"),
        (tmp_path / "absent.db", "not found"),
    ):
        with pytest.raises(maintenance.MaintenanceError, match=message):
            maintenance.restore_database(path, url, force=True)
    assert _count(make_session_factory(create_db_engine(url)), HoneypotSession) == before


def test_a_truncated_backup_is_detected(tmp_path):
    url, _ = _database(tmp_path)
    good = maintenance.backup_database(url, tmp_path / "bk", now=NOW).path
    broken = tmp_path / "broken.db"
    broken.write_bytes(good.read_bytes()[: good.stat().st_size // 2])
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.verify_backup(broken)


def test_a_compressed_backup_that_decompresses_to_junk_is_detected(tmp_path):
    junk = tmp_path / "junk.db.gz"
    with gzip.open(junk, "wb") as handle:
        handle.write(b"junk" * 100)
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.verify_backup(junk)


# --- retention ---------------------------------------------------------------------------------


def _ages(factory):
    with factory() as db:
        return {
            s.id: (s.end_time or s.start_time) for s in db.scalars(select(HoneypotSession)).all()
        }


def test_dry_run_reports_without_deleting(tmp_path):
    _, factory = _database(tmp_path)
    ages = _ages(factory)
    newest = max(ages.values())
    with factory() as db:
        result = maintenance.prune_database(
            db, older_than_days=1, now=newest + timedelta(days=30), dry_run=True
        )
    assert not result.deleted and result.sessions == len(ages)
    assert _count(factory, HoneypotSession) == len(ages)


def test_prune_deletes_old_sessions_and_everything_attached(tmp_path):
    _, factory = _database(tmp_path)
    with factory() as db:
        ids = sorted(db.scalars(select(HoneypotSession.id)).all())
        old_id, young_id = ids[0], ids[1]
        old, young = db.get(HoneypotSession, old_id), db.get(HoneypotSession, young_id)
        old.start_time = datetime(2026, 8, 1, 10, 0, tzinfo=UTC)
        old.end_time = datetime(2026, 8, 1, 10, 5, tzinfo=UTC)
        young.start_time = datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
        young.end_time = datetime(2026, 10, 1, 10, 5, tzinfo=UTC)
        old_ip, young_ip = old.src_ip, young.src_ip
        db.add(IpGeo(ip="198.51.100.77", looked_up_at=NOW))
        db.add(IpIntel(ip="198.51.100.77", provider="abuseipdb", fetched_at=NOW))
        db.commit()
        for ip in {old_ip, young_ip} - {None}:
            if db.get(IpGeo, ip) is None:
                db.add(IpGeo(ip=ip, looked_up_at=NOW))
        db.commit()
        # 30 days before 2026-10-09 is 2026-09-09: the August session is old, the October one not
        result = maintenance.prune_database(db, older_than_days=30, now=NOW, dry_run=False)

    assert result.deleted and result.sessions == 1 and result.logins >= 1
    with factory() as db:
        assert db.get(HoneypotSession, old_id) is None
        assert db.get(HoneypotSession, young_id) is not None
        for model in (Login, Command, TechniqueMatch):
            assert (
                db.scalar(select(func.count()).select_from(model).where(model.session_id == old_id))
                == 0
            )
        assert db.get(IpGeo, "198.51.100.77") is None  # nobody refers to it any more
        assert not db.scalars(select(IpIntel).where(IpIntel.ip == "198.51.100.77")).all()
        if young_ip not in (None, old_ip):
            assert db.get(IpGeo, young_ip) is not None  # still in use


def test_prune_with_nothing_old_is_a_no_op(tmp_path):
    _, factory = _database(tmp_path)
    before = _count(factory, HoneypotSession)
    with factory() as db:
        result = maintenance.prune_database(db, older_than_days=3650, now=NOW, dry_run=False)
    assert result.sessions == 0 and not result.deleted
    assert _count(factory, HoneypotSession) == before


def test_prune_validates_its_argument(tmp_path):
    _, factory = _database(tmp_path)
    with factory() as db, pytest.raises(maintenance.MaintenanceError, match="at least 1"):
        maintenance.prune_database(db, older_than_days=0)


def test_vacuum_reports_sizes(tmp_path):
    url, _ = _database(tmp_path)
    before, after = maintenance.vacuum(url)
    assert before > 0 and after > 0


# --- command line ------------------------------------------------------------------------------


def test_cli_backup_restore_and_prune(tmp_path, capsys):
    url, _ = _database(tmp_path)
    backups = tmp_path / "bk"

    assert main(["backup", "--db", url, "--directory", str(backups), "--compress"]) == 0
    out = capsys.readouterr().out
    assert "Backed up" in out and ".db.gz" in out
    backup = maintenance.list_backups(backups)[0]

    assert main(["restore", "--db", url, str(backup)]) == 1  # refuses without --force
    assert "--force" in capsys.readouterr().err
    assert main(["restore", "--db", url, str(backup), "--force"]) == 0
    assert "kept at" in capsys.readouterr().out

    assert main(["prune", "--db", url, "--older-than", "1"]) == 0
    out = capsys.readouterr().out
    assert "Would delete" in out and "Nothing was changed" in out
    assert _count(make_session_factory(create_db_engine(url)), HoneypotSession) > 0


def test_cli_prune_yes_deletes_and_rebuilds_campaigns(tmp_path, capsys):
    url, _ = _database(tmp_path)
    assert main(["prune", "--db", url, "--older-than", "1", "--yes", "--vacuum"]) == 0
    out = capsys.readouterr().out
    assert "Deleted" in out and "Database file" in out
    assert _count(make_session_factory(create_db_engine(url)), HoneypotSession) == 0


def test_cli_reports_errors_without_a_traceback(tmp_path, capsys):
    missing = f"sqlite:///{tmp_path / 'nope.db'}"
    assert main(["backup", "--db", missing]) == 1
    assert "not found" in capsys.readouterr().err
    assert main(["restore", "--db", missing, str(tmp_path / "x.db")]) == 1
    assert main(["prune", "--db", "postgresql://u@h/d", "--older-than", "1"]) == 1


def test_default_backup_directory_sits_next_to_the_database(tmp_path, capsys):
    url, _ = _database(tmp_path)
    assert main(["backup", "--db", url]) == 0
    assert os.path.isdir(tmp_path / "backups")


def test_pruning_updates_campaigns_so_they_never_count_deleted_sessions(tmp_path, capsys):
    from sample_events import SHA, T0, T_DL, make_event
    from surya_kundal.campaigns import build_campaigns
    from surya_kundal.database.models import Campaign

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
    url, factory = _database(tmp_path, events=SESSION_A_EVENTS + second)
    with factory() as db:
        build_campaigns(db)
        db.commit()
        assert db.scalar(select(func.count()).select_from(Campaign)) == 1
        old = db.get(HoneypotSession, "bbbbbbbbbbbb")
        old.start_time = datetime(2025, 1, 1, tzinfo=UTC)
        old.end_time = datetime(2025, 1, 1, 0, 5, tzinfo=UTC)
        db.commit()

    assert main(["prune", "--db", url, "--older-than", "30", "--yes"]) == 0
    capsys.readouterr()

    with factory() as db:
        assert db.get(HoneypotSession, "bbbbbbbbbbbb") is None
        assert (
            db.scalar(select(func.count()).select_from(Campaign)) == 0
        )  # one session is no campaign
