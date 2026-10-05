"""``surya-kundal doctor`` reports problems without changing anything."""

import os
import time

from surya_kundal.cli import main
from surya_kundal.config import Settings
from surya_kundal.database.engine import create_db_engine, init_db
from surya_kundal.doctor import check_geoip, check_log, check_tor, run_checks


def _settings(tmp_path, **env):
    base = {
        "COWRIE_LOG_PATH": str(tmp_path / "cowrie.json"),
        "GEOIP_DB_DIR": str(tmp_path / "geo"),
        "TOR_EXIT_LIST_PATH": str(tmp_path / "tor.txt"),
        "DATABASE_URL": f"sqlite:///{tmp_path / 'k.db'}",
    }
    return Settings.from_env({**base, **env})


def _by_name(checks):
    return {c.name: c for c in checks}


def test_everything_missing_fails_on_database_and_log_only(tmp_path):
    checks = _by_name(run_checks(_settings(tmp_path)))
    assert checks["database"].status == "FAIL" and checks["cowrie log"].status == "FAIL"
    assert checks["geoip"].status == "WARN" and checks["tor list"].status == "WARN"
    assert checks["AbuseIPDB key"].status == "WARN"
    assert not (tmp_path / "k.db").exists()  # doctor creates nothing


def test_healthy_installation(tmp_path):
    (tmp_path / "cowrie.json").write_text("{}\n")
    (tmp_path / "geo").mkdir()
    for name in ("GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"):
        (tmp_path / "geo" / name).write_bytes(b"x")
    (tmp_path / "tor.txt").write_text("1.2.3.4\n")
    init_db(create_db_engine(f"sqlite:///{tmp_path / 'k.db'}"))
    settings = _settings(
        tmp_path,
        ABUSEIPDB_API_KEY="a",
        VIRUSTOTAL_API_KEY="v",
        MAXMIND_ACCOUNT_ID="1",
        MAXMIND_LICENSE_KEY="k",
    )
    checks = run_checks(settings)
    assert {c.status for c in checks} == {"OK"}
    assert "a" not in "".join(c.detail for c in checks if "key" in c.name)  # never echoes keys


def test_stale_and_quiet_files_warn(tmp_path):
    old = time.time() - 100 * 86400
    log = tmp_path / "cowrie.json"
    log.write_text("{}\n")
    os.utime(log, (old, old))
    assert check_log(log, time.time()).status == "WARN"
    geo = tmp_path / "geo"
    geo.mkdir()
    for name in ("GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"):
        (geo / name).write_bytes(b"x")
        os.utime(geo / name, (old, old))
    assert check_geoip(geo, time.time()).status == "WARN"
    (geo / "GeoLite2-ASN.mmdb").unlink()
    assert "missing" in check_geoip(geo, time.time()).detail
    tor = tmp_path / "tor.txt"
    tor.write_text("x")
    os.utime(tor, (old, old))
    assert check_tor(tor, time.time()).status == "WARN"


def test_old_schema_fails(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'k.db'}")
    init_db(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql("UPDATE alembic_version SET version_num = '0001'")
    checks = _by_name(run_checks(_settings(tmp_path)))
    assert checks["database"].status == "FAIL" and "0001" in checks["database"].detail


def test_cli_exit_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    for name in ("COWRIE_LOG_PATH", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    assert (
        main(["doctor", "--db", f"sqlite:///{tmp_path / 'x.db'}", "--log", str(tmp_path / "l")])
        == 1
    )
    assert "FAIL" in capsys.readouterr().out
    (tmp_path / "l").write_text("{}\n")
    init_db(create_db_engine(f"sqlite:///{tmp_path / 'x.db'}"))
    assert (
        main(["doctor", "--db", f"sqlite:///{tmp_path / 'x.db'}", "--log", str(tmp_path / "l")])
        == 0
    )
