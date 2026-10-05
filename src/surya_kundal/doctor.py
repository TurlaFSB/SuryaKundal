"""``surya-kundal doctor``: check that an installation is healthy, without changing anything.

It never writes, never touches the network and never prints a secret. Each check is
OK, WARN (works, but look at it) or FAIL (something will not work). The exit code is
non-zero only for FAIL, so it can serve as a container health check or a cron probe.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from alembic.script import ScriptDirectory
from sqlalchemy import func, inspect, select, text

from surya_kundal.config import Settings
from surya_kundal.database.engine import create_db_engine
from surya_kundal.database.migrate import alembic_config
from surya_kundal.database.models import HoneypotSession

GEOIP_FILES = ("GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb")
GEOIP_STALE_DAYS = 45  # MaxMind publishes twice a week; the service refreshes daily
TOR_STALE_DAYS = 3
LOG_QUIET_HOURS = 24 * 3


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # "OK", "WARN" or "FAIL"
    detail: str


def _age_days(path: Path, now: float) -> float:
    return (now - path.stat().st_mtime) / 86400


def check_database(url: str) -> list[Check]:
    try:
        engine = create_db_engine(url, read_only=True)
    except FileNotFoundError:
        return [Check("database", "FAIL", "file not found; run `surya-kundal run` or `ingest`")]
    try:
        with engine.connect() as conn:
            tables = inspect(conn).get_table_names()
            if "alembic_version" not in tables:
                return [Check("database", "FAIL", "no schema; run any surya-kundal command")]
            current = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            head = ScriptDirectory.from_config(alembic_config()).get_current_head()
            if current != head:
                return [Check("database", "FAIL", f"schema {current}, code expects {head}")]
            sessions = conn.execute(select(func.count()).select_from(HoneypotSession)).scalar()
            return [Check("database", "OK", f"schema {head}, {sessions} sessions")]
    except Exception as error:
        return [Check("database", "FAIL", f"cannot read it ({type(error).__name__})")]
    finally:
        engine.dispose()


def check_log(path: Path, now: float) -> Check:
    if not path.is_file():
        return Check("cowrie log", "FAIL", f"not found: {path}")
    try:
        with path.open("rb"):
            pass
    except OSError:
        return Check("cowrie log", "FAIL", f"not readable: {path}")
    quiet = (now - path.stat().st_mtime) / 3600
    if quiet > LOG_QUIET_HOURS:
        return Check("cowrie log", "WARN", f"no new events for {quiet / 24:.0f} days")
    return Check("cowrie log", "OK", f"readable, last written {quiet:.1f} h ago")


def check_geoip(directory: Path, now: float) -> Check:
    missing = [f for f in GEOIP_FILES if not (directory / f).is_file()]
    if len(missing) == len(GEOIP_FILES):
        return Check("geoip", "WARN", "no GeoLite2 databases; run `surya-kundal geoip update`")
    if missing:
        return Check("geoip", "WARN", f"missing {', '.join(missing)}")
    oldest = max(_age_days(directory / f, now) for f in GEOIP_FILES)
    if oldest > GEOIP_STALE_DAYS:
        return Check("geoip", "WARN", f"databases are {oldest:.0f} days old")
    return Check("geoip", "OK", f"databases are {oldest:.0f} days old")


def check_tor(path: Path, now: float) -> Check:
    if not path.is_file():
        return Check("tor list", "WARN", "not downloaded yet (the service fetches it)")
    age = _age_days(path, now)
    if age > TOR_STALE_DAYS:
        return Check("tor list", "WARN", f"{age:.0f} days old")
    return Check("tor list", "OK", f"{age:.1f} days old")


def check_keys(settings: Settings) -> list[Check]:
    def key(name: str, present: bool, feature: str) -> Check:
        if present:
            return Check(name, "OK", "set")
        return Check(name, "WARN", f"not set; {feature} is skipped")

    return [
        key("AbuseIPDB key", bool(settings.abuseipdb_api_key), "IP reputation"),
        key("VirusTotal key", bool(settings.virustotal_api_key), "file verdicts"),
        key(
            "MaxMind key",
            bool(settings.maxmind_account_id and settings.maxmind_license_key),
            "GeoIP download",
        ),
    ]


def run_checks(
    settings: Settings, database_url: str | None = None, log: Path | None = None
) -> list[Check]:
    now = time.time()
    return [
        *check_database(database_url or settings.database_url),
        check_log(log or settings.log_path, now),
        check_geoip(settings.geoip_dir, now),
        check_tor(settings.tor_cache_path, now),
        *check_keys(settings),
    ]
