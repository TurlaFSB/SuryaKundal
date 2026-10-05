"""Enrich stored sessions with geolocation, Tor status, AbuseIPDB and VirusTotal data.

Every IP and every file hash is looked up once and cached in the database, so a
scanner that hits the honeypot a thousand times costs one API call. Quota is
tracked from the database itself, so it survives restarts, and a provider that
reports its limit stops being called for the rest of the run.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from surya_kundal.database.models import (
    Download,
    FileIntel,
    HoneypotSession,
    IpGeo,
    IpIntel,
    Upload,
)
from surya_kundal.enrichment import abuseipdb, virustotal
from surya_kundal.enrichment.abuseipdb import AbuseIPDBClient
from surya_kundal.enrichment.geoip import GeoIPLookup, is_public_ip
from surya_kundal.enrichment.http import ProviderError, QuotaExceeded
from surya_kundal.enrichment.tor import TorExitList
from surya_kundal.enrichment.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)

# Conservative budgets below the free-tier limits (1000 and 500 per UTC day).
DEFAULT_ABUSE_BUDGET = 900
DEFAULT_VT_BUDGET = 450
ABUSE_REFRESH_AFTER = timedelta(days=7)
VT_FOUND_REFRESH_AFTER = timedelta(days=30)
VT_NOT_FOUND_REFRESH_AFTER = timedelta(days=2)  # new malware often appears in VT later


@dataclass
class EnrichResult:
    geo: int = 0
    tor: int = 0
    abuse: int = 0
    files: int = 0
    errors: int = 0
    stopped: list[str] = field(default_factory=list)  # providers that hit a limit


def _day_start(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def _used_today(
    db: Session, model: type[IpIntel] | type[FileIntel], provider: str, now: datetime
) -> int:
    count = db.scalar(
        select(func.count())
        .select_from(model)
        .where(model.provider == provider, model.fetched_at >= _day_start(now))
    )
    return count or 0


def _upsert_ip_intel(
    db: Session,
    ip: str,
    provider: str,
    now: datetime,
    *,
    score: int | None = None,
    flagged: bool | None = None,
    payload: dict | None = None,
) -> None:
    row = db.scalar(select(IpIntel).where(IpIntel.ip == ip, IpIntel.provider == provider))
    if row is None:
        row = IpIntel(ip=ip, provider=provider)
        db.add(row)
    row.fetched_at, row.score, row.flagged, row.payload = now, score, flagged, payload


def _public_ips_newest_first(db: Session) -> list[str]:
    rows = db.execute(
        select(HoneypotSession.src_ip)
        .where(HoneypotSession.src_ip.is_not(None))
        .group_by(HoneypotSession.src_ip)
        .order_by(func.max(HoneypotSession.start_time).desc())
    ).scalars()
    return [ip for ip in rows if ip and is_public_ip(ip)]


def _enrich_geo(
    db: Session, ips: list[str], geo: GeoIPLookup, now: datetime, result: EnrichResult
) -> None:
    if not geo.available:
        return
    known = set(db.scalars(select(IpGeo.ip)))
    for ip in ips:
        if ip in known:
            continue
        info = geo.lookup(ip)
        row = IpGeo(ip=ip, looked_up_at=now)
        if info is not None:
            for name, value in vars(info).items():
                setattr(row, name, value)
        db.add(row)
        result.geo += 1
    db.commit()


def _enrich_tor(
    db: Session, ips: list[str], tor: TorExitList, now: datetime, result: EnrichResult
) -> None:
    existing = {row.ip: row for row in db.scalars(select(IpIntel).where(IpIntel.provider == "tor"))}
    for ip in ips:
        is_exit = ip in tor
        row = existing.get(ip)
        if row is not None and row.flagged == is_exit:
            continue
        _upsert_ip_intel(db, ip, "tor", now, flagged=is_exit, payload={"is_exit": is_exit})
        result.tor += 1
    db.commit()


def _enrich_abuse(
    db: Session,
    ips: list[str],
    client: AbuseIPDBClient,
    budget: int,
    now: datetime,
    result: EnrichResult,
    should_stop: Callable[[], bool],
) -> None:
    fetched = {
        row.ip: row.fetched_at
        for row in db.scalars(select(IpIntel).where(IpIntel.provider == abuseipdb.PROVIDER))
    }
    never = [ip for ip in ips if ip not in fetched]
    stale = sorted(
        (ip for ip in ips if ip in fetched and now - fetched[ip] > ABUSE_REFRESH_AFTER),
        key=lambda ip: fetched[ip],
    )
    remaining = budget - _used_today(db, IpIntel, abuseipdb.PROVIDER, now)
    for ip in (never + stale)[: max(remaining, 0)]:
        if should_stop():
            break
        try:
            data = client.check(ip)
        except QuotaExceeded as exc:
            logger.warning("%s; stopping AbuseIPDB for this run", exc)
            result.stopped.append(abuseipdb.PROVIDER)
            break
        except ProviderError as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            result.errors += 1
            continue
        _upsert_ip_intel(
            db, ip, abuseipdb.PROVIDER, now, score=int(data["abuseConfidenceScore"]), payload=data
        )
        db.commit()
        result.abuse += 1
    if remaining <= 0 and (never or stale):
        logger.info("AbuseIPDB daily budget used up; %d IPs wait for tomorrow", len(never + stale))


def _file_is_stale(row: FileIntel, now: datetime) -> bool:
    limit = VT_FOUND_REFRESH_AFTER if row.found else VT_NOT_FOUND_REFRESH_AFTER
    return now - row.fetched_at > limit


def _enrich_files(
    db: Session,
    client: VirusTotalClient,
    budget: int,
    now: datetime,
    result: EnrichResult,
    should_stop: Callable[[], bool],
) -> None:
    # Files the attacker fetched and files the attacker uploaded, newest first.
    seen = (
        select(Download.sha256.label("sha256"), Download.timestamp.label("at"))
        .where(Download.sha256.is_not(None))
        .union_all(select(Upload.sha256, Upload.timestamp).where(Upload.sha256.is_not(None)))
        .subquery()
    )
    hashes = [
        sha
        for sha in db.scalars(
            select(seen.c.sha256).group_by(seen.c.sha256).order_by(func.max(seen.c.at).desc())
        )
        if sha
    ]
    rows = {
        r.sha256: r for r in db.scalars(select(FileIntel).where(FileIntel.provider == "virustotal"))
    }
    never = [h for h in hashes if h not in rows]
    stale = [h for h in hashes if h in rows and _file_is_stale(rows[h], now)]
    remaining = budget - _used_today(db, FileIntel, virustotal.PROVIDER, now)
    for sha in (never + stale)[: max(remaining, 0)]:
        if should_stop():
            break
        try:
            report = client.lookup_file(sha)
        except QuotaExceeded as exc:
            logger.warning("%s; stopping VirusTotal for this run", exc)
            result.stopped.append(virustotal.PROVIDER)
            break
        except ProviderError as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", sha, exc)
            result.errors += 1
            continue
        row = rows.get(sha) or FileIntel(sha256=sha, provider=virustotal.PROVIDER)
        db.add(row)
        row.fetched_at, row.found, row.payload = now, report is not None, report
        if report is None:
            row.malicious = row.suspicious = row.engines = row.label = None
        else:
            stats = report["last_analysis_stats"]
            row.malicious = int(stats.get("malicious", 0))
            row.suspicious = int(stats.get("suspicious", 0))
            row.engines = sum(int(v) for v in stats.values())
            classification = report.get("popular_threat_classification") or {}
            label = classification.get("suggested_threat_label") or report.get("meaningful_name")
            row.label = str(label)[:255] if label else None
        db.commit()
        result.files += 1


def enrich_pending(
    db: Session,
    *,
    geo: GeoIPLookup | None = None,
    tor: TorExitList | None = None,
    abuse: AbuseIPDBClient | None = None,
    virustotal_client: VirusTotalClient | None = None,
    abuse_budget: int = DEFAULT_ABUSE_BUDGET,
    vt_budget: int = DEFAULT_VT_BUDGET,
    now: datetime | None = None,
    should_stop: Callable[[], bool] = lambda: False,
) -> EnrichResult:
    """Run one enrichment pass. Any provider left as None is simply skipped."""
    now = now or datetime.now(UTC)
    result = EnrichResult()
    ips = _public_ips_newest_first(db)
    if geo is not None:
        _enrich_geo(db, ips, geo, now, result)
    if tor is not None:
        _enrich_tor(db, ips, tor, now, result)
    if abuse is not None:
        _enrich_abuse(db, ips, abuse, abuse_budget, now, result, should_stop)
    if virustotal_client is not None:
        _enrich_files(db, virustotal_client, vt_budget, now, result, should_stop)
    return result
