"""Wiring: build the enrichment providers from settings and run a pass over the database."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx
from sqlalchemy.orm import Session, sessionmaker

from surya_kundal.config import Settings
from surya_kundal.enrichment.abuseipdb import AbuseIPDBClient
from surya_kundal.enrichment.enrich import (
    DEFAULT_ABUSE_BUDGET,
    DEFAULT_VT_BUDGET,
    EnrichResult,
    enrich_pending,
)
from surya_kundal.enrichment.geoip import GeoIPLookup
from surya_kundal.enrichment.geoip_update import GeoIPUpdateError, update_all
from surya_kundal.enrichment.tor import TorExitList
from surya_kundal.enrichment.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)


@dataclass
class Providers:
    """The enrichment sources that are configured. Missing ones are None and skipped."""

    geo: GeoIPLookup | None
    tor: TorExitList
    abuse: AbuseIPDBClient | None
    virustotal: VirusTotalClient | None
    notes: list[str]
    geoip_update: Callable[[], None] | None = None  # downloads fresh GeoLite2 files

    def close(self) -> None:
        if self.geo is not None:
            self.geo.close()
        for client in (self.abuse, self.virustotal):
            if client is not None:
                client.close()


def build_providers(
    settings: Settings,
    *,
    geoip_dir: Path | None = None,
    sleep: Callable[[float], object] | None = None,
) -> Providers:
    """Create providers from settings. ``sleep`` lets a service make pauses interruptible."""
    notes: list[str] = []
    geo = GeoIPLookup(geoip_dir or settings.geoip_dir)
    if not geo.available:
        notes.append("GeoIP databases not found; run: surya-kundal geoip update")
    pause = sleep or time.sleep
    abuse = virustotal = None
    if settings.abuseipdb_api_key:
        abuse = AbuseIPDBClient(settings.abuseipdb_api_key, sleep=pause)
    else:
        notes.append("ABUSEIPDB_API_KEY not set; skipping AbuseIPDB")
    if settings.virustotal_api_key:
        virustotal = VirusTotalClient(settings.virustotal_api_key, sleep=pause)
    else:
        notes.append("VIRUSTOTAL_API_KEY not set; skipping VirusTotal")
    updater: Callable[[], None] | None = None
    if settings.maxmind_account_id and settings.maxmind_license_key:
        directory = (geoip_dir or settings.geoip_dir).expanduser()
        account, key = settings.maxmind_account_id, settings.maxmind_license_key

        def updater() -> None:
            update_all(directory, account, key)

    return Providers(
        geo=geo,
        tor=TorExitList(settings.tor_cache_path),
        abuse=abuse,
        virustotal=virustotal,
        notes=notes,
    )


def run_enrichment(
    session_factory: sessionmaker[Session],
    providers: Providers,
    *,
    abuse_budget: int = DEFAULT_ABUSE_BUDGET,
    vt_budget: int = DEFAULT_VT_BUDGET,
    should_stop: Callable[[], bool] = lambda: False,
) -> EnrichResult:
    """One enrichment pass with the given providers."""
    with session_factory() as db:
        return enrich_pending(
            db,
            geo=providers.geo if providers.geo is not None and providers.geo.available else None,
            tor=providers.tor if providers.tor.load() else None,
            abuse=providers.abuse,
            virustotal_client=providers.virustotal,
            abuse_budget=abuse_budget,
            vt_budget=vt_budget,
            should_stop=should_stop,
        )


def refresh_geoip(providers: Providers) -> None:
    """Fetch newer GeoLite2 files if configured, then load whatever is on disk.

    Never raises: a failed download must not stop enrichment, and the databases on disk
    keep working. ``update_all`` skips files that are already fresh, so calling this
    daily costs nothing most days.
    """
    if providers.geoip_update is not None:
        try:
            providers.geoip_update()
        except (GeoIPUpdateError, httpx.HTTPError, OSError):
            logger.warning("GeoIP database update failed; keeping the current files", exc_info=True)
    if providers.geo is not None and providers.geo.refresh():
        logger.info("GeoIP databases reloaded")
