"""The long-running service: follow the log, map to ATT&CK, enrich in the background.

One process does the whole pipeline. The main thread follows the Cowrie log and maps
new activity to ATT&CK techniques (both are local and fast). A second thread does
enrichment, which waits on the network and on free-tier rate limits, so it must never
hold up capture.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from surya_kundal.mapping.store import map_pending
from surya_kundal.pipeline import Providers, refresh_geoip, run_enrichment
from surya_kundal.watcher import Watcher

logger = logging.getLogger(__name__)

GEOIP_REFRESH_SECONDS = 24 * 3600  # check for newer GeoLite2 files daily


class Service:
    def __init__(
        self,
        log_path: Path,
        session_factory: sessionmaker[Session],
        *,
        providers: Providers | None = None,
        interval: float = 1.0,
        from_end: bool = False,
        map_interval: float = 5.0,
        enrich_interval: float = 300.0,
        abuse_budget: int | None = None,
        vt_budget: int | None = None,
    ) -> None:
        self._factory = session_factory
        self._watcher = Watcher(log_path, session_factory, interval=interval, from_end=from_end)
        self._providers = providers
        self._interval = interval
        self._map_interval = map_interval
        self._enrich_interval = enrich_interval
        self._budgets = {
            key: value
            for key, value in (("abuse_budget", abuse_budget), ("vt_budget", vt_budget))
            if value is not None
        }

    def run(self, stop: threading.Event) -> None:
        thread = None
        if self._providers is not None:
            thread = threading.Thread(
                target=self._enrich_loop,
                args=(self._providers, stop),
                name="enrichment",
                daemon=True,
            )
            thread.start()
        logger.info("Service started")
        dirty = True  # map anything stored before startup, once
        last_map = float("-inf")
        try:
            while not stop.is_set():
                try:
                    if self._watcher.poll_once() > 0:
                        dirty = True
                    if dirty and time.monotonic() - last_map >= self._map_interval:
                        self._map()
                        dirty, last_map = False, time.monotonic()
                except Exception:
                    logger.exception("Unexpected error in service cycle")
                stop.wait(self._interval)
        finally:
            stop.set()
            if thread is not None:
                thread.join(timeout=30)
            if dirty:
                self._map()
            logger.info("Service stopped")

    def _map(self) -> None:
        try:
            with self._factory() as db:
                result = map_pending(db)
            if result.sessions:
                logger.info("Mapped %d session(s) to ATT&CK", result.sessions)
        except Exception:
            logger.exception("ATT&CK mapping failed; will retry")

    def _enrich_loop(self, providers: Providers, stop: threading.Event) -> None:
        last_geo_refresh = float("-inf")
        while not stop.is_set():
            if time.monotonic() - last_geo_refresh >= GEOIP_REFRESH_SECONDS:
                last_geo_refresh = time.monotonic()
                refresh_geoip(providers)
            try:
                result = run_enrichment(
                    self._factory, providers, should_stop=stop.is_set, **self._budgets
                )
                if result.geo or result.tor or result.abuse or result.files:
                    logger.info(
                        "Enriched: %d geo, %d tor, %d AbuseIPDB, %d VirusTotal",
                        result.geo,
                        result.tor,
                        result.abuse,
                        result.files,
                    )
            except Exception:
                logger.exception("Enrichment pass failed; will retry")
            stop.wait(self._enrich_interval)
