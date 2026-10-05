"""Tor exit-node list from the Tor Project, cached on disk and refreshed daily."""

from __future__ import annotations

import ipaddress
import logging
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import httpx

from surya_kundal.enrichment.http import DEFAULT_TIMEOUT, ProviderError, send

logger = logging.getLogger(__name__)

EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
MAX_AGE_SECONDS = 24 * 3600
MIN_ENTRIES = 10  # the real list has over a thousand; fewer means a broken response


def parse_exit_list(text: str) -> set[str]:
    addresses = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            addresses.add(str(ipaddress.ip_address(line)))
        except ValueError:
            continue
    return addresses


class TorExitList:
    def __init__(
        self,
        cache_path: str | Path,
        *,
        client: httpx.Client | None = None,
        url: str = EXIT_LIST_URL,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._path = Path(cache_path).expanduser()
        self._client = client
        self._url = url
        self._sleep = sleep
        self._addresses: set[str] = set()

    def __contains__(self, ip: str) -> bool:
        return ip in self._addresses

    def __len__(self) -> int:
        return len(self._addresses)

    def load(self, *, now: float | None = None) -> bool:
        """Refresh the cache if it is missing or old, then load it.

        Returns True if a usable list is loaded. A failed refresh falls back to the
        existing cache, so one network blip never loses the data.
        """
        now = time.time() if now is None else now
        if not self._path.is_file() or now - self._path.stat().st_mtime > MAX_AGE_SECONDS:
            try:
                self._refresh()
            except ProviderError as exc:
                logger.warning("Could not refresh the Tor exit list: %s", exc)
        if not self._path.is_file():
            return False
        self._addresses = parse_exit_list(self._path.read_text(encoding="utf-8", errors="replace"))
        return len(self._addresses) >= MIN_ENTRIES

    def _refresh(self) -> None:
        owns = self._client is None
        client = self._client or httpx.Client(timeout=DEFAULT_TIMEOUT)
        try:
            response = send(client, "GET", self._url, sleep=self._sleep)
        finally:
            if owns:
                client.close()
        if response.status_code != 200:
            raise ProviderError(f"Tor Project returned HTTP {response.status_code}")
        if len(parse_exit_list(response.text)) < MIN_ENTRIES:
            raise ProviderError("Tor exit list response looks empty or malformed")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", dir=self._path.parent, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(response.text)
        os.replace(tmp.name, self._path)  # atomic: never a half-written cache
