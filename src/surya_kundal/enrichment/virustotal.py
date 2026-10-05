"""VirusTotal v3 file-report client (free tier: 4 requests/minute, 500/day)."""

from __future__ import annotations

import re
import time
from collections.abc import Callable

import httpx

from surya_kundal.enrichment.http import DEFAULT_TIMEOUT, ProviderError, QuotaExceeded, send

FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
PROVIDER = "virustotal"
MIN_INTERVAL = 15.0  # 4 requests per minute
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

# VirusTotal's full report is large (one entry per antivirus engine); keep the useful part.
_KEEP = (
    "last_analysis_stats",
    "meaningful_name",
    "names",
    "type_description",
    "size",
    "first_submission_date",
    "last_analysis_date",
    "popular_threat_classification",
    "tags",
    "reputation",
)


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.Client | None = None,
        sleep: Callable[[float], object] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not api_key:
            raise ProviderError("VirusTotal API key is not set")
        self._key = api_key
        self._client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)
        self._sleep = sleep
        self._clock = clock
        self._last_call: float | None = None

    def _pace(self) -> None:
        if self._last_call is not None:
            wait = MIN_INTERVAL - (self._clock() - self._last_call)
            if wait > 0:
                self._sleep(wait)
        self._last_call = self._clock()

    def lookup_file(self, sha256: str) -> dict | None:
        """Return a trimmed report for the hash, or None if VirusTotal has never seen it."""
        if not _SHA256.match(sha256):
            raise ProviderError(f"not a SHA-256 hash: {sha256!r}")
        self._pace()
        response = send(
            self._client,
            "GET",
            FILE_URL.format(sha256=sha256.lower()),
            headers={"x-apikey": self._key, "Accept": "application/json"},
            sleep=self._sleep,
        )
        status = response.status_code
        if status == 404:
            return None
        if status == 429:
            raise QuotaExceeded("VirusTotal limit reached (429)")
        if status in (401, 403):
            raise ProviderError("VirusTotal rejected the API key")
        if status != 200:
            raise ProviderError(f"VirusTotal returned HTTP {status}")
        try:
            attributes = response.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            int(stats["malicious"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderError("VirusTotal returned an unexpected response") from exc
        report = {k: attributes[k] for k in _KEEP if k in attributes}
        if isinstance(report.get("names"), list):
            report["names"] = report["names"][:10]
        return report

    def close(self) -> None:
        self._client.close()
