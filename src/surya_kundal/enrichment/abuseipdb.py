"""AbuseIPDB client (free tier: 1,000 checks per day)."""

from __future__ import annotations

import time
from collections.abc import Callable

import httpx

from surya_kundal.enrichment.http import DEFAULT_TIMEOUT, ProviderError, QuotaExceeded, send

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
PROVIDER = "abuseipdb"


class AbuseIPDBClient:
    def __init__(
        self,
        api_key: str,
        *,
        max_age_days: int = 90,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key:
            raise ProviderError("AbuseIPDB API key is not set")
        self._key = api_key
        self._max_age = max_age_days
        self._client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)
        self._sleep = sleep

    def check(self, ip: str) -> dict:
        """Return AbuseIPDB's ``data`` object for ``ip``."""
        response = send(
            self._client,
            "GET",
            CHECK_URL,
            params={"ipAddress": ip, "maxAgeInDays": self._max_age},
            headers={"Key": self._key, "Accept": "application/json"},
            sleep=self._sleep,
        )
        status = response.status_code
        if status == 429:
            raise QuotaExceeded("AbuseIPDB limit reached (429)")
        if status in (401, 403):
            raise ProviderError("AbuseIPDB rejected the API key")
        if status == 422:
            raise ProviderError(f"AbuseIPDB rejected the address {ip!r}")
        if status != 200:
            raise ProviderError(f"AbuseIPDB returned HTTP {status}")
        try:
            data = response.json()["data"]
            int(data["abuseConfidenceScore"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderError("AbuseIPDB returned an unexpected response") from exc
        return data

    def close(self) -> None:
        self._client.close()
