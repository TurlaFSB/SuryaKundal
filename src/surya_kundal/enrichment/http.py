"""Shared HTTP helpers for threat-intel providers: errors and bounded retries."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=10.0)


class ProviderError(Exception):
    """A provider call failed. Messages never contain credentials or request URLs."""


class QuotaExceeded(ProviderError):  # noqa: N818 - reads better than QuotaExceededError
    """The provider's rate or daily limit was hit; stop calling it for now."""


def send(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    retries: int = 2,
    sleep: Callable[[float], None] = time.sleep,
    **kwargs,
) -> httpx.Response:
    """Send a request, retrying network errors and 5xx responses with backoff.

    4xx responses (including 429) are returned as-is: retrying them is pointless
    or harmful, so the caller decides what they mean.
    """
    for attempt in range(retries + 1):
        last = attempt == retries
        try:
            response = client.request(method, url, **kwargs)
        except httpx.TransportError as exc:
            if last:
                raise ProviderError(f"network error: {type(exc).__name__}") from exc
        else:
            if response.status_code < 500 or last:
                return response
        delay = 2**attempt
        logger.debug("retrying in %ss (attempt %d)", delay, attempt + 1)
        sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover
