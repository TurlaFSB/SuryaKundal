"""Shared HTTP helpers for threat-intel providers: errors and bounded retries."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=10.0)


class ProviderError(Exception):
    """A provider call failed. Messages never contain credentials or request URLs."""


class FatalProviderError(ProviderError):
    """Further calls in this run would fail the same way, so stop calling the provider."""


class QuotaExceeded(FatalProviderError):
    """The provider's rate or daily limit was hit; stop calling it for now."""


class AuthError(FatalProviderError):
    """The provider rejected the API key; retrying every item would waste time and quota."""


def send(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    retries: int = 2,
    sleep: Callable[[float], object] = time.sleep,
    **kwargs: Any,
) -> httpx.Response:
    """Send a request, retrying network errors and 5xx responses with backoff.

    4xx responses (including 429) are returned as-is: retrying them is pointless
    or harmful, so the caller decides what they mean.
    """
    for attempt in range(retries + 1):
        last = attempt == retries
        try:
            response = client.request(method, url, **kwargs)
        except (httpx.TransportError, httpx.DecodingError) as exc:
            if last:
                raise ProviderError(f"network error: {type(exc).__name__}") from exc
        else:
            if response.status_code < 500 or last:
                return response
        delay = 2**attempt
        logger.debug("retrying in %ss (attempt %d)", delay, attempt + 1)
        sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover
