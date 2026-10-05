"""Tests for the AbuseIPDB, VirusTotal and Tor clients, using mocked HTTP."""

import os
import time

import httpx
import pytest

from surya_kundal.enrichment.abuseipdb import AbuseIPDBClient
from surya_kundal.enrichment.http import ProviderError, QuotaExceeded, send
from surya_kundal.enrichment.tor import MIN_ENTRIES, TorExitList, parse_exit_list
from surya_kundal.enrichment.virustotal import MIN_INTERVAL, VirusTotalClient

SHA = "a" * 64
ABUSE_DATA = {"ipAddress": "203.0.113.7", "abuseConfidenceScore": 87, "totalReports": 12}


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _json(status, body):
    return httpx.Response(status, json=body)


# --- send() ----------------------------------------------------------------


def test_send_retries_server_errors_then_succeeds():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503 if len(calls) < 3 else 200)

    sleeps = []
    response = send(_client(handler), "GET", "https://x.test", sleep=sleeps.append)

    assert response.status_code == 200
    assert sleeps == [1, 2]


def test_send_does_not_retry_client_errors():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429)

    assert send(_client(handler), "GET", "https://x.test", sleep=lambda s: None).status_code == 429
    assert len(calls) == 1


def test_send_gives_up_on_persistent_network_errors():
    def handler(request):
        raise httpx.ConnectError("down", request=request)

    with pytest.raises(ProviderError, match="ConnectError"):
        send(_client(handler), "GET", "https://x.test", sleep=lambda s: None)


# --- AbuseIPDB -------------------------------------------------------------


def test_abuseipdb_sends_key_and_returns_data():
    seen = []

    def handler(request):
        seen.append(request)
        return _json(200, {"data": ABUSE_DATA})

    data = AbuseIPDBClient("secret", client=_client(handler)).check("203.0.113.7")

    assert data["abuseConfidenceScore"] == 87
    assert seen[0].headers["key"] == "secret"
    assert seen[0].url.params["ipAddress"] == "203.0.113.7"
    assert seen[0].url.params["maxAgeInDays"] == "90"
    assert "secret" not in str(seen[0].url)


@pytest.mark.parametrize(
    ("status", "error", "needle"),
    [(429, QuotaExceeded, "limit"), (401, ProviderError, "key"), (422, ProviderError, "rejected")],
)
def test_abuseipdb_errors(status, error, needle):
    client = AbuseIPDBClient("k", client=_client(lambda r: httpx.Response(status)))

    with pytest.raises(error, match=needle):
        client.check("203.0.113.7")


def test_abuseipdb_malformed_response():
    client = AbuseIPDBClient("k", client=_client(lambda r: _json(200, {"nope": 1})))

    with pytest.raises(ProviderError, match="unexpected"):
        client.check("203.0.113.7")


def test_abuseipdb_requires_a_key():
    with pytest.raises(ProviderError):
        AbuseIPDBClient("")


# --- VirusTotal ------------------------------------------------------------

VT_BODY = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 40, "suspicious": 2, "undetected": 20},
            "last_analysis_results": {"huge": "dict we drop"},
            "meaningful_name": "mirai.sh",
            "names": [f"n{i}" for i in range(30)],
        }
    }
}


def _vt(handler, **kw):
    return VirusTotalClient("vtkey", client=_client(handler), sleep=lambda s: None, **kw)


def test_virustotal_returns_a_trimmed_report():
    seen = []

    def handler(request):
        seen.append(request)
        return _json(200, VT_BODY)

    report = _vt(handler).lookup_file(SHA)

    assert report["last_analysis_stats"]["malicious"] == 40
    assert "last_analysis_results" not in report
    assert len(report["names"]) == 10
    assert seen[0].headers["x-apikey"] == "vtkey"
    assert seen[0].url.path.endswith(SHA)


def test_virustotal_unknown_hash_returns_none():
    assert _vt(lambda r: httpx.Response(404)).lookup_file(SHA) is None


@pytest.mark.parametrize(("status", "error"), [(429, QuotaExceeded), (401, ProviderError)])
def test_virustotal_errors(status, error):
    with pytest.raises(error):
        _vt(lambda r: httpx.Response(status)).lookup_file(SHA)


def test_virustotal_rejects_a_non_hash_without_a_request():
    def handler(request):
        raise AssertionError("no request expected")

    with pytest.raises(ProviderError, match="SHA-256"):
        _vt(handler).lookup_file("../etc/passwd")


def test_virustotal_paces_requests_to_four_per_minute():
    now = [100.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    client = VirusTotalClient(
        "k",
        client=_client(lambda r: httpx.Response(404)),
        sleep=sleep,
        clock=lambda: now[0],
    )
    client.lookup_file(SHA)
    now[0] += 5  # five seconds pass before the next call
    client.lookup_file(SHA)

    assert sleeps == [pytest.approx(MIN_INTERVAL - 5)]


# --- Tor -------------------------------------------------------------------

TOR_TEXT = "\n".join(f"198.51.100.{i}" for i in range(1, MIN_ENTRIES + 5)) + "\n"


def test_parse_exit_list_ignores_comments_and_junk():
    assert parse_exit_list("# c\n\n1.2.3.4\nnot-an-ip\n::1\n") == {"1.2.3.4", "::1"}


def test_tor_downloads_caches_and_answers_membership(tmp_path):
    tor = TorExitList(
        tmp_path / "tor.txt", client=_client(lambda r: httpx.Response(200, text=TOR_TEXT))
    )

    assert tor.load()
    assert "198.51.100.1" in tor
    assert "8.8.8.8" not in tor
    assert (tmp_path / "tor.txt").is_file()


def test_tor_uses_a_fresh_cache_without_network(tmp_path):
    path = tmp_path / "tor.txt"
    path.write_text(TOR_TEXT)

    def handler(request):
        raise AssertionError("cache is fresh")

    assert TorExitList(path, client=_client(handler)).load()


def test_tor_falls_back_to_a_stale_cache_when_refresh_fails(tmp_path):
    path = tmp_path / "tor.txt"
    path.write_text(TOR_TEXT)
    old = time.time() - 3 * 86400
    os.utime(path, (old, old))

    tor = TorExitList(path, client=_client(lambda r: httpx.Response(500)), sleep=lambda s: None)

    assert tor.load()
    assert "198.51.100.1" in tor


def test_tor_rejects_a_garbage_response_and_keeps_the_cache(tmp_path):
    path = tmp_path / "tor.txt"
    path.write_text(TOR_TEXT)
    old = time.time() - 3 * 86400
    os.utime(path, (old, old))

    tor = TorExitList(
        path,
        client=_client(lambda r: httpx.Response(200, text="<html>oops</html>")),
        sleep=lambda s: None,
    )

    assert tor.load()
    assert path.read_text() == TOR_TEXT


def test_tor_without_cache_or_network_is_unavailable(tmp_path):
    tor = TorExitList(
        tmp_path / "tor.txt", client=_client(lambda r: httpx.Response(500)), sleep=lambda s: None
    )

    assert not tor.load()


def test_refresh_geoip_survives_a_failed_download(caplog):
    from surya_kundal.enrichment.geoip_update import GeoIPUpdateError
    from surya_kundal.pipeline import Providers, refresh_geoip

    def failing():
        raise GeoIPUpdateError("boom")

    providers = Providers(
        geo=None, tor=None, abuse=None, virustotal=None, notes=[], geoip_update=failing
    )  # type: ignore[arg-type]
    refresh_geoip(providers)  # must not raise
    assert "GeoIP database update failed" in caplog.text
