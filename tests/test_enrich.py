"""Tests for the enrichment orchestrator, with fake providers."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from mmdb_helpers import ASN_RECORDS, CITY_RECORDS, build_mmdb
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import FileIntel, HoneypotSession, IpGeo, IpIntel
from surya_kundal.database.repository import save_session
from surya_kundal.enrichment.enrich import enrich_pending
from surya_kundal.enrichment.geoip import ASN_DB, CITY_DB, GeoIPLookup
from surya_kundal.enrichment.http import ProviderError, QuotaExceeded

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
PUBLIC_IP = "8.8.8.8"
OTHER_IP = "45.33.32.100"
SHA1, SHA2 = "a" * 64, "b" * 64


@pytest.fixture
def db():
    engine = create_db_engine("sqlite://")
    init_db(engine)
    with make_session_factory(engine)() as session:
        yield session


def _session(db, sid, ip, start="2026-10-05T10:00:00.000000Z", sha=None):
    summary = {
        "src_ip": ip, "start_time": start, "end_time": None, "duration_ms": None,
        "client_version": None, "hassh": None, "logins": [], "commands": [],
        "downloads": [{"url": "http://x/y", "sha256": sha, "timestamp": start}] if sha else [],
    }  # fmt: skip
    save_session(db, sid, summary)
    db.commit()


class FakeAbuse:
    def __init__(self, fail=None, quota_after=None):
        self.calls, self.fail, self.quota_after = [], fail or {}, quota_after

    def check(self, ip):
        if self.quota_after is not None and len(self.calls) >= self.quota_after:
            raise QuotaExceeded("limit")
        self.calls.append(ip)
        if ip in self.fail:
            raise ProviderError("boom")
        return {"ipAddress": ip, "abuseConfidenceScore": 42, "totalReports": 3}


class FakeVT:
    def __init__(self, reports=None):
        self.calls, self.reports = [], reports or {}

    def lookup_file(self, sha):
        self.calls.append(sha)
        return self.reports.get(sha)


class FakeTor:
    def __init__(self, exits=()):
        self.exits = set(exits)

    def __contains__(self, ip):
        return ip in self.exits


def _count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_each_ip_is_looked_up_once_however_many_sessions_it_has(db):
    for i in range(5):
        _session(db, f"s{i}", OTHER_IP)
    abuse = FakeAbuse()

    result = enrich_pending(db, abuse=abuse, now=NOW)

    assert abuse.calls == [OTHER_IP]
    assert result.abuse == 1
    row = db.scalar(select(IpIntel))
    assert (row.ip, row.provider, row.score) == (OTHER_IP, "abuseipdb", 42)
    assert row.payload["totalReports"] == 3


def test_a_second_run_does_nothing_new(db):
    _session(db, "s1", OTHER_IP)
    abuse = FakeAbuse()
    enrich_pending(db, abuse=abuse, now=NOW)

    enrich_pending(db, abuse=abuse, now=NOW + timedelta(hours=1))

    assert abuse.calls == [OTHER_IP]


def test_private_and_missing_ips_are_never_sent_to_providers(db):
    _session(db, "s1", "192.168.1.5")
    _session(db, "s2", "10.0.0.2")
    _session(db, "s3", None)
    abuse = FakeAbuse()

    enrich_pending(db, abuse=abuse, now=NOW)

    assert abuse.calls == []


def test_stale_entries_are_refreshed_after_new_ones(db):
    _session(db, "old", PUBLIC_IP)
    abuse = FakeAbuse()
    enrich_pending(db, abuse=abuse, now=NOW - timedelta(days=10))
    _session(db, "new", OTHER_IP)

    enrich_pending(db, abuse=abuse, now=NOW)

    assert abuse.calls == [PUBLIC_IP, OTHER_IP, PUBLIC_IP]
    assert _count(db, IpIntel) == 2  # refreshed in place, not duplicated


def test_daily_budget_is_respected_and_survives_restarts(db):
    for i in range(4):
        _session(db, f"s{i}", f"45.33.32.{i + 1}", start=f"2026-10-05T10:0{i}:00.000000Z")
    abuse = FakeAbuse()

    enrich_pending(db, abuse=abuse, abuse_budget=2, now=NOW)
    enrich_pending(db, abuse=abuse, abuse_budget=2, now=NOW + timedelta(hours=1))

    assert len(abuse.calls) == 2  # the second run knows today's budget is spent
    enrich_pending(db, abuse=abuse, abuse_budget=2, now=NOW + timedelta(days=1))
    assert len(abuse.calls) == 4


def test_newest_ips_are_enriched_first(db):
    _session(db, "a", "45.33.32.1", start="2026-10-05T08:00:00.000000Z")
    _session(db, "b", "45.33.32.2", start="2026-10-05T11:00:00.000000Z")
    abuse = FakeAbuse()

    enrich_pending(db, abuse=abuse, abuse_budget=1, now=NOW)

    assert abuse.calls == ["45.33.32.2"]


def test_a_quota_error_stops_that_provider_but_keeps_earlier_results(db):
    for i in range(3):
        _session(db, f"s{i}", f"45.33.32.{i + 1}", start=f"2026-10-05T10:0{i}:00.000000Z")

    result = enrich_pending(db, abuse=FakeAbuse(quota_after=1), now=NOW)

    assert result.abuse == 1
    assert result.stopped == ["abuseipdb"]
    assert _count(db, IpIntel) == 1


def test_one_failing_ip_does_not_block_the_rest(db):
    _session(db, "a", "45.33.32.1", start="2026-10-05T09:00:00.000000Z")
    _session(db, "b", "45.33.32.2", start="2026-10-05T10:00:00.000000Z")

    result = enrich_pending(db, abuse=FakeAbuse(fail={"45.33.32.2"}), now=NOW)

    assert (result.abuse, result.errors) == (1, 1)
    assert db.scalar(select(IpIntel.ip)) == "45.33.32.1"


def test_tor_membership_is_recorded_and_updated_when_it_changes(db):
    _session(db, "a", OTHER_IP)
    tor = FakeTor({OTHER_IP})
    enrich_pending(db, tor=tor, now=NOW)
    row = db.scalar(select(IpIntel).where(IpIntel.provider == "tor"))
    assert row.flagged is True

    tor.exits.clear()
    result = enrich_pending(db, tor=tor, now=NOW + timedelta(days=1))

    assert db.scalar(select(IpIntel.flagged).where(IpIntel.provider == "tor")) is False
    assert result.tor == 1
    assert enrich_pending(db, tor=tor, now=NOW + timedelta(days=2)).tor == 0


def test_geo_is_stored_per_ip(db, tmp_path):
    build_mmdb(tmp_path / CITY_DB, "GeoLite2-City", CITY_RECORDS)
    build_mmdb(tmp_path / ASN_DB, "GeoLite2-ASN", ASN_RECORDS)
    _session(db, "a", PUBLIC_IP)
    _session(db, "b", OTHER_IP)  # in no database: stored empty, not retried forever

    result = enrich_pending(db, geo=GeoIPLookup(tmp_path), now=NOW)

    assert result.geo == 2
    known = db.get(IpGeo, PUBLIC_IP)
    assert (known.country_code, known.asn, known.as_org) == ("US", 15169, "GOOGLE")
    assert db.get(IpGeo, OTHER_IP).country_code is None
    assert enrich_pending(db, geo=GeoIPLookup(tmp_path), now=NOW).geo == 0


def test_missing_geo_databases_store_nothing_so_a_later_run_can_fill_in(db, tmp_path):
    _session(db, "a", PUBLIC_IP)

    enrich_pending(db, geo=GeoIPLookup(tmp_path), now=NOW)

    assert _count(db, IpGeo) == 0


def test_virustotal_results_are_stored_per_hash(db):
    _session(db, "a", OTHER_IP, sha=SHA1)
    _session(db, "b", PUBLIC_IP, sha=SHA1)  # same file from two attackers: one lookup
    _session(db, "c", "45.33.32.9", sha=SHA2)
    report = {
        "last_analysis_stats": {"malicious": 30, "suspicious": 1, "undetected": 10},
        "meaningful_name": "bot.sh",
        "popular_threat_classification": {"suggested_threat_label": "trojan.mirai"},
    }
    vt = FakeVT({SHA1: report})

    result = enrich_pending(db, virustotal_client=vt, now=NOW)

    assert sorted(vt.calls) == [SHA1, SHA2]
    assert result.files == 2
    known = db.scalar(select(FileIntel).where(FileIntel.sha256 == SHA1))
    assert (known.found, known.malicious, known.suspicious, known.engines) == (True, 30, 1, 41)
    assert known.label == "trojan.mirai"
    unknown = db.scalar(select(FileIntel).where(FileIntel.sha256 == SHA2))
    assert (unknown.found, unknown.malicious) == (False, None)


def test_unknown_files_are_rechecked_sooner_than_known_ones(db):
    _session(db, "a", OTHER_IP, sha=SHA1)
    vt = FakeVT()
    enrich_pending(db, virustotal_client=vt, now=NOW)

    enrich_pending(db, virustotal_client=vt, now=NOW + timedelta(days=1))
    assert len(vt.calls) == 1
    enrich_pending(db, virustotal_client=vt, now=NOW + timedelta(days=3))
    assert len(vt.calls) == 2
    assert _count(db, FileIntel) == 1


def test_nothing_configured_is_a_clean_no_op(db):
    _session(db, "a", OTHER_IP, sha=SHA1)

    result = enrich_pending(db, now=NOW)

    assert (result.geo, result.tor, result.abuse, result.files) == (0, 0, 0, 0)
    assert _count(db, HoneypotSession) == 1
