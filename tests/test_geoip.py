"""Tests for the offline GeoIP lookup."""

import logging
import time

import pytest

from mmdb_helpers import ASN_RECORDS, CITY_RECORDS, build_mmdb
from surya_kundal.enrichment.geoip import ASN_DB, CITY_DB, GeoIPLookup, is_public_ip


@pytest.fixture
def db_dir(tmp_path):
    build_mmdb(tmp_path / CITY_DB, "GeoLite2-City", CITY_RECORDS)
    build_mmdb(tmp_path / ASN_DB, "GeoLite2-ASN", ASN_RECORDS)
    return tmp_path


def test_lookup_returns_location_and_asn(db_dir):
    info = GeoIPLookup(db_dir).lookup("8.8.8.8")

    assert info.country_code == "US"
    assert info.country_name == "United States"
    assert info.city == "Mountain View"
    assert info.latitude == pytest.approx(37.386)
    assert info.longitude == pytest.approx(-122.0838)
    assert info.accuracy_radius_km == 1000
    assert info.asn == 15169
    assert info.as_org == "GOOGLE"


def test_unknown_public_ip_returns_none(db_dir):
    assert GeoIPLookup(db_dir).lookup("1.1.1.1") is None


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.5", "127.0.0.1", "169.254.1.1", "::1"])
def test_private_and_loopback_addresses_return_none(db_dir, ip):
    assert GeoIPLookup(db_dir).lookup(ip) is None


@pytest.mark.parametrize("ip", ["", "not-an-ip", "999.1.1.1", "8.8.8"])
def test_invalid_addresses_return_none(db_dir, ip):
    assert GeoIPLookup(db_dir).lookup(ip) is None


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("10.1.2.3")
    assert not is_public_ip("garbage")


def test_missing_databases_degrade_gracefully(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        lookup = GeoIPLookup(tmp_path)

    assert not lookup.available
    assert lookup.lookup("8.8.8.8") is None
    assert "geoip update" in caplog.text


def test_works_with_only_the_asn_database(tmp_path):
    build_mmdb(tmp_path / ASN_DB, "GeoLite2-ASN", ASN_RECORDS)

    info = GeoIPLookup(tmp_path).lookup("8.8.8.8")

    assert info.asn == 15169
    assert info.country_code is None


def test_corrupt_database_is_reported_not_raised(tmp_path, caplog):
    (tmp_path / CITY_DB).write_bytes(b"this is not an mmdb file")

    with caplog.at_level(logging.WARNING):
        lookup = GeoIPLookup(tmp_path)

    assert not lookup.available
    assert "unreadable" in caplog.text


def test_stale_database_triggers_a_warning(tmp_path, caplog):
    old = int(time.time()) - 45 * 86400
    build_mmdb(tmp_path / CITY_DB, "GeoLite2-City", CITY_RECORDS, build_epoch=old)

    with caplog.at_level(logging.WARNING):
        GeoIPLookup(tmp_path)

    assert "days old" in caplog.text


def test_fresh_database_does_not_warn(db_dir, caplog):
    with caplog.at_level(logging.WARNING):
        GeoIPLookup(db_dir)

    assert caplog.text == ""


def test_refresh_picks_up_a_replaced_database(tmp_path):
    build_mmdb(tmp_path / CITY_DB, "GeoLite2-City", CITY_RECORDS)
    build_mmdb(tmp_path / ASN_DB, "GeoLite2-ASN", ASN_RECORDS)
    geo = GeoIPLookup(tmp_path)
    assert geo.lookup("8.8.8.8").city == "Mountain View"
    assert geo.refresh() is False  # nothing changed

    replacement = {"8.8.8.8": {"city": {"names": {"en": "Elsewhere"}}}}
    build_mmdb(tmp_path / "new.mmdb", "GeoLite2-City", replacement)
    (tmp_path / "new.mmdb").replace(tmp_path / CITY_DB)  # atomic swap, as an update does

    assert geo.refresh() is True
    assert geo.lookup("8.8.8.8").city == "Elsewhere"
    geo.close()


def test_refresh_loads_a_database_that_appears_later(tmp_path):
    geo = GeoIPLookup(tmp_path)
    assert not geo.available
    build_mmdb(tmp_path / CITY_DB, "GeoLite2-City", CITY_RECORDS)

    assert geo.refresh() is True
    assert geo.available
    geo.close()
