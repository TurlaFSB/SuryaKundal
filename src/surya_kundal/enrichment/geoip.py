"""Offline IP geolocation and ASN lookup using MaxMind GeoLite2 databases.

This product includes GeoLite2 data created by MaxMind, available from
https://www.maxmind.com.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import maxminddb

logger = logging.getLogger(__name__)

CITY_DB = "GeoLite2-City.mmdb"
ASN_DB = "GeoLite2-ASN.mmdb"
STALE_AFTER_DAYS = 30  # MaxMind's licence requires replacing databases within 30 days


@dataclass(frozen=True)
class GeoInfo:
    """Normalised geolocation facts for one public IP. Any field may be None."""

    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy_radius_km: int | None = None
    asn: int | None = None
    as_org: str | None = None


def is_public_ip(value: str) -> bool:
    """True for a syntactically valid, globally routable IP address."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def database_age_days(reader: maxminddb.Reader, now: float | None = None) -> float:
    return ((now if now is not None else time.time()) - reader.metadata().build_epoch) / 86400


def _name(record: dict | None) -> str | None:
    if not record:
        return None
    return (record.get("names") or {}).get("en")


class GeoIPLookup:
    """Reads the City and ASN databases. Missing databases degrade to empty results."""

    def __init__(self, db_dir: str | Path) -> None:
        self._dir = Path(db_dir).expanduser()
        self._city = self._open(CITY_DB)
        self._asn = self._open(ASN_DB)

    @property
    def available(self) -> bool:
        return self._city is not None or self._asn is not None

    def _open(self, filename: str) -> maxminddb.Reader | None:
        path = self._dir / filename
        if not path.is_file():
            logger.warning("GeoIP database not found: %s (run: surya-kundal geoip update)", path)
            return None
        try:
            reader = maxminddb.open_database(str(path))
        except (maxminddb.InvalidDatabaseError, OSError, ValueError) as exc:
            logger.warning("GeoIP database %s is unreadable: %s", path, exc)
            return None
        age = database_age_days(reader)
        if age > STALE_AFTER_DAYS:
            logger.warning(
                "%s is %d days old; MaxMind requires updates within %d days "
                "(run: surya-kundal geoip update)",
                filename,
                age,
                STALE_AFTER_DAYS,
            )
        return reader

    def lookup(self, ip: str) -> GeoInfo | None:
        """Return facts for a public IP, or None if it is private, invalid or unknown."""
        if not is_public_ip(ip):
            return None
        fields: dict = {}
        if self._city is not None:
            record = self._safe_get(self._city, ip) or {}
            location = record.get("location") or {}
            country = record.get("country") or {}
            fields.update(
                country_code=country.get("iso_code"),
                country_name=_name(country),
                city=_name(record.get("city")),
                latitude=location.get("latitude"),
                longitude=location.get("longitude"),
                accuracy_radius_km=location.get("accuracy_radius"),
            )
        if self._asn is not None:
            record = self._safe_get(self._asn, ip) or {}
            fields.update(
                asn=record.get("autonomous_system_number"),
                as_org=record.get("autonomous_system_organization"),
            )
        if not any(v is not None for v in fields.values()):
            return None
        return GeoInfo(**fields)

    @staticmethod
    def _safe_get(reader: maxminddb.Reader, ip: str) -> dict | None:
        try:
            record = reader.get(ip)
        except (ValueError, maxminddb.InvalidDatabaseError):
            return None
        return record if isinstance(record, dict) else None

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()
