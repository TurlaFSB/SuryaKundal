"""Build tiny synthetic GeoLite2-style databases (real ones cannot be committed)."""

import io
import tarfile
import time
from unittest import mock

import netaddr
from mmdb_writer import MMDBWriter


def build_mmdb(path, database_type, records, build_epoch=None):
    """Write a synthetic database; build_epoch lets tests make it look old."""
    writer = MMDBWriter(
        ip_version=6,
        ipv4_compatible=True,
        database_type=database_type,
        languages=["en"],
        description={"en": "synthetic test database"},
    )
    for network, data in records.items():
        writer.insert_network(netaddr.IPSet([network]), data)
    if build_epoch is None:
        writer.to_db_file(str(path))
    else:
        with mock.patch("mmdb_writer.time.time", return_value=build_epoch):
            writer.to_db_file(str(path))
    return path


CITY_RECORDS = {
    "8.8.8.0/24": {
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "city": {"names": {"en": "Mountain View"}},
        "location": {"latitude": 37.386, "longitude": -122.0838, "accuracy_radius": 1000},
    }
}
ASN_RECORDS = {
    "8.8.8.0/24": {
        "autonomous_system_number": 15169,
        "autonomous_system_organization": "GOOGLE",
    }
}


def make_archive(mmdb_path, member_name="GeoLite2-City_20261001/GeoLite2-City.mmdb"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(mmdb_path, arcname=member_name)
    return buf.getvalue()


def now():
    return int(time.time())
