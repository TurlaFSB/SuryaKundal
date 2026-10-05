"""Tests for the MaxMind downloader, using a mocked HTTP transport."""

import base64
import time

import httpx
import pytest

from mmdb_helpers import ASN_RECORDS, CITY_RECORDS, build_mmdb, make_archive
from surya_kundal import cli
from surya_kundal.enrichment.geoip_update import (
    GeoIPUpdateError,
    update_all,
    update_database,
)

ACCOUNT, KEY = "123456", "test-license-key"


def _archive(tmp_path, database_type="GeoLite2-City", records=CITY_RECORDS, epoch=None):
    src = build_mmdb(tmp_path / f"src-{database_type}.mmdb", database_type, records, epoch)
    return make_archive(src)


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _serve(archive_bytes, seen=None):
    """MaxMind-style: authenticated 302 to a storage host, which serves the archive."""

    def handler(request):
        if seen is not None:
            seen.append(request)
        if request.url.host == "download.maxmind.com":
            return httpx.Response(302, headers={"location": "https://storage.example.net/f.tgz"})
        return httpx.Response(200, content=archive_bytes)

    return handler


def test_downloads_validates_and_installs_the_database(tmp_path):
    out = tmp_path / "geo"
    client = _client(_serve(_archive(tmp_path)))

    result = update_database("GeoLite2-City", out, ACCOUNT, KEY, client=client)

    assert result.updated
    assert (out / "GeoLite2-City.mmdb").is_file()
    assert [p.name for p in out.iterdir()] == ["GeoLite2-City.mmdb"]  # temp dir cleaned up


def test_sends_basic_auth_to_maxmind_only_and_not_to_the_redirect_target(tmp_path):
    seen = []
    client = _client(_serve(_archive(tmp_path), seen))

    update_database("GeoLite2-City", tmp_path / "geo", ACCOUNT, KEY, client=client)

    first, second = seen
    expected = "Basic " + base64.b64encode(f"{ACCOUNT}:{KEY}".encode()).decode()
    assert first.url.host == "download.maxmind.com"
    assert first.headers["authorization"] == expected
    assert first.url.params["suffix"] == "tar.gz"
    assert second.url.host == "storage.example.net"
    assert "authorization" not in second.headers


@pytest.mark.parametrize(
    ("status", "needle"), [(401, "credentials"), (429, "limit"), (500, "HTTP 500")]
)
def test_http_errors_give_clear_messages(tmp_path, status, needle):
    client = _client(lambda request: httpx.Response(status))

    with pytest.raises(GeoIPUpdateError, match=needle):
        update_database("GeoLite2-City", tmp_path, ACCOUNT, KEY, client=client)


def test_network_failure_is_wrapped_and_leaks_no_credentials(tmp_path):
    def handler(request):
        raise httpx.ConnectError("boom", request=request)

    with pytest.raises(GeoIPUpdateError) as err:
        update_database("GeoLite2-City", tmp_path, ACCOUNT, KEY, client=_client(handler))

    assert KEY not in str(err.value)


def test_missing_credentials_are_rejected_before_any_request(tmp_path):
    def handler(request):
        raise AssertionError("no request expected")

    with pytest.raises(GeoIPUpdateError, match="MAXMIND"):
        update_database("GeoLite2-City", tmp_path, "", "", client=_client(handler))


def test_unknown_edition_is_rejected(tmp_path):
    with pytest.raises(GeoIPUpdateError, match="Unknown edition"):
        update_database("GeoLite2-Country", tmp_path, ACCOUNT, KEY)


def test_a_fresh_database_is_not_downloaded_again(tmp_path):
    out = tmp_path / "geo"
    update_database("GeoLite2-City", out, ACCOUNT, KEY, client=_client(_serve(_archive(tmp_path))))

    def handler(request):
        raise AssertionError("should not download")

    result = update_database("GeoLite2-City", out, ACCOUNT, KEY, client=_client(handler))

    assert not result.updated
    assert "fresh" in result.reason


def test_force_downloads_even_when_fresh(tmp_path):
    out = tmp_path / "geo"
    client = _client(_serve(_archive(tmp_path)))
    update_database("GeoLite2-City", out, ACCOUNT, KEY, client=client)

    result = update_database("GeoLite2-City", out, ACCOUNT, KEY, force=True, client=client)

    assert result.updated


def test_an_old_database_is_replaced(tmp_path):
    out = tmp_path / "geo"
    out.mkdir()
    old = int(time.time()) - 20 * 86400
    build_mmdb(out / "GeoLite2-City.mmdb", "GeoLite2-City", CITY_RECORDS, build_epoch=old)

    result = update_database(
        "GeoLite2-City", out, ACCOUNT, KEY, client=_client(_serve(_archive(tmp_path)))
    )

    assert result.updated


def _seed_old_database(out):
    out.mkdir()
    old = int(time.time()) - 20 * 86400
    path = build_mmdb(out / "GeoLite2-City.mmdb", "GeoLite2-City", CITY_RECORDS, build_epoch=old)
    return path, path.read_bytes()


def test_wrong_edition_is_rejected_and_the_old_file_is_kept(tmp_path):
    out = tmp_path / "geo"
    path, before = _seed_old_database(out)
    wrong = _archive(tmp_path, "GeoLite2-ASN", ASN_RECORDS)

    with pytest.raises(GeoIPUpdateError, match="Expected a GeoLite2-City"):
        update_database("GeoLite2-City", out, ACCOUNT, KEY, client=_client(_serve(wrong)))

    assert path.read_bytes() == before


def test_corrupt_archive_keeps_the_old_file(tmp_path):
    out = tmp_path / "geo"
    path, before = _seed_old_database(out)

    with pytest.raises(GeoIPUpdateError, match="corrupt"):
        update_database(
            "GeoLite2-City", out, ACCOUNT, KEY, client=_client(_serve(b"definitely not a tarball"))
        )

    assert path.read_bytes() == before


def test_invalid_mmdb_inside_a_valid_archive_keeps_the_old_file(tmp_path):
    out = tmp_path / "geo"
    path, before = _seed_old_database(out)
    bogus = tmp_path / "bogus.mmdb"
    bogus.write_bytes(b"not a database")

    with pytest.raises(GeoIPUpdateError, match="not a valid MMDB"):
        update_database(
            "GeoLite2-City", out, ACCOUNT, KEY, client=_client(_serve(make_archive(bogus)))
        )

    assert path.read_bytes() == before


def test_archive_without_an_mmdb_is_rejected(tmp_path):
    readme = tmp_path / "README.txt"
    readme.write_text("hello")
    archive = make_archive(readme, member_name="GeoLite2-City_1/README.txt")

    with pytest.raises(GeoIPUpdateError, match=r"no \.mmdb"):
        update_database(
            "GeoLite2-City", tmp_path / "geo", ACCOUNT, KEY, client=_client(_serve(archive))
        )


def test_update_all_fetches_both_editions(tmp_path):
    city = _archive(tmp_path)
    asn = _archive(tmp_path, "GeoLite2-ASN", ASN_RECORDS)

    def handler(request):
        if request.url.host == "download.maxmind.com":
            edition = request.url.path.split("/")[3]
            return httpx.Response(
                302, headers={"location": f"https://storage.example.net/{edition}.tgz"}
            )
        return httpx.Response(200, content=city if "City" in request.url.path else asn)

    results = update_all(tmp_path / "geo", ACCOUNT, KEY, client=_client(handler))

    assert {r.edition for r in results} == {"GeoLite2-City", "GeoLite2-ASN"}
    assert all(r.updated for r in results)


# --- CLI -------------------------------------------------------------------


def test_cli_geoip_update_without_credentials_fails_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("MAXMIND_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("MAXMIND_LICENSE_KEY", raising=False)
    monkeypatch.setattr(cli, "load_env_file", lambda *a, **k: None)  # ignore a developer's .env

    code = cli.main(["geoip", "update", "--dir", str(tmp_path)])

    assert code == 1
    assert "MAXMIND_LICENSE_KEY" in capsys.readouterr().err


def test_cli_geoip_lookup_prints_the_result(tmp_path, capsys):
    build_mmdb(tmp_path / "GeoLite2-City.mmdb", "GeoLite2-City", CITY_RECORDS)

    code = cli.main(["geoip", "lookup", "8.8.8.8", "--dir", str(tmp_path)])

    assert code == 0
    assert "Mountain View" in capsys.readouterr().out


def test_cli_geoip_lookup_without_databases_explains_what_to_do(tmp_path, capsys):
    code = cli.main(["geoip", "lookup", "8.8.8.8", "--dir", str(tmp_path)])

    assert code == 1
    assert "geoip update" in capsys.readouterr().err
