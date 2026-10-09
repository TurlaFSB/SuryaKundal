"""IOC export: what gets listed, what must never be listed, and that every format is valid."""

import csv
import io
import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from surya_kundal import export as ioc
from surya_kundal.cli import main
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import (
    Command,
    Download,
    FileIntel,
    HoneypotSession,
    IpGeo,
    IpIntel,
    Login,
    TechniqueMatch,
    TunnelRequest,
    Upload,
)

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64


@pytest.fixture
def db_url(tmp_path):
    url = f"sqlite:///{tmp_path / 'ioc.db'}"
    engine = create_db_engine(url)
    init_db(engine)
    engine.dispose()
    return url


@pytest.fixture
def db(db_url):
    engine = create_db_engine(db_url)
    factory = make_session_factory(engine)
    with factory() as session:
        yield session


def add_session(
    db,
    sid,
    ip,
    *,
    days_ago=1,
    failed=0,
    ok=0,
    commands=0,
    downloads=(),
    uploads=(),
    tunnels=0,
    techniques=(),
):
    when = NOW - timedelta(days=days_ago)
    session = HoneypotSession(id=sid, src_ip=ip, start_time=when)
    db.add(session)
    db.flush()
    for n in range(failed):
        db.add(
            Login(
                session_id=sid,
                username="root",
                password=f"pw{n}",
                success=False,
                timestamp=when + timedelta(seconds=n),
            )
        )
    for _ in range(ok):
        db.add(
            Login(session_id=sid, username="root", password="toor", success=True, timestamp=when)
        )
    for n in range(commands):
        db.add(
            Command(session_id=sid, command=f"uname -{n}", timestamp=when + timedelta(seconds=n))
        )
    for url, sha in downloads:
        db.add(Download(session_id=sid, url=url, sha256=sha, timestamp=when))
    for name, sha in uploads:
        db.add(Upload(session_id=sid, filename=name, sha256=sha, timestamp=when))
    for n in range(tunnels):
        db.add(
            TunnelRequest(
                session_id=sid,
                dst_ip="9.9.9.9",
                dst_port=80 + n,
                orig_ip="127.0.0.1",
                orig_port=1,
                timestamp=when,
            )
        )
    for technique in techniques:
        db.add(
            TechniqueMatch(
                session_id=sid,
                command_id=None,
                technique_id=technique,
                tactics="discovery",
                rule_id="r",
                confidence="high",
                evidence="e",
            )
        )
    db.commit()


@pytest.fixture
def seeded(db):
    add_session(db, "s1", "11.22.33.44", failed=12)  # guessing
    add_session(db, "s2", "11.22.33.45", ok=1)  # access
    add_session(db, "s3", "11.22.33.46", ok=1, commands=2, techniques=("T1082", "T1078.001"))
    add_session(
        db, "s4", "11.22.33.47", ok=1, commands=1, downloads=[("http://evil.example/x.sh", SHA_A)]
    )
    add_session(db, "s5", "11.22.33.48", failed=2)  # contact
    add_session(db, "s6", "10.0.0.5", ok=1, commands=3)  # private
    add_session(db, "s7", "127.0.0.1", ok=1, commands=1)  # loopback
    return db


def collect(db, **kwargs):
    return ioc.collect(db, now=NOW, filters=ioc.Filters(**kwargs))


def by_value(indicators):
    return {item.value: item for item in indicators}


# --- which addresses are listed ---------------------------------------------------


def test_levels_follow_how_far_the_attacker_got(seeded):
    indicators, _ = collect(seeded, min_level="contact")
    levels = {i.value: i.level for i in indicators if i.is_address}
    assert levels == {
        "11.22.33.44": "guessing",
        "11.22.33.45": "access",
        "11.22.33.46": "hands-on",
        "11.22.33.47": "action",
        "11.22.33.48": "contact",
    }


def test_default_minimum_leaves_out_a_scan_that_barely_touched_us(seeded):
    indicators, _ = collect(seeded)
    assert "11.22.33.48" not in by_value(indicators)
    assert "11.22.33.44" in by_value(indicators)


def test_higher_minimum_keeps_only_the_deeper_attackers(seeded):
    indicators, _ = collect(seeded, min_level="hands-on", types=("ip",))
    assert {i.value for i in indicators} == {"11.22.33.46", "11.22.33.47"}


def test_private_and_local_addresses_are_never_listed_by_default(seeded):
    indicators, summary = collect(seeded, min_level="contact")
    values = {i.value for i in indicators}
    assert "10.0.0.5" not in values and "127.0.0.1" not in values
    assert summary.non_public == 2


def test_include_private_is_available_for_lab_testing(seeded):
    indicators, summary = collect(seeded, min_level="contact", include_private=True)
    assert {"10.0.0.5", "127.0.0.1"} <= {i.value for i in indicators}
    assert summary.non_public == 0


def test_allow_list_removes_your_own_addresses(seeded):
    exclude = ioc.parse_networks(["11.22.33.44/31", "# comment", "", "2001:db8::/32"])
    indicators, summary = collect(seeded, exclude=exclude)
    values = {i.value for i in indicators if i.is_address}
    assert "11.22.33.44" not in values and "11.22.33.45" not in values
    assert "11.22.33.46" in values
    assert summary.excluded == 2


def test_bad_allow_list_entry_is_reported_by_name():
    with pytest.raises(ValueError, match="not an address or network"):
        ioc.parse_networks(["10.0.0.0/8", "banana"])


def test_ipv4_inside_ipv6_is_listed_as_ipv4(db):
    add_session(db, "m1", "::ffff:11.22.33.99", ok=1)
    indicators, _ = collect(db, types=("ip",))
    assert [(i.kind, i.value) for i in indicators] == [("ipv4", "11.22.33.99")]


def test_ipv6_addresses_are_listed(db):
    add_session(db, "v6", "2606:4700:4700::1111", ok=1)
    indicators, _ = collect(db, types=("ip",))
    assert [(i.kind, i.value) for i in indicators] == [("ipv6", "2606:4700:4700::1111")]


def test_junk_in_the_address_column_is_counted_not_exported(db):
    add_session(db, "j1", "not-an-ip", ok=1)
    add_session(db, "j2", "11.22.33.50", ok=1)
    indicators, summary = collect(db, types=("ip",))
    assert [i.value for i in indicators] == ["11.22.33.50"]
    assert summary.invalid == 1


def test_window_drops_old_activity_but_first_seen_stays_the_first_ever(db):
    add_session(db, "old", "11.22.33.60", days_ago=200, ok=1)
    add_session(db, "new", "11.22.33.60", days_ago=2, ok=1)
    add_session(db, "ancient", "11.22.33.61", days_ago=90, ok=1)
    indicators, _ = collect(db, days=30, types=("ip",))
    values = by_value(indicators)
    assert "11.22.33.61" not in values
    assert values["11.22.33.60"].sessions == 1
    assert values["11.22.33.60"].first_seen == NOW - timedelta(days=200)
    assert values["11.22.33.60"].last_seen == NOW - timedelta(days=2)


def test_confidence_rises_with_depth_and_with_abuse_score(db):
    add_session(db, "c1", "11.22.33.70", ok=1, commands=1)
    add_session(db, "c2", "11.22.33.71", ok=1, commands=1)
    db.add(IpIntel(ip="11.22.33.71", provider="abuseipdb", fetched_at=NOW, score=80))
    db.add(IpIntel(ip="11.22.33.70", provider="abuseipdb", fetched_at=NOW, score=10))
    db.commit()
    values = by_value(collect(db, types=("ip",))[0])
    assert values["11.22.33.70"].confidence == 70
    assert values["11.22.33.71"].confidence == 80


def test_enrichment_and_techniques_travel_with_the_address(db):
    add_session(db, "e1", "11.22.33.80", ok=1, commands=1, techniques=("T1082", "T1082", "T1033"))
    db.add(
        IpGeo(
            ip="11.22.33.80",
            country_code="NL",
            asn=64500,
            as_org="Example Hosting",
            looked_up_at=NOW,
        )
    )
    db.add(IpIntel(ip="11.22.33.80", provider="tor", fetched_at=NOW, flagged=True))
    db.commit()
    item = by_value(collect(db, types=("ip",))[0])["11.22.33.80"]
    assert (item.country, item.asn, item.as_org, item.tor) == ("NL", 64500, "Example Hosting", True)
    assert item.techniques == ("T1033", "T1082")


def test_nothing_to_export_is_an_empty_list_not_an_error(db):
    indicators, summary = collect(db)
    assert indicators == [] and summary.counts == {}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"min_level": "bogus"}, "unknown level"),
        ({"days": 0}, "at least 1"),
        ({"types": ("x",)}, "unknown type"),
    ],
)
def test_bad_filters_are_refused(db, kwargs, message):
    with pytest.raises(ValueError, match=message):
        collect(db, **kwargs)


# --- files and URLs --------------------------------------------------------------


def test_files_are_listed_with_virustotal_confidence(db):
    add_session(db, "f1", "11.22.33.90", ok=1, downloads=[("http://x.example/a", SHA_A)])
    add_session(db, "f2", "11.22.33.91", ok=1, uploads=[("tool.bin", SHA_B)])
    db.add(
        FileIntel(
            sha256=SHA_A,
            provider="virustotal",
            fetched_at=NOW,
            found=True,
            malicious=40,
            engines=70,
            label="trojan",
        )
    )
    db.commit()
    values = by_value(collect(db, types=("file",))[0])
    assert values[SHA_A].confidence == 90 and values[SHA_A].vt_malicious == 40
    assert values[SHA_B].confidence == 60 and values[SHA_B].vt_engines is None
    assert "uploaded tool.bin" in values[SHA_B].detail


@pytest.mark.parametrize(("malicious", "expected"), [(5, 90), (1, 75), (0, 30)])
def test_virustotal_verdict_sets_file_confidence(db, malicious, expected):
    add_session(db, "f", "11.22.33.92", ok=1, downloads=[("http://x.example/a", SHA_A)])
    db.add(
        FileIntel(
            sha256=SHA_A,
            provider="virustotal",
            fetched_at=NOW,
            found=True,
            malicious=malicious,
            engines=70,
        )
    )
    db.commit()
    assert collect(db, types=("file",))[0][0].confidence == expected


def test_empty_file_and_malformed_hashes_are_not_listed(db):
    add_session(
        db,
        "f",
        "11.22.33.93",
        ok=1,
        downloads=[("http://x.example/e", ioc.EMPTY_SHA256), ("http://x.example/b", "not-a-hash")],
        uploads=[("ok.bin", SHA_A.upper())],
    )
    indicators, summary = collect(db, types=("file",))
    assert [i.value for i in indicators] == [SHA_A]  # upper-case input is normalised
    assert summary.invalid == 1


def test_same_file_seen_twice_is_one_indicator(db):
    add_session(
        db, "f1", "11.22.33.94", days_ago=3, ok=1, downloads=[("http://x.example/a", SHA_A)]
    )
    add_session(db, "f2", "11.22.33.95", days_ago=1, ok=1, uploads=[("a.bin", SHA_A)])
    indicators, _ = collect(db, types=("file",))
    assert len(indicators) == 1 and indicators[0].sessions == 2


@pytest.mark.parametrize(
    ("url", "good"),
    [
        ("http://evil.example/x.sh", True),
        ("https://203.0.114.9:8443/a?b=c", True),
        ("ftp://files.example/payload", True),
        ("http://8.8.8.8/x", True),
        ("http://localhost/x", False),
        ("http://127.0.0.1/x", False),
        ("http://192.168.1.5/x", False),
        ("http://box.internal/x", False),
        ("http://evil.example/a b", False),
        ("http://evil.example/\x1b[2J", False),
        ("http://evil.example/‮gpj.exe", False),
        ("javascript:alert(1)", False),
        ("file:///etc/passwd", False),
        ("http://", False),
        ("http://evil.example:99999/x", False),
        ("", False),
        ("http://evil.example/" + "a" * 3000, False),
    ],
)
def test_url_validation(url, good):
    assert ioc.valid_url(url) is good


def test_urls_are_listed_and_bad_ones_counted(db):
    add_session(
        db,
        "u1",
        "11.22.33.96",
        ok=1,
        downloads=[("http://evil.example/x.sh", SHA_A), ("http://localhost/y", SHA_B)],
    )
    indicators, summary = collect(db, types=("url",))
    assert [i.value for i in indicators] == ["http://evil.example/x.sh"]
    assert summary.invalid == 1


# --- CSV -------------------------------------------------------------------------


def parse_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_csv_has_the_documented_columns_and_one_row_per_indicator(seeded):
    indicators, _ = collect(seeded)
    rows = parse_csv(ioc.to_csv(indicators))
    assert tuple(rows[0]) == ioc.CSV_COLUMNS
    assert len(rows) == len(indicators)
    first = next(r for r in rows if r["value"] == "11.22.33.46")
    assert first["type"] == "ipv4" and first["level"] == "hands-on" and first["confidence"] == "70"
    assert first["techniques"] == "T1078.001 T1082"
    assert first["last_seen"].endswith("Z")


def test_csv_cells_cannot_start_a_spreadsheet_formula(db):
    add_session(db, "x", "11.22.33.97", ok=1)
    db.add(
        IpGeo(
            ip="11.22.33.97",
            country_code="US",
            as_org='=HYPERLINK("http://evil/","click")',
            looked_up_at=NOW,
        )
    )
    db.commit()
    row = parse_csv(ioc.to_csv(collect(db, types=("ip",))[0]))[0]
    assert row["as_org"].startswith("'=")


@pytest.mark.parametrize("value", ["=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd"])
def test_every_formula_trigger_is_neutralised(value):
    assert not ioc._cell(value).startswith(("=", "+", "-", "@", "\t", "\r"))


def test_csv_cells_show_control_characters_as_escapes(db):
    add_session(db, "x", "11.22.33.98", ok=1, uploads=[("a\x1b[2Jb‮c.bin", SHA_A)])
    text = ioc.to_csv(collect(db, types=("file",))[0])
    assert "\x1b" not in text and "‮" not in text
    assert "\\x1b" in text


# --- STIX ------------------------------------------------------------------------


def stix(indicators, now=NOW, **filters):
    return ioc.to_stix(indicators, now=now, filters=ioc.Filters(**filters))


def test_stix_bundle_has_an_identity_and_an_indicator_per_value(seeded):
    indicators, _ = collect(seeded)
    bundle = stix(indicators)
    kinds = [o["type"] for o in bundle["objects"]]
    assert bundle["type"] == "bundle" and kinds[0] == "identity"
    assert kinds.count("indicator") == len(indicators)
    json.dumps(bundle)  # serialisable


def test_stix_patterns_by_kind(db):
    add_session(
        db,
        "p",
        "11.22.33.100",
        ok=1,
        downloads=[("http://evil.example/x.sh", SHA_A)],
    )
    add_session(db, "p6", "2606:4700:4700::1111", ok=1)
    patterns = {o["pattern"] for o in stix(collect(db)[0])["objects"] if o["type"] == "indicator"}
    assert patterns == {
        "[ipv4-addr:value = '11.22.33.100']",
        "[ipv6-addr:value = '2606:4700:4700::1111']",
        f"[file:hashes.'SHA-256' = '{SHA_A}']",
        "[url:value = 'http://evil.example/x.sh']",
    }


def test_stix_pattern_strings_are_escaped(db):
    add_session(db, "q", "11.22.33.101", ok=1, downloads=[("http://evil.example/a'b\\c", SHA_A)])
    patterns = [
        o["pattern"]
        for o in stix(collect(db, types=("url",))[0])["objects"]
        if o["type"] == "indicator"
    ]
    assert patterns == ["[url:value = 'http://evil.example/a\\'b\\\\c']"]


def test_stix_ids_are_stable_so_importers_update_instead_of_duplicating(seeded):
    indicators, _ = collect(seeded)
    first = stix(indicators)
    later = stix(indicators, now=NOW + timedelta(days=1))
    ids = lambda bundle: [o["id"] for o in bundle["objects"] if o["type"] == "indicator"]  # noqa: E731
    assert ids(first) == ids(later)
    assert first["id"] != later["id"]
    created = lambda bundle: [o["created"] for o in bundle["objects"]]  # noqa: E731
    assert created(first) == created(later)  # creation time never moves
    assert [o["modified"] for o in later["objects"][1:]] > [
        o["modified"] for o in first["objects"][1:]
    ]


def test_stix_expiry_matches_the_window_and_files_do_not_expire(db):
    add_session(
        db, "e", "11.22.33.102", days_ago=5, ok=1, downloads=[("http://evil.example/x", SHA_A)]
    )
    objects = [
        o for o in stix(collect(db, days=30)[0], days=30)["objects"] if o["type"] == "indicator"
    ]
    by_pattern = {o["pattern"]: o for o in objects}
    ip = by_pattern["[ipv4-addr:value = '11.22.33.102']"]
    assert ip["valid_until"] == (NOW - timedelta(days=5) + timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )
    assert "valid_until" not in by_pattern[f"[file:hashes.'SHA-256' = '{SHA_A}']"]
    assert all(o["valid_until"] > o["valid_from"] for o in objects if "valid_until" in o)


def test_stix_links_attack_techniques_with_correct_urls(seeded):
    item = next(
        o
        for o in stix(collect(seeded)[0])["objects"]
        if o["type"] == "indicator" and "11.22.33.46" in o["pattern"]
    )
    refs = {r["external_id"]: r["url"] for r in item["external_references"]}
    assert refs == {
        "T1078.001": "https://attack.mitre.org/techniques/T1078/001/",
        "T1082": "https://attack.mitre.org/techniques/T1082/",
    }


def test_stix_marks_shared_tor_exits_in_the_description(db):
    add_session(db, "t", "11.22.33.103", ok=1)
    db.add(IpIntel(ip="11.22.33.103", provider="tor", fetched_at=NOW, flagged=True))
    db.commit()
    objects = stix(collect(db)[0])["objects"]
    assert "Tor exit node" in objects[1]["description"]


def test_stix_bundle_passes_the_reference_validator(seeded):
    stix2 = pytest.importorskip("stix2")
    indicators, _ = collect(seeded, include_private=False)
    parsed = stix2.parse(json.dumps(stix(indicators)), allow_custom=False)
    assert len(parsed.objects) == len(indicators) + 1


def test_empty_stix_bundle_is_still_a_bundle():
    bundle = stix([])
    assert [o["type"] for o in bundle["objects"]] == ["identity"]


# --- blocklist and nftables --------------------------------------------------------


def test_blocklist_lists_only_addresses_sorted_numerically(seeded):
    indicators, _ = collect(seeded)
    text = ioc.to_blocklist(indicators, now=NOW, filters=ioc.Filters())
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    assert lines == ["11.22.33.44", "11.22.33.45", "11.22.33.46", "11.22.33.47"]
    assert text.startswith("# Surya Kundal blocklist")


def test_blocklist_sorts_ten_after_nine_not_after_one(db):
    for n, sid in ((9, "a"), (10, "b"), (100, "c")):
        add_session(db, sid, f"11.22.34.{n}", ok=1)
    text = ioc.to_blocklist(collect(db)[0], now=NOW, filters=ioc.Filters())
    assert [line for line in text.splitlines() if not line.startswith("#")] == [
        "11.22.34.9",
        "11.22.34.10",
        "11.22.34.100",
    ]


def test_nftables_entries_expire_with_the_window(db):
    add_session(db, "n1", "11.22.33.110", days_ago=10, ok=1)
    add_session(db, "n6", "2606:4700:4700::1111", days_ago=1, ok=1)
    filters = ioc.Filters(days=30)
    text = ioc.to_nftables(collect(db, days=30)[0], now=NOW, filters=filters)
    assert "add table inet surya_kundal" in text
    assert f"11.22.33.110 timeout {20 * 86400}s" in text
    assert f"2606:4700:4700::1111 timeout {29 * 86400}s" in text
    assert text.count("flush set") == 2  # reloading replaces the contents


def test_nftables_never_sets_a_timeout_under_a_minute(db):
    add_session(db, "n", "11.22.33.111", days_ago=29.9999, ok=1)  # type: ignore[arg-type]
    text = ioc.to_nftables(collect(db, days=30)[0], now=NOW, filters=ioc.Filters(days=30))
    assert "timeout 60s" in text or "timeout 8" in text


def test_nftables_with_no_addresses_still_loads(db):
    text = ioc.to_nftables([], now=NOW, filters=ioc.Filters())
    assert "add element" not in text and "add table" in text


@pytest.mark.skipif(shutil.which("nft") is None, reason="nft is not installed")
def test_nftables_script_is_accepted_by_the_real_nft(db, tmp_path):
    for n in range(1, 1200):  # more than one element line
        add_session(db, f"b{n}", f"11.22.{n // 250 + 40}.{n % 250 + 1}", ok=1)
    add_session(db, "six", "2606:4700:4700::1111", ok=1)
    script = tmp_path / "block.nft"
    script.write_text(ioc.to_nftables(collect(db)[0], now=NOW, filters=ioc.Filters()))
    nft = shutil.which("nft")
    assert nft is not None
    result = subprocess.run(  # noqa: S603  (fixed command, a file this test wrote)
        [nft, "-c", "-f", str(script)], capture_output=True, text=True, timeout=60, check=False
    )
    if "Operation not permitted" in result.stderr or "Permission denied" in result.stderr:
        pytest.skip("nft needs privileges that this environment does not give")
    assert result.returncode == 0, result.stderr


# --- writing files -----------------------------------------------------------------


def test_atomic_write_leaves_no_temp_files_and_sets_readable_mode(tmp_path):
    target = tmp_path / "out" / "iocs.csv"
    ioc.write_atomically(target, "a,b\n")
    assert target.read_text() == "a,b\n"
    assert target.stat().st_mode & 0o777 == 0o644
    assert [p.name for p in target.parent.iterdir()] == ["iocs.csv"]


def test_atomic_write_keeps_the_old_file_when_the_write_fails(tmp_path):
    target = tmp_path / "iocs.csv"
    target.write_text("old")
    with pytest.raises(UnicodeEncodeError):
        ioc.write_atomically(target, "bad \ud800")
    assert target.read_text() == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["iocs.csv"]


# --- the command ---------------------------------------------------------------------


@pytest.fixture
def cli_db(db_url):
    engine = create_db_engine(db_url)
    with make_session_factory(engine)() as session:
        add_session(session, "c1", "11.22.33.44", ok=1, commands=2, techniques=("T1082",))
        add_session(session, "c2", "10.0.0.9", ok=1)
        add_session(session, "c3", "11.22.33.55", failed=11)
    engine.dispose()
    return db_url


def test_command_writes_csv_to_stdout_and_a_summary_to_stderr(cli_db, capsys):
    assert main(["export", "--db", cli_db]) == 0
    out, err = capsys.readouterr()
    assert out.splitlines()[0].startswith("type,value,")
    assert "11.22.33.44" in out and "10.0.0.9" not in out
    assert "Exported 2 indicator(s) (2 ipv4)." in err
    assert "1 private or local address(es)" in err


def test_command_writes_a_file(cli_db, tmp_path, capsys):
    target = tmp_path / "out.json"
    assert main(["export", "--db", cli_db, "--format", "stix", "--output", str(target)]) == 0
    bundle = json.loads(target.read_text())
    assert bundle["type"] == "bundle"
    assert capsys.readouterr().out == ""


def test_command_blocklist_uses_addresses_only(cli_db, capsys):
    assert main(["export", "--db", cli_db, "--format", "blocklist", "--types", "file"]) == 0
    out = capsys.readouterr().out
    assert "11.22.33.44" in out  # the type filter does not apply to a blocklist


@pytest.mark.parametrize("fmt", ["blocklist", "nftables"])
def test_command_refuses_private_addresses_in_a_blocklist(cli_db, fmt, capsys):
    assert main(["export", "--db", cli_db, "--format", fmt, "--include-private"]) == 2
    assert "never" in capsys.readouterr().err


def test_command_include_private_works_for_csv(cli_db, capsys):
    assert main(["export", "--db", cli_db, "--include-private", "--min-level", "access"]) == 0
    assert "10.0.0.9" in capsys.readouterr().out


def test_command_exclude_flag_and_file(cli_db, tmp_path, capsys):
    allow = tmp_path / "mine.txt"
    allow.write_text("# my servers\n11.22.33.55\n")
    code = main(
        ["export", "--db", cli_db, "--exclude", "11.22.33.44", "--exclude-file", str(allow)]
    )
    out, err = capsys.readouterr()
    assert code == 0 and "11.22.33" not in out
    assert "Exported 0 indicator(s)." in err and "2 excluded" in err


def test_command_reports_a_bad_exclude_entry(cli_db, capsys):
    assert main(["export", "--db", cli_db, "--exclude", "banana"]) == 2
    assert "not an address or network" in capsys.readouterr().err


def test_command_reports_an_unreadable_exclude_file(cli_db, tmp_path, capsys):
    assert main(["export", "--db", cli_db, "--exclude-file", str(tmp_path / "missing")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_command_reports_bad_filters(cli_db, capsys):
    assert main(["export", "--db", cli_db, "--days", "0"]) == 2
    assert "at least 1" in capsys.readouterr().err
    assert main(["export", "--db", cli_db, "--types", "ip,banana"]) == 2


def test_command_does_not_create_a_missing_database(tmp_path, capsys):
    missing = tmp_path / "nope.db"
    assert main(["export", "--db", f"sqlite:///{missing}"]) == 2
    assert "does not exist" in capsys.readouterr().err
    assert not missing.exists()


def test_command_reports_a_database_without_tables(tmp_path, capsys):
    import sqlite3

    path = tmp_path / "empty.db"
    sqlite3.connect(path).close()
    assert main(["export", "--db", f"sqlite:///{path}"]) == 2
    assert "could not read the database" in capsys.readouterr().err


def test_command_never_writes_to_the_database(cli_db, tmp_path):
    path = tmp_path / "ioc.db"
    before = path.read_bytes()
    assert main(["export", "--db", cli_db, "--min-level", "contact"]) == 0
    assert path.read_bytes() == before


def test_min_confidence_drops_weak_indicators(seeded):
    everything, _ = collect(seeded, min_level="contact")
    strong, _ = collect(seeded, min_level="contact", min_confidence=60)
    assert {i.value for i in strong} == {
        "11.22.33.46",
        "11.22.33.47",
        "http://evil.example/x.sh",
        SHA_A,
    }
    assert len(strong) < len(everything)
    assert all(i.confidence >= 60 for i in strong)


@pytest.mark.parametrize("bad", [-1, 101])
def test_min_confidence_must_be_a_percentage(db, bad):
    with pytest.raises(ValueError, match="between 0 and 100"):
        collect(db, min_confidence=bad)


def test_command_min_confidence(cli_db, capsys):
    assert main(["export", "--db", cli_db, "--min-confidence", "60"]) == 0
    out = capsys.readouterr().out
    assert "11.22.33.44" in out and "11.22.33.55" not in out
