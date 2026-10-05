"""Property-based tests: attacker-controlled input must never break the pipeline.

Hypothesis generates thousands of odd inputs (control characters, huge strings, broken
JSON, lone surrogates) and checks properties that must hold for all of them.
"""

import json
import unicodedata

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import func, select

from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import Command, HoneypotSession, Login
from surya_kundal.ingest import store_events
from surya_kundal.mapping.engine import map_command, map_logins, normalize_segment, split_commands
from surya_kundal.parser.log_parser import parse_event_line, summarize
from surya_kundal.textsafe import printable

FAST = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# Text biased towards the characters shells and terminals treat specially.
shell_text = st.text(
    alphabet=st.sampled_from(
        list("abc xyz;|&$()`'\"\\<>*?~#!{}[]=-_/.\n\t\r\x1b\x00\u202e0123456789")
    ),
    max_size=300,
)
any_text = st.text(max_size=300)


@FAST
@given(any_text)
def test_parse_event_line_never_raises_and_only_returns_dicts(line):
    result = parse_event_line(line)

    assert result is None or isinstance(result, dict)


@FAST
@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(),
        lambda c: st.lists(c) | st.dictionaries(st.text(), c),
        max_leaves=20,
    )
)
def test_valid_json_of_any_shape_is_handled(value):
    result = parse_event_line(json.dumps(value))

    assert result is None or isinstance(result, dict)


@FAST
@given(shell_text)
def test_command_splitting_never_raises_and_returns_clean_segments(command):
    segments = split_commands(command)

    assert all(segment == segment.strip() and segment for segment in segments)
    assert all(isinstance(normalize_segment(segment), str) for segment in segments)


@FAST
@given(shell_text | any_text)
def test_mapping_never_raises_and_returns_real_matches(command):
    for match in map_command(command):
        assert match.technique.startswith("T")
        assert match.confidence in ("low", "medium", "high")
        assert len(match.evidence) <= 300


@FAST
@given(
    st.lists(st.fixed_dictionaries({"username": st.none() | st.text(), "success": st.booleans()}))
)
def test_login_mapping_never_raises(logins):
    for match in map_logins(logins):
        assert match.technique in {"T1110.001", "T1078", "T1078.001"}


@FAST
@given(st.text(max_size=500))
def test_printable_output_never_contains_a_control_character(text):
    shown = printable(text)

    assert all(unicodedata.category(ch)[0] != "C" for ch in shown)


@FAST
@given(st.text(max_size=100), st.text(max_size=100))
def test_printable_is_idempotent_on_its_own_output(a, b):
    once = printable(a + b)

    assert printable(once) == once


event_text = st.text(max_size=80).filter(lambda t: "\x00" not in t)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(event_text, min_size=0, max_size=6), st.lists(event_text, min_size=0, max_size=6))
def test_storing_the_same_events_twice_equals_storing_them_once(commands, passwords):
    stamp = "2026-10-05T07:11:{:02d}.000000Z"
    events = [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "45.33.32.156",
         "timestamp": stamp.format(0)},
    ]  # fmt: skip
    for i, text in enumerate(commands):
        events.append(
            {"eventid": "cowrie.command.input", "session": "s1", "input": text,
             "timestamp": stamp.format(i + 1)}
        )  # fmt: skip
    for i, text in enumerate(passwords):
        events.append(
            {"eventid": "cowrie.login.failed", "session": "s1", "username": "root",
             "password": text, "timestamp": stamp.format(i + 20)}
        )  # fmt: skip
    engine = create_db_engine("sqlite://")
    init_db(engine)
    try:
        with make_session_factory(engine)() as db:
            store_events(db, events)
            db.commit()
            first = _counts(db)
            store_events(db, events)
            db.commit()

            assert _counts(db) == first
            assert summarize(events)["src_ip"] == "45.33.32.156"
    finally:
        engine.dispose()


def _counts(db):
    return tuple(
        db.scalar(select(func.count()).select_from(model))
        for model in (HoneypotSession, Command, Login)
    )
