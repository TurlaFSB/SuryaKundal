"""Tests for the Cowrie log parser.

The sample events are trimmed from a real session captured on the dev VM
(session 051b29d11c6c). They keep the fields the parser cares about.

Contract that summarize() must satisfy:
    {
        "src_ip":   str | None,
        "logins":   [{"username": str, "password": str, "success": bool}, ...],
        "commands": [str, ...],          # in the order they were typed
    }
"""

import json

from parser.log_parser import group_by_session, read_events, summarize

SESSION_A = "051b29d11c6c"
SESSION_B = "aaaaaaaaaaaa"


def _event(session, eventid, **fields):
    return {"session": session, "src_ip": "203.0.113.7", "eventid": eventid, **fields}


SESSION_A_EVENTS = [
    _event(SESSION_A, "cowrie.session.connect"),
    _event(SESSION_A, "cowrie.login.failed", username="root", password="123456"),
    _event(SESSION_A, "cowrie.login.success", username="root", password="apple"),
    _event(SESSION_A, "cowrie.command.input", input="whoami"),
    _event(SESSION_A, "cowrie.command.input", input="cat /etc/passwd"),
    _event(SESSION_A, "cowrie.session.closed", duration_ms=72599),
]


# --- read_events -----------------------------------------------------------


def test_read_events_yields_one_dict_per_line(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text("\n".join(json.dumps(e) for e in SESSION_A_EVENTS) + "\n")

    events = list(read_events(log))

    assert len(events) == len(SESSION_A_EVENTS)
    assert events[0]["eventid"] == "cowrie.session.connect"


def test_read_events_skips_malformed_lines(tmp_path):
    log = tmp_path / "cowrie.json"
    good = json.dumps(SESSION_A_EVENTS[0])
    log.write_text(f"{good}\n{{not valid json\n{good}\n")

    events = list(read_events(log))

    assert len(events) == 2


# --- group_by_session ------------------------------------------------------


def test_group_by_session_groups_events_by_session_id():
    events = SESSION_A_EVENTS + [_event(SESSION_B, "cowrie.session.connect")]

    grouped = group_by_session(events)

    assert set(grouped) == {SESSION_A, SESSION_B}
    assert len(grouped[SESSION_A]) == len(SESSION_A_EVENTS)
    assert len(grouped[SESSION_B]) == 1


def test_group_by_session_preserves_event_order():
    grouped = group_by_session(SESSION_A_EVENTS)

    ids = [e["eventid"] for e in grouped[SESSION_A]]

    assert ids == [e["eventid"] for e in SESSION_A_EVENTS]


# --- summarize -------------------------------------------------------------


def test_summarize_extracts_src_ip():
    assert summarize(SESSION_A_EVENTS)["src_ip"] == "203.0.113.7"


def test_summarize_collects_logins_with_success_flag():
    logins = summarize(SESSION_A_EVENTS)["logins"]

    assert logins == [
        {"username": "root", "password": "123456", "success": False},
        {"username": "root", "password": "apple", "success": True},
    ]


def test_summarize_collects_commands_in_order():
    assert summarize(SESSION_A_EVENTS)["commands"] == ["whoami", "cat /etc/passwd"]


def test_summarize_empty_session_returns_empty_collections():
    summary = summarize([])

    assert summary == {"src_ip": None, "logins": [], "commands": []}
