"""Tests for the Cowrie log parser.

The sample events mirror a real session captured on the dev VM
(session 051b29d11c6c), trimmed to the fields the parser reads.

Contract that summarize() must satisfy:
    {
        "src_ip":         str | None,
        "start_time":     str | None,    # timestamp of the first event
        "end_time":       str | None,    # timestamp of cowrie.session.closed
        "duration_ms":    int | None,    # from cowrie.session.closed
        "client_version": str | None,    # from cowrie.client.version
        "hassh":          str | None,    # from cowrie.client.kex
        "logins":    [{"username", "password", "success": bool, "timestamp"}, ...],
        "commands":  [{"command", "timestamp"}, ...],        # in typed order
        "downloads": [{"url", "sha256", "timestamp"}, ...],
    }
"""

import json

from surya_kundal.parser.log_parser import group_by_session, read_events, summarize

SESSION_A = "051b29d11c6c"
SESSION_B = "aaaaaaaaaaaa"

T0 = "2026-10-05T07:11:23.959011Z"
T_FAIL = "2026-10-05T07:11:37.065293Z"
T_OK = "2026-10-05T07:11:53.466838Z"
T_CMD1 = "2026-10-05T07:12:02.484294Z"
T_CMD2 = "2026-10-05T07:12:13.200027Z"
T_DL = "2026-10-05T07:12:30.667343Z"
T_END = "2026-10-05T07:12:36.563805Z"

SHA = "25ddf2c883e0d1958ea971d279a7e4f0fd446724ee3db7db19dadabd4a62e484"


def _event(session, eventid, timestamp, **fields):
    return {
        "session": session,
        "src_ip": "203.0.113.7",
        "eventid": eventid,
        "timestamp": timestamp,
        **fields,
    }


SESSION_A_EVENTS = [
    _event(SESSION_A, "cowrie.session.connect", T0),
    _event(SESSION_A, "cowrie.client.version", T0, version="SSH-2.0-OpenSSH_10.4p1"),
    _event(SESSION_A, "cowrie.client.kex", T0, hassh="eeca2460550b9ded084ecf2f70a75356"),
    _event(SESSION_A, "cowrie.login.failed", T_FAIL, username="root", password="123456"),
    _event(SESSION_A, "cowrie.login.success", T_OK, username="root", password="apple"),
    _event(SESSION_A, "cowrie.command.input", T_CMD1, input="whoami"),
    _event(SESSION_A, "cowrie.command.input", T_CMD2, input="cat /etc/passwd"),
    _event(
        SESSION_A,
        "cowrie.session.file_download",
        T_DL,
        url="http://example.com/test/sh",
        shasum=SHA,
    ),
    _event(SESSION_A, "cowrie.session.closed", T_END, duration_ms=72599),
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
    events = SESSION_A_EVENTS + [_event(SESSION_B, "cowrie.session.connect", T0)]

    grouped = group_by_session(events)

    assert set(grouped) == {SESSION_A, SESSION_B}
    assert len(grouped[SESSION_A]) == len(SESSION_A_EVENTS)
    assert len(grouped[SESSION_B]) == 1


def test_group_by_session_preserves_event_order():
    grouped = group_by_session(SESSION_A_EVENTS)

    ids = [e["eventid"] for e in grouped[SESSION_A]]

    assert ids == [e["eventid"] for e in SESSION_A_EVENTS]


def test_group_by_session_skips_events_without_session_id():
    orphan = {"eventid": "cowrie.session.connect", "timestamp": T0}

    grouped = group_by_session([orphan] + SESSION_A_EVENTS)

    assert set(grouped) == {SESSION_A}


# --- summarize -------------------------------------------------------------


def test_summarize_extracts_src_ip():
    assert summarize(SESSION_A_EVENTS)["src_ip"] == "203.0.113.7"


def test_summarize_collects_logins_with_success_flag_and_timestamp():
    logins = summarize(SESSION_A_EVENTS)["logins"]

    assert logins == [
        {"username": "root", "password": "123456", "success": False, "timestamp": T_FAIL},
        {"username": "root", "password": "apple", "success": True, "timestamp": T_OK},
    ]


def test_summarize_collects_commands_in_order_with_timestamps():
    commands = summarize(SESSION_A_EVENTS)["commands"]

    assert commands == [
        {"command": "whoami", "timestamp": T_CMD1},
        {"command": "cat /etc/passwd", "timestamp": T_CMD2},
    ]


def test_summarize_collects_file_downloads():
    downloads = summarize(SESSION_A_EVENTS)["downloads"]

    assert downloads == [{"url": "http://example.com/test/sh", "sha256": SHA, "timestamp": T_DL}]


def test_summarize_extracts_session_timing():
    summary = summarize(SESSION_A_EVENTS)

    assert summary["start_time"] == T0
    assert summary["end_time"] == T_END
    assert summary["duration_ms"] == 72599


def test_summarize_extracts_client_fingerprints():
    summary = summarize(SESSION_A_EVENTS)

    assert summary["client_version"] == "SSH-2.0-OpenSSH_10.4p1"
    assert summary["hassh"] == "eeca2460550b9ded084ecf2f70a75356"


def test_summarize_unfinished_session_has_no_end_time():
    unfinished = [e for e in SESSION_A_EVENTS if e["eventid"] != "cowrie.session.closed"]

    summary = summarize(unfinished)

    assert summary["end_time"] is None
    assert summary["duration_ms"] is None


def test_summarize_empty_session_returns_empty_collections():
    summary = summarize([])

    assert summary == {
        "src_ip": None,
        "start_time": None,
        "end_time": None,
        "duration_ms": None,
        "client_version": None,
        "hassh": None,
        "logins": [],
        "commands": [],
        "downloads": [],
    }
