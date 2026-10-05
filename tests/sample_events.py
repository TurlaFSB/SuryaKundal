"""Sample Cowrie events shared by the test modules.

They mirror a real session captured on the dev VM (session 051b29d11c6c),
trimmed to the fields the code reads. The source IP is a documentation address.
"""

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
HASSH = "eeca2460550b9ded084ecf2f70a75356"
CLIENT_VERSION = "SSH-2.0-OpenSSH_10.4p1"


def make_event(session, eventid, timestamp, **fields):
    return {
        "session": session,
        "src_ip": "203.0.113.7",
        "eventid": eventid,
        "timestamp": timestamp,
        **fields,
    }


SESSION_A_EVENTS = [
    make_event(SESSION_A, "cowrie.session.connect", T0),
    make_event(SESSION_A, "cowrie.client.version", T0, version=CLIENT_VERSION),
    make_event(SESSION_A, "cowrie.client.kex", T0, hassh=HASSH),
    make_event(SESSION_A, "cowrie.login.failed", T_FAIL, username="root", password="123456"),
    make_event(SESSION_A, "cowrie.login.success", T_OK, username="root", password="apple"),
    make_event(SESSION_A, "cowrie.command.input", T_CMD1, input="whoami"),
    make_event(SESSION_A, "cowrie.command.input", T_CMD2, input="cat /etc/passwd"),
    make_event(
        SESSION_A,
        "cowrie.session.file_download",
        T_DL,
        url="http://example.com/test/sh",
        shasum=SHA,
    ),
    make_event(SESSION_A, "cowrie.session.closed", T_END, duration_ms=72599),
]

SESSION_B_EVENTS = [
    make_event(SESSION_B, "cowrie.session.connect", T0),
    make_event(SESSION_B, "cowrie.login.failed", T_FAIL, username="admin", password="admin"),
    make_event(SESSION_B, "cowrie.session.closed", T_END, duration_ms=1500),
]
