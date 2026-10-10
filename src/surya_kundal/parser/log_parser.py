import ipaddress
import json
import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Everything below is attacker-controlled text, so every field is checked and bounded here, once,
# before it can reach the database: wrong types become None, long text is cut, and one session
# cannot grow without limit.
MAX_LINE_LENGTH = 2_000_000
MAX_COMMAND = 20_000
MAX_CREDENTIAL = 256
MAX_URL = 2_000
MAX_NAME = 1_024
MAX_BANNER = 512
MAX_COMMANDS = 2_000
MAX_LOGINS = 500
MAX_TRANSFERS = 200
MAX_DURATION_MS = 10**12


def parse_event_line(line: str, line_number: int | None = None) -> dict | None:
    """Parse one line of the Cowrie JSON log into an event dict.

    Returns None for blank lines, malformed JSON, and JSON that is not an object,
    so a single bad line can never stop processing.
    """
    line = line.strip()
    if not line:
        return None
    where = f" {line_number}" if line_number is not None else ""
    if len(line) > MAX_LINE_LENGTH:
        logger.warning("Skipping oversized line%s (%d characters)", where, len(line))
        return None
    try:
        event = json.loads(line)
    except (ValueError, RecursionError):  # includes JSONDecodeError and digit-flood numbers
        logger.warning("Skipping malformed line%s", where)
        return None
    if not isinstance(event, dict):
        logger.warning("Skipping non-object JSON on line%s", where)
        return None
    return event


def read_events(log_path: Path) -> Iterator[dict]:
    """Yield one parsed event (dict) per line of the Cowrie JSON log."""
    with log_path.open(encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            event = parse_event_line(line, line_number)
            if event is not None:
                yield event


def group_by_session(events: Iterable[dict]) -> dict[str, list[dict]]:
    """Return {session_id: [event, event, ...]}."""
    sessions: defaultdict[str, list[dict]] = defaultdict(list)
    for event in events:
        session_id = event.get("session")
        if not isinstance(session_id, str) or not session_id:
            logger.warning("Skipping event without a usable session ID: %r", event.get("eventid"))
            continue
        sessions[session_id].append(event)
    return sessions


def _text(value: Any, limit: int) -> str | None:
    """A string cut to ``limit`` characters; anything that is not text is dropped.

    NUL characters and lone surrogates are replaced, because SQLite text and JSON exports
    cannot carry them reliably.
    """
    if not isinstance(value, str):
        return None
    cleaned = value.replace("\x00", "\ufffd")
    try:
        cleaned.encode("utf-8")
    except UnicodeEncodeError:
        cleaned = cleaned.encode("utf-8", errors="replace").decode("utf-8")
    return cleaned[:limit]


def _address(value: Any) -> str | None:
    """A plain IPv4 or IPv6 address, or None (scope IDs such as ``%eth0`` are refused)."""
    if not isinstance(value, str) or "%" in value or len(value) > 45:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | str):
        return None
    try:
        port = int(value)
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def _duration(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if value != value or value < 0 or value > MAX_DURATION_MS:  # NaN, negative, absurd
        return None
    return int(value)


def summarize(session_events: Iterable[dict]) -> dict[str, Any]:
    """Turn one session's events into a single summary dict (bounded and type-checked)."""
    summary: dict[str, Any] = {
        "src_ip": None,
        "start_time": None,
        "end_time": None,
        "duration_ms": None,
        "client_version": None,
        "hassh": None,
        "logins": [],
        "commands": [],
        "downloads": [],
        "uploads": [],
        "tunnels": [],
    }
    for event in session_events:
        timestamp = _text(event.get("timestamp"), 64)
        if summary["src_ip"] is None:
            summary["src_ip"] = _address(event.get("src_ip"))
        if summary["start_time"] is None:
            summary["start_time"] = timestamp

        eventid = event.get("eventid")
        if eventid in ("cowrie.login.failed", "cowrie.login.success"):
            if len(summary["logins"]) < MAX_LOGINS:
                summary["logins"].append(
                    {
                        "username": _text(event.get("username"), MAX_CREDENTIAL),
                        "password": _text(event.get("password"), MAX_CREDENTIAL),
                        "success": eventid == "cowrie.login.success",
                        "timestamp": timestamp,
                    }
                )
        elif eventid == "cowrie.command.input":
            if len(summary["commands"]) < MAX_COMMANDS:
                summary["commands"].append(
                    {"command": _text(event.get("input"), MAX_COMMAND), "timestamp": timestamp}
                )
        elif eventid == "cowrie.session.file_download":
            # Cowrie also logs this event when a command redirects output into a file
            # (``echo x > f``): no address, so nothing was downloaded from anywhere.
            url = _text(event.get("url"), MAX_URL)
            if url and len(summary["downloads"]) < MAX_TRANSFERS:
                summary["downloads"].append(
                    {
                        "url": url,
                        "sha256": _text(event.get("shasum"), 64),
                        "timestamp": timestamp,
                    }
                )
        elif eventid == "cowrie.session.file_upload":
            if len(summary["uploads"]) < MAX_TRANSFERS:
                summary["uploads"].append(
                    {
                        "filename": _text(event.get("filename"), MAX_NAME),
                        "destination": _text(event.get("destfile"), MAX_NAME),
                        "sha256": _text(event.get("shasum"), 64),
                        "timestamp": timestamp,
                    }
                )
        elif eventid == "cowrie.direct-tcpip.request":
            if len(summary["tunnels"]) < MAX_TRANSFERS:
                summary["tunnels"].append(
                    {
                        "dst_ip": _text(event.get("dst_ip"), 255),
                        "dst_port": _port(event.get("dst_port")),
                        "orig_ip": _text(event.get("orig_ip"), 255),
                        "orig_port": _port(event.get("orig_port")),
                        "timestamp": timestamp,
                    }
                )
        elif eventid == "cowrie.client.version":
            summary["client_version"] = _text(event.get("version"), MAX_BANNER)
        elif eventid == "cowrie.client.kex":
            summary["hassh"] = _text(event.get("hassh"), 32)
        elif eventid == "cowrie.session.closed":
            summary["end_time"] = timestamp
            summary["duration_ms"] = _duration(event.get("duration_ms"))
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    path = Path.home() / "cowrie/var/log/cowrie/cowrie.json"
    for sid, evs in group_by_session(read_events(path)).items():
        print(sid, summarize(evs))
