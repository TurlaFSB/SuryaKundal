import json
import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse_event_line(line: str, line_number: int | None = None) -> dict | None:
    """Parse one line of the Cowrie JSON log into an event dict.

    Returns None for blank lines, malformed JSON, and JSON that is not an object,
    so a single bad line can never stop processing.
    """
    line = line.strip()
    if not line:
        return None
    where = f" {line_number}" if line_number is not None else ""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
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
        if session_id is None:
            logger.warning("Skipping event without a session ID: %s", event.get("eventid"))
            continue
        sessions[session_id].append(event)
    return sessions


def summarize(session_events: Iterable[dict]) -> dict[str, Any]:
    """Turn one session's events into a single summary dict."""
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
        timestamp = event.get("timestamp")
        if summary["src_ip"] is None:
            summary["src_ip"] = event.get("src_ip")
        if summary["start_time"] is None:
            summary["start_time"] = timestamp

        eventid = event.get("eventid")
        if eventid in ("cowrie.login.failed", "cowrie.login.success"):
            summary["logins"].append(
                {
                    "username": event.get("username"),
                    "password": event.get("password"),
                    "success": eventid == "cowrie.login.success",
                    "timestamp": timestamp,
                }
            )
        elif eventid == "cowrie.command.input":
            summary["commands"].append({"command": event.get("input"), "timestamp": timestamp})
        elif eventid == "cowrie.session.file_download":
            summary["downloads"].append(
                {
                    "url": event.get("url"),
                    "sha256": event.get("shasum"),
                    "timestamp": timestamp,
                }
            )
        elif eventid == "cowrie.session.file_upload":
            summary["uploads"].append(
                {
                    "filename": event.get("filename"),
                    "destination": event.get("destfile"),
                    "sha256": event.get("shasum"),
                    "timestamp": timestamp,
                }
            )
        elif eventid == "cowrie.direct-tcpip.request":
            summary["tunnels"].append(
                {
                    "dst_ip": event.get("dst_ip"),
                    "dst_port": event.get("dst_port"),
                    "orig_ip": event.get("orig_ip"),
                    "orig_port": event.get("orig_port"),
                    "timestamp": timestamp,
                }
            )
        elif eventid == "cowrie.client.version":
            summary["client_version"] = event.get("version")
        elif eventid == "cowrie.client.kex":
            summary["hassh"] = event.get("hassh")
        elif eventid == "cowrie.session.closed":
            summary["end_time"] = timestamp
            summary["duration_ms"] = event.get("duration_ms")
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    path = Path.home() / "cowrie/var/log/cowrie/cowrie.json"
    for sid, evs in group_by_session(read_events(path)).items():
        print(sid, summarize(evs))
