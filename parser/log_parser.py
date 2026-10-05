import json
import logging
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


def read_events(log_path: Path):
    """Yield one parsed event (dict) per line of the Cowrie JSON log."""
    with log_path.open() as f:
        for line_number, line in enumerate(f, start=1):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed line %d", line_number)


def group_by_session(events):
    """Return {session_id: [event, event, ...]}."""
    sessions = defaultdict(list)
    for event in events:
        session_id = event.get("session")
        if session_id is None:
            logger.warning("Skipping event without a session ID: %s", event.get("eventid"))
            continue
        sessions[session_id].append(event)
    return sessions


def summarize(session_events):
    """Turn one session's events into a single summary dict."""
    summary = {"src_ip": None, "logins": [], "commands": []}
    for event in session_events:
        if summary["src_ip"] is None:
            summary["src_ip"] = event.get("src_ip")

        eventid = event.get("eventid")
        if eventid in ("cowrie.login.failed", "cowrie.login.success"):
            summary["logins"].append(
                {
                    "username": event.get("username"),
                    "password": event.get("password"),
                    "success": eventid == "cowrie.login.success",
                }
            )
        elif eventid == "cowrie.command.input":
            summary["commands"].append(event.get("input"))
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    path = Path.home() / "cowrie/var/log/cowrie/cowrie.json"
    for sid, evs in group_by_session(read_events(path)).items():
        print(sid, summarize(evs))
