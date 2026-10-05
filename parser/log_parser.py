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
        # TODO 1: append the event to the list for its session ID
        pass
    return sessions


def summarize(session_events):
    """Turn one session's events into a single summary dict."""
    summary = {"src_ip": None, "logins": [], "commands": []}
    for event in session_events:
        # TODO 2: fill src_ip, and append to logins / commands
        # based on event["eventid"]
        pass
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    path = Path.home() / "cowrie/var/log/cowrie/cowrie.json"
    for sid, evs in group_by_session(read_events(path)).items():
        print(sid, summarize(evs))
