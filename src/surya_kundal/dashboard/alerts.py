"""Read Wazuh's alert log for the dashboard (optional, read-only).

``wazuh/export-alerts.sh`` copies the manager's Cowrie alerts into a JSON-lines file.
This module reads only the end of that file, so a large file costs nothing, and keeps
alerts raised by this project's rules (IDs from 100500).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

FIRST_RULE_ID = 100500
TAIL_BYTES = 512 * 1024


@dataclass(frozen=True)
class Alert:
    time: str
    level: int
    rule_id: int
    description: str
    techniques: tuple[str, ...]
    src_ip: str
    command: str


def _parse(line: str) -> Alert | None:
    try:
        raw = json.loads(line)
        rule = raw["rule"]
        rule_id = int(rule["id"])
        if rule_id < FIRST_RULE_ID:
            return None
        data = raw.get("data") or {}
        mitre = (rule.get("mitre") or {}).get("id") or []
        return Alert(
            time=str(raw.get("timestamp", "")),
            level=int(rule.get("level", 0)),
            rule_id=rule_id,
            description=str(rule.get("description", "")),
            techniques=tuple(str(m) for m in mitre),
            src_ip=str(data.get("src_ip", "")),
            command=str(data.get("input", "")),
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        return None  # a partial or foreign line is skipped, never fatal


def recent_alerts(path: Path | None, limit: int = 8) -> list[Alert]:
    """The newest ``limit`` project alerts, newest first; empty if the file is absent."""
    if path is None:
        return []
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - TAIL_BYTES))
            chunk = handle.read()
    except OSError:
        return []
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    if size > TAIL_BYTES:
        lines = lines[1:]  # the first line is probably cut in half
    found: list[Alert] = []
    for line in reversed(lines):
        alert = _parse(line)
        if alert is not None:
            found.append(alert)
            if len(found) >= limit:
                break
    return found
