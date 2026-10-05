"""Reading and writing sessions. The caller owns the transaction (commit/rollback)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from surya_kundal.database.models import Command, Download, HoneypotSession, Login

logger = logging.getLogger(__name__)


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse a Cowrie ISO-8601 timestamp (e.g. ``2026-10-05T07:12:02.484294Z``) to UTC.

    Returns None for missing or malformed values instead of raising, so one bad
    timestamp does not cost us the whole session.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        logger.warning("Ignoring malformed timestamp: %r", value)
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def save_session(db: Session, session_id: str, summary: dict[str, Any]) -> HoneypotSession:
    """Store one session summary (the output of ``parser.log_parser.summarize``).

    Idempotent: saving the same session ID again replaces the earlier copy, so
    re-running an import never creates duplicates, and a session that was stored
    while still in progress is completed when its closing events arrive.
    """
    existing = db.get(HoneypotSession, session_id)
    if existing is not None:
        db.delete(existing)
        db.flush()

    record = HoneypotSession(
        id=session_id,
        src_ip=summary.get("src_ip"),
        start_time=parse_timestamp(summary.get("start_time")),
        end_time=parse_timestamp(summary.get("end_time")),
        duration_ms=summary.get("duration_ms"),
        client_version=summary.get("client_version"),
        hassh=summary.get("hassh"),
    )

    for login in summary.get("logins", []):
        record.logins.append(
            Login(
                username=login.get("username"),
                password=login.get("password"),
                success=bool(login.get("success")),
                timestamp=parse_timestamp(login.get("timestamp")),
            )
        )

    commands = [c for c in summary.get("commands", []) if c.get("command") is not None]
    for seq, command in enumerate(commands):
        record.commands.append(
            Command(
                seq=seq,
                command=command["command"],
                timestamp=parse_timestamp(command.get("timestamp")),
            )
        )

    for download in summary.get("downloads", []):
        record.downloads.append(
            Download(
                url=download.get("url"),
                sha256=download.get("sha256"),
                timestamp=parse_timestamp(download.get("timestamp")),
            )
        )

    db.add(record)
    return record
