"""Reading and writing sessions. The caller owns the transaction (commit/rollback)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from surya_kundal.database.models import (
    Command,
    Download,
    HoneypotSession,
    IngestOffset,
    Login,
    TunnelRequest,
    Upload,
)
from surya_kundal.internal import is_internal

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
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError, TypeError):
        logger.warning("Ignoring malformed timestamp: %r", value)
        return None


def _as_port(value: Any) -> int:
    """A port number, or 0 when the log has something that is not one."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 0
    return port if 0 <= port <= 65535 else 0


def _earliest(a: datetime | None, b: datetime | None) -> datetime | None:
    present = [t for t in (a, b) if t is not None]
    return min(present) if present else None


def _latest(a: datetime | None, b: datetime | None) -> datetime | None:
    present = [t for t in (a, b) if t is not None]
    return max(present) if present else None


def save_session(db: Session, session_id: str, summary: dict[str, Any]) -> HoneypotSession:
    """Merge one session summary (from ``parser.log_parser.summarize``) into the database.

    The merge is additive and idempotent:

    - A session seen for the first time is created.
    - A session already stored is extended: events we have not seen are added,
      events we already have are ignored, and nothing is ever deleted or rewritten.

    That makes it safe to feed the same events twice, to feed a session in several
    pieces (a live tail, or a session split across a log rotation), or to feed only
    a partial view. Row IDs stay stable, so later tables can reference them.

    Events are identified by their natural key (timestamp plus content). Two
    identical events with the same timestamp collapse into one.
    """
    record = db.get(HoneypotSession, session_id)
    if record is None:
        record = HoneypotSession(id=session_id)
        db.add(record)

    if summary.get("src_ip") is not None:
        record.src_ip = summary["src_ip"]
        record.internal = is_internal(record.src_ip)
    if summary.get("client_version") is not None:
        record.client_version = summary["client_version"]
    if summary.get("hassh") is not None:
        record.hassh = summary["hassh"]
    if summary.get("duration_ms") is not None:
        record.duration_ms = summary["duration_ms"]
    record.start_time = _earliest(record.start_time, parse_timestamp(summary.get("start_time")))
    record.end_time = _latest(record.end_time, parse_timestamp(summary.get("end_time")))

    seen_logins = {(x.timestamp, x.username, x.password, x.success) for x in record.logins}
    for login in summary.get("logins", []):
        timestamp = parse_timestamp(login.get("timestamp"))
        username, password = login.get("username"), login.get("password")
        success = bool(login.get("success"))
        key = (timestamp, username, password, success)
        if key not in seen_logins:
            seen_logins.add(key)
            record.logins.append(
                Login(username=username, password=password, success=success, timestamp=timestamp)
            )

    seen_commands = {(x.timestamp, x.command) for x in record.commands}
    for command in summary.get("commands", []):
        text = command.get("command")
        if text is None:
            continue
        timestamp = parse_timestamp(command.get("timestamp"))
        if (timestamp, text) not in seen_commands:
            seen_commands.add((timestamp, text))
            record.commands.append(Command(command=text, timestamp=timestamp))

    seen_downloads = {(x.timestamp, x.url, x.sha256) for x in record.downloads}
    for download in summary.get("downloads", []):
        timestamp = parse_timestamp(download.get("timestamp"))
        url, sha256 = download.get("url"), download.get("sha256")
        if (timestamp, url, sha256) not in seen_downloads:
            seen_downloads.add((timestamp, url, sha256))
            record.downloads.append(Download(url=url, sha256=sha256, timestamp=timestamp))

    seen_uploads = {(x.timestamp, x.filename, x.sha256) for x in record.uploads}
    for upload in summary.get("uploads", []):
        timestamp = parse_timestamp(upload.get("timestamp"))
        filename, sha256 = upload.get("filename") or "", upload.get("sha256")
        if (timestamp, filename, sha256) not in seen_uploads:
            seen_uploads.add((timestamp, filename, sha256))
            record.uploads.append(
                Upload(
                    filename=filename,
                    destination=upload.get("destination"),
                    sha256=sha256,
                    timestamp=timestamp,
                )
            )

    seen_tunnels = {
        (x.timestamp, x.dst_ip, x.dst_port, x.orig_ip, x.orig_port) for x in record.tunnels
    }
    for tunnel in summary.get("tunnels", []):
        timestamp = parse_timestamp(tunnel.get("timestamp"))
        tunnel_key = (
            timestamp,
            tunnel.get("dst_ip") or "",
            _as_port(tunnel.get("dst_port")),
            tunnel.get("orig_ip") or "",
            _as_port(tunnel.get("orig_port")),
        )
        if tunnel_key not in seen_tunnels:
            seen_tunnels.add(tunnel_key)
            record.tunnels.append(
                TunnelRequest(
                    timestamp=tunnel_key[0],
                    dst_ip=tunnel_key[1],
                    dst_port=tunnel_key[2],
                    orig_ip=tunnel_key[3],
                    orig_port=tunnel_key[4],
                )
            )

    return record


def load_offset(db: Session, path: str) -> tuple[int, int] | None:
    """Return ``(inode, offset)`` saved for ``path``, if any."""
    row = db.get(IngestOffset, path)
    return (row.inode, row.offset) if row else None


def save_offset(db: Session, path: str, inode: int, offset: int) -> None:
    now = datetime.now(UTC)
    row = db.get(IngestOffset, path)
    if row is None:
        db.add(IngestOffset(path=path, inode=inode, offset=offset, updated_at=now))
    else:
        row.inode, row.offset, row.updated_at = inode, offset, now
