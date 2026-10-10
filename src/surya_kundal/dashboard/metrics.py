"""Prometheus metrics for the dashboard: counts and freshness, nothing an attacker typed.

Every value is a number, and the only label is the program version, so hostile text in the data
can never reach the output. The endpoint sits behind the same password as the rest of the
dashboard; Prometheus can scrape it with ``basic_auth`` (any username, the token as password).
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from surya_kundal import __version__
from surya_kundal.dashboard import queries
from surya_kundal.database.models import Campaign

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def collect(db: Session) -> dict[str, float]:
    """The numbers behind /metrics. Missing data is reported as zero, never as an error."""
    values: dict[str, float] = {
        "sessions": 0,
        "source_ips": 0,
        "accepted_logins": 0,
        "commands": 0,
        "files": 0,
        "campaigns": 0,
        "last_session_timestamp_seconds": 0,
        "database_size_bytes": 0,
    }
    if queries.has_data(db):
        totals = queries.totals(db)
        values.update(
            sessions=totals.sessions,
            source_ips=totals.sources,
            accepted_logins=totals.accepted_logins,
            commands=totals.commands,
            files=totals.files,
        )
        if totals.last_event is not None:
            values["last_session_timestamp_seconds"] = totals.last_event.timestamp()
    try:
        values["campaigns"] = int(db.scalar(select(func.count()).select_from(Campaign)) or 0)
    except OperationalError:  # database not migrated to the campaigns table yet
        db.rollback()
    bind = db.get_bind()
    path = bind.engine.url.database if hasattr(bind, "engine") else None
    if path and path != ":memory:" and Path(path).is_file():
        values["database_size_bytes"] = Path(path).stat().st_size
    return values


_HELP = {
    "sessions": ("gauge", "Attacker sessions stored."),
    "source_ips": ("gauge", "Distinct source addresses seen."),
    "accepted_logins": ("gauge", "Logins the honeypot accepted."),
    "commands": ("gauge", "Shell commands recorded."),
    "files": ("gauge", "Files downloaded or uploaded by attackers."),
    "campaigns": ("gauge", "Groups of sessions judged to share an operator."),
    "last_session_timestamp_seconds": (
        "gauge",
        "Start time of the newest session, as a Unix timestamp (0 when there are none).",
    ),
    "database_size_bytes": ("gauge", "Size of the database file."),
}


def render(values: dict[str, float]) -> str:
    """Prometheus text exposition format 0.0.4."""
    lines = [
        "# HELP surya_kundal_info Program version.",
        "# TYPE surya_kundal_info gauge",
        f'surya_kundal_info{{version="{__version__}"}} 1',
    ]
    for name, (kind, help_text) in _HELP.items():
        number = values.get(name, 0)
        lines += [
            f"# HELP surya_kundal_{name} {help_text}",
            f"# TYPE surya_kundal_{name} {kind}",
            f"surya_kundal_{name} {number:.0f}",
        ]
    return "\n".join(lines) + "\n"
