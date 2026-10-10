"""Turn Cowrie events into stored sessions."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from surya_kundal.database.repository import save_session
from surya_kundal.parser.log_parser import group_by_session, read_events, summarize

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestResult:
    saved: int
    failed: int
    failed_ids: tuple[str, ...] = ()


def store_events(db: Session, events: Iterable[dict]) -> IngestResult:
    """Group events by session and merge each session into the database.

    Each session is stored inside its own savepoint, so one session that fails to
    save is logged and skipped instead of aborting the rest. The caller commits.
    """
    saved = 0
    failed_ids: list[str] = []
    for session_id, session_events in group_by_session(events).items():
        try:
            with db.begin_nested():
                save_session(db, session_id, summarize(session_events))
        except OperationalError:
            # A locked or unavailable database affects every session, not just this one: let the
            # caller retry the whole batch instead of waiting out the lock once per session.
            raise
        except Exception:  # one bad session must never stop the others, whatever it contains
            logger.exception("Could not store session %r", session_id)
            failed_ids.append(session_id)
        else:
            saved += 1
    return IngestResult(saved=saved, failed=len(failed_ids), failed_ids=tuple(failed_ids))


def ingest_log(db: Session, log_path: Path) -> IngestResult:
    """Parse the whole of ``log_path`` and store every session in it."""
    result = store_events(db, read_events(log_path))
    logger.info("Ingest finished: %d saved, %d failed", result.saved, result.failed)
    return result
