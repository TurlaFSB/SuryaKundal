"""Import a Cowrie JSON log into the database."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from surya_kundal.database.repository import save_session
from surya_kundal.parser.log_parser import group_by_session, read_events, summarize

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestResult:
    saved: int
    failed: int


def ingest_log(db: Session, log_path: Path) -> IngestResult:
    """Parse ``log_path`` and store every session in it.

    Each session is stored inside its own savepoint, so one session that fails
    to save is logged and skipped instead of aborting the whole import. The
    caller commits the transaction.
    """
    saved = 0
    failed = 0
    for session_id, events in group_by_session(read_events(log_path)).items():
        try:
            with db.begin_nested():
                save_session(db, session_id, summarize(events))
        except (SQLAlchemyError, ValueError):
            logger.exception("Could not store session %s", session_id)
            failed += 1
        else:
            saved += 1
    logger.info("Ingest finished: %d saved, %d failed", saved, failed)
    return IngestResult(saved=saved, failed=failed)
