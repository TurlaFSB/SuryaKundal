"""Apply the mapping engine to stored sessions and keep the results current."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from surya_kundal.database.models import (
    Command,
    HoneypotSession,
    Login,
    SessionMapping,
    TechniqueMatch,
)
from surya_kundal.mapping.attack import load_catalog
from surya_kundal.mapping.engine import RuleSet, load_rules, map_command, map_logins

logger = logging.getLogger(__name__)


@dataclass
class MapResult:
    sessions: int = 0
    matches: int = 0
    failed: int = 0


def _counts(db: Session, model) -> dict[str, int]:
    query = select(model.session_id, func.count()).group_by(model.session_id)
    return dict(db.execute(query).all())


def _pending_session_ids(db: Session, ruleset: RuleSet, attack_version: str) -> list[str]:
    commands = _counts(db, Command)
    logins = _counts(db, Login)
    done = {m.session_id: m for m in db.scalars(select(SessionMapping))}
    pending = []
    for session_id in db.scalars(select(HoneypotSession.id).order_by(HoneypotSession.start_time)):
        mapping = done.get(session_id)
        if (
            mapping is None
            or mapping.ruleset_version != ruleset.version
            or mapping.attack_version != attack_version
            or mapping.command_count != commands.get(session_id, 0)
            or mapping.login_count != logins.get(session_id, 0)
        ):
            pending.append(session_id)
    return pending


def map_session(db: Session, session_id: str, ruleset: RuleSet | None = None) -> int:
    """(Re)build one session's technique matches. Returns the number of matches stored."""
    ruleset = ruleset or load_rules()
    catalog = load_catalog()
    session = db.get(HoneypotSession, session_id)
    if session is None:
        raise KeyError(session_id)

    rows: list[TechniqueMatch] = []

    def add(match, command_id=None) -> None:
        technique = catalog.get(match.technique)
        rows.append(
            TechniqueMatch(
                session_id=session_id,
                command_id=command_id,
                technique_id=match.technique,
                tactics=",".join(technique.tactics) if technique else "",
                rule_id=match.rule_id,
                confidence=match.confidence,
                evidence=match.evidence,
            )
        )

    for command in session.commands:
        for match in map_command(command.command, ruleset):
            add(match, command.id)
    login_dicts = [{"username": x.username, "success": x.success} for x in session.logins]
    for match in map_logins(login_dicts):
        add(match)

    db.execute(delete(TechniqueMatch).where(TechniqueMatch.session_id == session_id))
    db.add_all(rows)
    mapping = db.get(SessionMapping, session_id) or SessionMapping(session_id=session_id)
    mapping.ruleset_version = ruleset.version
    mapping.attack_version = catalog.version
    mapping.command_count = len(session.commands)
    mapping.login_count = len(session.logins)
    mapping.mapped_at = datetime.now(UTC)
    db.add(mapping)
    return len(rows)


def map_pending(db: Session, ruleset: RuleSet | None = None) -> MapResult:
    """Map every session that is new or changed since it was last mapped."""
    ruleset = ruleset or load_rules()
    result = MapResult()
    for session_id in _pending_session_ids(db, ruleset, load_catalog().version):
        try:
            result.matches += map_session(db, session_id, ruleset)
            db.commit()
            result.sessions += 1
        except Exception:
            db.rollback()
            logger.exception("Could not map session %s", session_id)
            result.failed += 1
    return result
