"""Read-only queries behind the dashboard.

Every function takes an open SQLAlchemy session and returns plain data, so the web layer
holds no SQL and each query can be tested on its own. Nothing here writes.

Scalar subqueries are used instead of joins wherever a session has several kinds of
child rows: joining logins to commands would multiply rows (500 x 500 for one
brute-force session).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, distinct, func, or_, select, true
from sqlalchemy.orm import Session

from surya_kundal.database.models import (
    Command,
    Download,
    FetchAttempt,
    FileIntel,
    HoneypotSession,
    IpGeo,
    IpIntel,
    Login,
    TechniqueMatch,
    TunnelRequest,
    Upload,
)
from surya_kundal.mapping.attack import load_catalog

_include_internal: ContextVar[bool] = ContextVar("include_internal", default=False)


@contextmanager
def internal_traffic(show: bool) -> Iterator[None]:
    """Within the block, counts and lists include (or leave out) the operator's own sessions."""
    token = _include_internal.set(show)
    try:
        yield
    finally:
        _include_internal.reset(token)


def show_internal(show: bool) -> None:
    """Set for the current request or thread; the web layer calls this before each request."""
    _include_internal.set(show)


def _real() -> ColumnElement[bool]:
    """Condition on sessions: attackers only, unless internal traffic was asked for."""
    return true() if _include_internal.get() else HoneypotSession.internal.is_(False)


def _real_ids() -> Any:
    return select(HoneypotSession.id).where(_real())


# Rules that mean "the visitor is checking whether this is a honeypot or a sandbox".
PROBE_RULES = ("discovery-virtualization", "discovery-ssh-version")
# A session "took action" if it moved files or tunnelled, or did any of these.
ACTION_TACTICS = (
    "persistence",
    "privilege-escalation",
    "credential-access",
    "command-and-control",
    "lateral-movement",
    "collection",
    "exfiltration",
    "impact",
    "defense-impairment",
)
# Enterprise ATT&CK reading order, with the tactic names the vendored catalog uses.
TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)
PAGE_SIZE = 25
MAX_LOGINS_SHOWN = 100
MAX_COMMANDS_SHOWN = 500
MAX_FILES_SHOWN = 100
MAX_MATCHES_LOADED = 5000
MIN_PREFIX = 6  # a shorter prefix is not specific enough to name one session


@dataclass(frozen=True)
class Totals:
    sessions: int
    sources: int
    accepted_logins: int
    commands: int
    files: int
    last_event: datetime | None


@dataclass(frozen=True)
class Depth:
    """How far visitors got, each stage a subset of the one before it (roughly)."""

    contact: int
    access: int
    hands_on: int
    action: int


@dataclass(frozen=True)
class MapPoint:
    ip: str
    latitude: float
    longitude: float
    country: str | None
    city: str | None
    sessions: int


@dataclass(frozen=True)
class SessionRow:
    id: str
    ip: str | None
    start: datetime | None
    logins: int
    commands: int
    country: str | None
    abuse: int | None
    tor: bool | None
    techniques: tuple[str, ...]


@dataclass(frozen=True)
class SessionPage:
    rows: list[SessionRow]
    total: int
    page: int
    pages: int


@dataclass(frozen=True)
class TechniqueCount:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    sessions: int
    hits: int


@dataclass(frozen=True)
class Probe:
    session_id: str
    ip: str | None
    when: datetime | None
    rule_id: str
    evidence: str


@dataclass(frozen=True)
class CommandView:
    id: int
    text: str
    when: datetime | None
    matches: list[TechniqueMatch]


@dataclass(frozen=True)
class FileView:
    kind: str  # "downloaded" or "uploaded"
    name: str
    sha256: str | None
    when: datetime | None
    malicious: int | None
    engines: int | None
    label: str | None
    known: bool | None  # None: never looked up


@dataclass
class SessionDetail:
    session: HoneypotSession
    geo: IpGeo | None
    abuse: int | None
    tor: bool | None
    logins: list[Login]
    login_total: int
    commands: list[CommandView]
    command_total: int
    session_matches: list[TechniqueMatch]
    files: list[FileView]
    attempts: list[FetchAttempt]
    tunnels: list[TunnelRequest]
    techniques: list[TechniqueCount] = field(default_factory=list)


def _tactics(text: str) -> tuple[str, ...]:
    return tuple(t for t in text.split(",") if t)


def has_data(db: Session) -> bool:
    """False when the database has no tables yet (the pipeline has not run)."""
    from sqlalchemy import inspect

    bind = db.get_bind()
    return inspect(bind).has_table(HoneypotSession.__tablename__)


def pulse(db: Session) -> tuple[int, datetime | None]:
    row = db.execute(
        select(func.count(), func.max(HoneypotSession.start_time)).select_from(HoneypotSession)
    ).one()
    return int(row[0]), row[1]


def totals(db: Session) -> Totals:
    def count(model: Any) -> int:
        query = select(func.count()).select_from(model).where(model.session_id.in_(_real_ids()))
        return int(db.scalar(query) or 0)

    sessions, last = db.execute(
        select(func.count(), func.max(HoneypotSession.start_time))
        .select_from(HoneypotSession)
        .where(_real())
    ).one()
    sources = db.scalar(select(func.count(distinct(HoneypotSession.src_ip))).where(_real())) or 0
    accepted = (
        db.scalar(
            select(func.count()).where(Login.success.is_(True), Login.session_id.in_(_real_ids()))
        )
        or 0
    )
    return Totals(
        sessions=int(sessions),
        sources=int(sources),
        accepted_logins=int(accepted),
        commands=count(Command),
        files=count(Download) + count(Upload),
        last_event=last,
    )


def depth(db: Session) -> Depth:
    """How far sessions got. Each step is a subset of the one before it.

    "Took action" means the visitor got in and then moved a file, opened a tunnel, or ran a
    command that maps to a persistence, credential, command-and-control or similar technique.
    Session-level evidence such as password guessing does not count: it needs no access.
    """

    def count(*conditions: object) -> int:
        query = select(func.count()).select_from(HoneypotSession).where(_real())
        for condition in conditions:
            query = query.where(condition)  # type: ignore[arg-type]
        return int(db.scalar(query) or 0)

    sid = HoneypotSession.id
    accepted = select(Login.session_id).where(Login.success.is_(True))
    ran_command = select(Command.session_id)
    acted = (
        select(Download.session_id)
        .union(
            select(Upload.session_id),
            select(TunnelRequest.session_id),
            select(TechniqueMatch.session_id).where(
                TechniqueMatch.command_id.is_not(None),
                or_(*(TechniqueMatch.tactics.contains(t, autoescape=True) for t in ACTION_TACTICS)),
            ),
        )
        .subquery()
    )
    return Depth(
        contact=count(),
        access=count(sid.in_(accepted)),
        hands_on=count(sid.in_(accepted), sid.in_(ran_command)),
        action=count(sid.in_(accepted), sid.in_(select(acted.c.session_id))),
    )


def map_points(db: Session) -> list[MapPoint]:
    rows = db.execute(
        select(
            IpGeo.ip,
            IpGeo.latitude,
            IpGeo.longitude,
            IpGeo.country_code,
            IpGeo.city,
            func.count(HoneypotSession.id),
        )
        .join(HoneypotSession, HoneypotSession.src_ip == IpGeo.ip)
        .where(IpGeo.latitude.is_not(None), IpGeo.longitude.is_not(None), _real())
        .group_by(IpGeo.ip)
        .order_by(func.count(HoneypotSession.id).desc())
        .limit(500)
    ).all()
    return [
        MapPoint(r[0], r[1], r[2], r[3], r[4], r[5])
        for r in rows
        if r[1] is not None and r[2] is not None
    ]


def top_countries(db: Session, limit: int = 6) -> list[tuple[str, int]]:
    code = func.coalesce(IpGeo.country_code, "unknown")
    rows = db.execute(
        select(code, func.count(HoneypotSession.id))
        .select_from(HoneypotSession)
        .outerjoin(IpGeo, IpGeo.ip == HoneypotSession.src_ip)
        .where(_real())
        .group_by(code)
        .order_by(func.count(HoneypotSession.id).desc())
        .limit(limit)
    ).all()
    return [(r[0], int(r[1])) for r in rows]


def hourly_activity(db: Session, hours: int = 24, now: datetime | None = None) -> list[int]:
    """Sessions started in each of the last ``hours`` hours, oldest first."""
    now = now or datetime.now(UTC)
    top = now.replace(minute=0, second=0, microsecond=0)
    start = top - timedelta(hours=hours - 1)
    buckets = [0] * hours
    rows = db.execute(
        select(HoneypotSession.start_time)
        .where(HoneypotSession.start_time >= start, _real())
        .execution_options(yield_per=5000)
    )
    for (when,) in rows:
        if when is not None:
            index = int((when - start).total_seconds() // 3600)
            if 0 <= index < hours:
                buckets[index] += 1
    return buckets


def _row_techniques(db: Session, ids: list[str]) -> dict[str, tuple[str, ...]]:
    if not ids:
        return {}
    found: defaultdict[str, list[str]] = defaultdict(list)
    for session_id, technique in db.execute(
        select(TechniqueMatch.session_id, TechniqueMatch.technique_id)
        .where(TechniqueMatch.session_id.in_(ids))
        .group_by(TechniqueMatch.session_id, TechniqueMatch.technique_id)
        .order_by(TechniqueMatch.technique_id)
    ):
        found[session_id].append(technique)
    return {k: tuple(v) for k, v in found.items()}


def sessions_page(
    db: Session,
    *,
    page: int = 1,
    per_page: int = PAGE_SIZE,
    query: str = "",
    technique: str = "",
    country: str = "",
) -> SessionPage:
    sid = HoneypotSession.id
    logins = select(func.count()).where(Login.session_id == sid).scalar_subquery()
    commands = select(func.count()).where(Command.session_id == sid).scalar_subquery()
    country_of = select(IpGeo.country_code).where(IpGeo.ip == HoneypotSession.src_ip)
    abuse = (
        select(IpIntel.score)
        .where(IpIntel.ip == HoneypotSession.src_ip, IpIntel.provider == "abuseipdb")
        .scalar_subquery()
    )
    tor = (
        select(IpIntel.flagged)
        .where(IpIntel.ip == HoneypotSession.src_ip, IpIntel.provider == "tor")
        .scalar_subquery()
    )
    conditions = [_real()]
    if query:
        conditions.append(
            or_(
                HoneypotSession.src_ip.startswith(query, autoescape=True),
                sid.startswith(query, autoescape=True),
            )
        )
    if technique:
        # IN (subquery) lets SQLite use the technique index once, instead of per session.
        conditions.append(
            sid.in_(
                select(TechniqueMatch.session_id).where(TechniqueMatch.technique_id == technique)
            )
        )
    if country.lower() == "unknown":
        located = select(IpGeo.ip).where(IpGeo.country_code.is_not(None))
        conditions.append(HoneypotSession.src_ip.not_in(located) | HoneypotSession.src_ip.is_(None))
    elif country:
        conditions.append(country_of.where(IpGeo.country_code == country.upper()).exists())

    total = int(
        db.scalar(select(func.count()).select_from(HoneypotSession).where(*conditions)) or 0
    )
    pages = max(1, -(-total // per_page))
    page = min(max(page, 1), pages)
    rows = db.execute(
        select(
            HoneypotSession,
            logins,
            commands,
            country_of.scalar_subquery(),
            abuse,
            tor,
        )
        .where(*conditions)
        .order_by(HoneypotSession.start_time.desc(), sid)
        .limit(per_page)
        .offset((page - 1) * per_page)
    ).all()
    techniques = _row_techniques(db, [r[0].id for r in rows])
    return SessionPage(
        rows=[
            SessionRow(
                id=r[0].id,
                ip=r[0].src_ip,
                start=r[0].start_time,
                logins=int(r[1]),
                commands=int(r[2]),
                country=r[3],
                abuse=r[4],
                tor=r[5],
                techniques=techniques.get(r[0].id, ()),
            )
            for r in rows
        ],
        total=total,
        page=page,
        pages=pages,
    )


def technique_counts(db: Session, limit: int | None = None) -> list[TechniqueCount]:
    catalog = load_catalog()
    query = (
        select(
            TechniqueMatch.technique_id,
            func.max(TechniqueMatch.tactics),
            func.count(distinct(TechniqueMatch.session_id)),
            func.count(),
        )
        .where(TechniqueMatch.session_id.in_(_real_ids()))
        .group_by(TechniqueMatch.technique_id)
        .order_by(
            func.count(distinct(TechniqueMatch.session_id)).desc(), TechniqueMatch.technique_id
        )
    )
    if limit:
        query = query.limit(limit)
    result = []
    for technique_id, tactics, sessions, hits in db.execute(query):
        known = catalog.get(technique_id)
        result.append(
            TechniqueCount(
                technique_id=technique_id,
                name=known.name if known else technique_id,
                tactics=known.tactics if known else _tactics(tactics or ""),
                sessions=int(sessions),
                hits=int(hits),
            )
        )
    return result


def attack_matrix(db: Session) -> list[tuple[str, list[TechniqueCount]]]:
    """Techniques seen, grouped under each tactic in ATT&CK reading order."""
    columns: defaultdict[str, list[TechniqueCount]] = defaultdict(list)
    for item in technique_counts(db):
        for tactic in item.tactics or ("other",):
            columns[tactic].append(item)
    ordered = [t for t in TACTIC_ORDER if t in columns]
    ordered += sorted(t for t in columns if t not in TACTIC_ORDER)
    return [(tactic, columns[tactic]) for tactic in ordered]


def probes(db: Session, limit: int = 8) -> list[Probe]:
    rows = db.execute(
        select(
            TechniqueMatch.session_id,
            HoneypotSession.src_ip,
            HoneypotSession.start_time,
            TechniqueMatch.rule_id,
            TechniqueMatch.evidence,
        )
        .join(HoneypotSession, HoneypotSession.id == TechniqueMatch.session_id)
        .where(TechniqueMatch.rule_id.in_(PROBE_RULES), _real())
        .order_by(HoneypotSession.start_time.desc(), TechniqueMatch.id.desc())
        .limit(limit)
    ).all()
    return [Probe(*row) for row in rows]


def probing_sessions(db: Session) -> int:
    return int(
        db.scalar(
            select(func.count(distinct(TechniqueMatch.session_id))).where(
                TechniqueMatch.rule_id.in_(PROBE_RULES),
                TechniqueMatch.session_id.in_(_real_ids()),
            )
        )
        or 0
    )


def session_detail(db: Session, prefix: str) -> SessionDetail | None:
    """One session by exact ID, or by a unique prefix of at least six characters."""
    session = db.get(HoneypotSession, prefix)
    if session is None:
        if len(prefix) < MIN_PREFIX:
            return None
        found = db.scalars(
            select(HoneypotSession)
            .where(HoneypotSession.id.startswith(prefix, autoescape=True))
            .limit(2)
        ).all()
        if len(found) != 1:
            return None
        session = found[0]
    sid = session.id

    def limited(model: Any, order: tuple[Any, ...], cap: int) -> list[Any]:
        return list(
            db.scalars(select(model).where(model.session_id == sid).order_by(*order).limit(cap))
        )

    def total(model: Any) -> int:
        count = select(func.count()).select_from(model).where(model.session_id == sid)
        return int(db.scalar(count) or 0)

    logins = limited(Login, (Login.timestamp, Login.id), MAX_LOGINS_SHOWN)
    commands = limited(Command, (Command.timestamp, Command.id), MAX_COMMANDS_SHOWN)
    downloads = limited(Download, (Download.timestamp, Download.id), MAX_FILES_SHOWN)
    uploads = limited(Upload, (Upload.timestamp, Upload.id), MAX_FILES_SHOWN)
    attempts = limited(FetchAttempt, (FetchAttempt.timestamp, FetchAttempt.id), MAX_FILES_SHOWN)
    tunnels = limited(TunnelRequest, (TunnelRequest.timestamp, TunnelRequest.id), MAX_FILES_SHOWN)

    matches = db.scalars(
        select(TechniqueMatch)
        .where(TechniqueMatch.session_id == sid)
        .order_by(TechniqueMatch.id)
        .limit(MAX_MATCHES_LOADED)
    ).all()
    by_command: defaultdict[int | None, list[TechniqueMatch]] = defaultdict(list)
    for match in matches:
        by_command[match.command_id].append(match)

    hashes = [d.sha256 for d in downloads if d.sha256] + [u.sha256 for u in uploads if u.sha256]
    verdicts = {
        row.sha256: row
        for row in db.scalars(
            select(FileIntel).where(
                FileIntel.provider == "virustotal", FileIntel.sha256.in_(hashes)
            )
        )
    }

    def view(kind: str, name: str | None, sha: str | None, when: datetime | None) -> FileView:
        verdict = verdicts.get(sha or "")
        return FileView(
            kind=kind,
            name=name or "?",
            sha256=sha,
            when=when,
            malicious=verdict.malicious if verdict else None,
            engines=verdict.engines if verdict else None,
            label=verdict.label if verdict else None,
            known=verdict.found if verdict else None,
        )

    files = [view("downloaded", d.url, d.sha256, d.timestamp) for d in downloads]
    files += [view("uploaded", u.filename, u.sha256, u.timestamp) for u in uploads]
    geo = db.get(IpGeo, session.src_ip) if session.src_ip else None
    intel = {
        row.provider: row for row in db.scalars(select(IpIntel).where(IpIntel.ip == session.src_ip))
    }
    return SessionDetail(
        session=session,
        geo=geo,
        abuse=intel["abuseipdb"].score if "abuseipdb" in intel else None,
        tor=intel["tor"].flagged if "tor" in intel else None,
        logins=logins,
        login_total=total(Login),
        commands=[
            CommandView(c.id, c.command, c.timestamp, by_command.get(c.id, [])) for c in commands
        ],
        command_total=total(Command),
        session_matches=by_command.get(None, []),
        files=files,
        attempts=attempts,
        tunnels=tunnels,
    )
