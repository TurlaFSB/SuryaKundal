"""Read-only queries behind the dashboard.

Every function takes an open SQLAlchemy session and returns plain data, so the web layer
holds no SQL and each query can be tested on its own. Nothing here writes.

Scalar subqueries are used instead of joins wherever a session has several kinds of
child rows: joining logins to commands would multiply rows (500 x 500 for one
brute-force session).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import distinct, exists, func, or_, select
from sqlalchemy.orm import Session

from surya_kundal.database.models import (
    Command,
    Download,
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
    session_matches: list[TechniqueMatch]
    files: list[FileView]
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
    def count(model: type) -> int:
        return int(db.scalar(select(func.count()).select_from(model)) or 0)

    sessions, last = pulse(db)
    sources = db.scalar(select(func.count(distinct(HoneypotSession.src_ip)))) or 0
    accepted = db.scalar(select(func.count()).where(Login.success.is_(True))) or 0
    return Totals(
        sessions=sessions,
        sources=int(sources),
        accepted_logins=int(accepted),
        commands=count(Command),
        files=count(Download) + count(Upload),
        last_event=last,
    )


def depth(db: Session) -> Depth:
    def sessions_where(*conditions: object) -> int:
        query = select(func.count()).select_from(HoneypotSession)
        for condition in conditions:
            query = query.where(condition)  # type: ignore[arg-type]
        return int(db.scalar(query) or 0)

    sid = HoneypotSession.id
    took_action = or_(
        exists().where(Download.session_id == sid),
        exists().where(Upload.session_id == sid),
        exists().where(TunnelRequest.session_id == sid),
        exists().where(
            TechniqueMatch.session_id == sid,
            or_(*(TechniqueMatch.tactics.contains(t, autoescape=True) for t in ACTION_TACTICS)),
        ),
    )
    return Depth(
        contact=sessions_where(),
        access=sessions_where(exists().where(Login.session_id == sid, Login.success.is_(True))),
        hands_on=sessions_where(exists().where(Command.session_id == sid)),
        action=sessions_where(took_action),
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
        .where(IpGeo.latitude.is_not(None), IpGeo.longitude.is_not(None))
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
    for (when,) in db.execute(
        select(HoneypotSession.start_time).where(HoneypotSession.start_time >= start).limit(50_000)
    ):
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
    conditions = []
    if query:
        conditions.append(
            or_(
                HoneypotSession.src_ip.startswith(query, autoescape=True),
                sid.startswith(query, autoescape=True),
            )
        )
    if technique:
        conditions.append(
            exists().where(
                TechniqueMatch.session_id == sid, TechniqueMatch.technique_id == technique
            )
        )
    if country:
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
                tactics=_tactics(tactics or ""),
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
        .where(TechniqueMatch.rule_id.in_(PROBE_RULES))
        .order_by(HoneypotSession.start_time.desc(), TechniqueMatch.id.desc())
        .limit(limit)
    ).all()
    return [Probe(*row) for row in rows]


def probing_sessions(db: Session) -> int:
    return int(
        db.scalar(
            select(func.count(distinct(TechniqueMatch.session_id))).where(
                TechniqueMatch.rule_id.in_(PROBE_RULES)
            )
        )
        or 0
    )


def session_detail(db: Session, prefix: str) -> SessionDetail | None:
    """One session by full ID or unique prefix; None when there is not exactly one match."""
    found = db.scalars(
        select(HoneypotSession)
        .where(HoneypotSession.id.startswith(prefix, autoescape=True))
        .limit(2)
    ).all()
    if len(found) != 1:
        return None
    session = found[0]
    matches = db.scalars(
        select(TechniqueMatch)
        .where(TechniqueMatch.session_id == session.id)
        .order_by(TechniqueMatch.id)
    ).all()
    by_command: defaultdict[int | None, list[TechniqueMatch]] = defaultdict(list)
    for match in matches:
        by_command[match.command_id].append(match)

    verdicts = {
        row.sha256: row
        for row in db.scalars(
            select(FileIntel).where(
                FileIntel.provider == "virustotal",
                FileIntel.sha256.in_(
                    [d.sha256 for d in session.downloads if d.sha256]
                    + [u.sha256 for u in session.uploads if u.sha256]
                ),
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

    files = [view("downloaded", d.url, d.sha256, d.timestamp) for d in session.downloads]
    files += [view("uploaded", u.filename, u.sha256, u.timestamp) for u in session.uploads]
    geo = db.get(IpGeo, session.src_ip) if session.src_ip else None
    intel = {
        row.provider: row for row in db.scalars(select(IpIntel).where(IpIntel.ip == session.src_ip))
    }
    login_total = len(session.logins)
    return SessionDetail(
        session=session,
        geo=geo,
        abuse=intel["abuseipdb"].score if "abuseipdb" in intel else None,
        tor=intel["tor"].flagged if "tor" in intel else None,
        logins=list(session.logins[:MAX_LOGINS_SHOWN]),
        login_total=login_total,
        commands=[
            CommandView(c.id, c.command, c.timestamp, by_command.get(c.id, []))
            for c in session.commands
        ],
        session_matches=by_command.get(None, []),
        files=files,
        tunnels=list(session.tunnels),
    )
