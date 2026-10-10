"""Group sessions into campaigns: sessions that look like one operation.

One attacker, or one botnet, leaves the same marks in many sessions: the same payload, the
same download address, the same script typed word for word, the same SSH client library,
the same password list. This module finds those repeats and joins the sessions that share
enough of them.

How it decides
--------------
Every session is turned into a set of *features*, each with a weight that says how
distinctive it is:

=====================================  ======
feature                                weight
=====================================  ======
a file hash (sent or fetched)            5
a download URL                           5
a long or many-step command script       5   (shorter scripts: 3)
a very long single command               5   (long: 3)
a password list tried in the same order  4
a tunnel destination                     4
a download host                          3
the SSH client fingerprint (HASSH)       2
a rare username and password pair      1.5
the SSH client version string            1
=====================================  ======

Two sessions are linked when the weights of what they share add up to 5 or more, so one
shared payload links them, while a shared SSH client alone never does. Linked sessions form
a campaign. Free-standing sessions are not campaigns.

Noise control, so that unrelated attackers are not merged:

* A weak feature (weight under 5) seen in more than 25 sessions is ignored: it describes a
  popular tool, not one operation.
* Command scripts are normalised first: addresses, URLs, numbers and long random strings
  become placeholders, so the same script with a different target still matches.
* The empty-file hash is ignored.

Limits, stated plainly: a payload shared by two unrelated actors (a public tool, say) will
merge them, and an actor who changes everything between sessions will not be seen. The
evidence stored with each campaign shows exactly why sessions were grouped, so a wrong
merge is easy to spot.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from surya_kundal.database.models import (
    Campaign,
    CampaignEvidence,
    CampaignSession,
    Command,
    Download,
    FetchAttempt,
    HoneypotSession,
    Login,
    TunnelRequest,
    Upload,
)

logger = logging.getLogger(__name__)

LINK_THRESHOLD = 5.0
MAX_WEAK_GROUP = 25  # a weak feature shared by more sessions than this describes a popular tool
MAX_PAIRS = 2_000_000  # memory guard for weak-feature pairs; rarest features are used first
MAX_COMMANDS_PER_SESSION = 200
MAX_CREDENTIALS_PER_SESSION = 30
MAX_EVIDENCE = 12
CREDLIST_MIN = 8  # attempts before the order of the list is distinctive
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

KIND_LIMIT = {"file": 64, "url": 280, "tunnel": 80, "host": 120, "login": 120, "command": 280}

_URL = re.compile(r"\b(?:https?|ftp|tftp)://\S+", re.IGNORECASE)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX = re.compile(r"\b[0-9a-f]{8,}\b")
_RANDOM = re.compile(r"\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{10,}\b")
_NUMBER = re.compile(r"\d+")
_SPACE = re.compile(r"\s+")
_TRIVIAL = {"", "exit", "logout", "quit", "clear", "history -c"}


@dataclass
class SessionFacts:
    """What the database knows about one session, reduced to what grouping needs."""

    id: str
    ip: str | None
    start: datetime | None
    hassh: str | None = None
    client: str | None = None
    commands: list[str] = field(default_factory=list)
    credentials: list[tuple[str, str]] = field(default_factory=list)
    files: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    tunnels: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    sessions: int


@dataclass(frozen=True)
class Cluster:
    id: str
    session_ids: tuple[str, ...]
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class BuildResult:
    campaigns: int
    sessions: int  # sessions that belong to a campaign
    total: int  # all sessions looked at


# --- features --------------------------------------------------------------------


def normalise_command(command: str) -> str:
    """Reduce a command to its shape so the same script aimed at another target matches."""
    text = command.strip().lower()
    text = _URL.sub("<url>", text)
    text = _IPV4.sub("<ip>", text)
    text = _HEX.sub("<hex>", text)
    text = _RANDOM.sub("<rand>", text)
    text = _NUMBER.sub("<n>", text)
    return _SPACE.sub(" ", text)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _clean_url(url: str) -> str | None:
    """Scheme, host, port and path; queries and fragments differ per victim, so they go."""
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https", "ftp") or not host:
        return None
    netloc = host.lower() + (f":{port}" if port else "")
    return f"{parts.scheme}://{netloc}{parts.path}"[: KIND_LIMIT["url"]]


def features_of(facts: SessionFacts) -> dict[str, float]:
    """The session's features as ``{"kind:value": weight}``."""
    found: dict[str, float] = {}

    def add(kind: str, value: str, weight: float) -> None:
        found[f"{kind}:{value[: KIND_LIMIT.get(kind, 200)]}"] = weight

    for sha in facts.files:
        if sha != EMPTY_SHA256:
            add("file", sha, 5)
    for url in facts.urls:
        cleaned = _clean_url(url)
        if cleaned is None:
            continue
        add("url", cleaned, 5)
        host = urlsplit(cleaned).netloc
        if host:
            add("host", host, 3)
    for tunnel in facts.tunnels:
        add("tunnel", tunnel, 4)
    if facts.hassh:
        add("hassh", facts.hassh, 2)
    if facts.client:
        add("client", facts.client, 1)

    normalised = [normalise_command(c) for c in facts.commands[:MAX_COMMANDS_PER_SESSION]]
    meaningful = [c for c in normalised if c not in _TRIVIAL]
    for command in dict.fromkeys(meaningful):
        if len(command) >= 80:
            add("command", command, 5)
        elif len(command) >= 25:
            add("command", command, 3)
    if meaningful:
        total = sum(len(c) for c in meaningful)
        if len(meaningful) >= 4 or total >= 80:
            add("cmdseq", _digest("\n".join(meaningful)), 5)
        elif len(meaningful) >= 2 and total >= 30:
            add("cmdseq", _digest("\n".join(meaningful)), 3)

    pairs = list(dict.fromkeys(facts.credentials))
    if len(facts.credentials) >= CREDLIST_MIN:
        add("credlist", _digest(repr(facts.credentials[:CREDLIST_MIN])), 4)
    for user, password in pairs[:MAX_CREDENTIALS_PER_SESSION]:
        add("login", f"{user}:{password}", 1.5)
    return found


# --- grouping --------------------------------------------------------------------


class _Groups:
    """Union-find over session positions."""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: int, b: int) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            # the smaller position wins, so the result never depends on arrival order
            self._parent[max(root_a, root_b)] = min(root_a, root_b)


def cluster(sessions: Iterable[SessionFacts]) -> list[Cluster]:
    """Group sessions into campaigns. Pure: same input, same output."""
    ordered = sorted(sessions, key=lambda s: (s.start or datetime.max.replace(tzinfo=UTC), s.id))
    if len(ordered) < 2:
        return []
    per_session = [features_of(s) for s in ordered]

    index: dict[str, list[int]] = defaultdict(list)
    weight_of: dict[str, float] = {}
    for position, features in enumerate(per_session):
        for key, weight in features.items():
            index[key].append(position)
            weight_of[key] = weight

    groups = _Groups(len(ordered))
    weak: list[tuple[int, str]] = []
    for key, members in index.items():
        if len(members) < 2:
            continue
        if weight_of[key] >= LINK_THRESHOLD:
            for other in members[1:]:
                groups.union(members[0], other)
        elif len(members) <= MAX_WEAK_GROUP:
            weak.append((len(members), key))

    scores: defaultdict[tuple[int, int], float] = defaultdict(float)
    for _size, key in sorted(weak):  # rarest, most informative features first
        members = index[key]
        pairs = len(members) * (len(members) - 1) // 2
        if len(scores) + pairs > MAX_PAIRS:
            logger.warning("campaigns: too many weak links; keeping the most distinctive")
            break
        weight = weight_of[key]
        for i, a in enumerate(members):
            for b in members[i + 1 :]:
                scores[(a, b)] += weight
    for (a, b), score in scores.items():
        if score >= LINK_THRESHOLD:
            groups.union(a, b)

    members_of: dict[int, list[int]] = defaultdict(list)
    for position in range(len(ordered)):
        members_of[groups.find(position)].append(position)

    clusters: list[Cluster] = []
    for members in members_of.values():
        if len(members) < 2:
            continue
        first = ordered[members[0]]  # members are in time order, so this is the earliest
        evidence = _evidence(members, per_session, weight_of, index)
        clusters.append(
            Cluster(
                id="c" + _digest(first.id)[:10],
                session_ids=tuple(ordered[p].id for p in members),
                evidence=evidence,
            )
        )
    clusters.sort(key=lambda c: (-len(c.session_ids), c.id))
    return clusters


def _evidence(
    members: list[int],
    per_session: list[dict[str, float]],
    weight_of: Mapping[str, float],
    index: Mapping[str, list[int]],
) -> tuple[Evidence, ...]:
    """The features several members share, strongest first: why these sessions are one group."""
    counts: Counter[str] = Counter()
    for position in members:
        for key in per_session[position]:
            counts[key] += 1
    shared = [
        (weight_of[key] * math.log2(1 + count), count, key)
        for key, count in counts.items()
        if count >= 2
        # a weak feature that half the honeypot shares explains nothing about this group
        and (weight_of[key] >= LINK_THRESHOLD or len(index[key]) <= MAX_WEAK_GROUP)
    ]
    shared.sort(key=lambda item: (-item[0], item[2]))
    result = []
    for _score, count, key in shared[:MAX_EVIDENCE]:
        kind, _, value = key.partition(":")
        result.append(Evidence(kind=kind, value=value, sessions=count))
    return tuple(result)


# --- reading and writing the database -----------------------------------------------


def load_facts(db: Session) -> list[SessionFacts]:
    """Read every session with the few things grouping needs. Streams the big tables."""
    facts: dict[str, SessionFacts] = {}
    for row in db.execute(
        select(
            HoneypotSession.id,
            HoneypotSession.src_ip,
            HoneypotSession.start_time,
            HoneypotSession.hassh,
            HoneypotSession.client_version,
        )
    ):
        facts[row.id] = SessionFacts(
            id=row.id,
            ip=row.src_ip,
            start=row.start_time,
            hassh=row.hassh,
            client=row.client_version,
        )

    for sid, command in db.execute(
        select(Command.session_id, Command.command).order_by(
            Command.session_id, Command.timestamp, Command.id
        )
    ).yield_per(5000):
        item = facts.get(sid)
        if item is not None and len(item.commands) < MAX_COMMANDS_PER_SESSION:
            item.commands.append(command)

    for sid, user, password in db.execute(
        select(Login.session_id, Login.username, Login.password).order_by(
            Login.session_id, Login.timestamp, Login.id
        )
    ).yield_per(5000):
        item = facts.get(sid)
        if item is not None and len(item.credentials) < 200:
            item.credentials.append((user or "", password or ""))

    for sid, url, sha in db.execute(select(Download.session_id, Download.url, Download.sha256)):
        item = facts.get(sid)
        if item is None:
            continue
        if url:
            item.urls.add(url)
        if sha:
            item.files.add(sha.lower())
    for sid, url in db.execute(select(FetchAttempt.session_id, FetchAttempt.url)):
        item = facts.get(sid)
        if item is not None:
            item.urls.add(url)
    for sid, sha in db.execute(select(Upload.session_id, Upload.sha256)):
        item = facts.get(sid)
        if item is not None and sha:
            item.files.add(sha.lower())
    for sid, dst, port in db.execute(
        select(TunnelRequest.session_id, TunnelRequest.dst_ip, TunnelRequest.dst_port)
    ):
        item = facts.get(sid)
        if item is not None and dst:
            item.tunnels.add(f"{dst}:{port}")
    return list(facts.values())


def build_campaigns(db: Session, *, now: datetime | None = None) -> BuildResult:
    """Recompute every campaign from the sessions and replace the stored ones."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    sessions = load_facts(db)
    found = cluster(sessions)
    by_id = {s.id: s for s in sessions}
    # Reading and grouping can take a while. End the read transaction before writing: under
    # SQLite's WAL mode a transaction that read, then wants to write after another writer
    # committed in between, is refused as "database is locked".
    db.rollback()

    db.execute(delete(CampaignEvidence))
    db.execute(delete(CampaignSession))
    db.execute(delete(Campaign))
    covered = 0
    for item in found:
        members = [by_id[sid] for sid in item.session_ids]
        starts = [m.start for m in members if m.start is not None]
        db.add(
            Campaign(
                id=item.id,
                first_seen=min(starts) if starts else None,
                last_seen=max(starts) if starts else None,
                session_count=len(members),
                ip_count=len({m.ip for m in members if m.ip}),
                built_at=now,
            )
        )
        db.flush()
        db.add_all(CampaignSession(session_id=m.id, campaign_id=item.id) for m in members)
        db.add_all(
            CampaignEvidence(
                campaign_id=item.id, kind=e.kind, value=e.value[:300], sessions=e.sessions
            )
            for e in item.evidence
        )
        covered += len(members)
    db.commit()
    return BuildResult(campaigns=len(found), sessions=covered, total=len(sessions))


# --- reading campaigns back ------------------------------------------------------------


@dataclass(frozen=True)
class CampaignRow:
    id: str
    first_seen: datetime | None
    last_seen: datetime | None
    sessions: int
    ips: int
    top_evidence: Evidence | None


@dataclass(frozen=True)
class CampaignDetail:
    row: CampaignRow
    evidence: list[Evidence]
    ips: list[tuple[str, int, str | None]]  # address, sessions, country
    techniques: list[tuple[str, int]]  # technique, sessions
    commands: list[tuple[str, int]]  # command, times typed
    hassh: list[tuple[str, int]]
    sessions: list[tuple[str, str | None, datetime | None]]  # id, address, start


def list_campaigns(
    db: Session, *, limit: int = 20, offset: int = 0, min_ips: int = 1
) -> list[CampaignRow]:
    """Campaigns, biggest first."""
    rows = db.scalars(
        select(Campaign)
        .where(Campaign.ip_count >= min_ips)
        .order_by(Campaign.session_count.desc(), Campaign.last_seen.desc(), Campaign.id)
        .limit(limit)
        .offset(offset)
    ).all()
    if not rows:
        return []
    top: dict[str, Evidence] = {}
    for item in db.scalars(
        select(CampaignEvidence)
        .where(CampaignEvidence.campaign_id.in_([r.id for r in rows]))
        .order_by(CampaignEvidence.id)
    ):
        top.setdefault(
            item.campaign_id, Evidence(kind=item.kind, value=item.value, sessions=item.sessions)
        )
    return [
        CampaignRow(
            id=r.id,
            first_seen=r.first_seen,
            last_seen=r.last_seen,
            sessions=r.session_count,
            ips=r.ip_count,
            top_evidence=top.get(r.id),
        )
        for r in rows
    ]


def find_campaign(db: Session, text: str) -> str | None:
    """Resolve an ID or a unique prefix. Raises ValueError when the prefix is ambiguous."""
    exact = db.get(Campaign, text)
    if exact is not None:
        return exact.id
    found = db.scalars(
        select(Campaign.id).where(Campaign.id.startswith(text, autoescape=True)).limit(2)
    ).all()
    if len(found) > 1:
        raise ValueError(f"more than one campaign starts with {text!r}")
    return found[0] if found else None


def campaign_detail(db: Session, campaign_id: str) -> CampaignDetail | None:
    from sqlalchemy import func

    from surya_kundal.database.models import IpGeo, TechniqueMatch

    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        return None
    members = CampaignSession.campaign_id == campaign_id
    evidence = [
        Evidence(kind=e.kind, value=e.value, sessions=e.sessions)
        for e in db.scalars(
            select(CampaignEvidence)
            .where(CampaignEvidence.campaign_id == campaign_id)
            .order_by(CampaignEvidence.id)
        )
    ]
    sessions = [
        (sid, ip, start)
        for sid, ip, start in db.execute(
            select(HoneypotSession.id, HoneypotSession.src_ip, HoneypotSession.start_time)
            .join(CampaignSession, CampaignSession.session_id == HoneypotSession.id)
            .where(members)
            .order_by(HoneypotSession.start_time, HoneypotSession.id)
        )
    ]
    ips = [
        (ip, count, country)
        for ip, count, country in db.execute(
            select(HoneypotSession.src_ip, func.count(), func.max(IpGeo.country_code))
            .join(CampaignSession, CampaignSession.session_id == HoneypotSession.id)
            .outerjoin(IpGeo, IpGeo.ip == HoneypotSession.src_ip)
            .where(members, HoneypotSession.src_ip.is_not(None))
            .group_by(HoneypotSession.src_ip)
            .order_by(func.count().desc(), HoneypotSession.src_ip)
            .limit(50)
        )
        if ip is not None
    ]
    techniques = [
        (technique, count)
        for technique, count in db.execute(
            select(TechniqueMatch.technique_id, func.count(TechniqueMatch.session_id.distinct()))
            .join(CampaignSession, CampaignSession.session_id == TechniqueMatch.session_id)
            .where(members)
            .group_by(TechniqueMatch.technique_id)
            .order_by(
                func.count(TechniqueMatch.session_id.distinct()).desc(), TechniqueMatch.technique_id
            )
        )
    ]
    commands = [
        (command, count)
        for command, count in db.execute(
            select(Command.command, func.count())
            .join(CampaignSession, CampaignSession.session_id == Command.session_id)
            .where(members)
            .group_by(Command.command)
            .order_by(func.count().desc(), Command.command)
            .limit(15)
        )
    ]
    hassh = [
        (value, count)
        for value, count in db.execute(
            select(HoneypotSession.hassh, func.count())
            .join(CampaignSession, CampaignSession.session_id == HoneypotSession.id)
            .where(members, HoneypotSession.hassh.is_not(None))
            .group_by(HoneypotSession.hassh)
            .order_by(func.count().desc())
            .limit(10)
        )
        if value is not None
    ]
    row = CampaignRow(
        id=campaign.id,
        first_seen=campaign.first_seen,
        last_seen=campaign.last_seen,
        sessions=campaign.session_count,
        ips=campaign.ip_count,
        top_evidence=evidence[0] if evidence else None,
    )
    return CampaignDetail(
        row=row,
        evidence=evidence,
        ips=ips,
        techniques=techniques,
        commands=commands,
        hassh=hassh,
        sessions=sessions,
    )
