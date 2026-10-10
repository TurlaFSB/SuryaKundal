"""Export what the honeypot learned as indicators of compromise (IOCs).

Three kinds of indicator come out of the database:

* **addresses** of clients that attacked the honeypot,
* **file hashes** (SHA-256) of files they sent or fetched, and
* **URLs** they downloaded from.

They can be written as CSV, as a STIX 2.1 bundle (the standard exchange format, understood
by MISP, OpenCTI and most threat-intelligence platforms), as a plain blocklist, or as an
nftables script whose entries expire by themselves.

Safety rules, because an exported list is acted on automatically somewhere else:

* Only public addresses are exported. Private, loopback, link-local and documentation
  addresses are never listed unless ``include_private`` is set, which the command line
  allows for CSV and STIX only, never for a blocklist.
* An allow-list (``exclude``) removes your own infrastructure from every output.
* Every value is validated, and anything attacker-controlled that ends up in a cell or a
  pattern is neutralised: CSV cells cannot start a spreadsheet formula, STIX patterns are
  escaped, and URLs with control characters or whitespace are dropped.
* Nothing is written to the database.

How confident an indicator is
------------------------------
Confidence is a number from 0 to 100 that follows how far the attacker got, then moves
with outside evidence. For an address: contact only 25, password guessing (10 or more
failed logins) 45, got in 55, ran commands 70, moved files or tunnelled 85; plus 10 when
AbuseIPDB scores it 50 or more (capped at 95). For a file: 60 by default, 90 when
VirusTotal calls it malicious (5 or more engines), 75 for 1 to 4, and 30 when VirusTotal
knows it and every engine says clean. A URL is 60.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import tempfile
import uuid
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import ColumnElement, func, select, union
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
from surya_kundal.textsafe import printable

LEVELS = ("contact", "guessing", "access", "hands-on", "action")
GUESSING_THRESHOLD = 10
LEVEL_CONFIDENCE = {"contact": 25, "guessing": 45, "access": 55, "hands-on": 70, "action": 85}
TYPES = ("ip", "file", "url")

# SHA-256 of zero bytes: Cowrie logs empty downloads, and the hash says nothing.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

MAX_URL_LENGTH = 2048
MAX_TECHNIQUES = 20
CHUNK = 500
_SHA256 = re.compile(r"[0-9a-f]{64}")
_URL_SCHEMES = ("http", "https", "ftp")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

# Fixed namespace so the same indicator always gets the same STIX ID. Importers update
# the object instead of creating a duplicate each time the export runs.
NAMESPACE = uuid.UUID("5d0a8d5c-7f4e-4f4a-9d73-1c9a6b0d2e11")

CSV_COLUMNS = (
    "type",
    "value",
    "first_seen",
    "last_seen",
    "sessions",
    "level",
    "confidence",
    "country",
    "asn",
    "as_org",
    "abuse_score",
    "tor",
    "vt_malicious",
    "vt_engines",
    "techniques",
    "detail",
)


@dataclass(frozen=True)
class Indicator:
    """One thing worth blocking or sharing."""

    kind: str  # "ipv4", "ipv6", "sha256" or "url"
    value: str
    first_seen: datetime  # earliest sighting ever, so a STIX object's creation time is stable
    last_seen: datetime  # latest sighting inside the export window
    sessions: int  # sessions inside the window
    confidence: int
    level: str | None = None  # addresses only
    country: str | None = None
    asn: int | None = None
    as_org: str | None = None
    abuse_score: int | None = None
    tor: bool | None = None
    vt_malicious: int | None = None
    vt_engines: int | None = None
    techniques: tuple[str, ...] = ()
    detail: str = ""

    @property
    def is_address(self) -> bool:
        return self.kind in ("ipv4", "ipv6")


@dataclass
class Summary:
    """What was left out and why, for the command line to report."""

    non_public: int = 0
    excluded: int = 0
    invalid: int = 0
    counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Filters:
    days: int = 30
    min_level: str = "guessing"
    types: tuple[str, ...] = TYPES
    exclude: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    include_private: bool = False
    min_confidence: int = 0


# --- parsing and validation ----------------------------------------------------


def parse_networks(
    items: Iterable[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse addresses and CIDR ranges; raise ValueError naming the first bad entry."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in items:
        text = item.strip()
        if not text or text.startswith("#"):
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            raise ValueError(f"not an address or network: {printable(text, limit=60)!r}") from None
    return tuple(networks)


def normalise_ip(text: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an address; unwrap IPv4-in-IPv6; None if it is not an address at all."""
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def valid_url(url: str | None) -> bool:
    """A plain absolute URL with a public host and nothing that could be abused downstream."""
    if not url or len(url) > MAX_URL_LENGTH or not url.isascii():
        return False
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018  (raises ValueError on a bad port)
    except ValueError:
        return False
    if parts.scheme not in _URL_SCHEMES or not host:
        return False
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return False
    address = normalise_ip(host)
    return address is None or address.is_global


# --- collecting ------------------------------------------------------------------


def _chunks(items: Sequence[str]) -> Iterator[Sequence[str]]:
    for start in range(0, len(items), CHUNK):
        yield items[start : start + CHUNK]


def _aware(value: datetime | None) -> datetime | None:
    return None if value is None else value.astimezone(UTC)


def _address_indicators(
    db: Session, since: datetime, now: datetime, filters: Filters, summary: Summary
) -> list[Indicator]:
    window = (HoneypotSession.start_time >= since) & HoneypotSession.internal.is_(False)
    rows = db.execute(
        select(
            HoneypotSession.src_ip,
            func.min(HoneypotSession.start_time),
            func.max(HoneypotSession.start_time),
            func.count(),
        )
        .where(HoneypotSession.src_ip.is_not(None), window)
        .group_by(HoneypotSession.src_ip)
    ).all()

    chosen: dict[str, tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, datetime, int]] = {}
    for raw_ip, _first, last, count in rows:
        address = normalise_ip(raw_ip)
        if address is None or last is None:
            summary.invalid += 1
            continue
        if not filters.include_private and not address.is_global:
            summary.non_public += 1
            continue
        if any(address in network for network in filters.exclude):
            summary.excluded += 1
            continue
        key = str(address)
        previous = chosen.get(key)
        if previous is None:
            chosen[key] = (address, last, count)
        else:  # the same address stored in two spellings
            chosen[key] = (address, max(previous[1], last), previous[2] + count)
    if not chosen:
        return []

    spellings: dict[str, list[str]] = {}  # an address can be stored in more than one spelling
    for raw, *_ in rows:
        address = normalise_ip(raw)
        if address is not None and raw is not None:
            spellings.setdefault(str(address), []).append(raw)

    def sessions_with(model: Any, *extra: ColumnElement[bool]) -> set[str]:
        query = (
            select(HoneypotSession.src_ip)
            .join(model, model.session_id == HoneypotSession.id)
            .where(window, *extra)
            .distinct()
        )
        found: set[str] = set()
        for (raw,) in db.execute(query):
            address = normalise_ip(raw)
            if address is not None:
                found.add(str(address))
        return found

    accepted = sessions_with(Login, Login.success.is_(True))
    hands_on = sessions_with(Command)
    acted = (
        sessions_with(Download)
        | sessions_with(Upload)
        | sessions_with(TunnelRequest)
        | sessions_with(FetchAttempt)
    )

    failed: dict[str, int] = {}
    for raw, count in db.execute(
        select(HoneypotSession.src_ip, func.count())
        .join(Login, Login.session_id == HoneypotSession.id)
        .where(window, Login.success.is_(False))
        .group_by(HoneypotSession.src_ip)
    ):
        address = normalise_ip(raw)
        if address is not None:
            failed[str(address)] = failed.get(str(address), 0) + count

    minimum = LEVELS.index(filters.min_level)
    selected: dict[str, str] = {}
    for key in chosen:
        if key in acted:
            level = "action"
        elif key in hands_on:
            level = "hands-on"
        elif key in accepted:
            level = "access"
        elif failed.get(key, 0) >= GUESSING_THRESHOLD:
            level = "guessing"
        else:
            level = "contact"
        if LEVELS.index(level) >= minimum:
            selected[key] = level
    if not selected:
        return []

    raws = [raw for key in selected for raw in spellings.get(key, [])]
    first_ever: dict[str, datetime] = {}
    geo: dict[str, IpGeo] = {}
    abuse: dict[str, int | None] = {}
    tor: dict[str, bool | None] = {}
    techniques: dict[str, set[str]] = {}
    for part in _chunks(raws):
        for raw, first in db.execute(
            select(HoneypotSession.src_ip, func.min(HoneypotSession.start_time))
            .where(HoneypotSession.src_ip.in_(part), HoneypotSession.start_time.is_not(None))
            .group_by(HoneypotSession.src_ip)
        ):
            address = normalise_ip(raw)
            if address is not None and first is not None:
                key = str(address)
                first_ever[key] = min(first_ever.get(key, first), first)
        for row in db.scalars(select(IpGeo).where(IpGeo.ip.in_(part))):
            address = normalise_ip(row.ip)
            if address is not None:
                geo[str(address)] = row
        for intel in db.scalars(select(IpIntel).where(IpIntel.ip.in_(part))):
            address = normalise_ip(intel.ip)
            if address is None:
                continue
            if intel.provider == "abuseipdb":
                abuse[str(address)] = intel.score
            elif intel.provider == "tor":
                tor[str(address)] = intel.flagged
        for raw, technique in db.execute(
            select(HoneypotSession.src_ip, TechniqueMatch.technique_id)
            .join(TechniqueMatch, TechniqueMatch.session_id == HoneypotSession.id)
            .where(HoneypotSession.src_ip.in_(part), window)
            .distinct()
        ):
            address = normalise_ip(raw)
            if address is not None:
                techniques.setdefault(str(address), set()).add(technique)

    result: list[Indicator] = []
    for key, level in selected.items():
        address, last, count = chosen[key]
        score = abuse.get(key)
        confidence = LEVEL_CONFIDENCE[level] + (10 if score is not None and score >= 50 else 0)
        place = geo.get(key)
        first = first_ever.get(key, last)
        result.append(
            Indicator(
                kind="ipv4" if address.version == 4 else "ipv6",
                value=key,
                first_seen=_aware(first) or now,
                last_seen=_aware(last) or now,
                sessions=count,
                confidence=min(confidence, 95),
                level=level,
                country=place.country_code if place else None,
                asn=place.asn if place else None,
                as_org=place.as_org if place else None,
                abuse_score=score,
                tor=tor.get(key),
                techniques=tuple(sorted(techniques.get(key, ()))[:MAX_TECHNIQUES]),
            )
        )
    return result


@dataclass
class _FileSeen:
    last: datetime
    sessions: int = 0
    notes: list[str] = field(default_factory=list)


def _file_indicators(
    db: Session, since: datetime, now: datetime, summary: Summary
) -> list[Indicator]:
    found: dict[str, _FileSeen] = {}
    for model, sample_column, label in (
        (Download, Download.url, "downloaded"),
        (Upload, Upload.filename, "uploaded"),
    ):
        rows = db.execute(
            select(
                model.sha256,
                func.min(HoneypotSession.start_time),
                func.max(HoneypotSession.start_time),
                func.count(HoneypotSession.id.distinct()),
                func.min(sample_column),
            )
            .join(HoneypotSession, HoneypotSession.id == model.session_id)
            .where(
                model.sha256.is_not(None),
                HoneypotSession.start_time >= since,
                HoneypotSession.internal.is_(False),
            )
            .group_by(model.sha256)
        ).all()
        for sha, _first, last, count, sample in rows:
            digest = (sha or "").lower()
            if not _SHA256.fullmatch(digest):
                summary.invalid += 1
                continue
            if digest == EMPTY_SHA256:
                continue
            if last is None:
                summary.invalid += 1
                continue
            entry = found.setdefault(digest, _FileSeen(last=last))
            entry.last = max(entry.last, last)
            entry.sessions += count
            entry.notes.append(f"{label} {printable(sample, limit=100)}" if sample else label)
    if not found:
        return []

    hashes = sorted(found)
    first_ever: dict[str, datetime] = {}
    intel: dict[str, FileIntel] = {}
    for part in _chunks(hashes):
        for model in (Download, Upload):
            for sha, first in db.execute(
                select(model.sha256, func.min(HoneypotSession.start_time))
                .join(HoneypotSession, HoneypotSession.id == model.session_id)
                .where(model.sha256.in_(part), HoneypotSession.start_time.is_not(None))
                .group_by(model.sha256)
            ):
                if sha and first is not None:
                    key = sha.lower()
                    first_ever[key] = min(first_ever.get(key, first), first)
        for row in db.scalars(
            select(FileIntel).where(FileIntel.sha256.in_(part), FileIntel.provider == "virustotal")
        ):
            intel[row.sha256.lower()] = row

    result: list[Indicator] = []
    for digest in hashes:
        entry = found[digest]
        verdict = intel.get(digest)
        confidence = 60
        malicious = engines = None
        if verdict is not None and verdict.found:
            malicious, engines = verdict.malicious, verdict.engines
            if (malicious or 0) >= 5:
                confidence = 90
            elif (malicious or 0) >= 1:
                confidence = 75
            else:
                confidence = 30
        last = _aware(entry.last)
        result.append(
            Indicator(
                kind="sha256",
                value=digest,
                first_seen=_aware(first_ever.get(digest)) or last or now,
                last_seen=last or now,
                sessions=entry.sessions,
                confidence=confidence,
                vt_malicious=malicious,
                vt_engines=engines,
                detail="; ".join(sorted(set(entry.notes))[:3]),
            )
        )
    return result


def _url_indicators(
    db: Session, since: datetime, now: datetime, summary: Summary
) -> list[Indicator]:
    """Addresses downloaded or only attempted (egress blocked); one count per session."""
    seen = union(
        select(Download.url.label("url"), Download.session_id.label("sid")).where(
            Download.url.is_not(None)
        ),
        select(FetchAttempt.url.label("url"), FetchAttempt.session_id.label("sid")),
    ).subquery()
    rows = db.execute(
        select(
            seen.c.url,
            func.max(HoneypotSession.start_time),
            func.count(HoneypotSession.id.distinct()),
        )
        .join(HoneypotSession, HoneypotSession.id == seen.c.sid)
        .where(HoneypotSession.start_time >= since, HoneypotSession.internal.is_(False))
        .group_by(seen.c.url)
    ).all()
    good: list[tuple[str, datetime, int]] = []
    for url, last, count in rows:
        if url is not None and valid_url(url) and last is not None:
            good.append((url, last, count))
        else:
            summary.invalid += 1
    first_ever: dict[str, datetime] = {}
    fetched: set[str] = set()
    for part in _chunks([url for url, _, _ in good]):
        for model in (Download, FetchAttempt):
            for seen_url, first in db.execute(
                select(model.url, func.min(HoneypotSession.start_time))
                .join(HoneypotSession, HoneypotSession.id == model.session_id)
                .where(model.url.in_(part), HoneypotSession.start_time.is_not(None))
                .group_by(model.url)
            ):
                if seen_url is not None and first is not None:
                    first_ever[seen_url] = min(first_ever.get(seen_url, first), first)
                    if model is Download:
                        fetched.add(seen_url)
    return [
        Indicator(
            kind="url",
            value=url,
            first_seen=_aware(first_ever.get(url)) or _aware(last) or now,
            last_seen=_aware(last) or now,
            sessions=count,
            confidence=60 if url in fetched else 50,  # attempted only: never seen to deliver
        )
        for url, last, count in good
    ]


def collect(
    db: Session, *, now: datetime | None = None, filters: Filters | None = None
) -> tuple[list[Indicator], Summary]:
    """Gather indicators seen in the last ``filters.days`` days, most confident first."""
    filters = filters or Filters()
    if filters.min_level not in LEVELS:
        raise ValueError(f"unknown level {filters.min_level!r}; choose from {', '.join(LEVELS)}")
    if filters.days < 1:
        raise ValueError("days must be at least 1")
    if not 0 <= filters.min_confidence <= 100:
        raise ValueError("min-confidence must be between 0 and 100")
    unknown = set(filters.types) - set(TYPES)
    if unknown:
        raise ValueError(f"unknown type(s): {', '.join(sorted(unknown))}")
    now = (now or datetime.now(UTC)).astimezone(UTC)
    since = now - timedelta(days=filters.days)
    summary = Summary()

    indicators: list[Indicator] = []
    if "ip" in filters.types:
        indicators += _address_indicators(db, since, now, filters, summary)
    if "file" in filters.types:
        indicators += _file_indicators(db, since, now, summary)
    if "url" in filters.types:
        indicators += _url_indicators(db, since, now, summary)

    order = {"ipv4": 0, "ipv6": 1, "sha256": 2, "url": 3}
    indicators = [i for i in indicators if i.confidence >= filters.min_confidence]
    indicators.sort(key=lambda i: (-i.confidence, order[i.kind], _sort_value(i)))
    for item in indicators:
        summary.counts[item.kind] = summary.counts.get(item.kind, 0) + 1
    return indicators, summary


def _sort_value(item: Indicator) -> tuple[int, int | str]:
    if item.is_address:
        return (0, int(ipaddress.ip_address(item.value)))
    return (1, item.value)


# --- writers -----------------------------------------------------------------------


def _stamp(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cell(value: object) -> str:
    """Text for a spreadsheet cell: visible escapes for control characters, no formulas."""
    if value is None:
        return ""
    text = printable(value, limit=300) if isinstance(value, str) else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def to_csv(indicators: Sequence[Indicator]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for item in indicators:
        writer.writerow(
            [
                _cell(item.kind),
                _cell(item.value),
                _stamp(item.first_seen),
                _stamp(item.last_seen),
                item.sessions,
                _cell(item.level),
                item.confidence,
                _cell(item.country),
                _cell(item.asn),
                _cell(item.as_org),
                _cell(item.abuse_score),
                "" if item.tor is None else ("yes" if item.tor else "no"),
                _cell(item.vt_malicious),
                _cell(item.vt_engines),
                " ".join(item.techniques),
                _cell(item.detail),
            ]
        )
    return out.getvalue()


def _addresses(indicators: Sequence[Indicator]) -> list[Indicator]:
    return [item for item in indicators if item.is_address]


def to_blocklist(indicators: Sequence[Indicator], *, now: datetime, filters: Filters) -> str:
    """One address per line. Expiry is the window: an address that stops attacking drops out."""
    addresses = _addresses(indicators)
    lines = [
        "# Surya Kundal blocklist",
        f"# generated {_stamp(now)}",
        f"# addresses seen in the last {filters.days} days, minimum activity: {filters.min_level}",
        "# regenerate regularly: an address leaves the list once it has been quiet for the window",
    ]
    lines += [item.value for item in sorted(addresses, key=_sort_value)]
    return "\n".join(lines) + "\n"


def to_nftables(indicators: Sequence[Indicator], *, now: datetime, filters: Filters) -> str:
    """An nftables script whose entries remove themselves when their time runs out.

    The script only creates a table with two sets; it blocks nothing until a rule of
    yours refers to them, for example ``ip saddr @blocklist_v4 drop``. Loading it again
    replaces the contents, so run it on a schedule.
    """
    lines = [
        "# Surya Kundal blocklist for nftables",
        f"# generated {_stamp(now)}",
        f"# addresses seen in the last {filters.days} days, minimum activity: {filters.min_level}",
        "# This creates the sets only. Block with a rule of your own, e.g.:",
        "#   nft add rule inet filter input ip saddr @surya_kundal_v4 drop",
        "add table inet surya_kundal",
    ]
    for version, name, kind in (
        (4, "surya_kundal_v4", "ipv4_addr"),
        (6, "surya_kundal_v6", "ipv6_addr"),
    ):
        lines.append(f"add set inet surya_kundal {name} {{ type {kind}; flags timeout; }}")
        lines.append(f"flush set inet surya_kundal {name}")
        members = [
            item
            for item in sorted(_addresses(indicators), key=_sort_value)
            if item.kind == f"ipv{version}"
        ]
        elements = []
        for item in members:
            remaining = int((item.last_seen + timedelta(days=filters.days) - now).total_seconds())
            elements.append(f"{item.value} timeout {max(remaining, 60)}s")
        for start in range(0, len(elements), CHUNK):
            body = ", ".join(elements[start : start + CHUNK])
            lines.append(f"add element inet surya_kundal {name} {{ {body} }}")
    return "\n".join(lines) + "\n"


def _stix_time(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _pattern_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _pattern(item: Indicator) -> str:
    if item.kind == "ipv4":
        return f"[ipv4-addr:value = {_pattern_string(item.value)}]"
    if item.kind == "ipv6":
        return f"[ipv6-addr:value = {_pattern_string(item.value)}]"
    if item.kind == "sha256":
        return f"[file:hashes.'SHA-256' = {_pattern_string(item.value)}]"
    return f"[url:value = {_pattern_string(item.value)}]"


def _attack_reference(technique: str) -> dict[str, str]:
    path = technique.replace(".", "/")
    return {
        "source_name": "mitre-attack",
        "external_id": technique,
        "url": f"https://attack.mitre.org/techniques/{path}/",
    }


def _description(item: Indicator) -> str:
    where = f"{item.sessions} session{'s' if item.sessions != 1 else ''}"
    if item.is_address:
        parts = [
            f"Client address seen in {where} on an SSH honeypot; furthest stage: {item.level}."
        ]
        if item.country:
            parts.append(f"Country: {item.country}.")
        if item.asn:
            parts.append(f"AS{item.asn}.")
        if item.abuse_score is not None:
            parts.append(f"AbuseIPDB confidence score: {item.abuse_score}.")
        if item.tor:
            parts.append("Tor exit node: the address may be shared by many unrelated users.")
        return " ".join(parts)
    if item.kind == "sha256":
        text = f"File seen in {where} on an SSH honeypot."
        if item.vt_engines:
            text += f" VirusTotal: {item.vt_malicious or 0} of {item.vt_engines} engines flag it."
        return text
    return f"URL an attacker downloaded from, seen in {where} on an SSH honeypot."


def _title(item: Indicator) -> str:
    if item.is_address:
        return f"Hostile SSH client {item.value}"
    if item.kind == "sha256":
        return f"Attacker file {item.value[:16]}"
    return "Malware download URL"


def to_stix(
    indicators: Sequence[Indicator],
    *,
    now: datetime,
    filters: Filters,
    author: str = "Surya Kundal honeypot",
) -> dict[str, object]:
    """A STIX 2.1 bundle: one identity and one indicator per exported value."""
    identity_id = f"identity--{uuid.uuid5(NAMESPACE, 'identity:' + author)}"
    objects: list[dict[str, object]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": _stix_time(datetime(2026, 1, 1, tzinfo=UTC)),
            "modified": _stix_time(datetime(2026, 1, 1, tzinfo=UTC)),
            "name": author,
            "identity_class": "system",
        }
    ]
    stamp = _stix_time(now)
    for item in indicators:
        pattern = _pattern(item)
        valid_from = item.first_seen
        record: dict[str, object] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(NAMESPACE, pattern)}",
            "created_by_ref": identity_id,
            "created": _stix_time(valid_from),
            "modified": stamp,
            "name": _title(item),
            "description": _description(item),
            "indicator_types": [
                "malicious-activity"
                if item.kind in ("sha256", "url") or item.level in ("hands-on", "action")
                else "anomalous-activity"
            ],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": _stix_time(valid_from),
            "confidence": item.confidence,
            "labels": ["honeypot"],
        }
        if item.kind != "sha256":
            record["valid_until"] = _stix_time(item.last_seen + timedelta(days=filters.days))
        if item.techniques:
            record["external_references"] = [_attack_reference(t) for t in item.techniques]
        objects.append(record)
    ids = ",".join(str(o["id"]) for o in objects)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(NAMESPACE, f'{ids}@{stamp}')}",
        "objects": objects,
    }


def render(
    indicators: Sequence[Indicator],
    fmt: str,
    *,
    now: datetime,
    filters: Filters,
    author: str = "Surya Kundal honeypot",
) -> str:
    if fmt == "csv":
        return to_csv(indicators)
    if fmt == "stix":
        return (
            json.dumps(to_stix(indicators, now=now, filters=filters, author=author), indent=2)
            + "\n"
        )
    if fmt == "blocklist":
        return to_blocklist(indicators, now=now, filters=filters)
    if fmt == "nftables":
        return to_nftables(indicators, now=now, filters=filters)
    raise ValueError(f"unknown format {fmt!r}")


def write_atomically(path: Path, text: str) -> None:
    """Write so a reader never sees half a file: temp file in the same folder, then rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise
