"""SQLAlchemy models for captured honeypot sessions.

One row per attacker visit in ``sessions``; the things that happened during the
visit hang off it in ``logins``, ``commands`` and ``downloads``. Threat-intel
results live in ``ip_geo``, ``ip_intel`` and ``file_intel`` (keyed by IP address or
file hash, so each is looked up once however many sessions share it). ATT&CK tables
are added in their own phase.

Rows are only ever added, never rewritten, so other tables can safely point at a
command or download by ID.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    """Declarative base for all tables."""


class UTCDateTime(TypeDecorator[datetime]):
    """A DateTime that is always timezone-aware UTC in Python.

    SQLite has no real timezone support and silently returns naive datetimes.
    This type refuses naive values on the way in and restores UTC on the way
    out, so timestamps never get misread as local time.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Naive datetime not allowed; pass a timezone-aware value")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class HoneypotSession(Base):
    """One attacker visit, identified by Cowrie's own session ID."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    start_time: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    end_time: Mapped[datetime | None] = mapped_column(UTCDateTime)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    client_version: Mapped[str | None] = mapped_column(Text)
    hassh: Mapped[str | None] = mapped_column(String(32), index=True)

    # Children are listed in the order they happened (timestamp, then insertion order).
    logins: Mapped[list[Login]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by=lambda: (Login.timestamp, Login.id),
    )
    commands: Mapped[list[Command]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by=lambda: (Command.timestamp, Command.id),
    )
    downloads: Mapped[list[Download]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by=lambda: (Download.timestamp, Download.id),
    )
    uploads: Mapped[list[Upload]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by=lambda: (Upload.timestamp, Upload.id),
    )
    tunnels: Mapped[list[TunnelRequest]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by=lambda: (TunnelRequest.timestamp, TunnelRequest.id),
    )

    def __repr__(self) -> str:
        return f"<HoneypotSession {self.id} from {self.src_ip}>"


class Login(Base):
    """One credential attempt (failed or successful).

    The unique constraint is the event's natural identity, so seeing the same
    log line twice can never create a second row.
    """

    __tablename__ = "logins"
    __table_args__ = (
        UniqueConstraint(
            "session_id", "timestamp", "username", "password", "success", name="uq_login_event"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    username: Mapped[str | None] = mapped_column(Text)
    password: Mapped[str | None] = mapped_column(Text)
    success: Mapped[bool] = mapped_column(Boolean)
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)

    session: Mapped[HoneypotSession] = relationship(back_populates="logins")


class Command(Base):
    """One command typed by the attacker. Ordered by timestamp, then insertion order."""

    __tablename__ = "commands"
    __table_args__ = (
        UniqueConstraint("session_id", "timestamp", "command", name="uq_command_event"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    command: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)

    session: Mapped[HoneypotSession] = relationship(back_populates="commands")


class Download(Base):
    """A file the attacker pulled onto the honeypot (wget/curl)."""

    __tablename__ = "downloads"
    __table_args__ = (
        UniqueConstraint("session_id", "timestamp", "url", "sha256", name="uq_download_event"),
        Index("ix_downloads_sha256", "sha256"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)

    session: Mapped[HoneypotSession] = relationship(back_populates="downloads")


class Upload(Base):
    """A file the attacker sent to the honeypot over SFTP or SCP."""

    __tablename__ = "uploads"
    __table_args__ = (
        UniqueConstraint("session_id", "timestamp", "filename", "sha256", name="uq_upload_event"),
        Index("ix_uploads_sha256", "sha256"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(Text, default="")
    destination: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)

    session: Mapped[HoneypotSession] = relationship(back_populates="uploads")


class TunnelRequest(Base):
    """An attempt to use the honeypot as a relay (SSH direct-tcpip port forwarding)."""

    __tablename__ = "tunnel_requests"
    __table_args__ = (
        UniqueConstraint(
            "session_id",
            "timestamp",
            "dst_ip",
            "dst_port",
            "orig_ip",
            "orig_port",
            name="uq_tunnel_event",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    dst_ip: Mapped[str] = mapped_column(Text, default="")
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    orig_ip: Mapped[str] = mapped_column(Text, default="")
    orig_port: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)

    session: Mapped[HoneypotSession] = relationship(back_populates="tunnels")


class IpGeo(Base):
    """Offline geolocation and ASN facts for one IP (MaxMind GeoLite2)."""

    __tablename__ = "ip_geo"

    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    country_code: Mapped[str | None] = mapped_column(String(2), index=True)
    country_name: Mapped[str | None] = mapped_column(String(128))
    city: Mapped[str | None] = mapped_column(String(128))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    accuracy_radius_km: Mapped[int | None] = mapped_column(Integer)
    asn: Mapped[int | None] = mapped_column(Integer, index=True)
    as_org: Mapped[str | None] = mapped_column(String(255))
    looked_up_at: Mapped[datetime] = mapped_column(UTCDateTime)


class IpIntel(Base):
    """One provider's verdict on one IP. Provider-agnostic: new providers need no migration.

    ``score`` is a 0-100 risk score when the provider supplies one (AbuseIPDB's
    confidence score). ``flagged`` is a yes/no fact (Tor: is a current exit node).
    ``payload`` keeps the provider's answer so nothing is lost.
    """

    __tablename__ = "ip_intel"
    __table_args__ = (UniqueConstraint("ip", "provider", name="uq_ip_intel_provider"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    score: Mapped[int | None] = mapped_column(Integer)
    flagged: Mapped[bool | None] = mapped_column(Boolean)
    payload: Mapped[dict | None] = mapped_column(JSON)


class FileIntel(Base):
    """One provider's verdict on a file hash that an attacker downloaded."""

    __tablename__ = "file_intel"
    __table_args__ = (UniqueConstraint("sha256", "provider", name="uq_file_intel_provider"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    found: Mapped[bool] = mapped_column(Boolean)
    malicious: Mapped[int | None] = mapped_column(Integer)
    suspicious: Mapped[int | None] = mapped_column(Integer)
    engines: Mapped[int | None] = mapped_column(Integer)
    label: Mapped[str | None] = mapped_column(String(255))
    payload: Mapped[dict | None] = mapped_column(JSON)


class SessionMapping(Base):
    """Records that a session was mapped to ATT&CK, and from what.

    A session is mapped again when its commands or logins change, or when the rule
    set changes, so the matches below are always derived from current data.
    """

    __tablename__ = "session_mappings"

    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), primary_key=True
    )
    ruleset_version: Mapped[str] = mapped_column(String(16))
    attack_version: Mapped[str] = mapped_column(String(16))
    command_count: Mapped[int] = mapped_column(Integer)
    login_count: Mapped[int] = mapped_column(Integer)
    transfer_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    tunnel_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    mapped_at: Mapped[datetime] = mapped_column(UTCDateTime)


class TechniqueMatch(Base):
    """One rule firing: a technique seen in a session, usually tied to one command.

    ``command_id`` is empty for session-level evidence such as password guessing.
    These rows are derived data and are rebuilt whenever a session is re-mapped.
    """

    __tablename__ = "technique_matches"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    command_id: Mapped[int | None] = mapped_column(
        ForeignKey("commands.id", ondelete="CASCADE"), index=True
    )
    technique_id: Mapped[str] = mapped_column(String(12), index=True)
    tactics: Mapped[str] = mapped_column(String(255))  # comma-separated, e.g. "stealth,persistence"
    rule_id: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[str] = mapped_column(String(8))
    evidence: Mapped[str] = mapped_column(String(300))
