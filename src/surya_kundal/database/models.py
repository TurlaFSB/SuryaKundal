"""SQLAlchemy models for captured honeypot sessions.

One row per attacker visit in ``sessions``; the things that happened during the
visit hang off it in ``logins``, ``commands`` and ``downloads``. Threat-intel and
ATT&CK tables are added in their own phases.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
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

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Naive datetime not allowed; pass a timezone-aware value")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
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
    client_version: Mapped[str | None] = mapped_column(String(255))
    hassh: Mapped[str | None] = mapped_column(String(32), index=True)

    logins: Mapped[list[Login]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="Login.id",
    )
    commands: Mapped[list[Command]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="Command.seq",
    )
    downloads: Mapped[list[Download]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="Download.id",
    )

    def __repr__(self) -> str:
        return f"<HoneypotSession {self.id} from {self.src_ip}>"


class Login(Base):
    """One credential attempt (failed or successful)."""

    __tablename__ = "logins"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    username: Mapped[str | None] = mapped_column(String(255))
    password: Mapped[str | None] = mapped_column(String(255))
    success: Mapped[bool] = mapped_column(Boolean)
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)

    session: Mapped[HoneypotSession] = relationship(back_populates="logins")


class Command(Base):
    """One command typed by the attacker. ``seq`` preserves typing order."""

    __tablename__ = "commands"
    __table_args__ = (UniqueConstraint("session_id", "seq", name="uq_command_session_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    seq: Mapped[int] = mapped_column(Integer)
    command: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)

    session: Mapped[HoneypotSession] = relationship(back_populates="commands")


class Download(Base):
    """A file the attacker pulled onto the honeypot (wget/curl)."""

    __tablename__ = "downloads"
    __table_args__ = (Index("ix_downloads_sha256", "sha256"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)

    session: Mapped[HoneypotSession] = relationship(back_populates="downloads")
