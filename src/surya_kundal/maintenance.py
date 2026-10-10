"""Keeping the database safe and bounded: backup, restore and retention.

Backups use SQLite's online backup API, so they are consistent while the pipeline is writing and
need no downtime. A restore refuses to overwrite anything unless told to, and keeps a copy of what
it replaced. Pruning only ever deletes whole sessions older than a cutoff, and only when asked.
"""

from __future__ import annotations

import contextlib
import gzip
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from alembic.script import ScriptDirectory
from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult, make_url
from sqlalchemy.orm import Session

from surya_kundal.database.migrate import alembic_config
from surya_kundal.database.models import (
    Command,
    Download,
    FileIntel,
    HoneypotSession,
    IpGeo,
    IpIntel,
    Login,
    TunnelRequest,
    Upload,
)

BACKUP_PREFIX = "surya-kundal-"
BACKUP_SUFFIXES = (".db", ".db.gz")


class MaintenanceError(RuntimeError):
    """A backup, restore or prune could not be done safely."""


def sqlite_file(url: str) -> Path:
    """The database file behind a SQLite URL, or an error for anything else."""
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite" or parsed.database in (None, "", ":memory:"):
        raise MaintenanceError(
            "backup and restore work on SQLite files; back up other databases with their own tools"
        )
    return Path(str(parsed.database))


def _stamp(now: datetime) -> str:
    return now.astimezone(UTC).strftime("%Y%m%d-%H%M%S")


# --- verification ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Verification:
    sessions: int
    revision: str | None


def _known_revisions() -> set[str]:
    script = ScriptDirectory.from_config(alembic_config())
    return {r.revision for r in script.walk_revisions()}


def verify_file(path: Path) -> Verification:
    """Open a plain SQLite file read-only and check it is intact and not from a newer version."""
    uri = f"file:{path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise MaintenanceError(f"cannot open {path.name}: {exc}") from exc
    try:
        try:
            verdict = conn.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as exc:
            raise MaintenanceError(f"{path.name} is not a readable SQLite database: {exc}") from exc
        if not verdict or verdict[0] != "ok":
            raise MaintenanceError(f"{path.name} failed the SQLite integrity check: {verdict}")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "sessions" not in tables:
            raise MaintenanceError(
                f"{path.name} is not a Surya Kundal database (no sessions table)"
            )
        revision = None
        if "alembic_version" in tables:
            row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
            revision = row[0] if row else None
        if revision and revision not in _known_revisions():
            raise MaintenanceError(
                f"{path.name} is from a newer version of Surya Kundal (schema {revision}); "
                "upgrade the program before restoring it"
            )
        sessions = conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
        return Verification(sessions=int(sessions), revision=revision)
    finally:
        conn.close()


def verify_backup(path: Path) -> Verification:
    """Verify a backup file, decompressing a .gz one into a scratch directory first."""
    if not path.is_file():
        raise MaintenanceError(f"backup not found: {path}")
    if path.suffix != ".gz":
        return verify_file(path)
    # next to the backup, not in /tmp: the container's /tmp is a small memory-backed area
    with tempfile.TemporaryDirectory(prefix=".sk-verify-", dir=path.parent) as scratch:
        plain = Path(scratch) / "backup.db"
        try:
            with gzip.open(path, "rb") as src, plain.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        except (OSError, EOFError) as exc:
            raise MaintenanceError(f"{path.name} is not a valid gzip file: {exc}") from exc
        return verify_file(plain)


# --- backup ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class BackupResult:
    path: Path
    size: int
    sessions: int
    removed: tuple[Path, ...]


def _copy_with_backup_api(source: Path, destination: Path) -> None:
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        dst = sqlite3.connect(destination)
        try:
            src.backup(dst)
            # The live database is in WAL mode, which would leave -wal/-shm files beside every
            # copy that is opened. A backup should be one self-contained file.
            dst.execute("PRAGMA journal_mode=DELETE")
        finally:
            dst.close()
    finally:
        src.close()


def list_backups(directory: Path) -> list[Path]:
    """Backups in ``directory``, oldest first (the timestamp in the name sorts correctly)."""
    if not directory.is_dir():
        return []
    found = [
        p
        for p in directory.iterdir()
        if p.name.startswith(BACKUP_PREFIX) and p.name.endswith(BACKUP_SUFFIXES)
    ]
    return sorted(found, key=lambda p: p.name)


def backup_database(
    url: str,
    directory: Path,
    *,
    keep: int | None = None,
    compress: bool = False,
    now: datetime | None = None,
) -> BackupResult:
    """Write a verified, private copy of the database; optionally keep only the newest ``keep``."""
    source = sqlite_file(url)
    if not source.is_file():
        raise MaintenanceError(f"database not found: {source}")
    if keep is not None and keep < 1:
        raise MaintenanceError("--keep must be at least 1")
    now = now or datetime.now(UTC)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    final = directory / f"{BACKUP_PREFIX}{_stamp(now)}.db{'.gz' if compress else ''}"
    if final.exists():
        raise MaintenanceError(f"{final.name} already exists; wait a second and try again")

    scratch = Path(tempfile.mkdtemp(prefix=".sk-backup-", dir=directory))
    try:
        plain = scratch / "copy.db"
        _copy_with_backup_api(source, plain)
        os.chmod(plain, 0o600)
        check = verify_file(plain)  # never keep a backup that cannot be restored
        staged = plain
        if compress:
            staged = scratch / "copy.db.gz"
            with plain.open("rb") as src, gzip.open(staged, "wb", compresslevel=6) as dst:
                shutil.copyfileobj(src, dst)
            os.chmod(staged, 0o600)
        os.replace(staged, final)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    removed: list[Path] = []
    if keep is not None:
        old = [p for p in list_backups(directory) if p != final]
        for victim in old[: max(0, len(old) - (keep - 1))]:
            victim.unlink()
            removed.append(victim)
    return BackupResult(final, final.stat().st_size, check.sessions, tuple(removed))


# --- restore -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class RestoreResult:
    target: Path
    sessions: int
    safety_copy: Path | None


def restore_database(
    backup: Path, url: str, *, force: bool = False, now: datetime | None = None
) -> RestoreResult:
    """Put a verified backup in place of the database. Stop the pipeline and dashboard first."""
    target = sqlite_file(url)
    check = verify_backup(backup)
    safety: Path | None = None
    if target.exists():
        if not force:
            raise MaintenanceError(
                f"{target} already exists; pass --force to replace it "
                "(a copy of it is kept next to it first)"
            )
        safety = target.with_name(
            f"{target.name}.before-restore-{_stamp(now or datetime.now(UTC))}"
        )
        _copy_with_backup_api(target, safety)
        os.chmod(safety, 0o600)
    target.parent.mkdir(parents=True, exist_ok=True)

    staged = target.with_name(f".{target.name}.restore")
    try:
        if backup.suffix == ".gz":
            with gzip.open(backup, "rb") as src, staged.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        else:
            shutil.copyfile(backup, staged)
        os.chmod(staged, 0o600)
        # A leftover write-ahead log from the old database would be replayed onto the new one.
        for extra in ("-wal", "-shm"):
            with contextlib.suppress(FileNotFoundError):
                Path(f"{target}{extra}").unlink()
        os.replace(staged, target)
    finally:
        with contextlib.suppress(FileNotFoundError):
            staged.unlink()
    return RestoreResult(target, check.sessions, safety)


# --- retention ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class PruneResult:
    cutoff: datetime
    sessions: int
    logins: int
    commands: int
    transfers: int
    tunnels: int
    orphan_ips: int
    orphan_files: int
    deleted: bool


def prune_database(
    db: Session, *, older_than_days: int, dry_run: bool = True, now: datetime | None = None
) -> PruneResult:
    """Delete sessions that ended before the cutoff, with everything hanging off them."""
    if older_than_days < 1:
        raise MaintenanceError("--older-than must be at least 1 day")
    cutoff = (now or datetime.now(UTC)) - timedelta(days=older_than_days)
    moment = func.coalesce(HoneypotSession.end_time, HoneypotSession.start_time)
    old = select(HoneypotSession.id).where(moment < cutoff)

    def count(model: type, column: Any) -> int:
        return db.scalar(select(func.count()).select_from(model).where(column.in_(old))) or 0

    sessions = db.scalar(select(func.count()).select_from(old.subquery())) or 0
    counts = {
        "sessions": sessions,
        "logins": count(Login, Login.session_id),
        "commands": count(Command, Command.session_id),
        "transfers": count(Download, Download.session_id) + count(Upload, Upload.session_id),
        "tunnels": count(TunnelRequest, TunnelRequest.session_id),
    }
    if dry_run or not sessions:
        orphans = (0, 0)
        if not dry_run:
            orphans = _delete_orphans(db)
        return PruneResult(
            cutoff, **counts, orphan_ips=orphans[0], orphan_files=orphans[1], deleted=False
        )

    # The database cascades to logins, commands, transfers, mappings, techniques and campaign
    # links (foreign keys are switched on for every write connection).
    db.execute(delete(HoneypotSession).where(HoneypotSession.id.in_(old)))
    db.flush()
    orphan_ips, orphan_files = _delete_orphans(db)
    db.commit()
    return PruneResult(
        cutoff, **counts, orphan_ips=orphan_ips, orphan_files=orphan_files, deleted=True
    )


def _deleted(db: Session, statement: Any) -> int:
    return cast(CursorResult[Any], db.execute(statement)).rowcount or 0


def _delete_orphans(db: Session) -> tuple[int, int]:
    """Drop cached lookups for addresses and files no remaining session refers to."""
    live_ips = select(HoneypotSession.src_ip).where(HoneypotSession.src_ip.is_not(None))
    ips = _deleted(db, delete(IpGeo).where(IpGeo.ip.not_in(live_ips)))
    ips += _deleted(db, delete(IpIntel).where(IpIntel.ip.not_in(live_ips)))
    live_files = (
        select(Download.sha256)
        .where(Download.sha256.is_not(None))
        .union(select(Upload.sha256).where(Upload.sha256.is_not(None)))
    )
    files = _deleted(db, delete(FileIntel).where(FileIntel.sha256.not_in(live_files)))
    return ips, files


def vacuum(url: str) -> tuple[int, int]:
    """Return freed space to the filesystem. Returns the file size before and after."""
    path = sqlite_file(url)
    before = path.stat().st_size
    # VACUUM writes a full temporary copy; keep it beside the database, not in a small /tmp.
    previous = os.environ.get("SQLITE_TMPDIR")
    os.environ["SQLITE_TMPDIR"] = str(path.parent)
    conn = sqlite3.connect(path, timeout=30)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
    finally:
        conn.close()
        if previous is None:
            os.environ.pop("SQLITE_TMPDIR", None)
        else:
            os.environ["SQLITE_TMPDIR"] = previous
    return before, path.stat().st_size
