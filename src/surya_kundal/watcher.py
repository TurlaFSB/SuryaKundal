"""Follow a Cowrie JSON log and store new events as they are written.

Two pieces:

- ``LogTailer`` reads the lines appended to a file since the last call, and copes
  with the things that happen to a live log: it is rotated, truncated, not yet
  created, or caught halfway through writing a line.
- ``Watcher`` polls a tailer and stores what it finds through the database layer.

Polling (rather than OS file notifications) is deliberate: it behaves the same on
every platform and inside containers, and a one-second delay is irrelevant here.
"""

from __future__ import annotations

import logging
import os
import threading
from io import BufferedReader
from pathlib import Path
from typing import BinaryIO

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from surya_kundal.database.repository import load_offset, save_offset
from surya_kundal.ingest import store_events
from surya_kundal.parser.log_parser import parse_event_line

logger = logging.getLogger(__name__)

# A line longer than this without a newline is not a Cowrie event; dropping it stops a
# runaway or hostile file from growing memory without limit.
MAX_PARTIAL_BYTES = 16 * 1024 * 1024
# If the database stays unavailable, stop buffering after this many events and say so.
MAX_RETRY_EVENTS = 200_000
# The log is read in pieces of this size so a multi-gigabyte file never sits in memory.
READ_CHUNK = 4 * 1024 * 1024
# A session that still cannot be stored after this many cycles is dropped and logged
# loudly, so one poisoned session cannot block the buffer forever.
MAX_SESSION_ATTEMPTS = 5


class LogTailer:
    """Return the complete lines appended to ``path`` since the previous call."""

    def __init__(
        self,
        path: Path,
        *,
        from_end: bool = False,
        resume: tuple[int, int] | None = None,
    ) -> None:
        """``resume`` is ``(inode, offset)`` from a previous run; it beats ``from_end``."""
        self.path = Path(path)
        self._from_end = from_end
        self._resume = resume
        self._handle: BinaryIO | None = None
        self._partial = b""

    def read_new_lines(self) -> list[str]:
        """Return new complete lines. Never raises for ordinary log-file trouble."""
        lines: list[str] = []
        if self._handle is None and not self._open():
            return lines

        lines.extend(self._drain())

        # The path may now point at a different file (rotation), or the same
        # file may have been emptied (truncation).
        if self._rotated():
            while chunk := self._drain():  # finish the old file first
                lines.extend(chunk)
            self._close()
            if self._open(from_start=True):
                lines.extend(self._drain())
        elif self._handle is not None and self._truncated():
            logger.info("Log %s was truncated; reading from the start", self.path)
            self._handle.seek(0)
            self._partial = b""
            lines.extend(self._drain())
        return lines

    def position(self) -> tuple[int, int] | None:
        """``(inode, offset)`` just after the last complete line returned, if open."""
        if self._handle is None:
            return None
        inode = os.fstat(self._handle.fileno()).st_ino
        return inode, self._handle.tell() - len(self._partial)

    def close(self) -> None:
        self._close()

    # -- internals ----------------------------------------------------------

    def _open(self, *, from_start: bool = False) -> bool:
        # Skipping history only makes sense at startup: if the log does not exist
        # yet, everything that appears in it later is new.
        skip_history = self._from_end and not from_start
        self._from_end = False
        try:
            handle = self.path.open("rb")
        except FileNotFoundError:
            return False
        except OSError as error:
            logger.warning("Cannot open %s: %s", self.path, error)
            return False
        resume, self._resume = self._resume, None
        if resume is not None and not from_start:
            inode, offset = resume
            stat = os.fstat(handle.fileno())
            if stat.st_ino == inode and offset <= stat.st_size:
                handle.seek(offset)
                logger.info("Resuming %s at byte %d", self.path, offset)
            elif (older := self._find_rotated(inode, offset)) is not None:
                # The log was rotated while we were stopped: finish the old file first. The normal
                # rotation handling then moves on to the new file by itself.
                handle.close()
                handle = older
                logger.info("Resuming the rotated log %s at byte %d", older.name, offset)
            elif skip_history:
                handle.seek(0, os.SEEK_END)
        elif skip_history:
            handle.seek(0, os.SEEK_END)
        self._handle = handle
        self._partial = b""
        logger.info("Following %s", self.path)
        return True

    def _find_rotated(self, inode: int, offset: int) -> BufferedReader | None:
        """The rotated copy (``cowrie.json.DATE``) of the log we were reading, at ``offset``."""
        try:
            candidates = sorted(self.path.parent.glob(self.path.name + ".*"), reverse=True)[:30]
        except OSError:
            return None
        for candidate in candidates:
            try:
                handle = candidate.open("rb")
            except OSError:
                continue
            stat = os.fstat(handle.fileno())
            if stat.st_ino == inode and offset <= stat.st_size:
                handle.seek(offset)
                return handle
            handle.close()
        return None

    def _close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
            self._partial = b""

    def _drain(self) -> list[str]:
        """Read forward until at least one complete line (or the end), keeping a partial."""
        if self._handle is None:
            return []
        while True:
            chunk = self._handle.read(READ_CHUNK)
            if not chunk:
                return []
            *complete, self._partial = (self._partial + chunk).split(b"\n")
            if len(self._partial) > MAX_PARTIAL_BYTES:
                logger.error(
                    "Discarding %d bytes with no line break in %s", len(self._partial), self.path
                )
                self._partial = b""
            if complete:
                return [line.decode("utf-8", errors="replace") for line in complete]

    def _rotated(self) -> bool:
        try:
            on_disk = os.stat(self.path)
        except FileNotFoundError:
            return False  # between rotation and the new file appearing
        if self._handle is None:
            return False
        current = os.fstat(self._handle.fileno())
        return (on_disk.st_ino, on_disk.st_dev) != (current.st_ino, current.st_dev)

    def _truncated(self) -> bool:
        if self._handle is None:
            return False
        return os.fstat(self._handle.fileno()).st_size < self._handle.tell()


class Watcher:
    """Poll a log and store new events. ``poll_once`` does one cycle, ``run`` loops.

    The position reached in the log is saved with each successful batch, so a
    restart resumes where it stopped. It is only saved when nothing is waiting in
    the retry buffer: after a crash, anything unsaved is simply read again (storing
    is idempotent).
    """

    def __init__(
        self,
        log_path: Path,
        session_factory: sessionmaker[Session],
        *,
        interval: float = 1.0,
        from_end: bool = False,
    ) -> None:
        self._key = str(Path(log_path).expanduser().absolute())
        self._session_factory = session_factory
        self._interval = interval
        self._unsaved: list[dict] = []  # events a failed database write must not lose
        self._attempts: dict[str, int] = {}
        self._tailer = LogTailer(log_path, from_end=from_end, resume=self._saved_offset())

    def _saved_offset(self) -> tuple[int, int] | None:
        try:
            with self._session_factory() as db:
                return load_offset(db, self._key)
        except SQLAlchemyError:
            logger.warning("Could not read the saved log position; starting fresh", exc_info=True)
            return None

    def poll_once(self) -> int:
        """Store any new events. Returns the number of events stored this cycle.

        Events whose database write fails stay in memory and are retried on the next
        cycle, so a locked or briefly unavailable database delays data, never loses
        it. A single session that keeps failing is dropped after a few attempts.
        """
        stored = 0
        while True:
            lines = self._tailer.read_new_lines()
            events = self._unsaved
            for line in lines:
                event = parse_event_line(line)
                if event is not None:
                    events.append(event)
            if not events:
                return stored
            self._unsaved = events

            try:
                with self._session_factory() as db:
                    result = store_events(db, events)
                    retained = self._retain_failed(events, result.failed_ids)
                    position = self._tailer.position()
                    if not retained and position is not None:
                        save_offset(db, self._key, *position)
                    db.commit()
            except SQLAlchemyError:
                logger.exception("Database error while storing %d events; will retry", len(events))
                if len(events) > MAX_RETRY_EVENTS:
                    logger.error("Dropping %d buffered events", len(events) - MAX_RETRY_EVENTS)
                    self._unsaved = events[-MAX_RETRY_EVENTS:]
                return stored
            stored += len(events) - len(retained)
            self._unsaved = retained
            logger.debug("Stored %d events (%d sessions)", len(events), result.saved)
            if not lines:
                return stored

    def _retain_failed(self, events: list[dict], failed_ids: tuple[str, ...]) -> list[dict]:
        """Keep events of sessions that failed to save, giving up after a few tries."""
        failed = set(failed_ids)
        for session_id in list(self._attempts):
            if session_id not in failed:
                del self._attempts[session_id]
        keep: set[str] = set()
        for session_id in failed:
            self._attempts[session_id] = self._attempts.get(session_id, 0) + 1
            if self._attempts[session_id] >= MAX_SESSION_ATTEMPTS:
                logger.error(
                    "Giving up on session %s after %d failed attempts",
                    session_id,
                    MAX_SESSION_ATTEMPTS,
                )
                del self._attempts[session_id]
            else:
                keep.add(session_id)
        return [e for e in events if isinstance(e.get("session"), str) and e["session"] in keep]

    def run(self, stop: threading.Event | None = None) -> None:
        """Poll until ``stop`` is set. Safe to interrupt at any time."""
        stop = stop or threading.Event()
        logger.info("Watching %s every %.1fs", self._tailer.path, self._interval)
        try:
            while not stop.is_set():
                try:
                    self.poll_once()
                except Exception:
                    # A long-running service should survive a bad cycle; the
                    # traceback is logged so the bug is still visible.
                    logger.exception("Unexpected error in watch cycle")
                stop.wait(self._interval)
        finally:
            self._tailer.close()
            logger.info("Watcher stopped")
