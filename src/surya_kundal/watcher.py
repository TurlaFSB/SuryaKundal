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
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from surya_kundal.ingest import store_events
from surya_kundal.parser.log_parser import parse_event_line

logger = logging.getLogger(__name__)


class LogTailer:
    """Return the complete lines appended to ``path`` since the previous call."""

    def __init__(self, path: Path, *, from_end: bool = False) -> None:
        self.path = Path(path)
        self._from_end = from_end
        self._handle = None
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
            lines.extend(self._drain())  # finish the old file first
            self._close()
            if self._open(from_start=True):
                lines.extend(self._drain())
        elif self._truncated():
            logger.info("Log %s was truncated; reading from the start", self.path)
            self._handle.seek(0)
            self._partial = b""
            lines.extend(self._drain())
        return lines

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
        if skip_history:
            handle.seek(0, os.SEEK_END)
        self._handle = handle
        self._partial = b""
        logger.info("Following %s", self.path)
        return True

    def _close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
            self._partial = b""

    def _drain(self) -> list[str]:
        """Read everything currently available, keeping a half-written last line."""
        chunk = self._handle.read()
        if not chunk:
            return []
        data = self._partial + chunk
        *complete, self._partial = data.split(b"\n")
        return [line.decode("utf-8", errors="replace") for line in complete]

    def _rotated(self) -> bool:
        try:
            on_disk = os.stat(self.path)
        except FileNotFoundError:
            return False  # between rotation and the new file appearing
        current = os.fstat(self._handle.fileno())
        return (on_disk.st_ino, on_disk.st_dev) != (current.st_ino, current.st_dev)

    def _truncated(self) -> bool:
        return os.fstat(self._handle.fileno()).st_size < self._handle.tell()


class Watcher:
    """Poll a log and store new events. ``poll_once`` does one cycle, ``run`` loops."""

    def __init__(
        self,
        log_path: Path,
        session_factory: sessionmaker[Session],
        *,
        interval: float = 1.0,
        from_end: bool = False,
    ) -> None:
        self._tailer = LogTailer(log_path, from_end=from_end)
        self._session_factory = session_factory
        self._interval = interval

    def poll_once(self) -> int:
        """Store any new events. Returns the number of events read this cycle."""
        events = []
        for line in self._tailer.read_new_lines():
            event = parse_event_line(line)
            if event is not None:
                events.append(event)
        if not events:
            return 0

        try:
            with self._session_factory() as db:
                result = store_events(db, events)
                db.commit()
        except SQLAlchemyError:
            # Nothing is lost for good: the next start replays the log, and
            # storing is idempotent.
            logger.exception("Database error while storing %d events", len(events))
            return 0
        logger.debug("Stored %d events (%d sessions)", len(events), result.saved)
        return len(events)

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
