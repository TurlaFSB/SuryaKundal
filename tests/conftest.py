"""Shared test setup: nothing a test opens may outlive the test."""

import pytest
from sqlalchemy import create_engine

from surya_kundal.database import engine as engine_module
from surya_kundal.watcher import LogTailer


@pytest.fixture(autouse=True)
def _close_log_tailers(monkeypatch):
    """Close every log file a test opened."""
    opened = []
    original = LogTailer.__init__

    def tracking(self, *args, **kwargs):
        original(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(LogTailer, "__init__", tracking)
    yield
    for tailer in opened:
        tailer.close()


@pytest.fixture(autouse=True)
def _dispose_engines(monkeypatch):
    """Dispose every database engine the application code created during a test."""
    created = []

    def tracking(*args, **kwargs):
        engine = create_engine(*args, **kwargs)
        created.append(engine)
        return engine

    monkeypatch.setattr(engine_module, "create_engine", tracking)
    yield
    for engine in created:
        engine.dispose()
