"""Command-line entry point: ``surya-kundal ingest | watch | list``."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from sqlalchemy import func, select

from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import Command, HoneypotSession, Login
from surya_kundal.ingest import ingest_log
from surya_kundal.watcher import Watcher

DEFAULT_LOG_PATH = "~/cowrie/var/log/cowrie/cowrie.json"


def _add_log_and_db_options(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--log",
        type=Path,
        default=None,
        help=f"Cowrie JSON log (default: $COWRIE_LOG_PATH or {DEFAULT_LOG_PATH})",
    )
    subparser.add_argument("--db", default=None, help="database URL (default: $DATABASE_URL)")


def _resolve_log_path(args: argparse.Namespace) -> Path:
    return (args.log or Path(os.environ.get("COWRIE_LOG_PATH", DEFAULT_LOG_PATH))).expanduser()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="surya-kundal", description="Surya Kundal honeypot tools")
    sub = parser.add_subparsers(dest="action", required=True)

    ingest = sub.add_parser("ingest", help="import a Cowrie JSON log into the database")
    _add_log_and_db_options(ingest)

    watch = sub.add_parser("watch", help="follow a Cowrie JSON log and store events live")
    _add_log_and_db_options(watch)
    watch.add_argument("--interval", type=float, default=1.0, help="seconds between polls")
    watch.add_argument(
        "--from-end",
        action="store_true",
        help="ignore what is already in the log and store only new events",
    )

    listing = sub.add_parser("list", help="show stored sessions, newest first")
    listing.add_argument("--db", default=None, help="database URL (default: $DATABASE_URL)")
    listing.add_argument("--limit", type=int, default=20, help="maximum rows to show")
    return parser


def _run_watch(args: argparse.Namespace) -> int:
    log_path = _resolve_log_path(args)
    if args.interval <= 0:
        print("error: --interval must be greater than 0", file=sys.stderr)
        return 2

    engine = create_db_engine(args.db)
    init_db(engine)
    watcher = Watcher(
        log_path,
        make_session_factory(engine),
        interval=args.interval,
        from_end=args.from_end,
    )

    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())

    watcher.run(stop)
    return 0


def _run_ingest(args: argparse.Namespace) -> int:
    log_path = _resolve_log_path(args)
    if not log_path.is_file():
        print(f"error: log file not found: {log_path}", file=sys.stderr)
        return 2

    engine = create_db_engine(args.db)
    init_db(engine)
    with make_session_factory(engine)() as db:
        result = ingest_log(db, log_path)
        db.commit()
    print(f"Stored {result.saved} session(s); {result.failed} failed.")
    return 1 if result.failed else 0


def _run_list(args: argparse.Namespace) -> int:
    engine = create_db_engine(args.db)
    init_db(engine)

    logins = func.count(Login.id.distinct())
    commands = func.count(Command.id.distinct())
    query = (
        select(HoneypotSession, logins, commands)
        .outerjoin(Login)
        .outerjoin(Command)
        .group_by(HoneypotSession.id)
        .order_by(HoneypotSession.start_time.desc())
        .limit(args.limit)
    )

    with make_session_factory(engine)() as db:
        rows = db.execute(query).all()

    if not rows:
        print("No sessions stored yet. Run: surya-kundal ingest")
        return 0

    print(f"{'SESSION':<14}{'SOURCE IP':<18}{'START (UTC)':<22}{'LOGINS':>7}{'CMDS':>6}")
    for session, login_count, command_count in rows:
        start = session.start_time.strftime("%Y-%m-%d %H:%M:%S") if session.start_time else "-"
        print(
            f"{session.id:<14}{session.src_ip or '-':<18}{start:<22}"
            f"{login_count:>7}{command_count:>6}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = _build_parser().parse_args(argv)
    handlers = {"ingest": _run_ingest, "watch": _run_watch, "list": _run_list}
    return handlers[args.action](args)


if __name__ == "__main__":
    raise SystemExit(main())
