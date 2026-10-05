"""Command-line entry point: the ``surya-kundal`` command and its subcommands."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import func, select

from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.models import (
    Command,
    HoneypotSession,
    IpGeo,
    IpIntel,
    Login,
    TechniqueMatch,
)
from surya_kundal.enrichment.abuseipdb import AbuseIPDBClient
from surya_kundal.enrichment.enrich import (
    DEFAULT_ABUSE_BUDGET,
    DEFAULT_VT_BUDGET,
    enrich_pending,
)
from surya_kundal.enrichment.geoip import GeoIPLookup
from surya_kundal.enrichment.geoip_update import GeoIPUpdateError, update_all
from surya_kundal.enrichment.http import ProviderError
from surya_kundal.enrichment.tor import TorExitList
from surya_kundal.enrichment.virustotal import VirusTotalClient
from surya_kundal.ingest import ingest_log
from surya_kundal.mapping.attack import load_catalog
from surya_kundal.mapping.store import map_pending
from surya_kundal.watcher import Watcher

DEFAULT_LOG_PATH = "~/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_GEOIP_DIR = "data/geoip"
DEFAULT_TOR_CACHE = "data/tor_exit_nodes.txt"


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

    enrich = sub.add_parser("enrich", help="add geolocation and threat intel to stored sessions")
    enrich.add_argument("--db", default=None, help="database URL (default: $DATABASE_URL)")
    enrich.add_argument("--geoip-dir", type=Path, default=None, help="GeoLite2 directory")
    enrich.add_argument(
        "--abuse-budget", type=int, default=DEFAULT_ABUSE_BUDGET, help="max AbuseIPDB checks/day"
    )
    enrich.add_argument(
        "--vt-budget", type=int, default=DEFAULT_VT_BUDGET, help="max VirusTotal lookups/day"
    )

    mapping = sub.add_parser("map", help="map stored sessions to MITRE ATT&CK techniques")
    mapping.add_argument("--db", default=None, help="database URL (default: $DATABASE_URL)")

    techniques = sub.add_parser("techniques", help="show ATT&CK techniques seen, most common first")
    techniques.add_argument("--db", default=None, help="database URL (default: $DATABASE_URL)")
    techniques.add_argument("--limit", type=int, default=30, help="maximum rows to show")

    show = sub.add_parser("show", help="show one session's commands with their techniques")
    show.add_argument("session_id", help="session ID, or a unique prefix of it")
    show.add_argument("--db", default=None, help="database URL (default: $DATABASE_URL)")

    geoip = sub.add_parser("geoip", help="manage and query the offline GeoLite2 databases")
    geo_sub = geoip.add_subparsers(dest="geoip_action", required=True)
    update = geo_sub.add_parser("update", help="download or refresh the GeoLite2 databases")
    update.add_argument("--dir", type=Path, default=None, help="database directory")
    update.add_argument("--force", action="store_true", help="download even if recent")
    lookup = geo_sub.add_parser("lookup", help="look up one IP address")
    lookup.add_argument("ip")
    lookup.add_argument("--dir", type=Path, default=None, help="database directory")
    return parser


def _geoip_dir(args: argparse.Namespace) -> Path:
    return (args.dir or Path(os.environ.get("GEOIP_DB_DIR", DEFAULT_GEOIP_DIR))).expanduser()


def _run_geoip(args: argparse.Namespace) -> int:
    if args.geoip_action == "update":
        try:
            results = update_all(
                _geoip_dir(args),
                os.environ.get("MAXMIND_ACCOUNT_ID", "").strip(),
                os.environ.get("MAXMIND_LICENSE_KEY", "").strip(),
                force=args.force,
            )
        except GeoIPUpdateError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for r in results:
            print(f"{r.edition}: {'updated' if r.updated else 'skipped'} ({r.reason})")
        return 0

    lookup = GeoIPLookup(_geoip_dir(args))
    try:
        if not lookup.available:
            print(
                "error: no GeoIP databases found. Run: surya-kundal geoip update", file=sys.stderr
            )
            return 1
        info = lookup.lookup(args.ip)
    finally:
        lookup.close()
    if info is None:
        print(f"No data for {args.ip} (private, invalid or unknown address).")
        return 0
    for name, value in vars(info).items():
        print(f"{name:<20}{value if value is not None else '-'}")
    return 0


def _run_enrich(args: argparse.Namespace) -> int:
    engine = create_db_engine(args.db)
    init_db(engine)

    geo = GeoIPLookup(args.geoip_dir or Path(os.environ.get("GEOIP_DB_DIR", DEFAULT_GEOIP_DIR)))
    tor = TorExitList(os.environ.get("TOR_EXIT_LIST_PATH", DEFAULT_TOR_CACHE))
    abuse = vt = None
    try:
        if os.environ.get("ABUSEIPDB_API_KEY", "").strip():
            abuse = AbuseIPDBClient(os.environ["ABUSEIPDB_API_KEY"].strip())
        else:
            print("note: ABUSEIPDB_API_KEY not set; skipping AbuseIPDB", file=sys.stderr)
        if os.environ.get("VIRUSTOTAL_API_KEY", "").strip():
            vt = VirusTotalClient(os.environ["VIRUSTOTAL_API_KEY"].strip())
        else:
            print("note: VIRUSTOTAL_API_KEY not set; skipping VirusTotal", file=sys.stderr)
        with make_session_factory(engine)() as db:
            result = enrich_pending(
                db,
                geo=geo if geo.available else None,
                tor=tor if tor.load() else None,
                abuse=abuse,
                virustotal_client=vt,
                abuse_budget=args.abuse_budget,
                vt_budget=args.vt_budget,
            )
    except ProviderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        geo.close()
        for client in (abuse, vt):
            if client is not None:
                client.close()

    print(
        f"Enriched: {result.geo} geo, {result.tor} tor, {result.abuse} AbuseIPDB, "
        f"{result.files} VirusTotal; {result.errors} error(s)."
    )
    for provider in result.stopped:
        print(f"note: {provider} limit reached; remaining items wait for the next run")
    return 1 if result.errors else 0


def _run_map(args: argparse.Namespace) -> int:
    engine = create_db_engine(args.db)
    init_db(engine)
    with make_session_factory(engine)() as db:
        result = map_pending(db)
    print(
        f"Mapped {result.sessions} session(s): {result.matches} technique match(es); "
        f"{result.failed} failed."
    )
    return 1 if result.failed else 0


def _run_techniques(args: argparse.Namespace) -> int:
    engine = create_db_engine(args.db)
    init_db(engine)
    sessions_seen = func.count(TechniqueMatch.session_id.distinct())
    query = (
        select(TechniqueMatch.technique_id, sessions_seen, func.count())
        .group_by(TechniqueMatch.technique_id)
        .order_by(
            func.count(TechniqueMatch.session_id.distinct()).desc(), TechniqueMatch.technique_id
        )
        .limit(args.limit)
    )
    with make_session_factory(engine)() as db:
        rows = db.execute(query).all()
    if not rows:
        print("No technique matches yet. Run: surya-kundal map")
        return 0

    catalog = load_catalog()
    print(f"{'TECHNIQUE':<11}{'NAME':<44}{'TACTICS':<30}{'SESSIONS':>9}{'HITS':>6}")
    for technique_id, sessions, hits in rows:
        technique = catalog.get(technique_id)
        name = technique.name if technique else "?"
        tactics = ",".join(technique.tactics) if technique else "?"
        print(f"{technique_id:<11}{name[:42]:<44}{tactics[:28]:<30}{sessions:>9}{hits:>6}")
    print(f"\nMITRE ATT&CK Enterprise v{catalog.version}")
    return 0


def _run_show(args: argparse.Namespace) -> int:
    engine = create_db_engine(args.db)
    init_db(engine)
    with make_session_factory(engine)() as db:
        found = db.scalars(
            select(HoneypotSession).where(HoneypotSession.id.startswith(args.session_id))
        ).all()
        if len(found) != 1:
            reason = "no session" if not found else "more than one session"
            print(f"error: {reason} matches {args.session_id!r}", file=sys.stderr)
            return 2
        session = found[0]
        matches = db.scalars(
            select(TechniqueMatch).where(TechniqueMatch.session_id == session.id)
        ).all()
        by_command: dict[int | None, list[TechniqueMatch]] = {}
        for match in matches:
            by_command.setdefault(match.command_id, []).append(match)

        start = session.start_time.strftime("%Y-%m-%d %H:%M:%S") if session.start_time else "-"
        print(f"Session {session.id} from {session.src_ip or '-'} at {start} UTC")
        print(f"Client: {session.client_version or '-'}   HASSH: {session.hassh or '-'}")
        for login in session.logins:
            outcome = "accepted" if login.success else "rejected"
            print(f"  login {outcome}: {login.username}/{login.password}")
        for match in by_command.get(None, []):
            print(
                f"  [{match.technique_id}] {match.rule_id} ({match.confidence}): {match.evidence}"
            )
        for command in session.commands:
            print(f"  $ {command.command}")
            for match in by_command.get(command.id, []):
                print(f"      -> {match.technique_id} {match.rule_id} ({match.confidence})")
        for download in session.downloads:
            print(f"  downloaded {download.url} sha256={download.sha256}")
    return 0


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
    country = select(IpGeo.country_code).where(IpGeo.ip == HoneypotSession.src_ip).scalar_subquery()
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
    query = (
        select(HoneypotSession, logins, commands, country, abuse, tor)
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

    print(
        f"{'SESSION':<14}{'SOURCE IP':<18}{'START (UTC)':<22}{'LOGINS':>7}{'CMDS':>6}"
        f"  {'CC':<4}{'ABUSE':<7}TOR"
    )
    for session, login_count, command_count, cc, abuse_score, is_tor in rows:
        start = session.start_time.strftime("%Y-%m-%d %H:%M:%S") if session.start_time else "-"
        print(
            f"{session.id:<14}{session.src_ip or '-':<18}{start:<22}"
            f"{login_count:>7}{command_count:>6}"
            f"  {cc or '-':<4}{'-' if abuse_score is None else abuse_score:<7}"
            f"{'-' if is_tor is None else ('yes' if is_tor else 'no')}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # httpx logs full request URLs at INFO, including signed download links.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    args = _build_parser().parse_args(argv)
    handlers = {
        "ingest": _run_ingest,
        "watch": _run_watch,
        "list": _run_list,
        "geoip": _run_geoip,
        "enrich": _run_enrich,
        "map": _run_map,
        "techniques": _run_techniques,
        "show": _run_show,
    }
    return handlers[args.action](args)


if __name__ == "__main__":
    raise SystemExit(main())
