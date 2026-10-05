"""Command-line entry point: the ``surya-kundal`` command and its subcommands."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from surya_kundal import __version__
from surya_kundal.config import Settings, load_env_file
from surya_kundal.database.engine import create_db_engine, init_db, make_session_factory
from surya_kundal.database.migrate import SchemaError
from surya_kundal.database.models import (
    Command,
    HoneypotSession,
    IpGeo,
    IpIntel,
    Login,
    TechniqueMatch,
)
from surya_kundal.enrichment.enrich import DEFAULT_ABUSE_BUDGET, DEFAULT_VT_BUDGET
from surya_kundal.enrichment.geoip import GeoIPLookup
from surya_kundal.enrichment.geoip_update import GeoIPUpdateError, update_all
from surya_kundal.enrichment.http import ProviderError
from surya_kundal.ingest import ingest_log
from surya_kundal.mapping.attack import load_catalog
from surya_kundal.mapping.store import map_pending
from surya_kundal.pipeline import build_providers, run_enrichment
from surya_kundal.service import Service
from surya_kundal.textsafe import printable
from surya_kundal.watcher import Watcher


def _add_db_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", default=None, help="database URL (default: $DATABASE_URL)")


def _add_log_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log", type=Path, default=None, help="Cowrie JSON log (default: $COWRIE_LOG_PATH)"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="surya-kundal", description="Surya Kundal honeypot tools")
    parser.add_argument("--version", action="version", version=f"surya-kundal {__version__}")
    sub = parser.add_subparsers(dest="action", required=True)

    run = sub.add_parser(
        "run", help="run the whole pipeline: follow the log, map to ATT&CK, enrich in background"
    )
    _add_log_option(run)
    _add_db_option(run)
    run.add_argument("--interval", type=float, default=1.0, help="seconds between log polls")
    run.add_argument("--from-end", action="store_true", help="store only new events")
    run.add_argument("--no-enrich", action="store_true", help="skip threat-intel enrichment")
    run.add_argument(
        "--enrich-interval", type=float, default=300.0, help="seconds between enrichment passes"
    )

    ingest = sub.add_parser("ingest", help="import a Cowrie JSON log into the database")
    _add_log_option(ingest)
    _add_db_option(ingest)

    watch = sub.add_parser("watch", help="follow a Cowrie JSON log and store events live")
    _add_log_option(watch)
    _add_db_option(watch)
    watch.add_argument("--interval", type=float, default=1.0, help="seconds between polls")
    watch.add_argument(
        "--from-end",
        action="store_true",
        help="ignore what is already in the log and store only new events",
    )

    listing = sub.add_parser("list", help="show stored sessions, newest first")
    _add_db_option(listing)
    listing.add_argument("--limit", type=int, default=20, help="maximum rows to show")

    enrich = sub.add_parser("enrich", help="add geolocation and threat intel to stored sessions")
    _add_db_option(enrich)
    enrich.add_argument("--geoip-dir", type=Path, default=None, help="GeoLite2 directory")
    enrich.add_argument(
        "--abuse-budget", type=int, default=DEFAULT_ABUSE_BUDGET, help="max AbuseIPDB checks/day"
    )
    enrich.add_argument(
        "--vt-budget", type=int, default=DEFAULT_VT_BUDGET, help="max VirusTotal lookups/day"
    )

    mapping = sub.add_parser("map", help="map stored sessions to MITRE ATT&CK techniques")
    _add_db_option(mapping)

    techniques = sub.add_parser("techniques", help="show ATT&CK techniques seen, most common first")
    _add_db_option(techniques)
    techniques.add_argument("--limit", type=int, default=30, help="maximum rows to show")

    show = sub.add_parser("show", help="show one session's commands with their techniques")
    show.add_argument("session_id", help="session ID, or a unique prefix of it")
    _add_db_option(show)

    wazuh = sub.add_parser("wazuh-rules", help="generate the Wazuh rules for Cowrie's log")
    wazuh.add_argument("--output", type=Path, default=None, help="write here instead of stdout")

    geoip = sub.add_parser("geoip", help="manage and query the offline GeoLite2 databases")
    geo_sub = geoip.add_subparsers(dest="geoip_action", required=True)
    update = geo_sub.add_parser("update", help="download or refresh the GeoLite2 databases")
    update.add_argument("--dir", type=Path, default=None, help="database directory")
    update.add_argument("--force", action="store_true", help="download even if recent")
    lookup = geo_sub.add_parser("lookup", help="look up one IP address")
    lookup.add_argument("ip")
    lookup.add_argument("--dir", type=Path, default=None, help="database directory")
    return parser


def _open_database(args: argparse.Namespace, settings: Settings) -> sessionmaker[Session]:
    engine = create_db_engine(args.db or settings.database_url)
    init_db(engine)
    return make_session_factory(engine)


def _run_wazuh_rules(args: argparse.Namespace, settings: Settings) -> int:
    from surya_kundal.wazuh import generate_rules_xml

    xml = generate_rules_xml()
    if args.output is None:
        print(xml, end="")
    else:
        args.output.write_text(xml, encoding="utf-8")
        print(f"Wrote {args.output}")
    return 0


def _stop_on_signals() -> threading.Event:
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    return stop


# --- geoip -----------------------------------------------------------------


def _run_geoip(args: argparse.Namespace, settings: Settings) -> int:
    directory = (args.dir or settings.geoip_dir).expanduser()
    if args.geoip_action == "update":
        try:
            results = update_all(
                directory,
                settings.maxmind_account_id,
                settings.maxmind_license_key,
                force=args.force,
            )
        except GeoIPUpdateError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for r in results:
            print(f"{r.edition}: {'updated' if r.updated else 'skipped'} ({r.reason})")
        return 0

    lookup = GeoIPLookup(directory)
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
        print(f"No data for {printable(args.ip)} (private, invalid or unknown address).")
        return 0
    for name, value in vars(info).items():
        print(f"{name:<20}{value if value is not None else '-'}")
    return 0


# --- capture ---------------------------------------------------------------


def _log_path(args: argparse.Namespace, settings: Settings) -> Path:
    return (args.log or settings.log_path).expanduser()


def _run_ingest(args: argparse.Namespace, settings: Settings) -> int:
    log_path = _log_path(args, settings)
    if not log_path.is_file():
        print(f"error: log file not found: {log_path}", file=sys.stderr)
        return 2
    with _open_database(args, settings)() as db:
        result = ingest_log(db, log_path)
        db.commit()
    print(f"Stored {result.saved} session(s); {result.failed} failed.")
    return 1 if result.failed else 0


def _run_watch(args: argparse.Namespace, settings: Settings) -> int:
    if args.interval <= 0:
        print("error: --interval must be greater than 0", file=sys.stderr)
        return 2
    watcher = Watcher(
        _log_path(args, settings),
        _open_database(args, settings),
        interval=args.interval,
        from_end=args.from_end,
    )
    watcher.run(_stop_on_signals())
    return 0


def _run_service(args: argparse.Namespace, settings: Settings) -> int:
    if args.interval <= 0 or args.enrich_interval <= 0:
        print("error: intervals must be greater than 0", file=sys.stderr)
        return 2
    stop = _stop_on_signals()
    providers = None
    if not args.no_enrich:
        providers = build_providers(settings, sleep=stop.wait)
        for note in providers.notes:
            logging.getLogger("surya_kundal").warning(note)
    try:
        Service(
            _log_path(args, settings),
            _open_database(args, settings),
            providers=providers,
            interval=args.interval,
            from_end=args.from_end,
            enrich_interval=args.enrich_interval,
        ).run(stop)
    finally:
        if providers is not None:
            providers.close()
    return 0


# --- analysis --------------------------------------------------------------


def _run_enrich(args: argparse.Namespace, settings: Settings) -> int:
    factory = _open_database(args, settings)
    providers = build_providers(settings, geoip_dir=args.geoip_dir)
    try:
        for note in providers.notes:
            print(f"note: {note}", file=sys.stderr)
        result = run_enrichment(
            factory, providers, abuse_budget=args.abuse_budget, vt_budget=args.vt_budget
        )
    except ProviderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        providers.close()

    print(
        f"Enriched: {result.geo} geo, {result.tor} tor, {result.abuse} AbuseIPDB, "
        f"{result.files} VirusTotal; {result.errors} error(s)."
    )
    for provider in result.stopped:
        print(f"note: {provider} limit reached; remaining items wait for the next run")
    return 1 if result.errors else 0


def _run_map(args: argparse.Namespace, settings: Settings) -> int:
    with _open_database(args, settings)() as db:
        result = map_pending(db)
    print(
        f"Mapped {result.sessions} session(s): {result.matches} technique match(es); "
        f"{result.failed} failed."
    )
    return 1 if result.failed else 0


def _run_list(args: argparse.Namespace, settings: Settings) -> int:
    # Scalar subqueries, not joins: joining logins and commands multiplies rows
    # (500 logins x 500 commands = 250,000 rows for one brute-force session).
    logins = (
        select(func.count())
        .where(Login.session_id == HoneypotSession.id)
        .scalar_subquery()
        .label("logins")
    )
    commands = (
        select(func.count())
        .where(Command.session_id == HoneypotSession.id)
        .scalar_subquery()
        .label("commands")
    )
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
        .order_by(HoneypotSession.start_time.desc())
        .limit(args.limit)
    )
    with _open_database(args, settings)() as db:
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
            f"{printable(session.id, limit=13):<14}{printable(session.src_ip or '-'):<18}"
            f"{start:<22}{login_count:>7}{command_count:>6}"
            f"  {printable(cc or '-'):<4}{'-' if abuse_score is None else abuse_score:<7}"
            f"{'-' if is_tor is None else ('yes' if is_tor else 'no')}"
        )
    return 0


def _run_techniques(args: argparse.Namespace, settings: Settings) -> int:
    sessions_seen = func.count(TechniqueMatch.session_id.distinct())
    query = (
        select(TechniqueMatch.technique_id, sessions_seen, func.count())
        .group_by(TechniqueMatch.technique_id)
        .order_by(sessions_seen.desc(), TechniqueMatch.technique_id)
        .limit(args.limit)
    )
    with _open_database(args, settings)() as db:
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


def _run_show(args: argparse.Namespace, settings: Settings) -> int:
    with _open_database(args, settings)() as db:
        found = db.scalars(
            select(HoneypotSession).where(
                HoneypotSession.id.startswith(args.session_id, autoescape=True)
            )
        ).all()
        if len(found) != 1:
            reason = "no session" if not found else "more than one session"
            print(f"error: {reason} matches {printable(args.session_id)!r}", file=sys.stderr)
            return 2
        session = found[0]
        matches = db.scalars(
            select(TechniqueMatch).where(TechniqueMatch.session_id == session.id)
        ).all()
        by_command: dict[int | None, list[TechniqueMatch]] = {}
        for match in matches:
            by_command.setdefault(match.command_id, []).append(match)

        start = session.start_time.strftime("%Y-%m-%d %H:%M:%S") if session.start_time else "-"
        origin = printable(session.src_ip or "-")
        print(f"Session {printable(session.id)} from {origin} at {start} UTC")
        print(
            f"Client: {printable(session.client_version or '-')}   "
            f"HASSH: {printable(session.hassh or '-')}"
        )
        for login in session.logins:
            outcome = "accepted" if login.success else "rejected"
            print(f"  login {outcome}: {printable(login.username)}/{printable(login.password)}")
        for match in by_command.get(None, []):
            print(
                f"  {match.technique_id} {match.rule_id} ({match.confidence}): "
                f"{printable(match.evidence)}"
            )
        for command in session.commands:
            print(f"  $ {printable(command.command)}")
            for match in by_command.get(command.id, []):
                print(f"      -> {match.technique_id} {match.rule_id} ({match.confidence})")
        for download in session.downloads:
            print(f"  downloaded {printable(download.url)} sha256={printable(download.sha256)}")
        for upload in session.uploads:
            print(f"  uploaded {printable(upload.filename)} sha256={printable(upload.sha256)}")
        for tunnel in session.tunnels:
            print(f"  tunnel request to {printable(tunnel.dst_ip)}:{tunnel.dst_port}")
    return 0


def main(argv: list[str] | None = None) -> int:
    load_env_file()
    settings = Settings.from_env()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # httpx logs full request URLs at INFO, including signed download links.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("alembic").setLevel(logging.WARNING)
    args = _build_parser().parse_args(argv)
    handlers = {
        "run": _run_service,
        "ingest": _run_ingest,
        "watch": _run_watch,
        "list": _run_list,
        "geoip": _run_geoip,
        "enrich": _run_enrich,
        "map": _run_map,
        "techniques": _run_techniques,
        "show": _run_show,
        "wazuh-rules": _run_wazuh_rules,
    }
    try:
        return handlers[args.action](args, settings)
    except SchemaError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
