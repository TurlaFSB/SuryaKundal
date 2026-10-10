"""Command-line entry point: the ``surya-kundal`` command and its subcommands."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from surya_kundal import __version__
from surya_kundal.campaigns import CampaignDetail, CampaignRow
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
from surya_kundal.doctor import run_checks
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
    run.add_argument(
        "--campaign-interval",
        type=float,
        default=600.0,
        help="seconds between campaign regrouping when new sessions arrived",
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

    internal = sub.add_parser(
        "reclassify",
        help="re-check which sessions are your own traffic (run after changing INTERNAL_NETWORKS)",
    )
    _add_db_option(internal)

    techniques = sub.add_parser("techniques", help="show ATT&CK techniques seen, most common first")
    _add_db_option(techniques)
    techniques.add_argument("--limit", type=int, default=30, help="maximum rows to show")

    show = sub.add_parser("show", help="show one session's commands with their techniques")
    show.add_argument("session_id", help="session ID, or a unique prefix of it")
    _add_db_option(show)

    wazuh = sub.add_parser("wazuh-rules", help="generate the Wazuh rules for Cowrie's log")
    wazuh.add_argument("--output", type=Path, default=None, help="write here instead of stdout")

    doctor = sub.add_parser("doctor", help="check the installation (read-only; exit 1 on failure)")
    _add_db_option(doctor)
    _add_log_option(doctor)

    dash = sub.add_parser("dashboard", help="serve the read-only web dashboard")
    dash.add_argument("--host", default="127.0.0.1", help="address to listen on (default: local)")
    dash.add_argument("--port", type=int, default=8080)
    dash.add_argument("--alerts", type=Path, default=None, help="Wazuh alert export (JSON lines)")
    _add_db_option(dash)

    export = sub.add_parser(
        "export", help="export indicators of compromise (CSV, STIX 2.1, blocklist, nftables)"
    )
    export.add_argument("--format", choices=("csv", "stix", "blocklist", "nftables"), default="csv")
    export.add_argument("--days", type=int, default=30, help="only what was seen in this many days")
    export.add_argument(
        "--min-level",
        choices=("contact", "guessing", "access", "hands-on", "action"),
        default="guessing",
        help="how far an address must have got to be listed (default: guessing)",
    )
    export.add_argument(
        "--min-confidence",
        type=int,
        default=0,
        help="leave out indicators below this confidence, 0 to 100 (default: 0)",
    )
    export.add_argument(
        "--attempted-min-sources",
        type=int,
        default=3,
        metavar="N",
        help="list a URL that was only typed in commands (never downloaded) when at least N "
        "different addresses typed it; 0 lists them all (default: 3)",
    )
    export.add_argument(
        "--types",
        default="ip,file,url",
        help="comma-separated: ip, file, url (blocklist formats use ip only)",
    )
    export.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="CIDR",
        help="address or network never to list, e.g. your own (repeatable)",
    )
    export.add_argument(
        "--exclude-file", type=Path, default=None, help="file with one address or network per line"
    )
    export.add_argument(
        "--include-private",
        action="store_true",
        help="also list private and local addresses (CSV and STIX only; for lab testing)",
    )
    export.add_argument("--author", default="Surya Kundal honeypot", help="STIX identity name")
    export.add_argument("--output", type=Path, default=None, help="write here instead of stdout")
    _add_db_option(export)

    campaigns = sub.add_parser(
        "campaigns", help="group sessions into campaigns (same tools, payloads or scripts)"
    )
    camp_sub = campaigns.add_subparsers(dest="campaigns_action", required=True)
    build = camp_sub.add_parser("build", help="recompute the campaigns from all stored sessions")
    _add_db_option(build)
    camp_list = camp_sub.add_parser("list", help="show campaigns, biggest first")
    camp_list.add_argument("--limit", type=int, default=20)
    camp_list.add_argument(
        "--min-ips", type=int, default=1, help="only campaigns spread over this many addresses"
    )
    _add_db_option(camp_list)
    camp_show = camp_sub.add_parser("show", help="one campaign: why it was grouped, what it did")
    camp_show.add_argument("campaign_id", help="campaign ID or a unique prefix")
    _add_db_option(camp_show)

    backup = sub.add_parser(
        "backup", help="write a verified copy of the database (safe while the pipeline runs)"
    )
    _add_db_option(backup)
    backup.add_argument(
        "--directory",
        type=Path,
        default=None,
        help="where to write it (default: a backups folder next to the database)",
    )
    backup.add_argument("--keep", type=int, default=None, help="keep only this many newest backups")
    backup.add_argument("--compress", action="store_true", help="gzip the backup")

    restore = sub.add_parser(
        "restore", help="replace the database with a backup (stop the pipeline first)"
    )
    _add_db_option(restore)
    restore.add_argument("backup", type=Path, help="backup file written by `backup`")
    restore.add_argument(
        "--force", action="store_true", help="replace an existing database (a copy is kept)"
    )

    prune = sub.add_parser(
        "prune", help="delete sessions older than a cutoff (shows what it would do unless --yes)"
    )
    _add_db_option(prune)
    prune.add_argument("--older-than", type=int, required=True, metavar="DAYS")
    prune.add_argument(
        "--yes", action="store_true", help="actually delete; without it, only report"
    )
    prune.add_argument("--vacuum", action="store_true", help="shrink the database file afterwards")

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


def _run_export(args: argparse.Namespace, settings: Settings) -> int:
    from sqlalchemy.exc import OperationalError

    from surya_kundal import export as ioc

    if args.include_private and args.format in ("blocklist", "nftables"):
        print(
            "error: --include-private is only for CSV and STIX; a blocklist must never "
            "contain private or local addresses",
            file=sys.stderr,
        )
        return 2
    types = tuple(part.strip() for part in args.types.split(",") if part.strip())
    if args.format in ("blocklist", "nftables"):
        types = ("ip",)
    entries = list(args.exclude)
    if args.exclude_file is not None:
        try:
            entries += args.exclude_file.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            print(f"error: cannot read {args.exclude_file}: {error.strerror}", file=sys.stderr)
            return 2
    try:
        filters = ioc.Filters(
            days=args.days,
            min_level=args.min_level,
            types=types,
            exclude=ioc.parse_networks(entries),
            include_private=args.include_private,
            min_confidence=args.min_confidence,
            attempted_min_sources=args.attempted_min_sources,
        )
        factory = readonly_database(args.db or settings.database_url)
        now = datetime.now(UTC)
        with factory() as db:
            indicators, summary = ioc.collect(db, now=now, filters=filters)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(
            "error: the database does not exist yet; run `surya-kundal ingest` first",
            file=sys.stderr,
        )
        return 2
    except OperationalError as error:
        print(f"error: could not read the database: {printable(error.orig)}", file=sys.stderr)
        return 2

    text = ioc.render(indicators, args.format, now=now, filters=filters, author=args.author)
    if args.output is None:
        print(text, end="")
    else:
        ioc.write_atomically(args.output, text)
    kinds = ", ".join(f"{count} {kind}" for kind, count in sorted(summary.counts.items()))
    print(
        f"Exported {len(indicators)} indicator(s){f' ({kinds})' if kinds else ''}.", file=sys.stderr
    )
    skipped = []
    if summary.non_public:
        skipped.append(f"{summary.non_public} private or local address(es)")
    if summary.excluded:
        skipped.append(f"{summary.excluded} excluded address(es)")
    if summary.invalid:
        skipped.append(f"{summary.invalid} invalid value(s)")
    if summary.common:
        skipped.append(f"{summary.common} URL(s) on look-up services or popular sites")
    if summary.unverified:
        skipped.append(
            f"{summary.unverified} typed-only URL(s) seen from fewer than "
            f"{args.attempted_min_sources} addresses"
        )
    if skipped:
        print("Left out: " + ", ".join(skipped) + ".", file=sys.stderr)
    return 0


def _stamp(when: datetime | None) -> str:
    return when.strftime("%Y-%m-%d %H:%M") if when else "-"


def _run_campaigns(args: argparse.Namespace, settings: Settings) -> int:
    from surya_kundal import campaigns as camp

    url = args.db or settings.database_url
    if args.campaigns_action == "build":
        with _open_database(args, settings)() as db:
            result = camp.build_campaigns(db)
        print(
            f"Built {result.campaigns} campaign(s) covering {result.sessions} of "
            f"{result.total} session(s)."
        )
        return 0

    try:
        factory = readonly_database(url)
        with factory() as db:
            if args.campaigns_action == "list":
                return _print_campaigns(
                    camp.list_campaigns(db, limit=args.limit, min_ips=args.min_ips)
                )
            try:
                found = camp.find_campaign(db, args.campaign_id)
            except ValueError as error:
                print(f"error: {error}", file=sys.stderr)
                return 2
            if found is None:
                print(f"error: no campaign {printable(args.campaign_id)!r}", file=sys.stderr)
                return 2
            detail = camp.campaign_detail(db, found)
            assert detail is not None  # noqa: S101  (it was just found)
            return _print_campaign(detail)
    except FileNotFoundError:
        print(
            "error: the database does not exist yet; run `surya-kundal ingest` first",
            file=sys.stderr,
        )
        return 2


def _print_campaigns(rows: list[CampaignRow]) -> int:
    if not rows:
        print("No campaigns yet. Run: surya-kundal campaigns build")
        return 0
    print(
        f"{'CAMPAIGN':<13}{'SESSIONS':>9}{'IPS':>6}  {'FIRST SEEN':<17}{'LAST SEEN':<17}LINKED BY"
    )
    for row in rows:
        why = (
            f"{row.top_evidence.kind} {printable(row.top_evidence.value, limit=40)}"
            if row.top_evidence
            else "-"
        )
        print(
            f"{row.id:<13}{row.sessions:>9}{row.ips:>6}  "
            f"{_stamp(row.first_seen):<17}{_stamp(row.last_seen):<17}{why}"
        )
    return 0


def _print_campaign(detail: CampaignDetail) -> int:
    row = detail.row
    print(
        f"Campaign {row.id}: {row.sessions} sessions from {row.ips} address(es), "
        f"{_stamp(row.first_seen)} to {_stamp(row.last_seen)} UTC"
    )
    print("\nWhy these sessions are grouped (what they share):")
    for item in detail.evidence:
        print(f"  {item.kind:<9} in {item.sessions:>3} sessions  {printable(item.value, limit=90)}")
    print("\nAddresses:")
    for ip, count, country in detail.ips[:10]:
        print(f"  {printable(ip):<40} {count:>3} session(s)  {printable(country or '-')}")
    if len(detail.ips) > 10:
        print(f"  ... and {len(detail.ips) - 10} more")
    if detail.hassh:
        print("\nSSH client fingerprints:")
        for value, count in detail.hassh[:5]:
            print(f"  {printable(value)}  {count} session(s)")
    if detail.techniques:
        print("\nATT&CK techniques:")
        print("  " + ", ".join(f"{t} ({n})" for t, n in detail.techniques[:15]))
    if detail.commands:
        print("\nMost typed commands:")
        for command, count in detail.commands[:8]:
            print(f"  {count:>3}x  {printable(command, limit=100)}")
    return 0


def readonly_database(url: str) -> sessionmaker[Session]:
    """A session factory that cannot write; raises FileNotFoundError if the file is missing."""
    return make_session_factory(create_db_engine(url, read_only=True))


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _run_backup(args: argparse.Namespace, settings: Settings) -> int:
    from surya_kundal import maintenance

    url = args.db or settings.database_url
    try:
        directory = args.directory or maintenance.sqlite_file(url).parent / "backups"
        result = maintenance.backup_database(url, directory, keep=args.keep, compress=args.compress)
    except maintenance.MaintenanceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Backed up {result.sessions} session(s) to {result.path} ({_human_size(result.size)}).")
    for old in result.removed:
        print(f"Removed old backup {old.name}")
    return 0


def _run_restore(args: argparse.Namespace, settings: Settings) -> int:
    from surya_kundal import maintenance

    try:
        result = maintenance.restore_database(
            args.backup, args.db or settings.database_url, force=args.force
        )
    except maintenance.MaintenanceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Restored {result.sessions} session(s) to {result.target}.")
    if result.safety_copy:
        print(f"The database it replaced is kept at {result.safety_copy}.")
    return 0


def _run_prune(args: argparse.Namespace, settings: Settings) -> int:
    from surya_kundal import maintenance

    url = args.db or settings.database_url
    try:
        maintenance.sqlite_file(url)
        engine = create_db_engine(url)
        init_db(engine)
        with make_session_factory(engine)() as db:
            result = maintenance.prune_database(
                db, older_than_days=args.older_than, dry_run=not args.yes
            )
            if result.deleted:
                from surya_kundal.campaigns import build_campaigns

                build_campaigns(db)  # campaign totals must not count sessions that are gone
                db.commit()
    except maintenance.MaintenanceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    when = result.cutoff.strftime("%Y-%m-%d %H:%M UTC")
    verb = "Deleted" if result.deleted else "Would delete"
    print(
        f"{verb} {result.sessions} session(s) that ended before {when}: {result.logins} login(s), "
        f"{result.commands} command(s), {result.transfers} transfer(s), "
        f"{result.tunnels} tunnel(s)."
    )
    if result.deleted:
        print(
            f"Dropped {result.orphan_ips} cached IP lookup(s) and "
            f"{result.orphan_files} file lookup(s)."
        )
        if args.vacuum:
            before, after = maintenance.vacuum(url)
            print(f"Database file {_human_size(before)} -> {_human_size(after)}.")
    elif result.sessions:
        print("Nothing was changed. Back up first (`surya-kundal backup`), then add --yes.")
    return 0


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


MIN_TOKEN_LENGTH = 12


def _run_doctor(args: argparse.Namespace, settings: Settings) -> int:
    checks = run_checks(settings, args.db, args.log)
    for check in checks:
        print(f"{check.status:<5} {check.name:<16} {printable(check.detail)}")
    return 1 if any(c.status == "FAIL" for c in checks) else 0


def _run_dashboard(args: argparse.Namespace, settings: Settings) -> int:
    try:
        from waitress import serve

        from surya_kundal.dashboard.app import create_app, readonly_session_factory
    except ImportError as error:
        if (error.name or "").split(".")[0] not in ("flask", "waitress"):
            raise  # a real bug in our own code must not be reported as a missing extra
        print('error: the dashboard needs: pip install -e ".[dashboard]"', file=sys.stderr)
        return 2
    token = settings.dashboard_token
    local = args.host in ("127.0.0.1", "localhost", "::1")
    if not local and not token:
        print(
            "error: listening beyond localhost needs a password; set DASHBOARD_TOKEN in .env",
            file=sys.stderr,
        )
        return 2
    if token and len(token) < MIN_TOKEN_LENGTH:
        print(
            f"error: DASHBOARD_TOKEN must be at least {MIN_TOKEN_LENGTH} characters "
            "(try: python3 -c 'import secrets; print(secrets.token_urlsafe(24))')",
            file=sys.stderr,
        )
        return 2
    try:
        factory = readonly_session_factory(args.db or settings.database_url)
    except FileNotFoundError:
        print(
            "error: the database does not exist yet; run `surya-kundal run` or `ingest` first",
            file=sys.stderr,
        )
        return 2
    app = create_app(
        factory,
        alerts_path=args.alerts or settings.wazuh_alerts_path,
        token=token,
        allowed_hosts=(args.host,),
        show_internal=settings.show_internal,
    )
    print(
        f"Dashboard on http://{args.host}:{args.port}"
        + (" (password = DASHBOARD_TOKEN)" if token else "")
    )
    if not local:
        print("warning: this is plain HTTP; put it behind TLS (a reverse proxy) before exposing it")
    serve(
        app,
        host=args.host,
        port=args.port,
        threads=4,
        # The app only answers GET: refuse bodies, and bound headers and idle connections.
        max_request_body_size=1024,
        max_request_header_size=16384,
        connection_limit=100,
        channel_timeout=30,
    )
    return 0


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
            campaign_interval=args.campaign_interval,
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


def _run_reclassify(args: argparse.Namespace, settings: Settings) -> int:
    from surya_kundal.internal import InternalNetworksError, reclassify

    try:
        with _open_database(args, settings)() as db:
            changed, internal, total = reclassify(db)
    except InternalNetworksError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"{internal} of {total} session(s) are internal; {changed} changed.")
    if changed:
        print("Run `surya-kundal campaigns build` to rebuild campaigns without them.")
    return 0


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
        "reclassify": _run_reclassify,
        "techniques": _run_techniques,
        "show": _run_show,
        "wazuh-rules": _run_wazuh_rules,
        "export": _run_export,
        "campaigns": _run_campaigns,
        "backup": _run_backup,
        "restore": _run_restore,
        "prune": _run_prune,
        "dashboard": _run_dashboard,
        "doctor": _run_doctor,
    }
    try:
        return handlers[args.action](args, settings)
    except SchemaError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
