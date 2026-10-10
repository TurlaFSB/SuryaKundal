"""The Surya Kundal dashboard: a small, read-only, server-rendered Flask app.

Design choices that matter for a honeypot tool:

* Everything shown was typed by an attacker, so it is escaped by Jinja and also passed
  through ``printable`` (no control or invisible characters reach the browser).
* A strict Content-Security-Policy: no inline script or style, no external resources.
* The database is opened read-only (``readonly_session_factory``): SQLite itself refuses
  every write, and nothing is created at startup.
* Optional HTTP Basic password (the token), with a per-address failure throttle. Without
  a token only local host names are accepted, which blocks DNS-rebinding attacks.
* The overview is cached for a few seconds, so a burst of requests costs one set of
  queries, not one per request.
"""

from __future__ import annotations

import hmac
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, g, jsonify, render_template, request
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from surya_kundal.campaigns import campaign_detail, list_campaigns
from surya_kundal.dashboard import metrics, queries
from surya_kundal.dashboard.alerts import recent_alerts
from surya_kundal.database.engine import create_db_engine, make_session_factory
from surya_kundal.textsafe import printable

CSP = (
    "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
MAP_W, MAP_H = 960, 480
CACHE_SECONDS = 15.0
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
MAX_FAILURES = 5  # wrong passwords from one address ...
FAILURE_WINDOW = 60.0  # ... within this many seconds are answered with 429


def readonly_session_factory(url: str) -> sessionmaker[Session]:
    """A session factory whose connections cannot write. Raises if the database is missing."""
    return make_session_factory(create_db_engine(url, read_only=True))


def project(longitude: float, latitude: float) -> tuple[float, float]:
    """Equirectangular position on the 960x480 world map."""
    return round((longitude + 180) / 360 * MAP_W, 1), round((90 - latitude) / 180 * MAP_H, 1)


def ago(when: datetime | None, now: datetime | None = None) -> str:
    if when is None:
        return "never"
    now = now or datetime.now(UTC)
    seconds = int((now - when).total_seconds())
    if seconds < 0:
        return "just now"
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return f"{seconds}s ago"


def stamp(when: datetime | None) -> str:
    return "-" if when is None else when.strftime("%Y-%m-%d %H:%M:%S")


def _hostname(host: str) -> str:
    """The host part of a Host header, without port (handles bracketed IPv6)."""
    host = host.strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


class _Throttle:
    """Counts wrong passwords per client address; small, in memory, thread-safe."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = {}

    def blocked(self, client: str) -> bool:
        with self._lock:
            return len(self._recent(client)) >= MAX_FAILURES

    def record(self, client: str) -> None:
        with self._lock:
            if len(self._failures) > 10_000:  # a flood of addresses must not grow memory
                self._failures.clear()
            self._failures.setdefault(client, []).append(self._clock())

    def _recent(self, client: str) -> list[float]:
        cutoff = self._clock() - FAILURE_WINDOW
        kept = [t for t in self._failures.get(client, []) if t >= cutoff]
        if kept:
            self._failures[client] = kept
        else:
            self._failures.pop(client, None)
        return kept


class _Cache:
    """Keeps a computed value for a few seconds."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[str, tuple[float, Any]] = {}

    def get(self, key: str, build: Callable[[], Any]) -> Any:
        with self._lock:
            hit = self._items.get(key)
            if hit and self._clock() - hit[0] < CACHE_SECONDS:
                return hit[1]
        value = build()
        with self._lock:
            self._items[key] = (self._clock(), value)
        return value


def create_app(
    session_factory: sessionmaker[Session],
    *,
    alerts_path: Path | None = None,
    token: str = "",
    allowed_hosts: tuple[str, ...] = (),
    clock: Callable[[], float] = time.monotonic,
    show_internal: bool = False,
) -> Flask:
    """Build the app. Pass a factory from ``readonly_session_factory`` for production."""
    app = Flask(__name__)
    app.jinja_env.filters["p"] = printable
    app.jinja_env.filters["ago"] = ago
    app.jinja_env.filters["stamp"] = stamp
    app.jinja_env.globals["project"] = project
    throttle = _Throttle(clock)
    cache = _Cache(clock)
    hosts = LOCAL_HOSTS | {h.lower() for h in allowed_hosts}

    def db() -> Session:
        if "db" not in g:
            g.db = session_factory()
        return g.db  # type: ignore[no-any-return]

    app.extensions["surya_db"] = db

    @app.teardown_appcontext
    def close_db(_: BaseException | None) -> None:
        session = g.pop("db", None)
        if session is not None:
            session.close()

    @app.before_request
    def scope() -> None:
        queries.show_internal(show_internal)

    @app.before_request
    def guard() -> Response | None:
        # Without a password, only local names are served: a web page the analyst visits
        # could otherwise point its own domain at 127.0.0.1 and read this dashboard.
        if not token and _hostname(request.host) not in hosts:
            return Response("Unknown host", 421, mimetype="text/plain")
        if token and request.endpoint not in ("healthz", "static"):
            client = request.remote_addr or "?"
            if throttle.blocked(client):
                return Response("Too many attempts", 429, {"Retry-After": "60"})
            auth = request.authorization
            supplied = (auth.password or "") if auth else ""
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                if auth is not None:
                    throttle.record(client)
                return Response(
                    "Authentication required",
                    401,
                    {"WWW-Authenticate": 'Basic realm="Surya Kundal", charset="UTF-8"'},
                )
        return None

    @app.after_request
    def secure(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def global_state() -> dict[str, Any]:
        """Every page carries the global session count, so the "new activity" banner is exact."""
        try:
            count = queries.pulse(db())[0] if queries.has_data(db()) else 0
            hidden = queries.hidden_internal(db()) if count else 0
        except Exception:  # a page must still render if the count cannot be read
            count = hidden = 0
        return {"pulse_count": count, "hidden_internal": hidden}

    def page(template: str, build: Callable[[Session], dict[str, Any]]) -> str:
        """Render ``template`` with ``build(db)``; guide the user if nothing exists yet."""
        if not queries.has_data(db()):
            return render_template("empty.html")
        return render_template(template, **build(db()))

    @app.get("/healthz")
    def healthz() -> Response:
        try:
            db().execute(text("SELECT 1"))
        except Exception:
            return Response("database unavailable", 503, mimetype="text/plain")
        return Response("ok", mimetype="text/plain")

    @app.get("/metrics")
    def prometheus() -> Response:
        try:
            values = cache.get("metrics", lambda: metrics.collect(db()))
        except Exception:
            return Response("metrics unavailable", 503, mimetype="text/plain")
        return Response(metrics.render(values), content_type=metrics.CONTENT_TYPE)

    @app.get("/")
    def overview() -> str:
        def build(d: Session) -> dict[str, Any]:
            def compute() -> dict[str, Any]:
                return {
                    "totals": queries.totals(d),
                    "depth": queries.depth(d),
                    "points": queries.map_points(d),
                    "countries": queries.top_countries(d),
                    "hourly": queries.hourly_activity(d),
                    "techniques": queries.technique_counts(d, limit=8),
                    "probes": queries.probes(d),
                    "probing": queries.probing_sessions(d),
                }

            data = dict(cache.get("overview", compute))
            data["alerts"] = recent_alerts(alerts_path)
            data["alerts_enabled"] = alerts_path is not None and alerts_path.exists()
            return data

        return page("overview.html", build)

    @app.get("/sessions")
    def sessions() -> str:
        def build(d: Session) -> dict[str, Any]:
            result = queries.sessions_page(
                d,
                page=request.args.get("page", 1, type=int) or 1,
                query=request.args.get("q", "").strip()[:64],
                technique=request.args.get("technique", "").strip()[:16],
                country=request.args.get("country", "").strip()[:7],
            )
            return {"result": result, "args": request.args}

        return page("sessions.html", build)

    @app.get("/sessions/<session_id>")
    def session_view(session_id: str) -> str:
        if not queries.has_data(db()):
            return render_template("empty.html")
        detail = queries.session_detail(db(), session_id[:64])
        if detail is None:
            abort(404)
        return render_template("session.html", d=detail)

    @app.get("/campaigns")
    def campaigns() -> str:
        def build(d: Session) -> dict[str, Any]:
            try:
                rows = list_campaigns(d, limit=100)
            except OperationalError:  # database not yet migrated to the campaigns table
                rows = []
            return {"rows": rows}

        return page("campaigns.html", build)

    @app.get("/campaigns/<campaign_id>")
    def campaign_view(campaign_id: str) -> str:
        if not queries.has_data(db()):
            return render_template("empty.html")
        try:
            detail = campaign_detail(db(), campaign_id[:16])
        except OperationalError:
            detail = None
        if detail is None:
            abort(404)
        return render_template("campaign.html", d=detail)

    @app.get("/attack")
    def attack() -> str:
        return page("attack.html", lambda d: {"matrix": queries.attack_matrix(d)})

    @app.get("/api/pulse")
    def api_pulse() -> Response:
        if not queries.has_data(db()):
            return jsonify(sessions=0, last=None)
        count, last = queries.pulse(db())
        return jsonify(sessions=count, last=last.isoformat() if last else None)

    @app.errorhandler(404)
    def not_found(_: Exception) -> tuple[str, int]:
        return render_template("error.html", code=404, message="Nothing here."), 404

    @app.errorhandler(500)
    def broken(_: Exception) -> tuple[str, int]:
        return render_template("error.html", code=500, message="The dashboard hit an error."), 500

    return app
