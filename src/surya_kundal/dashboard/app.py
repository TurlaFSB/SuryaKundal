"""The Surya Kundal dashboard: a small, read-only, server-rendered Flask app.

Design choices that matter for a honeypot tool:

* Everything shown was typed by an attacker, so it is escaped by Jinja and also passed
  through ``printable`` (no control or invisible characters reach the browser).
* A strict Content-Security-Policy: no inline script or style, no external resources.
* The database connection is switched to ``query_only``; this app cannot write.
* Optional HTTP Basic password (the token); the CLI insists on one off-localhost.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, g, jsonify, render_template, request
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from surya_kundal.dashboard import queries
from surya_kundal.dashboard.alerts import recent_alerts
from surya_kundal.textsafe import printable

CSP = (
    "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
MAP_W, MAP_H = 960, 480


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


def _authorised(token: str) -> bool:
    auth = request.authorization
    supplied = (auth.password or "") if auth else ""
    return hmac.compare_digest(supplied.encode(), token.encode())


def create_app(
    session_factory: sessionmaker[Session],
    *,
    alerts_path: Path | None = None,
    token: str = "",
) -> Flask:
    app = Flask(__name__)
    app.jinja_env.filters["p"] = printable
    app.jinja_env.filters["ago"] = ago
    app.jinja_env.filters["stamp"] = stamp
    app.jinja_env.globals["project"] = project

    def db() -> Session:
        if "db" not in g:
            session = session_factory()
            if session.get_bind().dialect.name == "sqlite":
                session.execute(text("PRAGMA query_only=ON"))
            g.db = session
        return g.db  # type: ignore[no-any-return]

    app.extensions["surya_db"] = db

    @app.teardown_appcontext
    def close_db(_: BaseException | None) -> None:
        session = g.pop("db", None)
        if session is not None:
            if session.get_bind().dialect.name == "sqlite":
                # the setting belongs to the pooled connection; do not leave it behind
                session.rollback()
                session.execute(text("PRAGMA query_only=OFF"))
            session.close()

    @app.before_request
    def require_token() -> Response | None:
        if token and request.endpoint not in ("healthz", "static") and not _authorised(token):
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

    def page(template: str, build: Callable[[Session], dict[str, Any]]) -> str:
        """Render ``template`` with ``build(db)``; guide the user if nothing exists yet."""
        if not queries.has_data(db()):
            return render_template("empty.html")
        return render_template(template, **build(db()))

    @app.get("/healthz")
    def healthz() -> Response:
        return Response("ok", mimetype="text/plain")

    @app.get("/")
    def overview() -> str:
        def build(d: Session) -> dict[str, Any]:
            return {
                "totals": queries.totals(d),
                "depth": queries.depth(d),
                "points": queries.map_points(d),
                "countries": queries.top_countries(d),
                "hourly": queries.hourly_activity(d),
                "techniques": queries.technique_counts(d, limit=8),
                "probes": queries.probes(d),
                "probing": queries.probing_sessions(d),
                "alerts": recent_alerts(alerts_path),
                "alerts_enabled": alerts_path is not None and alerts_path.exists(),
            }

        return page("overview.html", build)

    @app.get("/sessions")
    def sessions() -> str:
        def build(d: Session) -> dict[str, Any]:
            result = queries.sessions_page(
                d,
                page=request.args.get("page", 1, type=int) or 1,
                query=request.args.get("q", "").strip()[:64],
                technique=request.args.get("technique", "").strip()[:16],
                country=request.args.get("country", "").strip()[:2],
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
