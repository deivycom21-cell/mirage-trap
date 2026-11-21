"""Surveillance dashboard: a separate, loopback-only, read-only process.

* Binds to 127.0.0.1 unless the operator explicitly overrides it.
* Every API call needs the local token (cookie set from ``/?token=...`` or a Bearer
  header). The ``Host`` header is validated to defeat DNS rebinding.
* Opens the telemetry database read-only. Live updates use Server-Sent Events.
* No external assets: nothing leaves the machine.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import secrets
import time
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from mirage_trap.core.db import Database
from mirage_trap.core.export import parse_since

STATIC = Path(__file__).resolve().parent / "static"
COOKIE = "mt_dash"
ACTIVE_WINDOW = 30 * 60
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
LOGIN_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>mirage-trap</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/static/app.css"></head>
<body class="locked"><main class="lock"><h1>mirage<span>trap</span></h1><p>This dashboard needs its local access token.</p>
<p>Open the URL printed by <code>mirage-trap dashboard</code>, or read the token from
<code>data/dashboard.token</code> and visit <code>/?token=&lt;token&gt;</code>.</p></main></body></html>"""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def load_or_create_token(data_dir: Path) -> str:
    p = data_dir / "dashboard.token"
    if p.exists():
        tok = p.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    data_dir.mkdir(parents=True, exist_ok=True)
    tok = secrets.token_urlsafe(32)
    p.write_text(tok + "\n", encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return tok


class Queries:
    """All SQL the dashboard runs, against a read-only connection."""

    def __init__(self, db: Database):
        self.db = db

    def overview(self, since: float) -> dict:
        q, one = self.db.query, self.db.one
        now = time.time()
        totals = {
            "sessions": one("SELECT COUNT(*) n FROM sessions WHERE last_seen >= ?", (since,))["n"],
            "active": one("SELECT COUNT(*) n FROM sessions WHERE last_seen >= ?", (now - ACTIVE_WINDOW,))["n"],
            "events": one("SELECT COUNT(*) n FROM events WHERE ts >= ?", (since,))["n"],
            "ips": one("SELECT COUNT(DISTINCT ip) n FROM events WHERE ts >= ?", (since,))["n"],
            "credentials": one("SELECT COUNT(*) n FROM credentials WHERE ts >= ?", (since,))["n"],
            "logins": one("SELECT COUNT(*) n FROM credentials WHERE ts >= ? AND success = 1", (since,))["n"],
            "canary_hits": one("SELECT COUNT(*) n FROM canary_hits WHERE ts >= ?", (since,))["n"],
            "commands": one("SELECT COUNT(*) n FROM events WHERE ts >= ? AND kind = 'command'", (since,))["n"],
            "llm_calls_today": one("SELECT COALESCE(SUM(calls),0) n FROM llm_usage WHERE day = ?",
                                   (time.strftime("%Y-%m-%d", time.gmtime()),))["n"],
        }
        span = max(3600.0, now - since) if since else 86400.0
        bucket = 3600 if span <= 2 * 86400 else 86400
        start = now - span
        timeline = q("SELECT CAST((ts - ?) / ? AS INTEGER) b, COUNT(*) n, "
                     "SUM(CASE WHEN attack_type IS NOT NULL AND attack_type != 'recon' THEN 1 ELSE 0 END) a "
                     "FROM events WHERE ts >= ? GROUP BY b ORDER BY b", (start, bucket, start))
        return {
            "totals": totals,
            "timeline": {"start": start, "bucket": bucket, "points": timeline},
            "kinds": q("SELECT COALESCE(kind,'unknown') k, COUNT(*) n FROM sessions WHERE last_seen >= ? "
                       "GROUP BY k ORDER BY n DESC", (since,)),
            "protocols": q("SELECT protocol k, COUNT(*) n FROM events WHERE ts >= ? GROUP BY k ORDER BY n DESC",
                           (since,)),
            "attacks": q("SELECT attack_type k, COUNT(*) n FROM events WHERE ts >= ? AND attack_type IS NOT NULL "
                         "GROUP BY k ORDER BY n DESC LIMIT 12", (since,)),
            "paths": q("SELECT path k, COUNT(*) n FROM events WHERE ts >= ? AND kind = 'request' "
                       "GROUP BY k ORDER BY n DESC LIMIT 15", (since,)),
            "payloads": q("SELECT attack_detail k, COUNT(*) n FROM events WHERE ts >= ? AND attack_detail IS NOT NULL "
                          "AND attack_type != 'recon' GROUP BY k ORDER BY n DESC LIMIT 12", (since,)),
            "commands": q("SELECT path k, COUNT(*) n FROM events WHERE ts >= ? AND kind = 'command' AND "
                          "method IN ('shell','exec') AND path != '(password)' GROUP BY k ORDER BY n DESC LIMIT 15",
                          (since,)),
            "countries": q("SELECT COALESCE(country,'??') k, COUNT(*) n FROM sessions WHERE last_seen >= ? "
                           "GROUP BY k ORDER BY n DESC LIMIT 12", (since,)),
            "asns": q("SELECT COALESCE('AS' || asn || ' ' || COALESCE(as_org,''), '??') k, COUNT(*) n FROM sessions "
                      "WHERE last_seen >= ? GROUP BY k ORDER BY n DESC LIMIT 12", (since,)),
            "tools": q("SELECT tool k, COUNT(*) n FROM sessions WHERE last_seen >= ? AND tool IS NOT NULL "
                       "GROUP BY k ORDER BY n DESC LIMIT 12", (since,)),
            "usernames": q("SELECT username k, COUNT(*) n FROM credentials WHERE ts >= ? GROUP BY k "
                           "ORDER BY n DESC LIMIT 12", (since,)),
            "passwords": q("SELECT password k, COUNT(*) n FROM credentials WHERE ts >= ? AND protocol != 'ssh-key' "
                           "GROUP BY k ORDER BY n DESC LIMIT 12", (since,)),
            "sophistication": q("SELECT COALESCE(sophistication,0) k, COUNT(*) n FROM sessions WHERE last_seen >= ? "
                                "GROUP BY k ORDER BY k", (since,)),
        }

    def sessions(self, *, active: bool, limit: int, q: str = "", since: float = 0.0) -> list[dict]:
        cutoff = time.time() - ACTIVE_WINDOW if active else since
        sql = ("SELECT id, protocol, first_seen, last_seen, ip, ips, user_agent, ja3, ja4, country, city, asn, as_org, "
               "kind, kind_confidence, tool, sophistication, req_count, authenticated, "
               "(SELECT COUNT(*) FROM canary_hits h WHERE h.session_id = sessions.id) AS canary_hits, "
               "(SELECT COUNT(*) FROM credentials c WHERE c.session_id = sessions.id AND c.success = 1) AS logins, "
               "(SELECT attack_type FROM events e WHERE e.session_id = sessions.id AND e.attack_type IS NOT NULL "
               " AND e.attack_type != 'recon' ORDER BY e.id DESC LIMIT 1) AS last_attack "
               "FROM sessions WHERE last_seen >= ?")
        params: list = [cutoff]
        if q:
            sql += " AND (ip LIKE ? OR ips LIKE ? OR user_agent LIKE ? OR tool LIKE ? OR country LIKE ? OR id = ?)"
            like = f"%{q}%"
            params += [like, like, like, like, like, q]
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        rows = self.db.query(sql, params)
        for r in rows:
            r["ips"] = json.loads(r["ips"] or "[]")
        return rows

    def session(self, sid: str, after: int = 0) -> dict | None:
        s = self.db.one("SELECT * FROM sessions WHERE id = ?", (sid,))
        if not s:
            return None
        s["ips"] = json.loads(s["ips"] or "[]")
        events = self.db.query(
            "SELECT id, ts, protocol, ip, port, kind, method, path, query, headers, body, body_len, attack_type, "
            "attack_detail, persona, status, response, response_len, latency_sim_ms, latency_real_ms, provider "
            "FROM events WHERE session_id = ? AND id > ? ORDER BY id LIMIT 3000", (sid, after))
        for e in events:
            try:
                e["headers"] = json.loads(e["headers"]) if e["headers"] else []
            except ValueError:
                e["headers"] = []
        return {
            "session": s,
            "events": events,
            "credentials": self.db.query("SELECT ts, protocol, username, password, success FROM credentials "
                                         "WHERE session_id = ? ORDER BY id", (sid,)),
            "iocs": self.db.query("SELECT ts, kind, value, context FROM iocs WHERE session_id = ? ORDER BY id", (sid,)),
            "canary_hits": self.db.query(
                "SELECT h.ts, h.token, h.context, c.kind, c.label FROM canary_hits h LEFT JOIN canaries c "
                "ON c.token = h.token WHERE h.session_id = ? ORDER BY h.id", (sid,)),
        }

    def canaries(self) -> dict:
        return {
            "tokens": self.db.query(
                "SELECT c.token, c.kind, c.label, COUNT(h.id) AS hits, MAX(h.ts) AS last_hit, "
                "COUNT(DISTINCT h.session_id) AS sessions FROM canaries c LEFT JOIN canary_hits h ON h.token = c.token "
                "GROUP BY c.token ORDER BY hits DESC, c.label"),
            "hits": self.db.query(
                "SELECT h.id, h.ts, h.token, h.context, h.session_id, c.label, c.kind, s.ip, s.country, s.protocol "
                "FROM canary_hits h LEFT JOIN canaries c ON c.token = h.token "
                "LEFT JOIN sessions s ON s.id = h.session_id ORDER BY h.id DESC LIMIT 500"),
        }

    def iocs(self, limit: int = 500) -> list[dict]:
        return self.db.query(
            "SELECT i.id, i.ts, i.kind, i.value, i.context, i.session_id, s.ip FROM iocs i "
            "LEFT JOIN sessions s ON s.id = i.session_id ORDER BY i.id DESC LIMIT ?", (limit,))

    def events_after(self, after: int, limit: int = 200) -> list[dict]:
        return self.db.query(
            "SELECT e.id, e.ts, e.session_id, e.protocol, e.ip, e.kind, e.method, e.path, e.status, e.attack_type, "
            "e.persona, s.country, s.kind AS session_kind FROM events e LEFT JOIN sessions s ON s.id = e.session_id "
            "WHERE e.id > ? ORDER BY e.id LIMIT ?", (after, limit))

    def last_event_id(self) -> int:
        row = self.db.one("SELECT COALESCE(MAX(id), 0) AS n FROM events")
        return row["n"] if row else 0


def create_app(db_path: Path, token: str, *, allowed_hosts: set[str] | None = None,
               poll_interval: float = 1.0) -> Starlette:
    allowed = {h.lower() for h in (allowed_hosts or {"127.0.0.1", "localhost", "[::1]", "::1"})}
    state: dict = {"db": None}

    def queries() -> Queries:
        if state["db"] is None:
            if not db_path.exists():
                raise FileNotFoundError(str(db_path))
            state["db"] = Database(db_path, readonly=True)
        return Queries(state["db"])

    def authed(request: Request) -> bool:
        cand = request.cookies.get(COOKIE, "")
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            cand = auth[7:].strip()
        return bool(cand) and hmac.compare_digest(cand.encode(), token.encode())

    async def call(fn, *args, **kw):
        try:
            return await asyncio.to_thread(fn, *args, **kw)
        except FileNotFoundError:
            return None

    def no_db() -> JSONResponse:
        return JSONResponse({"error": "no telemetry yet: start the trap with `mirage-trap run`"}, 503)

    async def index(request: Request):
        tok = request.query_params.get("token")
        if tok is not None:
            if hmac.compare_digest(tok.encode(), token.encode()):
                r = RedirectResponse("/", 303)
                r.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")
                return r
            return HTMLResponse(LOGIN_PAGE, 401)
        if not authed(request):
            return HTMLResponse(LOGIN_PAGE, 401)
        return FileResponse(STATIC / "index.html", media_type="text/html; charset=utf-8")

    def api(fn):
        async def endpoint(request: Request):
            if not authed(request):
                return JSONResponse({"error": "unauthorized"}, 401)
            try:
                return await fn(request)
            except ValueError as e:
                return JSONResponse({"error": str(e)}, 400)
        return endpoint

    @api
    async def overview(request: Request):
        raw = request.query_params.get("since")
        since = parse_since("24h" if raw is None else raw)
        data = await call(lambda: queries().overview(since))
        return JSONResponse(data) if data is not None else no_db()

    @api
    async def sessions(request: Request):
        p = request.query_params
        limit = max(1, min(int(p.get("limit", 200)), 1000))
        since = parse_since(p.get("since") or "")
        data = await call(lambda: queries().sessions(active=p.get("active") == "1", limit=limit,
                                                     q=p.get("q", "")[:100], since=since))
        return JSONResponse(data) if data is not None else no_db()

    @api
    async def session(request: Request):
        sid = request.path_params["sid"]
        after = int(request.query_params.get("after", 0))
        data = await call(lambda: queries().session(sid, after))
        if data is None:
            return JSONResponse({"error": "not found"}, 404)
        return JSONResponse(data)

    @api
    async def canaries(request: Request):
        data = await call(lambda: queries().canaries())
        return JSONResponse(data) if data is not None else no_db()

    @api
    async def iocs(request: Request):
        data = await call(lambda: queries().iocs())
        return JSONResponse(data) if data is not None else no_db()

    @api
    async def stream(request: Request):
        try:
            last = int(request.headers.get("last-event-id") or request.query_params.get("after") or -1)
        except ValueError:
            last = -1

        async def gen():
            nonlocal last
            if last < 0:
                last = (await call(lambda: queries().last_event_id())) or 0
            yield "retry: 3000\n\n"
            ticks = 0
            while True:
                if await request.is_disconnected():
                    return
                rows = await call(lambda: queries().events_after(last)) or []
                if rows:
                    last = rows[-1]["id"]
                    yield f"id: {last}\nevent: events\ndata: {json.dumps(rows, default=str)}\n\n"
                elif ticks % 15 == 0:
                    yield ": keep-alive\n\n"
                ticks += 1
                await asyncio.sleep(poll_interval)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"})

    async def guard(scope, receive, send, inner):
        if scope["type"] == "http":
            host = ""
            for k, v in scope["headers"]:
                if k == b"host":
                    host = v.decode("latin-1").lower()
                    break
            hostname = host.rsplit(":", 1)[0] if not host.endswith("]") else host
            if hostname not in allowed:
                resp = Response("Misdirected Request: invalid Host header\n", 421, media_type="text/plain")
                await resp(scope, receive, send)
                return

            async def send_with_headers(msg):
                if msg["type"] == "http.response.start":
                    hdrs = list(msg.get("headers", []))
                    present = {k.lower() for k, _ in hdrs}
                    for k, v in SECURITY_HEADERS.items():
                        if k.lower().encode() not in present:
                            hdrs.append((k.lower().encode(), v.encode()))
                    msg = {**msg, "headers": hdrs}
                await send(msg)
            await inner(scope, receive, send_with_headers)
            return
        await inner(scope, receive, send)

    app = Starlette(routes=[
        Route("/", index),
        Route("/api/overview", overview),
        Route("/api/sessions", sessions),
        Route("/api/sessions/{sid:str}", session),
        Route("/api/canaries", canaries),
        Route("/api/iocs", iocs),
        Route("/api/stream", stream),
        Mount("/static", StaticFiles(directory=str(STATIC)), name="static"),
    ])

    async def asgi(scope, receive, send):
        await guard(scope, receive, send, app)

    asgi.app = app  # type: ignore[attr-defined]
    return asgi  # type: ignore[return-value]


def run(db_path: Path, data_dir: Path, host: str, port: int, *, force_bind: bool = False) -> None:
    import uvicorn

    if not is_loopback(host) and not force_bind:
        raise SystemExit(f"refusing to bind the dashboard to {host}: it must stay on loopback. Use an SSH tunnel "
                         "(ssh -L 9090:127.0.0.1:9090 sensor) or pass --i-know-what-im-doing.")
    token = load_or_create_token(data_dir)
    allowed = {"127.0.0.1", "localhost", "[::1]", "::1"}
    if not is_loopback(host):
        allowed.add(host.lower())
    app = create_app(db_path, token, allowed_hosts=allowed)
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"mirage-trap dashboard: http://{shown}:{port}/?token={token}", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False, server_header=False)
