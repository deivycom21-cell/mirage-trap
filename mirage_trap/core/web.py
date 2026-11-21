"""HTTP application: request plumbing + per-profile handlers.

Every handler reproduces what the application source in the VFS would do (the
attacker can read that source through LFI or the exposed .git, so behaviour and
code must agree). SQL goes to the session's SQL engine, shell to the shell
emulator, file reads to the VFS with the web user's permissions.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import posixpath
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import formatdate
from typing import Awaitable, Callable
from urllib.parse import parse_qs, quote, unquote

import jinja2

from mirage_trap.config import Config
from mirage_trap.core import camouflage
from mirage_trap.core.camouflage import Fingerprint, Latency, Profile, nginx_etag, PROFILES_DIR
from mirage_trap.core.classifier import classify, summarize
from mirage_trap.core.deceiver import Deceiver
from mirage_trap.core.sqlemu import SqlResult
from mirage_trap.core.state import Session
from mirage_trap.core.vfs import FS_ERR_TEXT, FsError, node_size

log = logging.getLogger("mirage.web")

MAX_BODY = 1024 * 1024
MIME = {".txt": "text/plain", ".css": "text/css", ".js": "application/javascript", ".html": "text/html",
        ".htm": "text/html", ".json": "application/json", ".xml": "text/xml", ".pdf": "application/pdf",
        ".png": "image/png", ".jpg": "image/jpeg", ".gif": "image/gif", ".ico": "image/x-icon",
        ".svg": "image/svg+xml", ".zip": "application/zip", ".md": "text/markdown"}


@dataclass
class Req:
    method: str
    path: str
    raw_path: str
    query_string: str
    query: dict[str, str]
    headers: dict[str, str]
    raw_headers: list[tuple[str, str]]
    body: bytes
    form: dict[str, str]
    json: object
    cookies: dict[str, str]
    ip: str
    host: str
    port: int
    session: Session
    tls: dict | None = None

    def arg(self, name: str, default: str | None = None) -> str | None:
        return self.query.get(name, default)


@dataclass
class Resp:
    status: int = 200
    body: bytes | str = b""
    content_type: str | None = "text/html; charset=UTF-8"
    kind: str = "dynamic"          # dynamic | static | error | json
    headers: list[tuple[str, str]] = field(default_factory=list)
    location: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    chunked: bool | None = None     # None = family default
    start_session: bool = False
    latency: str = "dynamic"
    rows: int = 0
    extra_sleep: float = 0.0
    persona: str | None = None
    provider: str | None = None
    close: bool = False


Handler = Callable[[Req], Awaitable[Resp]]


def _parse_cookies(header: str) -> dict[str, str]:
    out = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out.setdefault(k, v)
    return out


def _first(qs: dict[str, list[str]]) -> dict[str, str]:
    return {k: v[0] for k, v in qs.items() if v}


# ---------------------------------------------------------------------------
# ASGI app
# ---------------------------------------------------------------------------

class MirageApp:
    def __init__(self, cfg: Config, profile: Profile, deceiver: Deceiver):
        self.cfg = cfg
        self.profile = profile
        self.fp = Fingerprint(profile)
        self.latency = Latency(profile.latency)
        self.deceiver = deceiver
        self.world = deceiver.world
        loader = jinja2.ChoiceLoader([
            jinja2.FileSystemLoader(str(profile.path / "templates")),
            jinja2.FileSystemLoader(str(PROFILES_DIR / "_shared" / "templates")),
        ])
        self.jinja = jinja2.Environment(loader=loader, autoescape=True, trim_blocks=True, lstrip_blocks=True)
        self.site = build_site(self)

    def render(self, name: str, **ctx) -> str:
        return self.jinja.get_template(name).render(world=self.world.data, company=self.world.company,
                                                    year=datetime.now(timezone.utc).year, **ctx)

    def error(self, status: int, req: Req | None = None, method: str = "GET", path: str = "/") -> Resp:
        ua = req.headers.get("user-agent", "") if req else ""
        host, port = self.public_host_port(req)
        body, ctype = self.fp.error_page(status, req.method if req else method, req.raw_path if req else path,
                                         ua, host, port)
        return Resp(status, body, ctype, kind="error", latency="error")

    @staticmethod
    def public_host_port(req: Req | None) -> tuple[str, int]:
        """Host/port as the client sees them (Apache's UseCanonicalName Off). The trap
        usually listens on 8080 behind a port redirect; leaking that would be a tell."""
        if req is None:
            return "localhost", 80
        host = req.host or "localhost"
        if host.startswith("["):
            name, _, rest = host.partition("]")
            name += "]"
            port_s = rest.lstrip(":")
        else:
            name, _, port_s = host.partition(":")
        default = 443 if req.tls else 80
        return name, int(port_s) if port_s.isdigit() else default

    # -- ASGI entry ----------------------------------------------------------------
    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        t0 = time.perf_counter()
        body = b""
        too_large = False
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body += msg.get("body", b"")
            if len(body) > MAX_BODY:
                too_large = True
                body = body[:MAX_BODY]
            if not msg.get("more_body"):
                break
        req = self._build_request(scope, body)
        try:
            resp = await self._route(req, scope, too_large)
        except Exception:   # never leak a Python traceback or a uvicorn 500
            log.exception("handler failed for %s %s", req.method, req.path)
            resp = self.error(500 if self.profile.family != "nginx" else 502, req)
        await self._finish(req, resp, scope, send, t0)

    def _build_request(self, scope, body: bytes) -> Req:
        raw_head = scope.get("mirage.raw_head", b"")
        raw_headers: list[tuple[str, str]] = []
        for line in raw_head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                raw_headers.append((k.decode("latin-1"), v.strip().decode("latin-1")))
        if not raw_headers:
            raw_headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]]
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        client = scope.get("client") or ("0.0.0.0", 0)
        ip = client[0]
        tls_fp = scope.get("mirage.tls")
        srv = self.cfg.server
        internal = {srv.client_ip_header.lower(), srv.ja3_header.lower(), srv.ja4_header.lower()}
        if srv.behind_proxy and _trusted(ip, srv.trusted_proxies):
            ip = headers.get(srv.client_ip_header.lower(), ip)
            if headers.get(srv.ja3_header.lower()):
                tls_fp = {"ja3": headers.get(srv.ja3_header.lower()), "ja4": headers.get(srv.ja4_header.lower())}
        if srv.behind_proxy:
            raw_headers = [(k, v) for k, v in raw_headers if k.lower() not in internal]
            headers = {k: v for k, v in headers.items() if k not in internal}
        qs = scope.get("query_string", b"").decode("latin-1")
        ctype = headers.get("content-type", "")
        form, js = {}, None
        if "application/x-www-form-urlencoded" in ctype:
            form = _first(parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True))
        elif "application/json" in ctype and body:
            try:
                js = json.loads(body)
            except ValueError:
                js = ValueError("bad json")
        elif "multipart/form-data" in ctype:
            form = _parse_multipart(body, ctype)
        cookies = _parse_cookies(headers.get("cookie", ""))
        raw_path = scope.get("raw_path", scope["path"].encode()).decode("latin-1")
        server = scope.get("server") or ("0.0.0.0", srv.port)
        session, _ = self.deceiver.sessions.resolve(
            ip, "http", cookie=cookies.get(self.profile.cookie_name), user_agent=headers.get("user-agent"),
            ja3=(tls_fp or {}).get("ja3"), ja4=(tls_fp or {}).get("ja4"))
        return Req(method=scope["method"], path=scope["path"], raw_path=raw_path, query_string=qs,
                   query=_first(parse_qs(qs, keep_blank_values=True)), headers=headers, raw_headers=raw_headers,
                   body=body, form=form, json=js, cookies=cookies, ip=ip, host=headers.get("host", server[0]),
                   port=server[1] or srv.port, session=session, tls=tls_fp)

    async def _route(self, req: Req, scope, too_large: bool) -> Resp:
        fam = self.profile.family
        if too_large:
            return self.error(413, req)
        if len(req.raw_path) + len(req.query_string) > 8190:
            return self.error(414, req)
        if req.method == "TRACE":
            return self.error(405, req)
        if fam in ("nginx", "apache"):
            # nginx/apache resolve "..": escaping the document root is a 400.
            depth = 0
            for part in unquote(req.raw_path).split("/"):
                if part == "..":
                    depth -= 1
                    if depth < 0:
                        return self.error(400, req)
                elif part not in ("", "."):
                    depth += 1
        return await self.site(req)

    async def _finish(self, req: Req, resp: Resp, scope, send, t0: float) -> None:
        body = resp.body.encode("utf-8") if isinstance(resp.body, str) else resp.body
        extra = list(resp.headers)
        s = req.session
        if resp.start_session and self.profile.cookie_format != "none" and self.profile.cookie_name not in req.cookies:
            value = self.profile.new_cookie_value()
            self.deceiver.sessions.bind_cookie(s, value)
            extra = [("Set-Cookie", self.profile.cookie_header(value)),
                     ("Expires", "Thu, 19 Nov 1981 08:52:00 GMT"),
                     ("Cache-Control", "no-store, no-cache, must-revalidate"), ("Pragma", "no-cache")] + extra
        elif resp.start_session and self.profile.cookie_format == "php":
            extra = [("Expires", "Thu, 19 Nov 1981 08:52:00 GMT"),
                     ("Cache-Control", "no-store, no-cache, must-revalidate"), ("Pragma", "no-cache")] + extra
        chunked = resp.chunked
        if chunked is None:
            chunked = self.profile.family == "nginx" and resp.kind == "dynamic"
        length = None if chunked else len(body)
        keep_alive = not scope.get("mirage.client_close") and not resp.close
        headers = self.fp.headers(status=resp.status, content_type=resp.content_type, length=length, kind=resp.kind,
                                  extra=extra, keep_alive=keep_alive, method=req.method, etag=resp.etag,
                                  last_modified=resp.last_modified, location=resp.location, body=body)
        # latency: realistic service time minus what we already spent, plus emulated sleeps
        spent = time.perf_counter() - t0
        target = self.latency.sample(resp.latency, resp.rows, s.id) + resp.extra_sleep
        if target > spent:
            await asyncio.sleep(target - spent)
        await send({"type": "http.response.start", "status": resp.status, "headers": headers})
        if req.method == "HEAD":
            await send({"type": "http.response.body", "body": b""})
        elif chunked and len(body) > 4096:
            for i in range(0, len(body), 8192):
                await send({"type": "http.response.body", "body": body[i:i + 8192], "more_body": i + 8192 < len(body)})
        else:
            await send({"type": "http.response.body", "body": body})
        await self.deceiver.commit(s)
        body_text = req.body.decode("utf-8", "replace")
        found = classify(req.method, req.raw_path, req.query_string, body_text, req.headers)
        attack, detail = summarize(found)
        self.deceiver.telemetry.event(
            s, protocol="https" if req.tls else "http", ip=req.ip, port=req.port, kind="request", method=req.method,
            path=req.raw_path, query=req.query_string, headers=req.raw_headers, body=req.body,
            attack_type=attack, attack_detail=detail, persona=resp.persona, status=resp.status, response=body,
            latency_sim_ms=round(target * 1000, 1), latency_real_ms=round((time.perf_counter() - t0) * 1000, 1),
            provider=resp.provider)
        self.deceiver.telemetry.scan(s, "\n".join([req.raw_path, req.query_string, body_text,
                                                   req.headers.get("authorization", ""), req.headers.get("cookie", "")]),
                                     "http request")


def _trusted(ip: str, nets: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        try:
            if addr in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def _parse_multipart(body: bytes, ctype: str) -> dict[str, str]:
    m = re.search(r"boundary=\"?([^\";]+)", ctype)
    if not m:
        return {}
    out = {}
    for part in body.split(b"--" + m.group(1).encode()):
        head, _, data = part.partition(b"\r\n\r\n")
        nm = re.search(rb'name="([^"]+)"', head)
        if nm:
            fn = re.search(rb'filename="([^"]*)"', head)
            key = nm.group(1).decode("latin-1")
            out[key] = data.rstrip(b"\r\n-").decode("utf-8", "replace")
            if fn:
                out[key + "__filename"] = fn.group(1).decode("latin-1")
    return out


# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------

WEBSHELL_RX = re.compile(r"(system|passthru|shell_exec|exec|popen|proc_open|eval|assert)\s*\(\s*(?:base64_decode\s*\(\s*)?"
                         r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]?(\w+)['\"]?\s*\]", re.I)


class Site:
    """Common behaviour for the PHP profiles: VFS-backed docroot + PHP handlers."""

    def __init__(self, app: MirageApp):
        self.app = app
        self.world = app.world
        self.d = app.deceiver
        self.webroot = self.world.stack["webroot"]
        self.web_user = self.world.stack["web_user"]
        self.handlers: dict[str, Handler] = {}

    async def __call__(self, req: Req) -> Resp:
        raise NotImplementedError

    # -- helpers ---------------------------------------------------------------
    def vfs(self, req: Req):
        return self.d.runtime(req.session).vfs

    def web_groups(self) -> tuple[str, ...]:
        groups = [self.web_user]
        try:
            for line in self.vfs_any().read("/etc/group").splitlines():
                p = line.split(":")
                if len(p) >= 4 and self.web_user in p[3].split(","):
                    groups.append(p[0])
        except FsError:
            pass
        return tuple(groups)

    def vfs_any(self):
        from mirage_trap.core.vfs import VirtualFS
        return VirtualFS(self.world, self.d.world_overlay, {})

    def sql(self, req: Req, query: str, multi: bool = False) -> list[SqlResult]:
        return self.d.run_sql(req.session, query, multi)

    async def shell_exec(self, req: Req, command: str) -> tuple[str, float]:
        rt = self.d.runtime(req.session)
        async with rt.lock:
            sh = self.d.shell(req.session, user=self.web_user, interactive=False, cwd=self.webroot, protocol="http")
            sh.ctx.cwd = self.webroot
            out, _ = await sh.run(command)
            await self.d.commit(req.session, sh)
            return out, sh.sleep_total

    def static(self, req: Req, path: str) -> Resp | None:
        """Serve a non-PHP file from the docroot like the web server would."""
        vfs = self.vfs(req)
        node = vfs.get(path)
        if node is None:
            return None
        if node.kind == "dir":
            return None
        if not vfs.can(node, self.web_user, self.web_groups(), 4):
            return self.app.error(403, req)
        content = vfs.read(path, "/", "root", ())
        body = content.encode("utf-8", "surrogateescape") if isinstance(content, str) else content
        ext = posixpath.splitext(path)[1].lower()
        fam = self.app.profile.family
        ctype = MIME.get(ext, "application/octet-stream" if fam != "apache" else None)
        if ctype and ctype.startswith("text/") and fam == "express":
            ctype += "; charset=UTF-8"
        mtime = node.mtime or self.world.data["host"]["installed"]
        lm = formatdate(mtime, usegmt=True)
        if fam == "express":
            etag = f'W/"{len(body):x}-{int(mtime * 1000):x}"'
        elif fam == "nginx":
            etag = nginx_etag(mtime, len(body))
        else:
            etag = f'"{len(body):x}-{int(mtime * 1e6):x}"'
        return Resp(200, body, ctype, kind="static", etag=etag, last_modified=lm, latency="static", chunked=False)

    def docroot_path(self, req: Req) -> str:
        return posixpath.normpath(self.webroot + "/" + unquote(req.raw_path.split("?", 1)[0]).lstrip("/"))

    async def php_file(self, req: Req, path: str) -> Resp:
        """A .php file that exists but has no dedicated handler."""
        vfs = self.vfs(req)
        node = vfs.get(path)
        content = node.content if node else ""
        m = WEBSHELL_RX.search(content)
        if m:
            source = {"GET": req.query, "POST": req.form, "REQUEST": {**req.query, **req.form},
                      "COOKIE": req.cookies}[m.group(2).upper()]
            arg = source.get(m.group(3), "")
            if m.group(0).lower().find("base64_decode") != -1:
                try:
                    arg = base64.b64decode(arg).decode("utf-8", "replace")
                except ValueError:
                    arg = ""
            func = m.group(1).lower()
            out, sleep = "", 0.0
            if arg:
                if func in ("eval", "assert"):
                    sh_cmd = _php_code_to_shell(arg)
                    if sh_cmd is not None:
                        out, sleep = await self.shell_exec(req, sh_cmd)
                else:
                    out, sleep = await self.shell_exec(req, arg)
                self.d.telemetry.ioc(req.session, "webshell", f"{path}?{m.group(3)}", arg[:500])
            if func == "exec":
                out = out.rstrip("\n").split("\n")[-1] if out else ""
            return Resp(200, out, start_session="session_start" in content, extra_sleep=sleep, persona="webshell")
        if "phpinfo()" in content:
            return Resp(200, self.app.render("phpinfo.html", req=req, server_ip=self.world.data["host"]["ip"]))
        # include-only files (config.php, auth.php...) execute and print nothing
        return Resp(200, "", start_session="session_start" in content or "config.php" in content)


def _php_code_to_shell(code: str) -> str | None:
    m = re.search(r"(system|passthru|shell_exec|exec)\s*\(\s*['\"](.+?)['\"]\s*\)", code)
    if m:
        return m.group(2)
    m = re.search(r"echo\s+['\"](.*?)['\"]", code)
    if m:
        return "echo " + json.dumps(m.group(1))
    return None


# ---------------------------------------------------------------------------
# phpMyAdmin (shared by the PHP profiles)
# ---------------------------------------------------------------------------

class PhpMyAdmin:
    def __init__(self, site: Site):
        self.site = site
        self.app = site.app
        self.world = site.world

    async def handle(self, req: Req, sub: str) -> Resp:
        s = req.session
        sec = self.world.data["secrets"]
        if sub in ("", "index.php") and req.method == "POST" and "pma_username" in req.form:
            user, pw = req.form.get("pma_username", ""), req.form.get("pma_password", "")
            ok = (user == sec["db_user"] and pw == sec["db_password"]) or (user == "root" and pw == sec["db_root_password"])
            self.site.d.telemetry.credential(s, "phpmyadmin", user, pw, ok)
            if ok:
                s.pma_user = user
                return Resp(302, "", location="index.php", start_session=True, latency="db")
            err = (f"mysqli_real_connect(): (HY000/1045): Access denied for user '{html.escape(user)}'@"
                   f"'{self.world.data['host']['ip']}' (using password: {'YES' if pw else 'NO'})")
            return Resp(200, self.app.render("pma_login.html", error=err), start_session=True, latency="db",
                        extra_sleep=0.4)
        if not s.pma_user:
            if sub in ("", "index.php"):
                return Resp(200, self.app.render("pma_login.html", error=None), start_session=True)
            return Resp(302, "", location="index.php", start_session=True)
        if sub == "logout.php":
            s.pma_user = None
            return Resp(302, "", location="index.php", start_session=True)
        tables = self.site.sql(req, "SHOW TABLES")[0].rows
        query = req.form.get("sql_query") or req.query.get("sql_query")
        result_html, error, sleep = None, None, 0.0
        if query:
            for r in self.site.sql(req, query, multi=True):
                sleep += r.sleep
                if r.error:
                    error = f"#{r.error.code} - {r.error.message}"
                    break
                result_html = r
        table = req.query.get("table")
        if table and not query:
            r = self.site.sql(req, f"SELECT * FROM `{table}` LIMIT 25")[0]
            if r.error:
                error = f"#{r.error.code} - {r.error.message}"
            else:
                result_html, query = r, f"SELECT * FROM `{table}` LIMIT 0, 25"
        return Resp(200, self.app.render("pma_main.html", user=s.pma_user, tables=[t[0] for t in tables],
                                         query=query, result=result_html, error=error,
                                         db=sec["db_name"], db_host=self.world.data["host"]["db_hostname"]),
                    start_session=True, latency="db", rows=len(result_html.rows) if result_html else 0,
                    extra_sleep=sleep, persona="mysql" if query else None)


# ---------------------------------------------------------------------------
# Profile: nginx-php-legacy (customer portal)
# ---------------------------------------------------------------------------

class PhpPortal(Site):
    def __init__(self, app: MirageApp):
        super().__init__(app)
        self.pma = PhpMyAdmin(self)
        self.handlers = {
            "/index.php": self.index, "/product.php": self.product, "/login.php": self.login,
            "/logout.php": self.logout, "/download.php": self.download, "/admin/index.php": self.admin,
            "/admin/users.php": self.admin_users, "/admin/tools.php": self.admin_tools,
        }

    async def __call__(self, req: Req) -> Resp:
        path = unquote(req.raw_path.split("?", 1)[0])
        if path.startswith("/phpmyadmin"):
            if path == "/phpmyadmin":
                return self._redirect_dir(req, "/phpmyadmin/")
            return await self.pma.handle(req, path[len("/phpmyadmin/"):])
        full = self.docroot_path(req)
        vfs = self.vfs(req)
        node = vfs.get(full)
        if node is not None and node.kind == "dir":
            if not path.endswith("/"):
                return self._redirect_dir(req, path + "/")
            idx = posixpath.join(full, "index.php")
            if vfs.get(idx) is None:
                return self.app.error(403, req)
            full = idx
        rel = full[len(self.webroot):] or "/"
        if rel in self.handlers:
            return await self.handlers[rel](req)
        if full.endswith(".php"):
            if vfs.get(full) is None:
                return self.app.error(404, req)
            return await self.php_file(req, full)
        resp = self.static(req, full)
        return resp or self.app.error(404, req)

    def _redirect_dir(self, req: Req, location: str) -> Resp:
        r = self.app.error(301, req)
        scheme = "https" if req.tls else "http"
        r.location = f"{scheme}://{req.headers.get('host', 'localhost')}{location}"
        if self.app.profile.family != "nginx":
            host, port = self.app.public_host_port(req)
            r.body = (f'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>301 Moved Permanently</title>\n'
                      f"</head><body>\n<h1>Moved Permanently</h1>\n<p>The document has moved <a href=\"{html.escape(r.location)}\">here</a>.</p>\n"
                      f"<hr>\n<address>{self.app.profile.server} Server at {html.escape(host)} Port {port}</address>\n"
                      f"</body></html>\n").encode()
        return r

    async def index(self, req: Req) -> Resp:
        r = self.sql(req, "SELECT id, name, price FROM products")[0]
        return Resp(200, self.app.render("home.html", products=r.rows, user=req.session.web_user),
                    start_session=True, latency="db", rows=len(r.rows))

    async def product(self, req: Req) -> Resp:
        pid = req.query.get("id", "")
        res = self.sql(req, f"SELECT id, name, price, description FROM products WHERE id = {pid}")[0]
        if res.error:
            # `or die(mysqli_error($conn))`: only the message, nothing else
            return Resp(200, res.error.message, start_session=True, latency="db", extra_sleep=res.sleep,
                        persona="mysql")
        row = res.rows[0] if res.rows else None
        return Resp(200, self.app.render("product.html", p=row, user=req.session.web_user), start_session=True,
                    latency="db", rows=len(res.rows), extra_sleep=res.sleep, persona="mysql")

    async def login(self, req: Req) -> Resp:
        error = None
        if req.method == "POST":
            u, p = req.form.get("username", ""), req.form.get("password", "")
            self.d.telemetry.credential(req.session, "http-login", u, p, False)
            pmd5 = hashlib.md5(p.encode()).hexdigest()
            res = self.sql(req, f"SELECT * FROM users WHERE username='{u}' AND password='{pmd5}'")[0]
            if not res.error and res.rows:
                cols = res.columns
                row = dict(zip(cols, res.rows[0]))
                req.session.web_user = str(row.get("username", res.rows[0][1] if len(res.rows[0]) > 1 else "admin"))
                return Resp(302, "", location="/admin/", start_session=True, latency="db", extra_sleep=res.sleep)
            error = "Invalid username or password"
            return Resp(200, self.app.render("login.html", error=error), start_session=True, latency="db",
                        extra_sleep=res.sleep)
        return Resp(200, self.app.render("login.html", error=error), start_session=True)

    async def logout(self, req: Req) -> Resp:
        req.session.web_user = None
        return Resp(302, "", location="/login.php", start_session=True)

    def _need_login(self, req: Req) -> Resp | None:
        if not req.session.web_user:
            return Resp(302, "", location="/login.php", start_session=True)
        return None

    async def admin(self, req: Req) -> Resp:
        if (r := self._need_login(req)):
            return r
        stats = {}
        for key, q in [("customers", "SELECT COUNT(*) FROM customers"), ("orders", "SELECT COUNT(*) FROM orders"),
                       ("revenue", "SELECT ROUND(SUM(total),2) FROM orders WHERE status IN ('paid','shipped')"),
                       ("pending", "SELECT COUNT(*) FROM orders WHERE status='pending'")]:
            res = self.sql(req, q)[0]
            stats[key] = res.rows[0][0] if res.rows else 0
        recent = self.sql(req, "SELECT o.id, c.name, p.name, o.total, o.status, o.created_at FROM orders o "
                               "JOIN customers c ON c.id=o.customer_id JOIN products p ON p.id=o.product_id "
                               "ORDER BY o.created_at DESC LIMIT 10")[0]
        return Resp(200, self.app.render("admin.html", user=req.session.web_user, stats=stats, recent=recent.rows),
                    start_session=True, latency="db", rows=10)

    async def admin_users(self, req: Req) -> Resp:
        if (r := self._need_login(req)):
            return r
        res = self.sql(req, "SELECT id, username, email, role, active FROM users")[0]
        return Resp(200, self.app.render("users.html", user=req.session.web_user, users=res.rows),
                    start_session=True, latency="db", rows=len(res.rows))

    async def admin_tools(self, req: Req) -> Resp:
        if (r := self._need_login(req)):
            return r
        output, sleep, host = None, 0.0, req.form.get("host")
        if req.method == "POST" and host is not None:
            output, sleep = await self.shell_exec(req, "ping -c 4 " + host)
        return Resp(200, self.app.render("tools.html", user=req.session.web_user, output=output, host=host or ""),
                    start_session=True, extra_sleep=sleep, persona="bash" if output is not None else None)

    async def download(self, req: Req) -> Resp:
        f = req.query.get("file", "")
        path = posixpath.join(self.webroot, "uploads/" + f)
        try:
            data = self.vfs(req).read(path, self.webroot, self.web_user, self.web_groups())
        except FsError:
            data = ""   # readfile() warning, display_errors=Off -> empty body
        return Resp(200, data.encode("utf-8", "surrogateescape"), "application/octet-stream", chunked=True,
                    persona="file")


# ---------------------------------------------------------------------------
# Profile: ubuntu-admin-panel (Apache + PHP ops console)
# ---------------------------------------------------------------------------

class OpsPanel(PhpPortal):
    def __init__(self, app: MirageApp):
        Site.__init__(self, app)
        self.pma = PhpMyAdmin(self)
        self.handlers = {
            "/index.php": self.index, "/login.php": self.login, "/logout.php": self.logout,
            "/dashboard.php": self.dashboard, "/tools/diagnostics.php": self.diagnostics, "/logs.php": self.logs,
        }

    async def __call__(self, req: Req) -> Resp:
        path = unquote(req.raw_path.split("?", 1)[0])
        if path in ("/server-status", "/server-info") or path.startswith("/cgi-bin/"):
            return self.app.error(403 if path != "/cgi-bin/" else 403, req)
        if posixpath.basename(path).startswith(".ht"):
            return self.app.error(403, req)
        return await super().__call__(req)

    async def index(self, req: Req) -> Resp:
        if req.session.web_user:
            return Resp(302, "", location="dashboard.php", start_session=True)
        return Resp(200, self.app.render("login.html", error=req.query.get("error")), start_session=True)

    async def login(self, req: Req) -> Resp:
        u, p = req.form.get("username", ""), req.form.get("password", "")
        if req.method != "POST":
            return Resp(302, "", location="index.php", start_session=True)
        self.d.telemetry.credential(req.session, "http-login", u, p, False)
        pmd5 = hashlib.md5(p.encode()).hexdigest()
        res = self.sql(req, f"SELECT * FROM users WHERE username='{u}' AND password='{pmd5}' AND role='admin'")[0]
        if not res.error and res.rows:
            row = dict(zip(res.columns, res.rows[0]))
            req.session.web_user = str(row.get("username", "admin"))
            return Resp(302, "", location="dashboard.php", start_session=True, latency="db", extra_sleep=res.sleep)
        return Resp(302, "", location="index.php?error=1", start_session=True, latency="db", extra_sleep=res.sleep)

    async def logout(self, req: Req) -> Resp:
        req.session.web_user = None
        return Resp(302, "", location="index.php", start_session=True)

    def _need_login(self, req: Req) -> Resp | None:
        if not req.session.web_user:
            depth = req.raw_path.count("/") - 1
            return Resp(302, "", location="../" * depth + "index.php", start_session=True)
        return None

    async def dashboard(self, req: Req) -> Resp:
        if (r := self._need_login(req)):
            return r
        h = self.world.data["host"]
        load = self.vfs(req).read("/proc/loadavg").split()[:3]
        up_days = int(self.world.uptime_seconds() // 86400)
        services = [("apache2", "active (running)"), ("mysql (remote)", h["db_hostname"]),
                    ("cron", "active (running)"), ("ssh", "active (running)"), ("redis-server", "active (running)")]
        return Resp(200, self.app.render("dashboard.html", user=req.session.web_user, host=h, load=load,
                                         up_days=up_days, services=services), start_session=True)

    async def diagnostics(self, req: Req) -> Resp:
        if (r := self._need_login(req)):
            return r
        host, tool = req.query.get("host", ""), req.query.get("tool", "ping")
        output, sleep = None, 0.0
        if host:
            cmd = {"ping": "ping -c 4 ", "dig": "dig +short "}.get(tool, "traceroute -m 10 ") + host
            output, sleep = await self.shell_exec(req, cmd)
        return Resp(200, self.app.render("diagnostics.html", user=req.session.web_user, output=output, host=host,
                                         tool=tool), start_session=True, extra_sleep=sleep,
                    persona="bash" if output is not None else None)

    async def logs(self, req: Req) -> Resp:
        if (r := self._need_login(req)):
            return r
        f = req.query.get("file", "syslog")
        try:
            content = self.vfs(req).read("/var/log/" + f, "/", self.web_user, self.web_groups())
        except FsError:
            content = ""
        return Resp(200, self.app.render("logs.html", user=req.session.web_user, file=f, content=content),
                    start_session=True, persona="file")


# ---------------------------------------------------------------------------
# Profile: node-express-api
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class NodeApi(Site):
    def __init__(self, app: MirageApp):
        super().__init__(app)
        self.secret = self.world.data["secrets"]["jwt_secret"].encode()
        self.boot = time.time() - (self.world.uptime_seconds() % (86400 * 9))

    def json(self, obj, status: int = 200) -> Resp:
        body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str).encode()
        return Resp(status, body, "application/json; charset=utf-8", kind="json")

    def jwt(self, user: dict) -> str:
        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        now = int(time.time())
        payload = _b64url(json.dumps({"id": user["id"], "username": user["username"], "role": user["role"],
                                      "iat": now, "exp": now + 3600}, separators=(",", ":")).encode())
        sig = _b64url(hmac.new(self.secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
        return f"{header}.{payload}.{sig}"

    def verify(self, req: Req) -> tuple[dict | None, Resp | None]:
        auth = req.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return None, self.json({"error": "No token provided"}, 401)
        token = auth[7:].strip()
        parts = token.split(".")
        if len(parts) != 3:
            return None, self.json({"error": "jwt malformed"}, 401)
        try:
            header = json.loads(_b64url_dec(parts[0]))
            payload = json.loads(_b64url_dec(parts[1]))
        except (ValueError, TypeError):
            return None, self.json({"error": "invalid token"}, 401)
        if header.get("alg") != "HS256":
            return None, self.json({"error": "invalid algorithm"}, 401)
        expected = _b64url(hmac.new(self.secret, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, parts[2]):
            return None, self.json({"error": "invalid signature"}, 401)
        if payload.get("exp") and payload["exp"] < time.time():
            return None, self.json({"error": "jwt expired"}, 401)
        req.session.api_tokens.add(token[-16:])
        return payload, None

    async def __call__(self, req: Req) -> Resp:
        path = unquote(req.raw_path.split("?", 1)[0])
        m, p = req.method, path.rstrip("/") or "/"
        if isinstance(req.json, ValueError):
            return self.app.error(400, req)
        if m == "GET" and p == "/":
            return self.json({"name": f"{self.world.company['slug']}-api", "version": "2.3.1", "status": "ok"})
        if m == "GET" and p == "/health":
            return self.json({"status": "ok", "uptime": round(time.time() - self.boot, 3), "db": "connected"})
        if p == "/api/v1/auth/login" and m == "POST":
            return await self.login(req)
        if p == "/api/v1/backups/download" and m == "GET":
            return self.backup_download(req)
        if p == "/graphql" and m in ("GET", "POST"):
            return await self.graphql(req)
        mm = re.fullmatch(r"/api/v1/(users|orders|customers|products)(?:/(\w+))?", p)
        if mm:
            return await self.resource(req, mm.group(1), mm.group(2))
        if m in ("GET", "HEAD"):
            full = posixpath.normpath(self.webroot + "/" + path.lstrip("/"))
            if full.startswith(self.webroot + "/") and not full.startswith(self.webroot + "/node_modules"):
                resp = self.static(req, full)
                if resp:
                    return resp
        return self.app.error(404, req)

    async def login(self, req: Req) -> Resp:
        data = req.json if isinstance(req.json, dict) else req.form
        ident = str(data.get("email") or data.get("username") or "")
        pw = str(data.get("password") or "")
        if not ident or not pw:
            return self.json({"error": "Email and password are required"}, 400)
        esc = ident.replace("'", "''")
        res = self.sql(req, f"SELECT id, username, email, role, password FROM users WHERE email = '{esc}' OR username = '{esc}'")[0]
        ok, user = False, None
        if res.rows:
            row = dict(zip(res.columns, res.rows[0]))
            emp = self.world.find_employee(row["username"])
            created = self.d.store.load_ns(req.session.id, "api_users").get(row["username"])
            ok = (emp is not None and emp["password"] == pw and emp["active"]) or (created is not None and created == pw)
            user = row
        self.d.telemetry.credential(req.session, "api-login", ident, pw, ok)
        if not ok:
            r = self.json({"error": "Invalid credentials"}, 401)
        else:
            req.session.web_user = user["username"]
            r = self.json({"token": self.jwt(user), "expiresIn": 3600,
                           "user": {k: user[k] for k in ("id", "username", "email", "role")}})
        r.latency, r.extra_sleep = "db", 0.08   # bcrypt.compare cost
        return r

    async def resource(self, req: Req, name: str, item: str | None) -> Resp:
        claims, err = self.verify(req)
        if err:
            return err
        cols = {"users": "id, username, email, first_name, last_name, role, department, active, created_at",
                "orders": "id, customer_id, product_id, qty, total, status, created_at",
                "customers": "id, name, email, phone, city, created_at",
                "products": "id, sku, name, price, stock"}[name]
        m = req.method
        if m == "GET" and item is None:
            if name == "users":
                q = req.query.get("search", "")
                sql = f"SELECT {cols} FROM users WHERE username LIKE '%{q}%'"
            else:
                try:
                    limit = min(int(req.query.get("limit", 50)), 500)
                    offset = int(req.query.get("offset", 0))
                except ValueError:
                    return self.json({"error": "Invalid pagination parameters"}, 400)
                sql = f"SELECT {cols} FROM {name} ORDER BY id LIMIT {limit} OFFSET {offset}"
            res = self.sql(req, sql)[0]
            if res.error:
                return self._db_error(res)
            r = self.json([dict(zip(res.columns, row)) for row in res.rows])
            r.latency, r.rows, r.extra_sleep, r.persona = "db", len(res.rows), res.sleep, "mysql"
            return r
        if m == "GET":
            res = self.sql(req, f"SELECT {cols} FROM {name} WHERE id = {_int_or_quoted(item)}")[0]
            if res.error:
                return self._db_error(res)
            if not res.rows:
                return self.json({"error": f"{name[:-1].capitalize()} not found"}, 404)
            return self.json(dict(zip(res.columns, res.rows[0])))
        if name != "users":
            return self.app.error(404, req)
        if claims.get("role") != "admin":
            return self.json({"error": "Forbidden"}, 403)
        body = req.json if isinstance(req.json, dict) else req.form
        if m == "POST" and item is None:
            username = str(body.get("username", "")).replace("'", "''")
            email = str(body.get("email", "")).replace("'", "''")
            role = str(body.get("role", "user")).replace("'", "''")
            pw = str(body.get("password", ""))
            if not username or not email or not pw:
                return self.json({"error": "username, email and password are required"}, 400)
            res = self.sql(req, f"INSERT INTO users (username, email, password, role, active, created_at) "
                                f"VALUES ('{username}', '{email}', '{_fake_bcrypt(pw)}', '{role}', 1, NOW())")[0]
            if res.error:
                return self._db_error(res)
            await self.d.store.asave(req.session.id, "api_users", {body.get("username"): pw})
            return self.json({"id": res.insert_id, "username": body.get("username"), "email": body.get("email"),
                              "role": body.get("role", "user")}, 201)
        if m in ("PUT", "PATCH") and item:
            sets = ", ".join(f"{k} = '{str(v).replace(chr(39), chr(39) * 2)}'" for k, v in body.items()
                             if k in ("email", "role", "first_name", "last_name", "department", "active"))
            if not sets:
                return self.json({"error": "Nothing to update"}, 400)
            res = self.sql(req, f"UPDATE users SET {sets} WHERE id = {_int_or_quoted(item)}")[0]
            if res.error:
                return self._db_error(res)
            return self.json({"updated": res.affected})
        if m == "DELETE" and item:
            res = self.sql(req, f"DELETE FROM users WHERE id = {_int_or_quoted(item)}")[0]
            if res.error:
                return self._db_error(res)
            return Resp(204, b"", None, kind="json")
        return self.app.error(404, req)

    def _db_error(self, res: SqlResult) -> Resp:
        e = res.error
        code = {1064: "ER_PARSE_ERROR", 1054: "ER_BAD_FIELD_ERROR", 1146: "ER_NO_SUCH_TABLE",
                1222: "ER_WRONG_NUMBER_OF_COLUMNS_IN_SELECT", 1305: "ER_SP_DOES_NOT_EXIST",
                1105: "ER_UNKNOWN_ERROR", 1062: "ER_DUP_ENTRY"}.get(e.code, "ER_UNKNOWN_ERROR")
        r = self.json({"error": e.message, "code": code, "errno": e.code, "sqlState": e.state}, 500)
        r.extra_sleep, r.persona = res.sleep, "mysql"
        return r

    def backup_download(self, req: Req) -> Resp:
        f = req.query.get("file", "")
        target = posixpath.normpath(posixpath.join("/srv/app/backups", f))
        try:
            content = self.vfs(req).read(target, "/", "node", ("node",))
        except FsError as e:
            msg = {"ENOENT": "no such file or directory", "EACCES": "permission denied",
                   "EISDIR": "illegal operation on a directory"}.get(e.kind, "unknown error")
            op = "read" if e.kind == "EISDIR" else f"open '{target}'"
            return self.json({"error": f"{e.kind}: {msg}, {op}"}, 404 if e.kind == "ENOENT" else 500)
        return Resp(200, content, "text/html; charset=utf-8", kind="json", persona="file",
                    etag=camouflage.express_etag(content.encode("utf-8", "surrogateescape")))

    async def graphql(self, req: Req) -> Resp:
        body = req.json if isinstance(req.json, dict) else {}
        query = str(body.get("query") or req.query.get("query") or "")
        if not query:
            return self.json({"errors": [{"message": "Must provide query string."}]}, 400)
        if "__schema" in query or "__type" in query:
            return self.json(GRAPHQL_INTROSPECTION)
        m = re.fullmatch(r"\s*(?:query\s*\w*\s*)?\{\s*(users|orders|customers)\s*(?:\(\s*limit\s*:\s*(\d+)\s*\))?\s*\{([\w\s,]+)\}\s*\}\s*", query)
        mm = re.fullmatch(r"\s*(?:query\s*\w*\s*)?\{\s*(user|order|customer)\s*\(\s*id\s*:\s*\"?(\d+)\"?\s*\)\s*\{([\w\s,]+)\}\s*\}\s*", query)
        if m or mm:
            name = (m or mm).group(1)
            table = name if m else name + "s"
            fields = [f for f in re.split(r"[\s,]+", (m or mm).group(3)) if f]
            allowed = GRAPHQL_FIELDS[table]
            for f_ in fields:
                if f_ not in allowed:
                    col = query.find(f_) + 1
                    return self.json({"errors": [{"message": f'Cannot query field "{f_}" on type "{table[:-1].capitalize()}".',
                                                  "locations": [{"line": 1, "column": col}]}]}, 400)
            cols = ", ".join(GRAPHQL_COLS[table].get(f_, f_) for f_ in fields)
            if m:
                res = self.sql(req, f"SELECT {cols} FROM {table} ORDER BY id LIMIT {int(m.group(2) or 100)}")[0]
                data = [dict(zip(fields, row)) for row in res.rows]
            else:
                res = self.sql(req, f"SELECT {cols} FROM {table} WHERE id = {int(mm.group(2))}")[0]
                data = dict(zip(fields, res.rows[0])) if res.rows else None
            return self.json({"data": {name: data}})
        sample = self.sql(req, "SELECT id, username, email, role FROM users ORDER BY id LIMIT 5")[0]
        prompt = (f"<world>{self.d.world_brief()}</world>\n<schema>{GRAPHQL_SDL}</schema>\n"
                  f"<data>{json.dumps([dict(zip(sample.columns, r)) for r in sample.rows])}</data>\n"
                  f"<input>{json.dumps({'query': query[:4000], 'variables': body.get('variables')})}</input>")
        data, provider = await self.d.ask("graphql", prompt, ip=req.ip, max_len=8000)
        if data is not None:
            try:
                status = int(data.get("status", 200))
                parsed = json.loads(data["output"])
                r = self.json(parsed, status if status in (200, 400) else 200)
                r.persona, r.provider = "graphql", provider
                return r
            except (ValueError, TypeError):
                pass
        return self.json({"errors": [{"message": f"Syntax Error: Unexpected Name \"{query.split()[0][:30] if query.split() else ''}\".",
                                      "locations": [{"line": 1, "column": 1}]}]}, 400)


def _int_or_quoted(v: str) -> str:
    return v if v.isdigit() else f"'{v}'"


def _fake_bcrypt(pw: str) -> str:
    digest = base64.b64encode(hashlib.sha256(pw.encode()).digest()).decode().replace("+", ".").replace("=", "")
    return ("$2a$10$" + (digest * 2))[:60]


GRAPHQL_FIELDS = {"users": {"id", "username", "email", "role", "firstName", "lastName", "department"},
                  "orders": {"id", "customerId", "productId", "qty", "total", "status", "createdAt"},
                  "customers": {"id", "name", "email", "phone", "city"}}
GRAPHQL_COLS = {"users": {"firstName": "first_name", "lastName": "last_name"},
                "orders": {"customerId": "customer_id", "productId": "product_id", "createdAt": "created_at"},
                "customers": {}}
GRAPHQL_SDL = ("type User { id: ID! username: String! email: String! role: String firstName: String lastName: String "
               "department: String } type Order { id: ID! customerId: Int productId: Int qty: Int total: Float "
               "status: String createdAt: String } type Customer { id: ID! name: String email: String phone: String "
               "city: String } type Query { users(limit: Int): [User] user(id: ID!): User orders(limit: Int): [Order] "
               "order(id: ID!): Order customers(limit: Int): [Customer] customer(id: ID!): Customer } "
               "type Mutation { updateUserRole(id: ID!, role: String!): User }")


def _gql_type(name: str, fields: list[tuple[str, str, str | None]]) -> dict:
    out = []
    for fname, kind, of in fields:
        t = {"kind": kind, "name": of if kind != "NON_NULL" else None,
             "ofType": {"kind": "SCALAR", "name": of, "ofType": None} if kind == "NON_NULL" else None}
        out.append({"name": fname, "description": None, "args": [], "type": t, "isDeprecated": False,
                    "deprecationReason": None})
    return {"kind": "OBJECT", "name": name, "description": None, "fields": out, "inputFields": None,
            "interfaces": [], "enumValues": None, "possibleTypes": None}


GRAPHQL_INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "subscriptionType": None,
    "types": [
        _gql_type("Query", [("users", "LIST", "User"), ("user", "OBJECT", "User"), ("orders", "LIST", "Order"),
                            ("order", "OBJECT", "Order"), ("customers", "LIST", "Customer"), ("customer", "OBJECT", "Customer")]),
        _gql_type("Mutation", [("updateUserRole", "OBJECT", "User")]),
        _gql_type("User", [("id", "NON_NULL", "ID"), ("username", "NON_NULL", "String"), ("email", "NON_NULL", "String"),
                           ("role", "SCALAR", "String"), ("firstName", "SCALAR", "String"), ("lastName", "SCALAR", "String"),
                           ("department", "SCALAR", "String")]),
        _gql_type("Order", [("id", "NON_NULL", "ID"), ("customerId", "SCALAR", "Int"), ("productId", "SCALAR", "Int"),
                            ("qty", "SCALAR", "Int"), ("total", "SCALAR", "Float"), ("status", "SCALAR", "String"),
                            ("createdAt", "SCALAR", "String")]),
        _gql_type("Customer", [("id", "NON_NULL", "ID"), ("name", "SCALAR", "String"), ("email", "SCALAR", "String"),
                               ("phone", "SCALAR", "String"), ("city", "SCALAR", "String")]),
        {"kind": "SCALAR", "name": "ID", "description": None, "fields": None, "inputFields": None, "interfaces": None,
         "enumValues": None, "possibleTypes": None},
        {"kind": "SCALAR", "name": "String", "description": None, "fields": None, "inputFields": None,
         "interfaces": None, "enumValues": None, "possibleTypes": None},
        {"kind": "SCALAR", "name": "Int", "description": None, "fields": None, "inputFields": None, "interfaces": None,
         "enumValues": None, "possibleTypes": None},
        {"kind": "SCALAR", "name": "Float", "description": None, "fields": None, "inputFields": None,
         "interfaces": None, "enumValues": None, "possibleTypes": None},
        {"kind": "SCALAR", "name": "Boolean", "description": None, "fields": None, "inputFields": None,
         "interfaces": None, "enumValues": None, "possibleTypes": None},
    ],
    "directives": []}}}


def build_site(app: MirageApp) -> Site:
    return {"nginx-php-legacy": PhpPortal, "ubuntu-admin-panel": OpsPanel,
            "node-express-api": NodeApi}[app.profile.name](app)
