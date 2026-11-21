"""Network camouflage: byte-level imitation of nginx, Apache and Express.

Covers what fingerprinting tools look at: status-line reason phrases, header names,
casing and order, keep-alive semantics, native error pages (including nginx's
MSIE/Chrome padding), malformed-request handling, and realistic latency. Uvicorn
and Starlette never get to emit a byte of their own.
"""

from __future__ import annotations

import base64
import hashlib
import html
import math
import random
import secrets
import string
import tomllib
from dataclasses import dataclass, field
from email.utils import formatdate
from pathlib import Path
from urllib.parse import quote

import h11
from uvicorn.protocols.http import h11_impl
from uvicorn.protocols.http.h11_impl import H11Protocol

from mirage_trap.core import tls

PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@dataclass
class Profile:
    name: str
    family: str                    # nginx | apache | express
    server: str                    # Server header value ("" for express)
    powered_by: str
    cookie_name: str
    cookie_format: str             # php | express
    keepalive_timeout: int
    latency: dict = field(default_factory=dict)
    description: str = ""
    path: Path = PROFILES_DIR

    @classmethod
    def load(cls, name: str) -> "Profile":
        d = PROFILES_DIR / name
        if not (d / "profile.toml").exists():
            available = sorted(p.name for p in PROFILES_DIR.iterdir() if (p / "profile.toml").exists())
            raise ValueError(f"unknown profile {name!r}; available: {', '.join(available)}")
        with (d / "profile.toml").open("rb") as fh:
            raw = tomllib.load(fh)
        ident = raw["identity"]
        return cls(name=name, family=ident["family"], server=ident.get("server", ""),
                   powered_by=ident.get("powered_by", ""), cookie_name=raw["session"]["cookie_name"],
                   cookie_format=raw["session"]["cookie_format"], keepalive_timeout=ident.get("keepalive_timeout", 75),
                   latency=raw.get("latency", {}), description=raw.get("description", ""), path=d)

    def new_cookie_value(self) -> str:
        if self.cookie_format == "php":
            return "".join(secrets.choice(string.ascii_lowercase[:22] + string.digits) for _ in range(26))
        sid = secrets.token_urlsafe(24)
        sig = base64.b64encode(hashlib.sha256(sid.encode()).digest()).decode().rstrip("=")
        return f"s%3A{sid}.{quote(sig, safe='')}"

    def cookie_header(self, value: str) -> str:
        if self.cookie_format == "php":
            return f"{self.cookie_name}={value}; path=/"
        return f"{self.cookie_name}={value}; Path=/; HttpOnly"


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------

class Latency:
    """Log-normal service times. Uniform jitter is statistically obvious; log-normal
    with a per-session link offset matches what real servers look like."""

    DEFAULTS = {"static": (3.0, 0.35), "dynamic": (35.0, 0.55), "error": (2.0, 0.3), "db": (18.0, 0.6)}

    def __init__(self, cfg: dict):
        self.params = dict(self.DEFAULTS)
        for k, v in cfg.items():
            self.params[k] = (float(v.get("median", self.DEFAULTS.get(k, (10, 0.5))[0])),
                              float(v.get("sigma", self.DEFAULTS.get(k, (10, 0.5))[1])))

    def sample(self, kind: str, rows: int = 0, session_seed: str = "") -> float:
        median, sigma = self.params.get(kind, self.params["dynamic"])
        ms = random.lognormvariate(math.log(median), sigma)
        if kind == "db" or rows:
            ms += rows * 0.25
        if session_seed:
            ms += (int(hashlib.md5(session_seed.encode()).hexdigest()[:4], 16) % 40) / 10.0
        return ms / 1000.0


# ---------------------------------------------------------------------------
# Status lines and error pages
# ---------------------------------------------------------------------------

NGINX_REASONS = {
    200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content", 301: "Moved Permanently",
    302: "Moved Temporarily", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect",
    308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Not Allowed", 406: "Not Acceptable", 408: "Request Time-out", 409: "Conflict", 413: "Request Entity Too Large",
    414: "Request-URI Too Large", 415: "Unsupported Media Type", 429: "Too Many Requests", 500: "Internal Server Error",
    501: "Not Implemented", 502: "Bad Gateway", 503: "Service Temporarily Unavailable", 504: "Gateway Time-out",
}
APACHE_400_EXTRA = {400: "Your browser sent a request that this server could not understand.<br />\n",
                    403: "You don't have permission to access this resource.",
                    404: "The requested URL was not found on this server.",
                    405: "The requested method {method} is not allowed for this URL.",
                    413: "The requested resource does not allow request data with {method} requests, or the amount of data "
                         "provided in\nthe request exceeds the capacity limit.",
                    414: "The requested URL's length exceeds the capacity\nlimit for this server.<br />\n",
                    500: "The server encountered an internal error or\nmisconfiguration and was unable to complete\nyour request.",
                    }
APACHE_TITLES = {400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
                 413: "Request Entity Too Large", 414: "Request-URI Too Long", 500: "Internal Server Error",
                 502: "Proxy Error", 503: "Service Unavailable"}
NGINX_PADDING = ("<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n" * 6).encode()


def http_date() -> str:
    return formatdate(usegmt=True)


@dataclass
class Fingerprint:
    profile: Profile

    def reason(self, status: int) -> str:
        if self.profile.family == "nginx":
            return NGINX_REASONS.get(status, "")
        try:
            from http import HTTPStatus
            phrase = HTTPStatus(status).phrase
        except ValueError:
            return ""
        if self.profile.family == "apache" and status == 414:
            return "Request-URI Too Long"
        return phrase

    def install_reasons(self) -> None:
        """uvicorn looks reason phrases up in a module-level table; this process serves
        exactly one profile, so we rewrite that table once at startup."""
        for code in range(100, 600):
            r = self.reason(code)
            if r:
                h11_impl.STATUS_PHRASES[code] = r.encode()

    # -- error pages -----------------------------------------------------------
    def error_page(self, status: int, method: str = "GET", path: str = "/", user_agent: str = "",
                   host: str = "localhost", port: int = 80) -> tuple[bytes, str]:
        fam = self.profile.family
        if fam == "nginx":
            title = f"{status} {NGINX_REASONS.get(status, '')}"
            body = (f"<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n<center><h1>{title}</h1></center>\r\n"
                    f"<hr><center>{self.profile.server}</center>\r\n</body>\r\n</html>\r\n").encode()
            if status >= 400 and ("MSIE " in user_agent or "Chrome/" in user_agent):
                body += NGINX_PADDING
            return body, "text/html"
        if fam == "apache":
            title = APACHE_TITLES.get(status, "Error")
            msg = APACHE_400_EXTRA.get(status, "").format(method=html.escape(method))
            if status == 500:
                body_html = (f"<p>{msg}</p>\n<p>Please contact the server administrator at \n webmaster@localhost to inform them "
                             "of the time this error occurred,\n and the actions you performed just before this error.</p>\n"
                             "<p>More information about this error may be available\nin the server error log.</p>\n")
            elif status in (400, 414):
                body_html = f"<p>{msg}</p>\n"
            else:
                body_html = f"<p>{msg}</p>\n"
            body = (f'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>{status} {title}</title>\n'
                    f"</head><body>\n<h1>{title}</h1>\n{body_html}<hr>\n<address>{self.profile.server} Server at {html.escape(host)} "
                    f"Port {port}</address>\n</body></html>\n").encode()
            return body, "text/html; charset=iso-8859-1"
        # express / finalhandler
        if status == 404:
            text = f"Cannot {html.escape(method)} {html.escape(quote(path, safe='/%?=&:@!$,;~+*()[]'))}"
        else:
            from http import HTTPStatus
            try:
                text = HTTPStatus(status).phrase
            except ValueError:
                text = "Error"
        body = (f'<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Error</title>\n</head>\n'
                f"<body>\n<pre>{text}</pre>\n</body>\n</html>\n").encode()
        return body, "text/html; charset=utf-8"

    # -- headers ---------------------------------------------------------------
    def headers(self, *, status: int, content_type: str | None, length: int | None, kind: str,
                extra: list[tuple[str, str]] | None = None, keep_alive: bool = True, method: str = "GET",
                etag: str | None = None, last_modified: str | None = None, location: str | None = None,
                body: bytes = b"") -> list[tuple[bytes, bytes]]:
        """kind: dynamic | static | error | json."""
        p = self.profile
        extra = list(extra or [])
        out: list[tuple[str, str]] = []
        date = http_date()
        conn = "keep-alive" if keep_alive else "close"
        if p.family == "nginx":
            out.append(("Server", p.server))
            out.append(("Date", date))
            if content_type:
                out.append(("Content-Type", content_type))
            if length is not None:
                out.append(("Content-Length", str(length)))
            if last_modified:
                out.append(("Last-Modified", last_modified))
            if location:
                out.append(("Location", location))
            if length is None and status not in (204, 304) and method != "HEAD":
                out.append(("Transfer-Encoding", "chunked"))
            out.append(("Connection", conn))
            if kind == "dynamic" and p.powered_by:
                out.append(("X-Powered-By", p.powered_by))
            if etag:
                out.append(("ETag", etag))
            if kind == "static":
                out.append(("Accept-Ranges", "bytes"))
            out.extend(extra)
        elif p.family == "apache":
            out.append(("Date", date))
            out.append(("Server", p.server))
            if kind == "dynamic" and p.powered_by:
                out.append(("X-Powered-By", p.powered_by))
            out.extend(extra)
            if location:
                out.append(("Location", location))
            if last_modified:
                out.append(("Last-Modified", last_modified))
            if etag:
                out.append(("ETag", etag))
            if kind == "static":
                out.append(("Accept-Ranges", "bytes"))
            if length is not None:
                out.append(("Content-Length", str(length)))
            if keep_alive:
                out.append(("Keep-Alive", f"timeout={p.keepalive_timeout}, max=100"))
                out.append(("Connection", "Keep-Alive"))
            else:
                out.append(("Connection", "close"))
            if content_type:
                out.append(("Content-Type", content_type))
        else:  # express
            if p.powered_by:
                out.append(("X-Powered-By", p.powered_by))
            if kind == "error":
                out.append(("Content-Security-Policy", "default-src 'none'"))
                out.append(("X-Content-Type-Options", "nosniff"))
            out.extend(extra)
            if location:
                out.append(("Location", location))
                out.append(("Vary", "Accept"))
            if kind == "static":
                out.append(("Accept-Ranges", "bytes"))
                out.append(("Cache-Control", "public, max-age=0"))
                if last_modified:
                    out.append(("Last-Modified", last_modified))
            if content_type:
                out.append(("Content-Type", content_type))
            if length is not None:
                out.append(("Content-Length", str(length)))
            if etag or (kind in ("json", "dynamic") and body and status == 200):
                out.append(("ETag", etag or express_etag(body)))
            out.append(("Date", date))
            out.append(("Connection", conn))
            if keep_alive:
                out.append(("Keep-Alive", f"timeout={p.keepalive_timeout}"))
        return [(k.encode("latin-1"), v.encode("latin-1", "replace")) for k, v in out]

    def reorder_head(self, data: bytes) -> bytes:
        """h11 re-appends ``Transfer-Encoding`` (always) and ``Connection: close`` (when
        it decides to close) at the very end of the header block. Put them back where
        the imitated server writes them. Node really appends both last, so Express is
        left untouched."""
        fam = self.profile.family
        end = data.find(b"\r\n\r\n")
        if fam == "express" or end == -1:
            return data
        lines = data[:end].split(b"\r\n")
        status, headers = lines[0], lines[1:]
        moved: dict[bytes, bytes | None] = {b"transfer-encoding": None, b"connection": None}
        rest = []
        for line in headers:
            name = line.split(b":", 1)[0].strip().lower()
            if name in moved and moved[name] is None:
                moved[name] = line
            else:
                rest.append(line)
        if fam == "nginx":
            # Server, Date, Content-Type, Content-Length, Last-Modified, Location, TE, Connection, ...
            lead = {b"server", b"date", b"content-type", b"content-length", b"last-modified", b"location"}
            at = next((i for i, ln in enumerate(rest) if ln.split(b":", 1)[0].strip().lower() not in lead), len(rest))
            block = [moved[b"transfer-encoding"], moved[b"connection"]]
        else:
            # Apache: ..., Keep-Alive, Connection, Transfer-Encoding, Content-Type
            at = next((i for i, ln in enumerate(rest) if ln.split(b":", 1)[0].strip().lower() == b"content-type"),
                      len(rest))
            block = [moved[b"connection"], moved[b"transfer-encoding"]]
        rest[at:at] = [b for b in block if b is not None]
        return b"\r\n".join([status] + rest) + data[end:]

    def bad_request_bytes(self) -> bytes:
        """What the real server writes for a request it cannot parse."""
        if self.profile.family == "express":
            return b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
        body, ctype = self.error_page(400)
        hdrs = self.headers(status=400, content_type=ctype, length=len(body), kind="error", keep_alive=False)
        head = b"HTTP/1.1 400 " + self.reason(400).encode() + b"\r\n"
        head += b"".join(k + b": " + v + b"\r\n" for k, v in hdrs)
        return head + b"\r\n" + body


def express_etag(body: bytes) -> str:
    digest = base64.b64encode(hashlib.sha1(body).digest()).decode()[:27]
    return f'W/"{len(body):x}-{digest}"'


def nginx_etag(mtime: float, size: int) -> str:
    return f'"{int(mtime):x}-{size:x}"'


# ---------------------------------------------------------------------------
# Uvicorn protocol override
# ---------------------------------------------------------------------------

FINGERPRINT: Fingerprint | None = None   # set once at startup (one profile per process)


class MirageH11Protocol(H11Protocol):
    """H11 protocol that (1) answers malformed requests like the imitated server,
    (2) exposes raw request headers (original casing/order) and the TLS fingerprint
    to the app, and (3) keeps uvicorn from appending its own lowercase headers."""

    def connection_made(self, transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        self._raw_buf = bytearray()
        self._last_scope = None
        self.mirage_tls = tls.pop_fingerprint(transport.get_extra_info("ssl_object"))
        if FINGERPRINT is not None:
            fp, h11_send = FINGERPRINT, self.conn.send

            def send(event):
                data = h11_send(event)
                if data and isinstance(event, h11.Response):
                    data = fp.reorder_head(data)
                return data
            self.conn.send = send  # type: ignore[method-assign]

    def data_received(self, data: bytes) -> None:
        self._raw_buf += data
        if len(self._raw_buf) > 65536:
            del self._raw_buf[: len(self._raw_buf) - 65536]
        super().data_received(data)

    def handle_events(self) -> None:
        super().handle_events()
        scope = self.scope
        if scope is not None and scope is not self._last_scope:
            self._last_scope = scope
            idx = self._raw_buf.find(b"\r\n\r\n")
            if idx != -1:
                scope["mirage.raw_head"] = bytes(self._raw_buf[:idx])
                del self._raw_buf[: idx + 4]
            scope["mirage.tls"] = self.mirage_tls
            # h11 already knows the client asked to close; removing the header from the
            # scope stops uvicorn from appending a lowercase "connection: close".
            scope["mirage.client_close"] = (b"connection", b"close") in scope["headers"]
            scope["headers"][:] = [h for h in scope["headers"] if h != (b"connection", b"close")]

    def send_400_response(self, msg: str) -> None:  # noqa: ARG002 - uvicorn signature
        if FINGERPRINT is None:
            return super().send_400_response(msg)
        try:
            self.transport.write(FINGERPRINT.bad_request_bytes())
        finally:
            self.transport.close()
