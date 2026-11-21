"""Byte-level fidelity: headers, order, casing, error pages, malformed requests."""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from mirage_trap.core import camouflage, runner
from mirage_trap.core.camouflage import Fingerprint, Profile
from tests.conftest import client

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
NGINX_404 = (b"<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
             b"<hr><center>nginx/1.18.0 (Ubuntu)</center>\r\n</body>\r\n</html>\r\n")


def names(r) -> list[bytes]:
    return [k for k, _ in r.headers.raw]


async def test_nginx_404_is_byte_exact(make_trap):
    c = make_trap("nginx-php-legacy")
    async with client(c) as http:
        r = await http.get("/definitely-missing", headers={"User-Agent": "curl/8.4.0"})
    assert r.status_code == 404
    assert r.content == NGINX_404
    assert names(r) == [b"Server", b"Date", b"Content-Type", b"Content-Length", b"Connection"]
    assert r.headers["content-type"] == "text/html"


async def test_nginx_pads_error_pages_for_chrome(make_trap):
    c = make_trap("nginx-php-legacy")
    async with client(c) as http:
        r = await http.get("/missing", headers={"User-Agent": CHROME})
    assert r.content.startswith(NGINX_404)
    assert r.content.count(b"a padding to disable MSIE and Chrome friendly error page") == 6


async def test_nginx_dynamic_page_headers(make_trap):
    c = make_trap("nginx-php-legacy")
    async with client(c) as http:
        r = await http.get("/")
    assert r.status_code == 200
    n = names(r)
    assert n[:3] == [b"Server", b"Date", b"Content-Type"]
    assert b"X-Powered-By" in n and r.headers["x-powered-by"].startswith("PHP/7.4")
    assert r.headers["set-cookie"].startswith("PHPSESSID=") and r.headers["set-cookie"].endswith("; path=/")
    assert r.headers["expires"] == "Thu, 19 Nov 1981 08:52:00 GMT"


async def test_nginx_trace_and_traversal(make_trap):
    c = make_trap("nginx-php-legacy")
    async with client(c) as http:
        assert (await http.request("TRACE", "/")).status_code == 405
        r = await http.get("/%2e%2e/%2e%2e/etc/passwd")
        assert r.status_code == 400 and b"400 Bad Request" in r.content


async def test_apache_profile(make_trap):
    c = make_trap("ubuntu-admin-panel")
    async with client(c) as http:
        r = await http.get("/nope")
        assert r.status_code == 404
        assert names(r)[:2] == [b"Date", b"Server"]
        assert r.headers["server"] == "Apache/2.4.41 (Ubuntu)"
        assert r.headers["content-type"] == "text/html; charset=iso-8859-1"
        assert b"<address>Apache/2.4.41 (Ubuntu) Server at victim.test Port 80</address>" in r.content
        assert (await http.get("/.htaccess")).status_code == 403
        assert (await http.get("/server-status")).status_code == 403


async def test_express_profile(make_trap):
    c = make_trap("node-express-api")
    async with client(c) as http:
        r = await http.get("/nope/x")
        assert r.status_code == 404
        assert b"<pre>Cannot GET /nope/x</pre>" in r.content
        assert names(r)[0] == b"X-Powered-By" and r.headers["x-powered-by"] == "Express"
        assert b"Server" not in names(r)
        assert r.headers["content-security-policy"] == "default-src 'none'"
        ok = await http.get("/")
        assert ok.json()["status"] == "ok"
        assert ok.headers["etag"].startswith('W/"')


async def test_head_has_no_body(make_trap):
    c = make_trap("nginx-php-legacy")
    async with client(c) as http:
        r = await http.head("/robots.txt")
    assert r.status_code == 200 and r.content == b""


async def test_no_framework_endpoints(make_trap):
    for profile in ("nginx-php-legacy", "node-express-api", "ubuntu-admin-panel"):
        c = make_trap(profile)
        async with client(c) as http:
            for p in ("/docs", "/openapi.json", "/redoc"):
                r = await http.get(p)
                assert r.status_code == 404, (profile, p)
                low = r.text.lower()
                assert "uvicorn" not in low and "starlette" not in low and "python" not in low


@pytest.mark.parametrize("family,expect", [
    ("nginx", b"HTTP/1.1 200 OK\r\nServer: x\r\nDate: d\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n"
              b"Connection: close\r\nX-Powered-By: PHP\r\nSet-Cookie: a=b\r\n\r\nbody"),
    ("apache", b"HTTP/1.1 200 OK\r\nDate: d\r\nServer: x\r\nX-Powered-By: PHP\r\nSet-Cookie: a=b\r\nConnection: close\r\n"
               b"Transfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\nbody"),
])
def test_reorder_head_matches_server(family, expect):
    """h11 appends Transfer-Encoding / Connection: close last; we move them back."""
    prof = Profile(name="t", family=family, server="x", powered_by="PHP", cookie_name="a", cookie_format="php",
                   keepalive_timeout=5)
    if family == "nginx":
        h11_out = (b"HTTP/1.1 200 OK\r\nServer: x\r\nDate: d\r\nContent-Type: text/html\r\nX-Powered-By: PHP\r\n"
                   b"Set-Cookie: a=b\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nbody")
    else:
        h11_out = (b"HTTP/1.1 200 OK\r\nDate: d\r\nServer: x\r\nX-Powered-By: PHP\r\nSet-Cookie: a=b\r\n"
                   b"Content-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nbody")
    assert Fingerprint(prof).reorder_head(h11_out) == expect


# -- on the wire (real uvicorn + our h11 protocol) ------------------------------------------

@contextlib.asynccontextmanager
async def live(c: runner.Components):
    cfg = runner.uvicorn_config(c, "127.0.0.1", 0)
    server = runner._QuietServer(cfg)
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)


async def raw(port: int, data: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    chunks = []
    try:
        while True:
            d = await asyncio.wait_for(reader.read(65536), 2)
            if not d:
                break
            chunks.append(d)
    except asyncio.TimeoutError:
        pass
    writer.close()
    return b"".join(chunks)


async def test_wire_malformed_request_looks_like_nginx(make_trap):
    c = make_trap("nginx-php-legacy")
    async with live(c) as port:
        resp = await raw(port, b"GET / HTTP/1.1\r\nHost x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.18.0 (Ubuntu)\r\nDate: ")
    assert b"<center><h1>400 Bad Request</h1></center>" in resp
    assert b"Invalid HTTP request" not in resp and b"uvicorn" not in resp.lower()


async def test_wire_header_order_and_reason(make_trap):
    c = make_trap("nginx-php-legacy")
    async with live(c) as port:
        resp = await raw(port, b"GET / HTTP/1.1\r\nHost: victim.test\r\nConnection: close\r\n\r\n")
        moved = await raw(port, b"GET /admin HTTP/1.1\r\nHost: victim.test\r\nConnection: close\r\n\r\n")
    head = resp.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    hnames = [h.split(b":", 1)[0] for h in head[1:]]
    assert head[0] == b"HTTP/1.1 200 OK"
    assert hnames[:5] == [b"Server", b"Date", b"Content-Type", b"Transfer-Encoding", b"Connection"]
    assert all(n != n.lower() for n in hnames)
    assert moved.startswith(b"HTTP/1.1 301 Moved Permanently\r\n")
    assert b"Location: http://victim.test/admin/\r\n" in moved


async def test_wire_express_reason_phrases(make_trap):
    c = make_trap("node-express-api")
    assert camouflage.FINGERPRINT is not None and camouflage.FINGERPRINT.profile.family == "express"
    async with live(c) as port:
        resp = await raw(port, b"GET /api/v1/users HTTP/1.1\r\nHost: api\r\nConnection: close\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 401 Unauthorized\r\nX-Powered-By: Express\r\n")
