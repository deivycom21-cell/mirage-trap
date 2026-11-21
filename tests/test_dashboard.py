"""Dashboard isolation: loopback bind, token, Host validation, read-only data access."""

from __future__ import annotations

import httpx
import pytest

from mirage_trap.dashboard.server import COOKIE, create_app, is_loopback, load_or_create_token, run
from tests.conftest import client

TOKEN = "t0k3n-for-tests"


def dash(c, host="127.0.0.1:9090", **kw):
    app = create_app(c.cfg.db_path, TOKEN, poll_interval=0.05)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=f"http://{host}", **kw)


async def _traffic(c):
    async with client(c, ip="203.0.113.9") as http:
        await http.get("/.env")
        await http.get("/product.php", params={"id": "1 UNION SELECT 1,2,3,4"})
    c.telemetry.flush()


def test_loopback_detection():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.168.1.10")


def test_refuses_public_bind(tmp_path):
    with pytest.raises(SystemExit):
        run(tmp_path / "x.db", tmp_path, "0.0.0.0", 9090)


def test_token_is_persistent(tmp_path):
    a = load_or_create_token(tmp_path)
    assert a == load_or_create_token(tmp_path) and len(a) >= 32


async def test_requires_token(make_trap):
    c = make_trap()
    await _traffic(c)
    async with dash(c) as d:
        assert (await d.get("/api/overview")).status_code == 401
        assert (await d.get("/")).status_code == 401
        assert (await d.get("/?token=wrong")).status_code == 401
        r = await d.get(f"/?token={TOKEN}")
        assert r.status_code == 303 and COOKIE in r.headers["set-cookie"]
        assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
        d.cookies.set(COOKIE, TOKEN)
        page = await d.get("/")
        assert page.status_code == 200 and "app.js" in page.text
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]


async def test_rejects_foreign_host_header(make_trap):
    c = make_trap()
    async with dash(c, host="evil.example:9090") as d:
        r = await d.get("/api/overview", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 421


async def test_api_endpoints(make_trap):
    c = make_trap()
    await _traffic(c)
    auth = {"Authorization": f"Bearer {TOKEN}"}
    async with dash(c) as d:
        ov = (await d.get("/api/overview", headers=auth)).json()
        assert ov["totals"]["events"] == 2 and ov["totals"]["sessions"] == 1
        assert {"k": "sqli", "n": 1} in ov["attacks"]
        all_time = (await d.get("/api/overview?since=", headers=auth)).json()
        assert all_time["totals"]["events"] == 2
        sessions = (await d.get("/api/sessions?limit=10", headers=auth)).json()
        assert sessions[0]["ip"] == "203.0.113.9" and sessions[0]["last_attack"] == "sqli"
        assert (await d.get("/api/sessions?q=203.0.113", headers=auth)).json()
        assert not (await d.get("/api/sessions?q=10.9.9.9", headers=auth)).json()
        detail = (await d.get(f"/api/sessions/{sessions[0]['id']}", headers=auth)).json()
        assert [e["path"] for e in detail["events"]] == ["/.env", "/product.php"]
        assert detail["events"][0]["headers"]
        assert (await d.get("/api/sessions/nope", headers=auth)).status_code == 404
        can = (await d.get("/api/canaries", headers=auth)).json()
        assert len(can["tokens"]) == len({t for t, _, _ in c.world.canaries()})   # shared weak passwords dedupe
        assert (await d.get("/api/iocs", headers=auth)).status_code == 200
        assert (await d.get("/static/app.js")).status_code == 200


async def test_dashboard_cannot_write(make_trap):
    c = make_trap()
    await _traffic(c)
    from mirage_trap.core.db import Database
    ro = Database(c.cfg.db_path, readonly=True)
    import sqlite3
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("DELETE FROM events")
    ro.close()


async def test_no_db_yet(tmp_path):
    app = create_app(tmp_path / "missing.db", TOKEN)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as d:
        r = await d.get("/api/overview", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 503
