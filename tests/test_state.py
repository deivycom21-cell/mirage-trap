"""Per-attacker state: coherence within a session, isolation across sessions,
persistence across restarts and across protocols."""

from __future__ import annotations

from tests.conftest import client


async def _pma_login(http, world):
    sec = world.data["secrets"]
    r = await http.post("/phpmyadmin/index.php", data={"pma_username": sec["db_user"], "pma_password": sec["db_password"]})
    assert r.status_code == 302


async def _pma_sql(http, q: str) -> str:
    r = await http.post("/phpmyadmin/index.php", data={"sql_query": q})
    assert r.status_code == 200
    return r.text


async def test_sql_changes_persist_in_session_and_stay_isolated(make_trap):
    c = make_trap()
    n_users = len(c.world.data["employees"])
    async with client(c, ip="198.51.100.1") as a, client(c, ip="198.51.100.2") as b:
        await _pma_login(a, c.world)
        await _pma_sql(a, "INSERT INTO users (username, email, password, role, active) "
                          "VALUES ('h4x0r', 'h@x.test', 'x', 'admin', 1)")
        out = await _pma_sql(a, "SELECT COUNT(*) FROM users")
        assert str(n_users + 1) in out
        probe = "SELECT CONCAT('found-', username) FROM users WHERE username = 'h4x0r'"
        out = await _pma_sql(a, probe)
        assert "found-h4x0r" in out
        # another attacker sees the pristine database
        await _pma_login(b, c.world)
        out = await _pma_sql(b, probe)
        assert "found-h4x0r" not in out
        # create -> delete -> list stays coherent
        await _pma_sql(a, "DELETE FROM users WHERE username = 'h4x0r'")
        out = await _pma_sql(a, "SELECT COUNT(*) FROM users")
        assert str(n_users) in out


async def test_state_survives_a_restart(make_trap, tmp_path):
    data = tmp_path / "persist"
    c = make_trap(data_dir=data)
    async with client(c, ip="198.51.100.3") as a:
        await _pma_login(a, c.world)
        cookie = a.cookies.get("PHPSESSID")
        assert cookie
        await _pma_sql(a, "UPDATE products SET name = 'Backdoored Widget' WHERE id = 1")
    c.telemetry.flush()
    c.close()

    c2 = make_trap(data_dir=data)
    # same cookie from a different IP (proxy rotation) -> same session, same data
    async with client(c2, ip="203.0.113.77", cookies={"PHPSESSID": cookie}) as a2:
        r = await a2.get("/product.php?id=1")
        assert "Backdoored Widget" in r.text
    s = c2.deceiver.sessions.by_cookie[cookie]
    assert {"198.51.100.3", "203.0.113.77"} <= s.ips


async def test_shell_state_is_shared_across_protocols(make_trap):
    c = make_trap()
    d = c.deceiver
    s, _ = d.sessions.resolve("198.51.100.9", "ssh")
    root = d.shell(s, user="root", interactive=True, cwd="/root", protocol="ssh")
    await root.run("echo 'stolen' > /tmp/loot.txt && chmod 644 /tmp/loot.txt")
    await d.commit(s, root)
    s2, new = d.sessions.resolve("198.51.100.9", "http")
    assert s2 is s and not new
    web = d.shell(s2, user="www-data", interactive=False, cwd="/var/www/html", protocol="http")
    out, code = await web.run("cat /tmp/loot.txt")
    assert out == "stolen\n" and code == 0
    out, _ = await web.run("cat /etc/shadow")
    assert "Permission denied" in out


async def test_shell_context_persists(make_trap, tmp_path):
    data = tmp_path / "shellp"
    c = make_trap(data_dir=data)
    d = c.deceiver
    s, _ = d.sessions.resolve("198.51.100.10", "ssh")
    sh = d.shell(s, user="root", interactive=True, cwd="/root", protocol="ssh")
    await sh.run("cd /var/log")
    await sh.run("export STAGE=two")
    await sh.run("mkdir /opt/.cache && echo x > /opt/.cache/implant")
    await d.commit(s, sh)
    c.telemetry.session(s)
    c.telemetry.flush()
    c.close()

    c2 = make_trap(data_dir=data)
    s2, new = c2.deceiver.sessions.resolve("198.51.100.10", "ssh")
    assert not new and s2.id == s.id
    sh2 = c2.deceiver.shell(s2, user="root", interactive=True, cwd="/root", protocol="ssh")
    assert sh2.ctx.cwd == "/var/log"
    out, _ = await sh2.run("echo $STAGE; cat /opt/.cache/implant")
    assert out == "two\nx\n"
    out, _ = await sh2.run("history")
    assert "export STAGE=two" in out
