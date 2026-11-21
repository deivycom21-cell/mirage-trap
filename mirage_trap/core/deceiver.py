"""Deception engine: wires world, per-session state, emulators and the LLM chain.

Resolution order for anything the attacker asks for:
    1. deterministic emulators (HTTP handlers, SQL engine, shell, VFS)  -> instant, coherent
    2. cache (world-level for stateless facts, session-level otherwise) -> identical on replay
    3. LLM chain (temperature 0, strict JSON, sanitized)                -> long tail only
    4. deterministic fallback (the error the real program would print)  -> never a Python error
Whatever the LLM produces is persisted, so the next read is identical.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import posixpath
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from mirage_trap.adapters import LLMProvider, ProviderError
from mirage_trap.config import Config
from mirage_trap.core.db import Database
from mirage_trap.core.sanitizer import Rejected, check_text, sanitize
from mirage_trap.core.shell import Shell, ShellContext
from mirage_trap.core.sqlemu import SqlEngine, base_image
from mirage_trap.core.state import WORLD_SCOPE, Session, SessionManager, StateStore
from mirage_trap.core.telemetry import Telemetry
from mirage_trap.core.vfs import Node, VirtualFS
from mirage_trap.core.world import World
from mirage_trap import prompts

log = logging.getLogger("mirage.deceiver")

LLM_FILE_ROOTS = ("/etc/", "/usr/share/", "/usr/lib/", "/var/lib/", "/opt/", "/lib/systemd/", "/usr/local/")
ENOENT = "__ENOENT__"


@dataclass
class SessionRuntime:
    vfs: VirtualFS
    sql: SqlEngine | None = None
    sql_dirty: bool = False
    shells: dict[str, ShellContext] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class Deceiver:
    def __init__(self, cfg: Config, world: World, db: Database, telemetry: Telemetry,
                 providers: list[LLMProvider]):
        self.cfg = cfg
        self.world = world
        self.db = db
        self.telemetry = telemetry
        self.providers = providers
        self.store = StateStore(db)
        self.sessions = SessionManager(db)
        self.world_overlay: dict[str, dict] = self.store.load_ns(WORLD_SCOPE, "vfs")
        self._base_sql = base_image(world)
        self._runtimes: dict[str, SessionRuntime] = {}
        self._key_locks: dict[str, asyncio.Lock] = {}
        telemetry.load_canaries(world.canaries())

    # -- per-session runtime --------------------------------------------------------
    def runtime(self, s: Session) -> SessionRuntime:
        rt = self._runtimes.get(s.id)
        if rt is None:
            overlay = self.store.load_ns(s.id, "vfs")
            rt = SessionRuntime(vfs=VirtualFS(self.world, self.world_overlay, overlay))
            self._runtimes[s.id] = rt
            if len(self._runtimes) > 400:
                for sid in list(self._runtimes)[:100]:
                    if sid != s.id:
                        old = self._runtimes.pop(sid)
                        if old.sql:
                            old.sql.close()
        return rt

    def sql(self, s: Session) -> SqlEngine:
        rt = self.runtime(s)
        if rt.sql is None:
            saved = self.store.load_ns(s.id, "sql").get("image")
            rt.sql = SqlEngine(self.world, saved if isinstance(saved, bytes) else self._base_sql)
        return rt.sql

    def run_sql(self, s: Session, query: str, multi: bool = False):
        eng = self.sql(s)
        results = eng.execute(query, multi=multi)
        if any(r.modified for r in results):
            self.runtime(s).sql_dirty = True
        self.telemetry.scan(s, query, "sql")
        return results

    def shell(self, s: Session, *, user: str, interactive: bool, tty: bool = False, cwd: str | None = None,
              protocol: str = "http") -> Shell:
        rt = self.runtime(s)
        key = f"{protocol}:{user}"
        ctx = rt.shells.get(key)
        if ctx is None:
            saved = self.store.load_ns(s.id, "shell").get(key)
            home_cwd = cwd or "/"
            ctx = ShellContext.from_json(saved, user=user, cwd=home_cwd, interactive=interactive, tty=tty) if saved \
                else ShellContext(user=user, cwd=home_cwd, interactive=interactive, tty=tty)
            rt.shells[key] = ctx
        ctx.interactive, ctx.tty = interactive, tty
        return Shell(
            self.world, rt.vfs, ctx,
            sql=lambda: self.sql(s),
            llm_command=lambda cmdline, sh, stdin: self.llm_command(s, cmdline, sh, stdin),
            llm_file=self.llm_file,
            on_ioc=lambda kind, value, context: self.telemetry.ioc(s, kind, value, context),
            on_credential=lambda u, p, ok: self.telemetry.credential(s, protocol, u, p, ok),
            client_ip=s.ip,
        )

    async def commit(self, s: Session, shell: Shell | None = None) -> None:
        """Persist whatever changed in this session (VFS overlay, SQL image, shell context)."""
        rt = self._runtimes.get(s.id)
        if rt is None:
            return
        if rt.vfs.dirty:
            dirty, rt.vfs.dirty = dict(rt.vfs.dirty), {}
            await self.store.asave(s.id, "vfs", dirty)
        if shell is not None and shell.sql_modified:
            rt.sql_dirty = True
        if rt.sql_dirty and rt.sql:
            rt.sql_dirty = False
            await self.store.asave(s.id, "sql", {"image": rt.sql.image()})
        if rt.shells:
            await self.store.asave(s.id, "shell", {k: v.to_json() for k, v in rt.shells.items()})

    # -- LLM plumbing -------------------------------------------------------------------
    def world_brief(self) -> str:
        d = self.world.data
        h, c, sec = d["host"], d["company"], d["secrets"]
        stack = self.world.stack
        return json.dumps({
            "os": d["os"]["pretty"], "kernel": d["os"]["kernel"], "hostname": h["hostname"], "ip": h["ip"],
            "gateway": h["gateway"], "domain": c["domain"], "company": c["name"],
            "web_server": f"{stack['server']} {stack['server_version']}", "php": stack["php"] or None,
            "webroot": stack["webroot"], "db_host": f"{h['db_hostname']} ({h['db_host']})", "db_name": sec["db_name"],
            "cpus": h["cpus"], "mem_mb": h["mem_mb"], "disk_gb": h["disk_gb"],
            "uptime_days": int(self.world.uptime_seconds() // 86400),
            "now_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        }, separators=(",", ":"))

    def _budget_ok(self, ip: str) -> bool:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        row = self.db.one("SELECT calls FROM llm_usage WHERE day=? AND ip=?", (day, ip))
        total = self.db.one("SELECT COALESCE(SUM(calls),0) AS n FROM llm_usage WHERE day=?", (day,))["n"]
        if (row and row["calls"] >= self.cfg.llm.max_calls_per_ip_per_day) or total >= self.cfg.llm.max_calls_global_per_day:
            return False
        self.db.execute("INSERT INTO llm_usage(day, ip, calls) VALUES (?,?,1) "
                        "ON CONFLICT(day, ip) DO UPDATE SET calls = calls + 1", (day, ip))
        return True

    def _cache_get(self, key: str) -> str | None:
        row = self.db.one("SELECT output FROM llm_cache WHERE key=?", (key,))
        return row["output"] if row else None

    def _cache_put(self, key: str, scope: str, output: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO llm_cache(key, scope, output, created) VALUES (?,?,?,?)",
                        (key, scope, output, time.time()))

    async def ask(self, persona: str, prompt: str, *, ip: str, field_name: str = "output",
                  max_len: int = 8000, max_tokens: int = 1200) -> tuple[dict | None, str]:
        """Run the provider chain. Returns (sanitized json, provider name)."""
        system = prompts.load(persona)
        allow = (self.world.company["name"], self.world.hostname)
        for provider in self.providers:
            if provider.name == "static":
                return None, "static"
            if not await asyncio.to_thread(self._budget_ok, ip):
                return None, "budget"
            try:
                raw = await provider.generate(system, prompt, max_tokens=max_tokens, temperature=0.0, json_mode=True)
                data = sanitize(raw, field=field_name, max_len=max_len, allow=allow)
                return data, provider.name
            except ProviderError as e:
                log.info("provider %s failed: %s", provider.name, e)
            except Rejected as e:
                log.warning("provider %s output rejected: %s", provider.name, e)
        return None, "none"

    def _lock(self, key: str) -> asyncio.Lock:
        lock = self._key_locks.get(key)
        if lock is None:
            lock = self._key_locks[key] = asyncio.Lock()
        return lock

    async def llm_file(self, path: str) -> str | None:
        """Content for a plausible system file missing from the base VFS (world-wide, cached)."""
        path = posixpath.normpath(path)
        if not path.startswith(LLM_FILE_ROOTS) or len(path) > 200 or not re.fullmatch(r"[\w./+@-]+", path):
            return None
        key = "file:" + hashlib.sha256(path.encode()).hexdigest()
        async with self._lock(key):
            cached = await asyncio.to_thread(self._cache_get, key)
            if cached is not None:
                return None if cached == ENOENT else cached
            prompt = f"<world>{self.world_brief()}</world>\n<input>{json.dumps({'path': path})}</input>"
            data, provider = await self.ask("file", prompt, ip="__world__", field_name="content", max_len=20000,
                                            max_tokens=2500)
            if data is None:
                return None       # no model available: behave as "No such file" without caching
            if not data.get("exists"):
                await asyncio.to_thread(self._cache_put, key, "world", ENOENT)
                return None
            content = data["content"]
            try:
                mode = int(str(data.get("mode", "0644")), 8)
            except ValueError:
                mode = 0o644
            node = Node("file", content, mode, str(data.get("owner", "root"))[:32], str(data.get("group", "root"))[:32],
                        self.world.data["host"]["installed"])
            self.world_overlay[path] = node.to_json()
            await self.store.asave(WORLD_SCOPE, "vfs", {path: node.to_json()})
            await asyncio.to_thread(self._cache_put, key, "world", content)
            return content

    async def llm_command(self, s: Session, cmdline: str, sh: Shell, stdin: str) -> str | None:
        """Output for an installed-but-unimplemented command (session-scoped cache)."""
        ctx = sh.ctx
        key = "cmd:" + hashlib.sha256(f"{s.id}|{ctx.user}|{ctx.cwd}|{cmdline}|{stdin[:2000]}".encode()).hexdigest()
        cached = await asyncio.to_thread(self._cache_get, key)
        if cached is not None:
            return cached
        listing = []
        try:
            listing = [n for n, _ in sh.vfs.listdir(ctx.cwd, "/", "root", ())][:40]
        except Exception:
            pass
        shell_info = {"user": ctx.user, "cwd": ctx.cwd, "cwd_listing": listing, "groups": list(sh.groups),
                      "recent_history": ctx.history[-8:]}
        prompt = (f"<world>{self.world_brief()}</world>\n<shell>{json.dumps(shell_info)}</shell>\n"
                  f"<input>{json.dumps({'command': cmdline, 'stdin': stdin[:2000]})}</input>")
        data, provider = await self.ask("bash", prompt, ip=s.ip, max_len=12000)
        if data is None:
            return None
        for w in (data.get("writes") or [])[:5]:
            try:
                p, content = str(w["path"]), check_text(str(w.get("content", "")), max_len=20000)
                sh.vfs.write(p, content, ctx.cwd, ctx.user, sh.groups)
            except Exception:
                continue
        out = data["output"]
        await asyncio.to_thread(self._cache_put, key, s.id, out)
        return out

    async def warm(self, paths: list[str]) -> dict[str, bool]:
        """Pre-generate common files so the first attacker read is instant."""
        out = {}
        for p in paths:
            out[p] = (await self.llm_file(p)) is not None
        return out


WARM_FILES = [
    "/etc/nginx/mime.types", "/etc/php/7.4/fpm/php.ini", "/etc/php/7.4/fpm/pool.d/www.conf", "/etc/fstab",
    "/etc/ssh/ssh_config", "/etc/login.defs", "/etc/environment", "/etc/profile", "/etc/bash.bashrc",
    "/etc/apt/sources.list", "/etc/netplan/50-cloud-init.yaml", "/etc/logrotate.conf", "/etc/motd",
    "/etc/mysql/my.cnf", "/etc/redis/redis.conf", "/etc/systemd/system/multi-user.target.wants/nginx.service",
]
