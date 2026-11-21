"""Process orchestration: build every component from the config and serve.

One process serves one profile on HTTP (+ optional TLS), SSH and Telnet, plus two
background loops: the profiler and the retention sweeper. The dashboard is a
separate process (``mirage-trap dashboard``) that only reads the database.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import ssl
import time
from dataclasses import dataclass
from pathlib import Path

import uvicorn

from mirage_trap.adapters import build_providers
from mirage_trap.config import Config
from mirage_trap.core import camouflage, tls
from mirage_trap.core.camouflage import Fingerprint, MirageH11Protocol, Profile
from mirage_trap.core.db import Database
from mirage_trap.core.deceiver import Deceiver
from mirage_trap.core.geo import GeoIP
from mirage_trap.core.profiler import Profiler
from mirage_trap.core.telemetry import Telemetry
from mirage_trap.core.web import MirageApp
from mirage_trap.core.world import World, load_world

log = logging.getLogger("mirage.runner")


class WorldMissing(RuntimeError):
    pass


@dataclass
class Components:
    cfg: Config
    world: World
    db: Database
    telemetry: Telemetry
    deceiver: Deceiver
    profile: Profile
    app: MirageApp

    def close(self) -> None:
        self.telemetry.close()
        self.db.close()


def build(cfg: Config) -> Components:
    """Wire world, storage, telemetry, LLM chain, deception engine and the ASGI app."""
    if not cfg.world_path.exists():
        raise WorldMissing(f"no world at {cfg.world_path}; run `mirage-trap world init` first")
    world = load_world(cfg.world_path)
    if world.profile != cfg.server.profile:
        raise WorldMissing(
            f"the world was generated for profile {world.profile!r} but the config asks for "
            f"{cfg.server.profile!r}; run `mirage-trap world init --profile {cfg.server.profile} --force`")
    profile = Profile.load(cfg.server.profile)
    db = Database(cfg.db_path)
    geo = GeoIP(cfg.storage.geoip_city, cfg.storage.geoip_asn)
    telemetry = Telemetry(db, geo, cfg.storage.max_body_bytes)
    deceiver = Deceiver(cfg, world, db, telemetry, build_providers(cfg.llm))
    app = MirageApp(cfg, profile, deceiver)
    fp = Fingerprint(profile)
    camouflage.FINGERPRINT = fp
    fp.install_reasons()
    return Components(cfg, world, db, telemetry, deceiver, profile, app)


class _QuietServer(uvicorn.Server):
    """Signals are handled once by the runner, not by every uvicorn instance."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def uvicorn_config(c: Components, host: str, port: int, *, tls_cert: str = "", tls_key: str = "") -> uvicorn.Config:
    kw = dict(
        app=c.app, host=host, port=port, http=MirageH11Protocol, ws="none", lifespan="on", interface="asgi3",
        server_header=False, date_header=False, proxy_headers=False, access_log=False, log_level="warning",
        timeout_keep_alive=c.profile.keepalive_timeout, h11_max_incomplete_event_size=16 * 1024,
    )
    if tls_cert:
        def factory(_config, default):
            ctx: ssl.SSLContext = default()
            tls.install(ctx)
            return ctx
        kw.update(ssl_certfile=tls_cert, ssl_keyfile=tls_key or None, ssl_context_factory=factory)
    return uvicorn.Config(**kw)


def purge_old(db: Database, retention_days: int, now: float | None = None) -> int:
    """Delete telemetry older than the retention window. Returns deleted events."""
    if retention_days <= 0:
        return 0
    cutoff = (now or time.time()) - retention_days * 86400

    def tx(conn):
        n = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
        conn.execute("DELETE FROM credentials WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM iocs WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM canary_hits WHERE ts < ?", (cutoff,))
        old = [r[0] for r in conn.execute("SELECT id FROM sessions WHERE last_seen < ?", (cutoff,))]
        for i in range(0, len(old), 500):
            chunk = old[i:i + 500]
            marks = ",".join("?" * len(chunk))
            conn.execute(f"DELETE FROM state_kv WHERE session_id IN ({marks})", chunk)
            conn.execute(f"DELETE FROM llm_cache WHERE scope IN ({marks})", chunk)
            conn.execute(f"DELETE FROM sessions WHERE id IN ({marks})", chunk)
        conn.execute("DELETE FROM llm_usage WHERE day < ?", (time.strftime("%Y-%m-%d", time.gmtime(cutoff)),))
        return n

    return db.transaction(tx)


async def _loop(name: str, interval: float, fn, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.to_thread(fn)
        except Exception:
            log.exception("%s loop failed", name)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), interval)


async def serve(cfg: Config, *, ssh: bool | None = None, telnet: bool | None = None,
                on_ready=None) -> None:
    c = build(cfg)
    srv = cfg.server
    servers: list[uvicorn.Server] = [_QuietServer(uvicorn_config(c, srv.host, srv.port))]
    if srv.tls_port and srv.tls_cert:
        servers.append(_QuietServer(uvicorn_config(c, srv.host, srv.tls_port, tls_cert=srv.tls_cert,
                                                   tls_key=srv.tls_key)))
    extra_servers = []
    try:
        if cfg.ssh.enabled if ssh is None else ssh:
            from mirage_trap.core.ssh import SshTrap
            trap = SshTrap(c.deceiver, cfg.ssh.host, cfg.ssh.port, cfg.data_path, cfg.ssh.accept)
            extra_servers.append(await trap.start())
        if cfg.telnet.enabled if telnet is None else telnet:
            from mirage_trap.core.telnet import TelnetTrap
            extra_servers.append(await TelnetTrap(c.deceiver, cfg.telnet.host, cfg.telnet.port).start())

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()

        def request_stop(*_):
            loop.call_soon_threadsafe(stop.set)
            for s in servers:
                s.should_exit = True

        previous = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(ValueError, OSError):
                previous[sig] = signal.signal(sig, request_stop)

        profiler = Profiler(c.db)
        bg = [asyncio.create_task(_loop("profiler", 15, profiler.run_once, stop)),
              asyncio.create_task(_loop("retention", 3600, lambda: purge_old(c.db, cfg.storage.retention_days), stop))]
        tasks = [asyncio.create_task(s.serve()) for s in servers]
        if on_ready:
            while not all(s.started for s in servers) and not any(t.done() for t in tasks):
                await asyncio.sleep(0.05)
            on_ready(c)
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                if t.exception():
                    raise t.exception()
        finally:
            request_stop()
            await asyncio.gather(*tasks, return_exceptions=True)
            for t in bg:
                t.cancel()
            await asyncio.gather(*bg, return_exceptions=True)
            for sig, h in previous.items():
                with contextlib.suppress(ValueError, OSError):
                    signal.signal(sig, h)
    finally:
        for s in extra_servers:
            s.close()
            with contextlib.suppress(Exception):
                await s.wait_closed()
        with contextlib.suppress(Exception):
            Profiler(c.db).run_once()
        c.close()


def ensure_data_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        path.chmod(0o700)
