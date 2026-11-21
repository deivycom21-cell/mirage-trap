"""Telnet front-end (Ubuntu telnetd look-alike) feeding the shared shell emulator."""

from __future__ import annotations

import asyncio
import logging
import random
import time

from mirage_trap.core.deceiver import Deceiver
from mirage_trap.core.ssh import motd

log = logging.getLogger("mirage.telnet")

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA, TTYPE, NAWS = 1, 3, 24, 31


class _LineReader:
    """Byte-level reader that strips telnet negotiation and handles line editing."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer
        self.buf = bytearray()

    async def _byte(self) -> int | None:
        if self.buf:
            return self.buf.pop(0)
        b = await self.reader.read(1)
        return b[0] if b else None

    async def readline(self, echo: bool, timeout: float = 600) -> str | None:
        line = bytearray()
        while True:
            try:
                c = await asyncio.wait_for(self._byte(), timeout)
            except asyncio.TimeoutError:
                return None
            if c is None:
                return None
            if c == IAC:
                cmd = await self._byte()
                if cmd in (DO, DONT, WILL, WONT):
                    await self._byte()
                elif cmd == SB:
                    while True:
                        x = await self._byte()
                        if x is None:
                            return None
                        if x == IAC:
                            if await self._byte() == SE:
                                break
                elif cmd == IAC:
                    line.append(IAC)
                continue
            if c in (13, 10):
                if c == 13:   # CR LF or CR NUL
                    try:
                        nxt = await asyncio.wait_for(self.reader.read(1), 0.05)
                        if nxt and nxt not in (b"\n", b"\0"):
                            self.buf += nxt
                    except asyncio.TimeoutError:
                        pass
                if echo:
                    self.writer.write(b"\r\n")
                return line.decode("utf-8", "replace")
            if c in (8, 127):
                if line:
                    line.pop()
                    if echo:
                        self.writer.write(b"\b \b")
                continue
            if c == 3:        # ctrl-C
                if echo:
                    self.writer.write(b"^C\r\n")
                return ""
            if c == 4 and not line:
                return None
            if c < 32:
                continue
            line.append(c)
            if echo:
                self.writer.write(bytes([c]))


class TelnetTrap:
    def __init__(self, deceiver: Deceiver, host: str, port: int):
        self.deceiver = deceiver
        self.host, self.port = host, port

    async def start(self):
        server = await asyncio.start_server(self._handle, self.host, self.port)
        log.info("telnet listening on %s:%s", self.host, self.port)
        return server

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        d = self.deceiver
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        session, _ = d.sessions.resolve(peer[0], "telnet")
        d.telemetry.event(session, protocol="telnet", kind="connect", ip=peer[0], port=peer[1])
        hostname = d.world.hostname
        lr = _LineReader(reader, writer)
        try:
            writer.write(bytes([IAC, DO, TTYPE, IAC, DO, NAWS, IAC, WILL, ECHO, IAC, WILL, SGA]))
            writer.write(f"{d.world.data['os']['pretty']}\r\n{hostname} login: ".encode())
            await writer.drain()
            user = None
            for attempt in range(3):
                username = await lr.readline(echo=True, timeout=60)
                if username is None:
                    return
                writer.write(b"Password: ")
                await writer.drain()
                password = await lr.readline(echo=False, timeout=60)
                if password is None:
                    return
                writer.write(b"\r\n")
                ok = d.world.system_password_ok(username.strip(), password)
                d.telemetry.credential(session, "telnet", username.strip(), password, ok)
                if ok:
                    user = username.strip()
                    break
                await asyncio.sleep(random.uniform(2.0, 3.2))
                writer.write(f"\r\nLogin incorrect\r\n{hostname} login: ".encode())
                await writer.drain()
            if not user:
                return
            writer.write(motd(d, user, peer[0]).encode())
            home = "/root" if user == "root" else f"/home/{user}"
            sh = d.shell(session, user=user, interactive=True, tty=True, cwd=home, protocol="telnet")
            sh.ctx.cwd = home
            while not sh.ctx.exited:
                writer.write(sh.prompt().encode())
                await writer.drain()
                pending = sh.ctx.pending is not None
                line = await lr.readline(echo=not pending)
                if line is None:
                    break
                t0 = time.perf_counter()
                sh.sleep_total = 0.0
                async with d.runtime(session).lock:
                    out, code = await sh.run(line)
                if sh.sleep_total:
                    await asyncio.sleep(sh.sleep_total)
                writer.write(out.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace"))
                d.telemetry.event(session, protocol="telnet", kind="command", ip=peer[0], method="shell",
                                  path="(password)" if pending else line[:4000], status=code, response=out,
                                  persona="bash", latency_real_ms=round((time.perf_counter() - t0) * 1000, 1))
                if not pending:
                    d.telemetry.scan(session, line, "telnet command")
                await d.commit(session, sh)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
