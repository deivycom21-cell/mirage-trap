"""SSH front-end (asyncssh) feeding the shared shell emulator.

Mimics OpenSSH 8.2p1 on Ubuntu 20.04: banner, algorithm order (so the HASSH server
fingerprint is plausible), persistent host keys, Ubuntu MOTD and "Last login" line.
Credentials are always recorded; only the world's credentials and a short,
deterministic weak list are accepted (never "any password").
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import asyncssh

from mirage_trap.core.deceiver import Deceiver
from mirage_trap.core.vfs import render_dynamic

log = logging.getLogger("mirage.ssh")

SSH_VERSION = "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
# OpenSSH 8.2 defaults, filtered at runtime to what asyncssh supports.
KEX = ["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
       "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
       "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256"]
CIPHERS = ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
           "aes256-gcm@openssh.com"]
MACS = ["umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com",
        "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"]
COMPRESSION = ["none", "zlib@openssh.com"]


def _lf(text: str) -> str:
    """asyncssh's line editor already maps LF to CRLF on a PTY (as a tty's onlcr does),
    and a channel without a PTY carries bare LF, so we always write bare LF. Writing
    CRLF ourselves would put CR CR LF on the wire: a classic emulator tell."""
    return text.replace("\r\n", "\n")


def _supported(wanted: list[str], available: list[bytes]) -> list[str]:
    names = {a.decode() for a in available}
    return [w for w in wanted if w in names]


def ensure_host_keys(data_dir: Path) -> list[str]:
    paths = []
    for alg, name in (("ssh-ed25519", "ssh_host_ed25519_key"), ("ssh-rsa", "ssh_host_rsa_key"),
                      ("ecdsa-sha2-nistp256", "ssh_host_ecdsa_key")):
        p = data_dir / name
        if not p.exists():
            key = asyncssh.generate_private_key(alg, key_size=3072) if alg == "ssh-rsa" else asyncssh.generate_private_key(alg)
            key.write_private_key(str(p))
        paths.append(str(p))
    return paths


def motd(deceiver: Deceiver, user: str, ip: str) -> str:
    w = deceiver.world
    h = w.data["host"]
    rng = random.Random(f"{w.data['seed']}-{user}")
    now = datetime.now(timezone.utc)
    load = render_dynamic(w, "loadavg", {}).split()[0]
    last_src = f"10.{rng.randint(10, 60)}.{rng.randint(1, 30)}.{rng.randint(2, 250)}"
    last = datetime.fromtimestamp(time.time() - rng.randint(3600, 86400 * 3), timezone.utc)
    return (
        f"Welcome to {w.data['os']['pretty']} (GNU/Linux {w.data['os']['kernel']} x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        f"  System information as of {now:%a %b %e %H:%M:%S UTC %Y}\r\n\r\n"
        f"  System load:  {load}               Processes:             {130 + rng.randint(0, 40)}\r\n"
        f"  Usage of /:   {h['disk_used_pct']}.{rng.randint(0, 9)}% of {h['disk_gb'] - 1}.{rng.randint(10, 99)}GB   "
        f"Users logged in:       0\r\n"
        f"  Memory usage: {rng.randint(28, 61)}%                IPv4 address for ens5: {h['ip']}\r\n"
        f"  Swap usage:   0%\r\n\r\n"
        " * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s\r\n"
        "   just raised the bar for easy, resilient and secure K8s cluster deployment.\r\n\r\n"
        "   https://ubuntu.com/engage/secure-kubernetes-at-the-edge\r\n\r\n"
        "Expanded Security Maintenance for Applications is not enabled.\r\n\r\n"
        f"{rng.randint(0, 12)} updates can be applied immediately.\r\n"
        "To see these additional updates run: apt list --upgradable\r\n\r\n"
        f"{rng.randint(20, 60)} additional security updates can be applied with ESM Apps.\r\n"
        "Learn more about enabling ESM Apps service at https://ubuntu.com/esm\r\n\r\n\r\n"
        f"Last login: {last:%a %b %e %H:%M:%S %Y} from {last_src}\r\n"
    )


class _Server(asyncssh.SSHServer):
    def __init__(self, trap: "SshTrap"):
        self.trap = trap
        self.conn = None
        self.session = None
        self.user = None

    def connection_made(self, conn):
        self.conn = conn
        ip = (conn.get_extra_info("peername") or ("0.0.0.0", 0))[0]
        self.session, _ = self.trap.deceiver.sessions.resolve(ip, "ssh")
        client_version = conn.get_extra_info("client_version") or ""
        self.trap.deceiver.telemetry.event(self.session, protocol="ssh", kind="connect", ip=ip,
                                           port=(conn.get_extra_info("peername") or (0, 0))[1],
                                           headers=[["client_version", str(client_version)]])

    def connection_lost(self, exc):
        pass

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        fp = key.get_fingerprint() if hasattr(key, "get_fingerprint") else "?"
        self.trap.deceiver.telemetry.credential(self.session, "ssh-key", username, fp, False)
        return False

    def kbdint_auth_supported(self):
        return False

    async def validate_password(self, username, password):
        ok = self.trap.accepts(username, password)
        self.trap.deceiver.telemetry.credential(self.session, "ssh", username, password, ok)
        if not ok:
            await asyncio.sleep(random.uniform(1.8, 2.6))     # PAM failure delay
        else:
            self.user = username
        return ok


class SshTrap:
    def __init__(self, deceiver: Deceiver, host: str, port: int, data_dir: Path, extra_accept: list[str]):
        self.deceiver = deceiver
        self.host, self.port = host, port
        self.data_dir = data_dir
        self.extra = {tuple(x.split(":", 1)) for x in extra_accept if ":" in x}
        self.server = None

    def accepts(self, username: str, password: str) -> bool:
        if (username, password) in self.extra:
            return True
        return self.deceiver.world.system_password_ok(username, password)

    async def start(self):
        keys = ensure_host_keys(self.data_dir)
        kw = dict(
            server_host_keys=keys, server_version=SSH_VERSION, process_factory=self._process,
            kex_algs=_supported(KEX, asyncssh.kex.get_kex_algs()),
            encryption_algs=_supported(CIPHERS, asyncssh.encryption.get_encryption_algs()),
            mac_algs=_supported(MACS, asyncssh.mac.get_mac_algs()),
            compression_algs=_supported(COMPRESSION, asyncssh.compression.get_compression_algs()),
            sftp_factory=None, allow_scp=False, agent_forwarding=False, x11_forwarding=False,
            login_timeout=120, keepalive_interval=0, line_editor=True, line_echo=True,
        )
        self.server = await asyncssh.create_server(lambda: _Server(self), self.host, self.port, **kw)
        log.info("ssh listening on %s:%s", self.host, self.port)
        return self.server

    async def _process(self, process: asyncssh.SSHServerProcess):
        conn = process.channel.get_connection()
        handler = conn.get_owner()
        session = getattr(handler, "session", None)
        user = conn.get_extra_info("username") or "root"
        if session is None:
            ip = (conn.get_extra_info("peername") or ("0.0.0.0", 0))[0]
            session, _ = self.deceiver.sessions.resolve(ip, "ssh")
        d = self.deceiver
        home_cwd = "/root" if user == "root" else f"/home/{user}"
        if process.subsystem:
            d.telemetry.event(session, protocol="ssh", kind="command", ip=session.ip, method="subsystem",
                              path=process.subsystem, status=1)
            process.stderr.write(f"subsystem request failed on channel 0\r\n")
            process.exit(1)
            return
        command = process.command
        tty = process.term_type is not None
        sh = d.shell(session, user=user, interactive=True, tty=tty, cwd=home_cwd, protocol="ssh")
        if not sh.ctx.history and sh.ctx.cwd != home_cwd and not command:
            sh.ctx.cwd = home_cwd
        if command:      # ssh host 'cmd'
            sh.ctx.tty = False
            out, code = await self._run(session, sh, command, "exec")
            process.stdout.write(_lf(out))
            await d.commit(session, sh)
            process.exit(code)
            return
        process.stdout.write(_lf(motd(d, user, session.ip)))
        sh.ctx.cwd = home_cwd
        try:
            while not sh.ctx.exited:
                process.stdout.write(sh.prompt())
                try:
                    line = await process.stdin.readline()
                except asyncssh.TerminalSizeChanged:
                    continue
                except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                    process.stdout.write("^C\n")
                    continue
                if line == "":       # EOF / ctrl-D
                    process.stdout.write("logout\n")
                    break
                line = line.rstrip("\r\n")
                pending = sh.ctx.pending is not None
                if pending:
                    process.channel.set_echo(True)
                out, code = await self._run(session, sh, line, "shell", secret=pending)
                if sh.ctx.pending is not None:
                    process.channel.set_echo(False)
                process.stdout.write(_lf(out))
                await d.commit(session, sh)
        except (asyncssh.ConnectionLost, BrokenPipeError, ConnectionResetError):
            pass
        finally:
            await d.commit(session, sh)
        process.exit(0)

    async def _run(self, session, sh, line: str, mode: str, secret: bool = False) -> tuple[str, int]:
        t0 = time.perf_counter()
        sh.sleep_total = 0.0
        rt = self.deceiver.runtime(session)
        async with rt.lock:
            out, code = await sh.run(line)
        if sh.sleep_total:
            await asyncio.sleep(sh.sleep_total)
        self.deceiver.telemetry.event(
            session, protocol="ssh", kind="command", ip=session.ip, method=mode,
            path="(password)" if secret else line[:4000], status=code, response=out, persona="bash",
            latency_real_ms=round((time.perf_counter() - t0) * 1000, 1))
        if not secret:
            self.deceiver.telemetry.scan(session, line, "ssh command")
        return out, code
