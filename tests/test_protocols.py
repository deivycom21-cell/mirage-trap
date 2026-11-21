"""Live listeners: TLS with JA3/JA4 capture, SSH and Telnet."""

from __future__ import annotations

import asyncio
import datetime
import re
import ssl

import asyncssh
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mirage_trap.core import tls
from mirage_trap.core.ssh import SshTrap
from mirage_trap.core.telnet import TelnetTrap
from tests.test_fingerprint import live


def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "portal.example-corp.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    cp, kp = tmp_path / "cert.pem", tmp_path / "key.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return str(cp), str(kp)


def test_parse_client_hello_and_grease():
    # minimal TLS 1.2 ClientHello: version, random, empty session id, 2 ciphers (+GREASE), null compression,
    # extensions: GREASE, supported_groups(29,23), ec_point_formats(0)
    body = bytes.fromhex("0303") + b"\x00" * 32 + b"\x00" + bytes.fromhex("0006" "0a0a" "c02f" "c030") + b"\x01\x00"
    exts = bytes.fromhex("0a0a0000") + bytes.fromhex("000a" "0006" "0004" "001d" "0017") + bytes.fromhex("000b" "0002" "0100")
    body += len(exts).to_bytes(2, "big") + exts
    msg = b"\x01" + len(body).to_bytes(3, "big") + body
    h = tls.parse_client_hello(msg)
    text, digest = tls.ja3(h)
    assert text == "771,49199-49200,2570-10-11,29-23,0".replace("2570-", "")
    assert re.fullmatch(r"[0-9a-f]{32}", digest)
    assert tls.ja4(h).startswith("t12i0202")


async def test_tls_listener_captures_ja3_ja4(make_trap, tmp_path):
    cert, key = _self_signed(tmp_path)
    c = make_trap()
    from mirage_trap.core import runner
    cfg = runner.uvicorn_config(c, "127.0.0.1", 0, tls_cert=cert, tls_key=key)
    server = runner._QuietServer(cfg)
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        async with httpx.AsyncClient(verify=ctx) as http:
            r = await http.get(f"https://127.0.0.1:{port}/robots.txt")
        assert r.status_code == 200 and r.headers["server"].startswith("nginx")
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
    s = next(iter(c.deceiver.sessions.by_id.values()))
    assert re.fullmatch(r"[0-9a-f]{32}", s.ja3 or "")
    assert re.fullmatch(r"t1[23][di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}", s.ja4 or "")
    c.telemetry.flush()
    assert c.db.one("SELECT protocol FROM events")["protocol"] == "https"


async def test_ssh_trap(make_trap, tmp_path):
    c = make_trap()
    trap = SshTrap(c.deceiver, "127.0.0.1", 0, tmp_path, ["ops:letmein"])
    server = await trap.start()
    port = server.sockets[0].getsockname()[1]
    user, pw = c.world.data["ssh_accept"][0]
    try:
        try:
            async with asyncssh.connect("127.0.0.1", port, username="root", password="admin", known_hosts=None):
                raise AssertionError("weak password accepted")
        except asyncssh.PermissionDenied:
            pass
        async with asyncssh.connect("127.0.0.1", port, username=user, password=pw, known_hosts=None) as conn:
            assert conn.get_extra_info("server_version") == "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            r = await conn.run("hostname; whoami")
            assert r.stdout == f"{c.world.hostname}\n{user}\n" and r.exit_status == 0
            r = await conn.run("false")
            assert r.exit_status == 1
            async with conn.create_process(term_type="xterm", encoding=None) as proc:
                async def until(token: bytes) -> bytes:
                    buf = b""
                    while token not in buf:
                        buf += await asyncio.wait_for(proc.stdout.read(4096), 5)
                    return buf
                banner = await until(b"# " if user == "root" else b"$ ")
                assert b"Welcome to Ubuntu 20.04.6 LTS" in banner and b"Last login:" in banner
                assert b"\r\r\n" not in banner and b"\r\n" in banner
                proc.stdin.write(b"echo marker-ok\n")
                out = await until(b"marker-ok\r\n")
                assert b"\r\r\n" not in out
                proc.stdin.write(b"exit\n")
        async with asyncssh.connect("127.0.0.1", port, username="ops", password="letmein", known_hosts=None) as conn:
            assert (await conn.run("id -un")).stdout == "ops\n"
    finally:
        server.close()
        await server.wait_closed()
    c.telemetry.flush()
    creds = c.db.query("SELECT username, success FROM credentials WHERE protocol='ssh' ORDER BY id")
    assert creds[0] == {"username": "root", "success": 0}
    assert {"username": user, "success": 1} in creds
    assert c.db.one("SELECT COUNT(*) n FROM events WHERE kind='command'")["n"] >= 3
    # host keys are persistent
    assert (tmp_path / "ssh_host_ed25519_key").exists()


async def test_telnet_trap(make_trap):
    c = make_trap()
    server = await TelnetTrap(c.deceiver, "127.0.0.1", 0).start()
    port = server.sockets[0].getsockname()[1]
    user, pw = c.world.data["ssh_accept"][-1]

    async def until(reader, token: bytes, timeout=6.0) -> bytes:
        buf = b""
        while token not in buf:
            buf += await asyncio.wait_for(reader.read(4096), timeout)
        return buf

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        first = await until(reader, b"login: ")
        assert first.startswith(bytes([255, 253, 24])) and b"Ubuntu 20.04.6 LTS" in first
        writer.write(b"root\r\n")
        await until(reader, b"Password: ")
        writer.write(b"wrong\r\n")
        assert b"Login incorrect" in await until(reader, b"login: ")
        writer.write(user.encode() + b"\r\n")
        await until(reader, b"Password: ")
        writer.write(pw.encode() + b"\r\n")
        await until(reader, b"$ ")
        writer.write(b"pwd\r\n")
        out = await until(reader, b"$ ")
        assert f"/home/{user}".encode() in out
    finally:
        writer.close()
        server.close()
        await server.wait_closed()
