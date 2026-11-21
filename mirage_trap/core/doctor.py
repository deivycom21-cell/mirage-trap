"""Self-audit: configuration, providers, invariants and fingerprint tells.

The fingerprint audit replays the probes that scanners and honeypot detectors use
(malformed requests, TRACE, traversal, random paths, framework endpoints) against
the in-process app and, optionally, against a live listener over a raw socket.
"""

from __future__ import annotations

import ast
import asyncio
import ipaddress
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path

import httpx

from mirage_trap.config import Config

PACKAGE = Path(__file__).resolve().parent.parent
EXEC_ALLOWED = {"adapters/claude_cli.py"}
FORBIDDEN_CALLS = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"), ("os", "execvp"),
                   ("os", "spawnl"), ("os", "spawnv"), ("os", "fork"), ("pty", "spawn")}
FORBIDDEN_NAMES = {"eval", "exec", "compile", "__import__"}
TELLS = ("uvicorn", "starlette", "python", "fastapi", "werkzeug", "asgi", "invalid http request", "traceback",
         "mirage", "honeypot")


@dataclass
class Check:
    area: str
    name: str
    ok: bool | None          # None = warning / informational
    detail: str = ""


def scan_execution_sinks(root: Path = PACKAGE) -> list[str]:
    """Static invariant: no process spawning or dynamic code evaluation outside the
    claude CLI adapter. Returns a list of violations (file:line: what)."""
    bad = []
    for py in sorted(root.rglob("*.py")):
        rel = py.relative_to(root).as_posix()
        if rel in EXEC_ALLOWED:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for n in names:
                    if n and n.split(".")[0] in ("subprocess", "pty", "multiprocessing"):
                        bad.append(f"{rel}:{node.lineno}: imports {n}")
            elif isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Name) and f.id in FORBIDDEN_NAMES:
                    bad.append(f"{rel}:{node.lineno}: calls {f.id}()")
                elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and \
                        (f.value.id, f.attr) in FORBIDDEN_CALLS:
                    bad.append(f"{rel}:{node.lineno}: calls {f.value.id}.{f.attr}()")
                elif isinstance(f, ast.Attribute) and f.attr in ("create_subprocess_exec", "create_subprocess_shell"):
                    bad.append(f"{rel}:{node.lineno}: calls {f.attr}()")
    return bad


async def fingerprint_probes(app, family: str) -> list[Check]:
    """Probe the in-process ASGI app the way scanners and honeypot detectors do."""
    out: list[Check] = []
    transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as c:
        r1 = await c.get(f"/{secrets.token_hex(6)}.php")
        r2 = await c.get(f"/{secrets.token_hex(8)}/")
        out.append(Check("fingerprint", "random paths are 404", r1.status_code == 404 and r2.status_code == 404,
                         f"{r1.status_code}, {r2.status_code} (a honeypot answering 200 everywhere is a known tell)"))
        names = [k for k, _ in r1.headers.raw]
        lowered = [n.lower() for n in names]
        if family == "nginx":
            ok = lowered[:2] == [b"server", b"date"]
        elif family == "apache":
            ok = lowered[:2] == [b"date", b"server"]
        else:
            ok = lowered[0] == b"x-powered-by" and b"server" not in lowered
        out.append(Check("fingerprint", f"{family} header order", ok, b", ".join(names).decode()))
        out.append(Check("fingerprint", "header casing preserved", all(n != n.lower() for n in names),
                         "lowercase header names give away h11/uvicorn"))
        everything = (r1.text + " " + " ".join(f"{k}: {v}" for k, v in r1.headers.items())).lower()
        leaks = [t for t in TELLS if t in everything]
        out.append(Check("fingerprint", "no framework tells in 404", not leaks, ", ".join(leaks) or "clean"))
        for path in ("/docs", "/openapi.json", "/redoc"):
            r = await c.get(path)
            out.append(Check("fingerprint", f"{path} not exposed", r.status_code == 404, str(r.status_code)))
        r = await c.request("TRACE", "/")
        out.append(Check("fingerprint", "TRACE refused", r.status_code == 405, str(r.status_code)))
        if family in ("nginx", "apache"):
            r = await c.get("/%2e%2e/%2e%2e/etc/passwd")   # httpx would normalise a literal "../"
            out.append(Check("fingerprint", "docroot escape is 400", r.status_code == 400, str(r.status_code)))
        r = await c.get("/x" * 5000)
        out.append(Check("fingerprint", "very long URI rejected", r.status_code in (414, 404), str(r.status_code)))
        a, b = await c.get("/"), await c.get("/")
        out.append(Check("fingerprint", "home page is stable", a.status_code == b.status_code and
                         len(a.content) == len(b.content), f"{a.status_code}/{len(a.content)} B"))
    return out


def live_probe(host: str, port: int, timeout: float = 4.0) -> list[Check]:
    """Raw-socket probes against a running listener (catches what ASGI tests cannot:
    the server's own handling of garbage on the wire)."""
    out: list[Check] = []

    def send(raw: bytes) -> bytes:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(raw)
            chunks = []
            try:
                while True:
                    d = s.recv(65536)
                    if not d:
                        break
                    chunks.append(d)
                    if sum(len(x) for x in chunks) > 200_000:
                        break
            except socket.timeout:
                pass
            return b"".join(chunks)

    try:
        garbage = send(b"GARBAGE / HTTP/1.1\r\nHost: x\r\n\r\n")
        bad = send(b"GET / HTTP/1.1\r\nHost x\r\n\r\n")
        normal = send(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    except OSError as e:
        return [Check("live", f"connect {host}:{port}", False, str(e))]
    for label, resp in (("unknown method", garbage), ("malformed header", bad), ("normal GET", normal)):
        low = resp.lower()
        leaks = [t for t in TELLS if t.encode() in low]
        status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        out.append(Check("live", f"{label} → {status or '(closed)'}", not leaks, ", ".join(leaks) or "no tells"))
    head = normal.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
    names = [h.split(b":", 1)[0] for h in head if b":" in h]
    out.append(Check("live", "wire header casing", bool(names) and all(n != n.lower() for n in names),
                     b", ".join(names).decode("latin-1")))
    return out


async def provider_checks(cfg: Config) -> list[Check]:
    from mirage_trap.adapters import build_providers
    out = []
    for p in build_providers(cfg.llm):
        try:
            ok, detail = await asyncio.wait_for(p.health(), 10)
        except Exception as e:  # noqa: BLE001 - doctor reports, never crashes
            ok, detail = False, str(e)
        if p.name == "static" or ok:
            out.append(Check("llm", p.name, True, detail))
        else:   # the chain falls through to the next provider; the trap still works
            out.append(Check("llm", p.name, None, f"{detail} (skipped, next provider answers)"))
    remote = [p for p in cfg.llm.providers if p in ("anthropic", "anthropic_api", "openai", "openai_compat",
                                                    "claude", "claude_cli")]
    if remote:
        out.append(Check("llm", "privacy", None, f"{', '.join(remote)} send attacker payloads to a third party; "
                                                 "prefer ollama for full privacy"))
    return out


def config_checks(cfg: Config) -> list[Check]:
    out = []
    dh = cfg.dashboard.host
    try:
        loop = dh == "localhost" or ipaddress.ip_address(dh).is_loopback
    except ValueError:
        loop = False
    out.append(Check("config", "dashboard bound to loopback", loop, dh))
    data = cfg.data_path
    out.append(Check("config", "data dir exists", data.exists(), str(data)))
    out.append(Check("config", "world generated", cfg.world_path.exists(), str(cfg.world_path)))
    tok = data / "dashboard.token"
    out.append(Check("config", "dashboard token", tok.exists(), str(tok) if tok.exists() else "run `mirage-trap init`"))
    if cfg.ssh.enabled:
        keys = [data / n for n in ("ssh_host_ed25519_key", "ssh_host_rsa_key", "ssh_host_ecdsa_key")]
        out.append(Check("config", "persistent SSH host keys", all(k.exists() for k in keys),
                         "generated on first run if missing (host keys must never change)"))
        if cfg.ssh.port == 22 or cfg.server.port in (80, 443):
            out.append(Check("config", "privileged ports", None,
                             "don't run as root: use setcap/authbind or an iptables redirect"))
    if cfg.server.tls_port and not (cfg.server.tls_cert and Path(cfg.server.tls_cert).exists()):
        out.append(Check("config", "TLS certificate", False, cfg.server.tls_cert or "tls_cert is empty"))
    if cfg.server.behind_proxy:
        out.append(Check("config", "behind proxy", None,
                         f"trusting {cfg.server.client_ip_header} from {', '.join(cfg.server.trusted_proxies)}"))
    if cfg.storage.retention_days <= 0:
        out.append(Check("config", "retention", None, "telemetry is kept forever (retention_days = 0)"))
    return out


def run_doctor(cfg: Config, target: str | None = None) -> list[Check]:
    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)
    checks: list[Check] = config_checks(cfg)
    violations = scan_execution_sinks()
    checks.append(Check("invariant", "no execution sinks outside claude_cli",
                        not violations, "; ".join(violations[:5]) or "ast scan clean"))
    checks += asyncio.run(provider_checks(cfg))
    if cfg.world_path.exists():
        import tempfile

        from mirage_trap.core import runner

        with tempfile.TemporaryDirectory(prefix="mt-doctor-") as tmp:
            probe_cfg = cfg.model_copy(deep=True)
            probe_cfg.llm.providers = ["static"]
            probe_cfg.storage.data_dir = tmp
            (Path(tmp) / "world.json").write_bytes(cfg.world_path.read_bytes())
            try:
                c = runner.build(probe_cfg)
            except Exception as e:  # noqa: BLE001
                checks.append(Check("fingerprint", "build app", False, str(e)))
            else:
                try:
                    checks += asyncio.run(fingerprint_probes(c.app, c.profile.family))
                finally:
                    c.close()
    if target:
        host, _, port = target.rpartition(":")
        checks += live_probe(host or "127.0.0.1", int(port))
    return checks
