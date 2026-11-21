"""Command line: init | world | run | dashboard | export | doctor."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from importlib import resources
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from mirage_trap import __version__
from mirage_trap.config import Config, load_config

app = typer.Typer(add_completion=False, no_args_is_help=True, rich_markup_mode="rich",
                  help="mirage-trap: high-interaction deception honeypot (HTTP, SSH, Telnet).")
world_app = typer.Typer(no_args_is_help=True, help="Generate and inspect the fictitious world.")
app.add_typer(world_app, name="world")
for _stream in (sys.stdout, sys.stderr):      # Windows consoles default to cp1252
    try:
        _stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
console = Console()
err = Console(stderr=True)


def _can(ch: str) -> bool:
    try:
        ch.encode(console.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


_U = _can("✓✗•→·")
OK = "[green]✓[/green]" if _U else "[green]+[/green]"
WARN = "[yellow]•[/yellow]" if _U else "[yellow]![/yellow]"
FAIL = "[red]✗[/red]" if _U else "[red]x[/red]"
ARROW = " → " if _U else " -> "
DOT = " · " if _U else " | "


def _mark(ok: bool | None) -> str:
    return OK if ok else (WARN if ok is None else FAIL)


PROFILES = ["nginx-php-legacy", "node-express-api", "ubuntu-admin-panel"]


class _State:
    config_path: Optional[Path] = None


S = _State()


def _cfg() -> Config:
    try:
        return load_config(S.config_path)
    except FileNotFoundError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(2)
    except Exception as e:  # pydantic / toml errors
        err.print(f"[red]invalid configuration:[/red] {e}")
        raise typer.Exit(2)


def _version(value: bool):
    if value:
        console.print(f"mirage-trap {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config.toml (default: ./config.toml)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging."),
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show version."),
):
    S.config_path = config
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")


def _example_config() -> str:
    try:
        return resources.files("mirage_trap").joinpath("config.example.toml").read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return (Path(__file__).resolve().parent.parent / "config.example.toml").read_text(encoding="utf-8")


def _set_toml(text: str, section: str, key: str, value: str) -> str:
    """Minimal in-place edit of `key = ...` inside `[section]` keeping comments."""
    out, cur, done = [], None, False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            cur = stripped.strip("[]")
        elif cur == section and not done and stripped.split("=", 1)[0].strip() == key:
            comment = ""
            if "#" in line.split("=", 1)[1]:
                comment = "   #" + line.split("#", 1)[1]
            line = f"{key} = {value}{comment}"
            done = True
        out.append(line)
    return "\n".join(out) + "\n"


def _generate_world(cfg: Config, profile: str, seed: int, domain: str, force: bool) -> dict | None:
    from mirage_trap.core.world import generate_world, save_world

    if cfg.world_path.exists() and not force:
        return None
    data = generate_world(profile, seed or cfg.world.seed, domain or cfg.world.domain)
    save_world(data, cfg.world_path)
    try:
        cfg.world_path.chmod(0o600)
    except OSError:
        pass
    # A new world invalidates everything derived from the old one.
    if cfg.db_path.exists():
        from mirage_trap.core.db import Database
        db = Database(cfg.db_path)
        db.transaction(lambda c: [c.execute("DELETE FROM state_kv"), c.execute("DELETE FROM llm_cache"),
                                  c.execute("DELETE FROM canaries")])
        db.close()
    return data


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@app.command()
def init(
    profile: str = typer.Option("nginx-php-legacy", "--profile", "-p", help=f"One of: {', '.join(PROFILES)}."),
    domain: str = typer.Option("", help="Domain the fake company uses (ideally one you control)."),
    seed: int = typer.Option(0, help="World seed (0 = random)."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config.toml and world."),
):
    """Create config.toml, the data dir, dashboard token, SSH host keys and the world."""
    if profile not in PROFILES:
        err.print(f"[red]unknown profile {profile!r}[/red]; choose one of {', '.join(PROFILES)}")
        raise typer.Exit(2)
    cfg_path = S.config_path or Path("config.toml")
    if cfg_path.exists() and not force:
        console.print(WARN + f" {cfg_path} exists, keeping it (use --force to overwrite)")
    else:
        text = _example_config()
        text = _set_toml(text, "server", "profile", json.dumps(profile))
        if domain:
            text = _set_toml(text, "world", "domain", json.dumps(domain))
        if seed:
            text = _set_toml(text, "world", "seed", str(seed))
        cfg_path.write_text(text, encoding="utf-8")
        try:
            cfg_path.chmod(0o600)
        except OSError:
            pass
        console.print(OK + f" wrote {cfg_path}")
    S.config_path = cfg_path
    cfg = _cfg()
    from mirage_trap.core.runner import ensure_data_dir
    from mirage_trap.dashboard.server import load_or_create_token

    ensure_data_dir(cfg.data_path)
    console.print(OK + f" data dir {cfg.data_path}")
    load_or_create_token(cfg.data_path)
    console.print(OK + f" dashboard token in {cfg.data_path / 'dashboard.token'}")
    if cfg.ssh.enabled:
        from mirage_trap.core.ssh import ensure_host_keys
        ensure_host_keys(cfg.data_path)
        console.print(OK + " persistent SSH host keys")
    if cfg.world_path.exists() and cfg.server.profile != profile and not force:
        err.print(WARN + f" config uses profile {cfg.server.profile!r}; world left untouched")
    data = _generate_world(cfg, cfg.server.profile, seed, domain, force)
    if data:
        console.print(OK + f" world: [bold]{data['company']['name']}[/bold] ({data['company']['domain']}), "
                      f"host {data['host']['hostname']}, seed {data['seed']}")
    else:
        console.print(WARN + f" world exists at {cfg.world_path}, keeping it")
    from mirage_trap.core.doctor import provider_checks
    for c in asyncio.run(provider_checks(cfg)):
        mark = _mark(c.ok)
        console.print(f"{mark} llm {c.name}: {c.detail}")
    console.print("\nNext: [bold]mirage-trap run[/bold]   then   [bold]mirage-trap dashboard[/bold]")


# ---------------------------------------------------------------------------
# world
# ---------------------------------------------------------------------------

@world_app.command("init")
def world_init(
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Defaults to [server].profile."),
    seed: int = typer.Option(0, help="World seed (0 = config value or random)."),
    domain: str = typer.Option("", help="Company domain."),
    force: bool = typer.Option(False, "--force", help="Replace the existing world (resets attacker state)."),
):
    """Generate the world: company, staff, credentials, database and filesystem."""
    cfg = _cfg()
    profile = profile or cfg.server.profile
    if profile not in PROFILES:
        err.print(f"[red]unknown profile {profile!r}[/red]")
        raise typer.Exit(2)
    if profile != cfg.server.profile:
        err.print(f"[yellow]note:[/yellow] config.toml still says profile = {cfg.server.profile!r}; "
                  f"set it to {profile!r} before `run`.")
    data = _generate_world(cfg, profile, seed, domain, force)
    if data is None:
        err.print(f"[yellow]a world already exists at {cfg.world_path}[/yellow] (use --force to replace it)")
        raise typer.Exit(1)
    console.print(OK + f" {data['company']['name']}{DOT}{data['company']['domain']}{DOT}"
                  f"{data['host']['hostname']}{DOT}seed {data['seed']}")


@world_app.command("show")
def world_show(
    secrets: bool = typer.Option(False, "--secrets", help="Also print canary credentials."),
    as_json: bool = typer.Option(False, "--json", help="Dump the raw world.json."),
):
    """Inspect the generated world."""
    cfg = _cfg()
    if not cfg.world_path.exists():
        err.print("[red]no world yet[/red]: run `mirage-trap world init`")
        raise typer.Exit(1)
    from mirage_trap.core.world import load_world
    w = load_world(cfg.world_path)
    d = w.data
    if as_json:
        console.print_json(json.dumps(d if secrets else {k: v for k, v in d.items() if k not in ("secrets",)}))
        return
    c, h = d["company"], d["host"]
    console.print(f"[bold]{c['name']}[/bold]  ({c['sector']}, {c['city']} {c['country']})  domain [cyan]{c['domain']}[/cyan]")
    console.print(f"profile {d['profile']}{DOT}seed {d['seed']}{DOT}host {h['hostname']} {h['ip']}{DOT}db {h['db_hostname']} "
                  f"{h['db_host']}")
    console.print(f"{len(d['employees'])} employees{DOT}{len(d['customers'])} customers{DOT}{len(d['orders'])} orders{DOT}"
                  f"{len(d['products'])} products{DOT}{len(w.vfs)} filesystem nodes")
    t = Table(title="Accounts with shell access", show_lines=False)
    for col in ("username", "title", "email") + (("password",) if secrets else ()):
        t.add_column(col)
    for e in d["employees"]:
        if e["shell_access"]:
            t.add_row(e["username"], e["title"], e["email"], *((e["password"],) if secrets else ()))
    console.print(t)
    if secrets:
        t = Table(title="Canary tokens (any reuse is recorded as a hit)")
        t.add_column("label")
        t.add_column("kind")
        t.add_column("token")
        for tok, kind, label in w.canaries():
            if not label.startswith("employee"):
                t.add_row(label, kind, tok)
        console.print(t)
        console.print("SSH/Telnet accepted logins: " + ", ".join(f"{u}:{p}" for u, p in d["ssh_accept"]))
    else:
        console.print("[dim]use --secrets to print the canary credentials[/dim]")


@world_app.command("warm")
def world_warm():
    """Pre-generate common system files with the LLM so first reads are instant."""
    cfg = _cfg()
    from mirage_trap.core.deceiver import WARM_FILES
    from mirage_trap.core.runner import WorldMissing, build
    try:
        c = build(cfg)
    except WorldMissing as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    try:
        res = asyncio.run(c.deceiver.warm(WARM_FILES))
    finally:
        c.close()
    for path, ok in res.items():
        console.print(f"{OK if ok else WARN} {path}")
    if not any(res.values()):
        console.print("[yellow]no LLM produced content[/yellow] (static-only chain, or provider unreachable)")


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@app.command()
def run(
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Override [server].profile."),
    host: Optional[str] = typer.Option(None, help="Override [server].host."),
    port: Optional[int] = typer.Option(None, help="Override [server].port."),
    tls_port: Optional[int] = typer.Option(None, help="Also serve HTTPS on this port (needs --tls-cert)."),
    tls_cert: Optional[Path] = typer.Option(None, help="PEM certificate for standalone TLS."),
    tls_key: Optional[Path] = typer.Option(None, help="PEM private key for standalone TLS."),
    ssh: Optional[bool] = typer.Option(None, "--ssh/--no-ssh", help="Override [ssh].enabled."),
    telnet: Optional[bool] = typer.Option(None, "--telnet/--no-telnet", help="Override [telnet].enabled."),
):
    """Start the trap (HTTP + optional TLS, SSH and Telnet)."""
    cfg = _cfg()
    s = cfg.server
    if profile:
        s.profile = profile
    if host:
        s.host = host
    if port:
        s.port = port
    if tls_cert:
        s.tls_cert = str(tls_cert)
        s.tls_key = str(tls_key or "")
        s.tls_port = tls_port or s.tls_port or 8443
    elif tls_port:
        s.tls_port = tls_port
    if s.tls_port and not s.tls_cert:
        err.print("[red]--tls-port needs --tls-cert (or [server].tls_cert)[/red]")
        raise typer.Exit(2)
    from mirage_trap.core import runner
    runner.ensure_data_dir(cfg.data_path)

    def ready(c):
        w = c.world.data
        lines = [f"[bold green]mirage-trap {__version__}[/bold green]{DOT}profile [bold]{c.profile.name}[/bold]{DOT}"
                 f"{w['company']['name']} ({w['host']['hostname']})",
                 f"  http   {s.host}:{s.port}"]
        if s.tls_port and s.tls_cert:
            lines.append(f"  https  {s.host}:{s.tls_port}  (JA3/JA4 capture on)")
        if cfg.ssh.enabled if ssh is None else ssh:
            lines.append(f"  ssh    {cfg.ssh.host}:{cfg.ssh.port}")
        if cfg.telnet.enabled if telnet is None else telnet:
            lines.append(f"  telnet {cfg.telnet.host}:{cfg.telnet.port}")
        lines.append(f"  llm    {ARROW.join(p.name for p in c.deceiver.providers)}")
        lines.append(f"  data   {cfg.data_path}")
        lines.append(f"[dim]dashboard: mirage-trap dashboard (separate process){DOT}Ctrl+C to stop[/dim]")
        console.print("\n".join(lines))

    try:
        asyncio.run(runner.serve(cfg, ssh=ssh, telnet=telnet, on_ready=ready))
    except runner.WorldMissing as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    except ValueError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(2)
    except KeyboardInterrupt:
        pass
    console.print("stopped.")


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------

@app.command()
def dashboard(
    host: Optional[str] = typer.Option(None, help="Bind address (default [dashboard].host = 127.0.0.1)."),
    port: Optional[int] = typer.Option(None, help="Port (default [dashboard].port = 9090)."),
    i_know: bool = typer.Option(False, "--i-know-what-im-doing", help="Allow binding to a non-loopback address."),
):
    """Serve the local surveillance dashboard (read-only, loopback only)."""
    cfg = _cfg()
    from mirage_trap.dashboard.server import run as run_dash
    try:
        run_dash(cfg.db_path, cfg.data_path, host or cfg.dashboard.host, port or cfg.dashboard.port, force_bind=i_know)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@app.command()
def export(
    fmt: str = typer.Option("jsonl", "--format", "-f", help="jsonl | csv | stix"),
    since: str = typer.Option("", help="Time window, e.g. 24h, 7d, or an ISO date (default: everything)."),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output file (default: stdout)."),
):
    """Export telemetry for SIEMs and threat-intel platforms."""
    cfg = _cfg()
    if not cfg.db_path.exists():
        err.print(f"[red]no telemetry database at {cfg.db_path}[/red]")
        raise typer.Exit(1)
    from mirage_trap.core.db import Database
    from mirage_trap.core.export import export as do_export, parse_since
    try:
        ts = parse_since(since)
    except ValueError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(2)
    db = Database(cfg.db_path, readonly=True)
    try:
        if out:
            with out.open("w", encoding="utf-8", newline="") as fh:
                n = do_export(db, fmt, fh, ts)
            err.print(OK + f" {n} records{ARROW}{out}")
        else:
            sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
            do_export(db, fmt, sys.stdout, ts)
    except ValueError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(2)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

@app.command()
def doctor(
    target: Optional[str] = typer.Option(None, help="Also probe a running listener, e.g. 127.0.0.1:8080."),
):
    """Audit config, LLM providers, the no-execution invariant and fingerprint tells."""
    cfg = _cfg()
    from mirage_trap.core.doctor import run_doctor
    checks = run_doctor(cfg, target)
    t = Table(show_header=True, header_style="bold")
    t.add_column("")
    t.add_column("area")
    t.add_column("check")
    t.add_column("detail", overflow="fold")
    for c in checks:
        mark = _mark(c.ok)
        t.add_row(mark, c.area, c.name, c.detail)
    console.print(t)
    failed = [c for c in checks if c.ok is False]
    if failed:
        console.print(f"[red]{len(failed)} check(s) failed[/red]")
        raise typer.Exit(1)
    console.print("[green]all checks passed[/green]")


if __name__ == "__main__":
    app()
