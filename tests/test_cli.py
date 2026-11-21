"""End-to-end CLI: init, world, doctor, export."""

from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from mirage_trap.cli import _set_toml, app


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for k in list(os.environ):
        if k.startswith("MIRAGE_"):
            monkeypatch.delenv(k)
    return tmp_path


def run(*args):
    r = CliRunner().invoke(app, list(args), catch_exceptions=False)
    return r


def test_set_toml_keeps_comments():
    text = '[server]\nprofile = "a"      # comment\nport = 1\n[world]\nseed = 0\n'
    out = _set_toml(text, "server", "profile", '"b"')
    assert 'profile = "b"   # comment' in out and "port = 1" in out
    assert _set_toml(text, "world", "seed", "5").count("seed = 5") == 1


def test_init_world_doctor_export(workdir):
    r = run("init", "--profile", "node-express-api", "--seed", "77", "--domain", "corp.test")
    assert r.exit_code == 0, r.output
    assert (workdir / "config.toml").exists()
    assert 'profile = "node-express-api"' in (workdir / "config.toml").read_text()
    data = workdir / "data"
    assert (data / "world.json").exists() and (data / "dashboard.token").exists()
    assert (data / "ssh_host_ed25519_key").exists()
    world = json.loads((data / "world.json").read_text())
    assert world["seed"] == 77 and world["company"]["domain"] == "corp.test"

    r = run("world", "show")
    assert r.exit_code == 0 and "corp.test" in r.output
    r = run("world", "show", "--secrets")
    assert world["secrets"]["db_password"] in r.output

    r = run("world", "init")
    assert r.exit_code == 1                          # refuses to clobber without --force
    r = run("world", "init", "--force", "--seed", "78")
    assert r.exit_code == 0
    assert json.loads((data / "world.json").read_text())["seed"] == 78

    # use only the static provider so doctor doesn't depend on a local ollama
    cfg = (workdir / "config.toml").read_text().replace('providers = ["ollama", "static"]', 'providers = ["static"]')
    (workdir / "config.toml").write_text(cfg)
    r = run("doctor")
    assert r.exit_code == 0, r.output
    assert "no execution sinks" in r.output

    r = run("export", "--format", "jsonl")
    assert r.exit_code == 1                          # nothing recorded yet


def test_run_refuses_mismatched_world(workdir):
    assert run("init", "--profile", "nginx-php-legacy", "--seed", "3").exit_code == 0
    r = run("run", "--profile", "node-express-api", "--no-ssh")
    assert r.exit_code == 1 and "world init" in r.output


def test_dashboard_refuses_public_bind(workdir):
    assert run("init", "--seed", "4").exit_code == 0
    r = CliRunner().invoke(app, ["dashboard", "--host", "0.0.0.0"])
    assert r.exit_code != 0
    assert "refusing to bind" in str(r.exception) + r.output


def test_unknown_profile(workdir):
    assert run("init", "--profile", "iis").exit_code == 2
