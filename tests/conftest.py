"""Shared fixtures: a fully wired trap per profile, in a temp data dir, no LLM."""

from __future__ import annotations

import httpx
import pytest

from mirage_trap.config import Config
from mirage_trap.core import runner
from mirage_trap.core.world import generate_world, save_world

DOMAIN = "example-corp.test"


class FakeProvider:
    """Deterministic stand-in for an LLM: returns a canned reply (or a function of the prompt)."""

    def __init__(self, reply, name: str = "fake"):
        self.reply = reply
        self.name = name
        self.calls = 0
        self.prompts: list[str] = []

    async def generate(self, system, prompt, *, max_tokens=1024, temperature=0.0, json_mode=True):
        self.calls += 1
        self.prompts.append(prompt)
        return self.reply(prompt) if callable(self.reply) else self.reply

    async def health(self):
        return True, "fake"


def make_config(data_dir, profile: str = "nginx-php-legacy", **over) -> Config:
    raw = {"server": {"profile": profile}, "storage": {"data_dir": str(data_dir)}, "llm": {"providers": ["static"]}}
    for k, v in over.items():
        raw.setdefault(k, {}).update(v)
    return Config.model_validate(raw)


@pytest.fixture
def make_trap(tmp_path):
    built: list[runner.Components] = []

    def _make(profile: str = "nginx-php-legacy", seed: int = 1234, providers=None, data_dir=None, **over):
        d = data_dir or (tmp_path / profile)
        cfg = make_config(d, profile, **over)
        if not cfg.world_path.exists():
            save_world(generate_world(profile, seed, DOMAIN), cfg.world_path)
        c = runner.build(cfg)
        if providers is not None:
            from mirage_trap.adapters.static import StaticProvider
            c.deceiver.providers = list(providers) + [StaticProvider()]
        built.append(c)
        return c

    yield _make
    for c in built:
        try:
            c.close()
        except Exception:
            pass


def client(c: runner.Components, ip: str = "198.51.100.20", **kw) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=c.app, client=(ip, 40000))
    return httpx.AsyncClient(transport=transport, base_url="http://victim.test", **kw)
