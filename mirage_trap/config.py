"""Configuration loading (TOML file + MIRAGE_* environment overrides)."""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field


class ServerCfg(BaseModel):
    profile: str = "nginx-php-legacy"
    host: str = "0.0.0.0"
    port: int = 8080
    tls_port: int = 0
    tls_cert: str = ""
    tls_key: str = ""
    behind_proxy: bool = False
    trusted_proxies: list[str] = Field(default_factory=lambda: ["127.0.0.1"])
    client_ip_header: str = "X-Real-IP"
    ja3_header: str = "X-Mirage-JA3"
    ja4_header: str = "X-Mirage-JA4"


class SshCfg(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 2222
    accept: list[str] = Field(default_factory=list)


class TelnetCfg(BaseModel):
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 2323


class WorldCfg(BaseModel):
    seed: int = 0
    domain: str = ""


class OllamaCfg(BaseModel):
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:7b-instruct"


class AnthropicCfg(BaseModel):
    model: str = "claude-haiku-5-5"
    api_key_env: str = "ANTHROPIC_API_KEY"


class OpenAICfg(BaseModel):
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    api_key_env: str = "OPENAI_API_KEY"


class ClaudeCliCfg(BaseModel):
    binary: str = "claude"
    model: str = ""


class LlmCfg(BaseModel):
    providers: list[str] = Field(default_factory=lambda: ["ollama", "static"])
    timeout: float = 25
    max_calls_per_ip_per_day: int = 150
    max_calls_global_per_day: int = 3000
    ollama: OllamaCfg = Field(default_factory=OllamaCfg)
    anthropic: AnthropicCfg = Field(default_factory=AnthropicCfg)
    openai: OpenAICfg = Field(default_factory=OpenAICfg)
    claude_cli: ClaudeCliCfg = Field(default_factory=ClaudeCliCfg)


class DashboardCfg(BaseModel):
    host: str = "127.0.0.1"
    port: int = 9090


class StorageCfg(BaseModel):
    data_dir: str = "data"
    retention_days: int = 90
    max_body_bytes: int = 65536
    geoip_city: str = ""
    geoip_asn: str = ""


class Config(BaseModel):
    server: ServerCfg = Field(default_factory=ServerCfg)
    ssh: SshCfg = Field(default_factory=SshCfg)
    telnet: TelnetCfg = Field(default_factory=TelnetCfg)
    world: WorldCfg = Field(default_factory=WorldCfg)
    llm: LlmCfg = Field(default_factory=LlmCfg)
    dashboard: DashboardCfg = Field(default_factory=DashboardCfg)
    storage: StorageCfg = Field(default_factory=StorageCfg)

    @property
    def data_path(self) -> Path:
        return Path(self.storage.data_dir).expanduser().resolve()

    @property
    def db_path(self) -> Path:
        return self.data_path / "mirage.db"

    @property
    def world_path(self) -> Path:
        return self.data_path / "world.json"


def _apply_env(raw: dict) -> dict:
    """MIRAGE_SECTION__KEY=value overrides, e.g. MIRAGE_SERVER__PORT=80.
    Lists/objects are given as JSON: MIRAGE_LLM__PROVIDERS='["ollama","static"]'.
    A third level reaches nested tables: MIRAGE_LLM__OLLAMA__BASE_URL=http://ollama:11434."""
    for name, value in os.environ.items():
        if not name.startswith("MIRAGE_") or "__" not in name:
            continue
        path = name[len("MIRAGE_"):].lower().split("__")
        parsed: object = value
        if value[:1] in ("[", "{"):
            try:
                parsed = json.loads(value)
            except ValueError:
                pass
        node = raw
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = parsed
    return raw


def load_config(path: str | Path | None = None) -> Config:
    raw: dict = {}
    candidate = Path(path) if path else Path("config.toml")
    if candidate.exists():
        with candidate.open("rb") as fh:
            raw = tomllib.load(fh)
    elif path:
        raise FileNotFoundError(f"config file not found: {candidate}")
    return Config.model_validate(_apply_env(raw))
