"""LLM provider factory."""

from __future__ import annotations

from mirage_trap.adapters.anthropic_api import AnthropicProvider
from mirage_trap.adapters.base import LLMProvider, ProviderError
from mirage_trap.adapters.claude_cli import ClaudeCliProvider
from mirage_trap.adapters.ollama import OllamaProvider
from mirage_trap.adapters.openai_compat import OpenAICompatProvider
from mirage_trap.adapters.static import StaticProvider
from mirage_trap.config import LlmCfg

__all__ = ["build_providers", "LLMProvider", "ProviderError"]


def build_providers(cfg: LlmCfg) -> list[LLMProvider]:
    out: list[LLMProvider] = []
    for name in cfg.providers:
        if name == "ollama":
            out.append(OllamaProvider(cfg.ollama.base_url, cfg.ollama.model, cfg.timeout))
        elif name in ("anthropic", "anthropic_api"):
            out.append(AnthropicProvider(cfg.anthropic.model, cfg.anthropic.api_key_env, cfg.timeout))
        elif name in ("openai", "openai_compat"):
            out.append(OpenAICompatProvider(cfg.openai.base_url, cfg.openai.model, cfg.openai.api_key_env, cfg.timeout))
        elif name in ("claude_cli", "claude"):
            out.append(ClaudeCliProvider(cfg.claude_cli.binary, cfg.claude_cli.model, cfg.timeout))
        elif name == "static":
            out.append(StaticProvider())
        else:
            raise ValueError(f"unknown LLM provider {name!r}")
    if not out or out[-1].name != "static":
        out.append(StaticProvider())
    return out
