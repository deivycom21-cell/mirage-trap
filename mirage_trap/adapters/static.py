"""No-LLM provider: always "fails over" to the deterministic fallbacks.

It exists so the chain always terminates in something that cannot error out or
leak, and so the honeypot is fully usable without any model at all.
"""

from __future__ import annotations

from mirage_trap.adapters.base import ProviderError


class StaticProvider:
    name = "static"

    async def generate(self, system: str, prompt: str, *, max_tokens: int = 1024,
                       temperature: float = 0.0, json_mode: bool = True) -> str:
        raise ProviderError("static: no model")

    async def health(self) -> tuple[bool, str]:
        return True, "deterministic fallbacks only"
