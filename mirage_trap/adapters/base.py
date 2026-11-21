"""Provider protocol shared by every LLM backend."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ProviderError(Exception):
    pass


@dataclass
class Completion:
    text: str
    provider: str


class LLMProvider(Protocol):
    name: str

    async def generate(self, system: str, prompt: str, *, max_tokens: int = 1024,
                       temperature: float = 0.0, json_mode: bool = True) -> str:
        """Return raw model text. Raise ProviderError on any failure."""
        ...

    async def health(self) -> tuple[bool, str]:
        ...
