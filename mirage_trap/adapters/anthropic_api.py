"""Anthropic Messages API (BYOK). The key is read from an environment variable."""

from __future__ import annotations

import os

import httpx

from mirage_trap.adapters.base import ProviderError

API_URL = "https://api.anthropic.com/v1/messages"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str, api_key_env: str, timeout: float):
        self.model = model
        self.api_key_env = api_key_env
        self.timeout = timeout

    @property
    def key(self) -> str | None:
        return os.environ.get(self.api_key_env)

    async def generate(self, system: str, prompt: str, *, max_tokens: int = 1024,
                       temperature: float = 0.0, json_mode: bool = True) -> str:
        if not self.key:
            raise ProviderError(f"anthropic: ${self.api_key_env} not set")
        # No assistant prefill (recent models reject it); the sanitizer extracts the JSON object.
        messages = [{"role": "user", "content": prompt}]
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                "system": system, "messages": messages}
        headers = {"x-api-key": self.key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(API_URL, json=body, headers=headers)
                r.raise_for_status()
                data = r.json()
                text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        except (httpx.HTTPError, ValueError) as e:
            raise ProviderError(f"anthropic: {e}") from e
        return text

    async def health(self) -> tuple[bool, str]:
        if not self.key:
            return False, f"${self.api_key_env} not set"
        return True, f"{self.model} (key from ${self.api_key_env})"
