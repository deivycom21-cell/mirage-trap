"""OpenAI-compatible Chat Completions endpoint (OpenAI, OpenRouter, vLLM, LM Studio...)."""

from __future__ import annotations

import os

import httpx

from mirage_trap.adapters.base import ProviderError


class OpenAICompatProvider:
    name = "openai"

    def __init__(self, base_url: str, model: str, api_key_env: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.timeout = timeout

    async def generate(self, system: str, prompt: str, *, max_tokens: int = 1024,
                       temperature: float = 0.0, json_mode: bool = True) -> str:
        key = os.environ.get(self.api_key_env, "")
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": temperature, "seed": 7,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
            raise ProviderError(f"openai: {e}") from e

    async def health(self) -> tuple[bool, str]:
        if "api.openai.com" in self.base_url and not os.environ.get(self.api_key_env):
            return False, f"${self.api_key_env} not set"
        return True, f"{self.model} @ {self.base_url}"
