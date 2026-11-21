"""Local Ollama provider (default): nothing leaves the machine."""

from __future__ import annotations

import httpx

from mirage_trap.adapters.base import ProviderError


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str, model: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    async def generate(self, system: str, prompt: str, *, max_tokens: int = 1024,
                       temperature: float = 0.0, json_mode: bool = True) -> str:
        body = {
            "model": self.model,
            "system": system,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens, "seed": 7},
        }
        if json_mode:
            body["format"] = "json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/api/generate", json=body)
                r.raise_for_status()
                return r.json()["response"]
        except (httpx.HTTPError, KeyError, ValueError) as e:
            raise ProviderError(f"ollama: {e}") from e

    async def health(self) -> tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/api/tags")
                r.raise_for_status()
                models = [m["name"] for m in r.json().get("models", [])]
        except (httpx.HTTPError, ValueError) as e:
            return False, f"unreachable at {self.base_url} ({e.__class__.__name__})"
        if not any(m == self.model or m.split(":")[0] == self.model.split(":")[0] for m in models):
            return False, f"model '{self.model}' not pulled (run: ollama pull {self.model})"
        return True, f"{self.model} @ {self.base_url}"
