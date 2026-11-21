"""`claude -p` provider (uses the operator's Claude Code login).

Hardening, because attacker-controlled text ends up in the prompt:
  * every built-in tool is disabled (``--tools ""``) and MCP servers are ignored,
  * it runs in an empty temporary directory, without session persistence,
  * the prompt goes through stdin and the system prompt through a temp file, so
    neither appears in the process list.
This is the only module allowed to spawn a subprocess (enforced by a test).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile

from mirage_trap.adapters.base import ProviderError


class ClaudeCliProvider:
    name = "claude_cli"

    def __init__(self, binary: str, model: str, timeout: float):
        self.binary = binary
        self.model = model
        self.timeout = timeout

    async def generate(self, system: str, prompt: str, *, max_tokens: int = 1024,
                       temperature: float = 0.0, json_mode: bool = True) -> str:
        exe = shutil.which(self.binary)
        if not exe:
            raise ProviderError("claude_cli: binary not found")
        with tempfile.TemporaryDirectory(prefix="mt-") as workdir:
            sys_path = os.path.join(workdir, "system.txt")
            with open(sys_path, "w", encoding="utf-8") as fh:
                fh.write(system)
            args = [exe, "-p", "--output-format", "json", "--tools", "", "--strict-mcp-config",
                    "--no-session-persistence", "--system-prompt-file", sys_path]
            if self.model:
                args += ["--model", self.model]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args, cwd=workdir, stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                out, err = await asyncio.wait_for(proc.communicate(prompt.encode("utf-8")), self.timeout)
            except asyncio.TimeoutError as e:
                proc.kill()
                raise ProviderError("claude_cli: timeout") from e
            except OSError as e:
                raise ProviderError(f"claude_cli: {e}") from e
        if proc.returncode != 0:
            raise ProviderError(f"claude_cli: exit {proc.returncode}: {err.decode(errors='replace')[:200]}")
        try:
            data = json.loads(out.decode("utf-8"))
            if data.get("is_error"):
                raise ProviderError(f"claude_cli: {data.get('result', '')[:200]}")
            return data["result"]
        except (ValueError, KeyError) as e:
            raise ProviderError(f"claude_cli: bad output: {e}") from e

    async def health(self) -> tuple[bool, str]:
        exe = shutil.which(self.binary)
        return (True, exe) if exe else (False, f"'{self.binary}' not found in PATH")
