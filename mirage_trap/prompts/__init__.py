"""System prompts per persona. Kept as plain text files so operators can tune them."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

from mirage_trap.core.sanitizer import PROMPT_MARKER


@lru_cache(maxsize=None)
def load(name: str) -> str:
    text = resources.files(__package__).joinpath(f"{name}.txt").read_text(encoding="utf-8")
    common = resources.files(__package__).joinpath("_rules.txt").read_text(encoding="utf-8")
    return common.replace("{MARKER}", PROMPT_MARKER) + "\n\n" + text
