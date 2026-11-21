"""Output filter for LLM responses.

Anything that smells like an assistant, a model, a simulation or our own prompt is
rejected, and the caller falls back to a deterministic response instead. A rejected
answer costs one deterministic error message; a leaked one burns the honeypot.
"""

from __future__ import annotations

import json
import re

PROMPT_MARKER = "MT-RULESET-7F3A"

# Always fatal, whatever the length: these never appear in genuine program output.
_STRONG = [
    r"\bas an ai\b", r"\blanguage model\b", r"\bi(?:'m| am) (?:sorry|unable|not able)\b", r"\bi can(?:no|')t\b",
    r"\bi apologi[sz]e\b", r"\blo siento\b", r"\bcomo (?:ia|modelo)\b", r"\bopenai\b", r"\banthropic\b",
    r"\bchatgpt\b", r"\bgpt-\d", r"\bollama\b", r"\bllama\s?\d", r"\bqwen\b", r"\bhoneypot\b", r"```",
    r"\bsimulated\b", r"\bfictitious\b", r"\bin a real (?:system|environment|server)\b", r"\bmirage\b",
    re.escape(PROMPT_MARKER),
]
# Conversational tells: legitimate inside long files (e.g. bash.bashrc mentions "prompt"),
# suspicious in short outputs where they can only be the model talking.
_SOFT = [
    r"^\s*here(?:'s| is) (?:the|an?|your)\b", r"^\s*(?:note|explanation):", r"\bhypothetical\b",
    r"\bfictional\b", r"\bplaceholder\b", r"\bexample output\b", r"\bpretend\b", r"\bassistant\b",
    r"\bprompt\b", r"\bsimulat(?:ion|ing)\b",
]
_STRONG_RX = re.compile("|".join(_STRONG), re.I | re.M)
_SOFT_RX = re.compile("|".join(_SOFT), re.I | re.M)
SOFT_LIMIT = 600


class Rejected(Exception):
    pass


def extract_json(text: str) -> dict:
    text = text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise Rejected("no json object")
    try:
        data = json.loads(text[start:end + 1])
    except ValueError as e:
        raise Rejected(f"bad json: {e}") from e
    if not isinstance(data, dict):
        raise Rejected("json is not an object")
    return data


def check_text(value: str, *, max_len: int, allow: tuple[str, ...] = ()) -> str:
    if not isinstance(value, str):
        raise Rejected("not a string")
    if len(value) > max_len:
        value = value[:max_len]
    probe = value
    for a in allow:          # world facts that may legitimately contain a tell word
        probe = probe.replace(a, "")
    m = _STRONG_RX.search(probe) or (_SOFT_RX.search(probe) if len(probe) < SOFT_LIMIT else None)
    if m:
        raise Rejected(f"tell: {m.group(0)!r}")
    return value.replace("\r\n", "\n")


def sanitize(raw: str, *, field: str = "output", max_len: int = 8000, allow: tuple[str, ...] = ()) -> dict:
    data = extract_json(raw)
    if field not in data:
        raise Rejected(f"missing {field!r}")
    data[field] = check_text(data[field], max_len=max_len, allow=allow)
    return data
