"""Attack/payload classification for HTTP requests (telemetry + profiling only;
responses never depend on it, so a wrong label cannot make the trap act oddly)."""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

RULES: list[tuple[str, str, re.Pattern]] = [
    ("log4shell", "jndi lookup", re.compile(r"\$\{\s*(jndi|\$\{lower:j\}|env:|sys:)", re.I)),
    ("sqli", "union", re.compile(r"\bunion\b[\s/*()]+(all[\s/*()]+)?select\b", re.I)),
    ("sqli", "time-based", re.compile(r"\b(sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay", re.I)),
    ("sqli", "error-based", re.compile(r"\b(extractvalue|updatexml|exp\(~|floor\(rand)", re.I)),
    ("sqli", "boolean", re.compile(r"['\"\)]\s*(or|and|\|\||&&)\s*['\"\d(]|\b(or|and)\s+\d+\s*[=<>]\s*\d+", re.I)),
    ("sqli", "schema enum", re.compile(r"information_schema|@@version|\bversion\(\)|\bdatabase\(\)", re.I)),
    ("sqli", "order-by probe", re.compile(r"\border\s+by\s+\d+", re.I)),
    ("sqli", "quote/comment", re.compile(r"('|%27)\s*(--|#|/\*)|'\s*$", re.I)),
    ("lfi", "traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|\.\.%2f)", re.I)),
    ("lfi", "php wrapper", re.compile(r"\b(php|zip|phar|data|expect|file)://", re.I)),
    ("lfi", "sensitive file", re.compile(r"/etc/(passwd|shadow|hosts)|/proc/self|win\.ini|boot\.ini", re.I)),
    ("rce", "command chaining", re.compile(r"(;|\|\|?|&&|\n|%0a)\s*(id|whoami|uname|cat|ls|wget|curl|nc|bash|sh|"
                                           r"python3?|perl|php|echo|ping|busybox|chmod|tftp)\b", re.I)),
    ("rce", "substitution", re.compile(r"\$\([^)]*\)|`[^`]+`")),
    ("rce", "shellshock", re.compile(r"\(\)\s*\{\s*:\s*;\s*\}")),
    ("ssti", "template", re.compile(r"\{\{.*?\}\}|\{%.*?%\}|<%=.*?%>|#\{.*?\}")),
    ("xss", "script", re.compile(r"<\s*script|on(error|load|mouseover)\s*=|javascript:|<\s*svg[^>]*on\w+=", re.I)),
    ("xxe", "entity", re.compile(r"<!ENTITY|<!DOCTYPE[^>]*\[", re.I)),
    ("ssrf", "internal url", re.compile(r"=(https?|gopher|dict|ftp)://(127\.|localhost|0\.0\.0\.0|169\.254|"
                                        r"metadata|\[::1?\]|10\.|192\.168\.)", re.I)),
    ("deserialization", "php/java", re.compile(r"O:\d+:\"[A-Za-z_\\]+\":\d+:\{|rO0AB|aced0005", re.I)),
]

RECON_PATHS = re.compile(
    r"(^/\.env|/\.git/|/\.aws/|/\.ssh/|/\.svn/|/\.DS_Store|/wp-(login|admin|content|includes)|/xmlrpc\.php|"
    r"/phpmyadmin|/pma/|/myadmin|/adminer|/server-status|/server-info|/actuator|/cgi-bin/|/HNAP1|/boaform|"
    r"/vendor/phpunit|/solr/|/owa/|/autodiscover|/\.well-known/security|/config\.(json|php|yml)|/backup|"
    r"\.(bak|old|swp|sql|zip|tar\.gz)$|/debug|/console|/telescope|/_profiler|/api/swagger|/swagger|"
    r"/v2/api-docs|/graphql|/manager/html|/jenkins|/druid|/nacos|/geoserver|/remote/login|/global-protect|"
    r"/sslvpn|/dana-na|/ecp/|/mgmt/|/setup\.cgi|/shell|/cmd|/eval)",
    re.I,
)


def _decode(s: str) -> str:
    prev = s
    for _ in range(3):
        cur = unquote_plus(prev)
        if cur == prev:
            break
        prev = cur
    return prev


def classify(method: str, path: str, query: str, body: str, headers: dict[str, str]) -> list[tuple[str, str]]:
    # NUL separator: joining with "\n" would glue fields together and fake "command
    # chaining" (newline + a "python-requests" User-Agent looks like "\npython").
    hay = "\x00".join([_decode(path), _decode(query), _decode(body[:20000])] +
                      [v for k, v in headers.items() if k in ("user-agent", "referer", "cookie", "x-forwarded-for",
                                                               "x-api-version", "x-request-id")])
    found: list[tuple[str, str]] = []
    seen = set()
    for kind, detail, rx in RULES:
        if kind in seen and kind != "sqli":
            continue
        if rx.search(hay):
            found.append((kind, detail))
            seen.add(kind)
    if RECON_PATHS.search(path):
        found.append(("recon", "sensitive path"))
    if method not in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"):
        found.append(("recon", f"method {method}"))
    return found


def summarize(found: list[tuple[str, str]]) -> tuple[str | None, str | None]:
    if not found:
        return None, None
    priority = ["rce", "log4shell", "sqli", "lfi", "deserialization", "xxe", "ssti", "ssrf", "xss", "recon"]
    found.sort(key=lambda f: priority.index(f[0]) if f[0] in priority else 99)
    return found[0][0], ", ".join(sorted({f"{k}:{d}" for k, d in found}))
