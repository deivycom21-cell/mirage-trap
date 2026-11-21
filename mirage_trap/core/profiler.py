"""Bot vs. human classification and attacker sophistication.

Rule-based and explainable on purpose: every verdict comes with the signals that
produced it, so an analyst can disagree with it. Runs in the background over the
telemetry database and never touches the request path.

Output per session:
    kind            scanner | bot | human | hybrid | unknown
    kind_confidence 0..1
    tool            best guess of the client tool (sqlmap, nuclei, Hydra, ...)
    sophistication  0 (mass scan) .. 5 (manual chaining + evasion/persistence)
"""

from __future__ import annotations

import json
import logging
import re
import statistics
import time
from dataclasses import dataclass, field

from mirage_trap.core.db import Database

log = logging.getLogger("mirage.profiler")

# (regex over User-Agent or SSH client version, tool name, family)
TOOL_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"sqlmap/([\d.]+)", re.I), "sqlmap", "exploit"),
    (re.compile(r"Nuclei", re.I), "nuclei", "scanner"),
    (re.compile(r"Nikto", re.I), "Nikto", "scanner"),
    (re.compile(r"WPScan", re.I), "WPScan", "scanner"),
    (re.compile(r"gobuster", re.I), "gobuster", "scanner"),
    (re.compile(r"feroxbuster", re.I), "feroxbuster", "scanner"),
    (re.compile(r"Fuzz Faster U Fool|ffuf", re.I), "ffuf", "scanner"),
    (re.compile(r"DirBuster", re.I), "DirBuster", "scanner"),
    (re.compile(r"dirb", re.I), "dirb", "scanner"),
    (re.compile(r"masscan", re.I), "masscan", "scanner"),
    (re.compile(r"zgrab", re.I), "zgrab", "scanner"),
    (re.compile(r"Nmap Scripting Engine|nmap", re.I), "nmap", "scanner"),
    (re.compile(r"WhatWeb", re.I), "WhatWeb", "scanner"),
    (re.compile(r"CensysInspect|Expanse|Shodan|internet-measurement|Palo Alto Networks", re.I), "internet survey",
     "scanner"),
    (re.compile(r"Hydra", re.I), "Hydra", "bruteforce"),
    (re.compile(r"python-requests/([\d.]+)", re.I), "python-requests", "script"),
    (re.compile(r"python-httpx|aiohttp|Python-urllib", re.I), "python", "script"),
    (re.compile(r"Go-http-client", re.I), "Go-http-client", "script"),
    (re.compile(r"^curl/([\d.]+)", re.I), "curl", "manual-cli"),
    (re.compile(r"^Wget/", re.I), "wget", "manual-cli"),
    (re.compile(r"libwww-perl", re.I), "libwww-perl", "script"),
    (re.compile(r"Java/|Apache-HttpClient|okhttp", re.I), "java", "script"),
    (re.compile(r"Burp|burpcollaborator", re.I), "Burp Suite", "manual-proxy"),
    (re.compile(r"Mozilla/5\.0.*(?:Chrome|Firefox|Safari|Edg)/", re.I), "browser", "browser"),
]
SSH_CLIENTS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"libssh2", re.I), "libssh2", "bruteforce"),
    (re.compile(r"libssh[_-]", re.I), "libssh", "bruteforce"),
    (re.compile(r"SSH-2\.0-Go", re.I), "Go x/crypto/ssh", "bruteforce"),
    (re.compile(r"paramiko", re.I), "paramiko", "script"),
    (re.compile(r"AsyncSSH", re.I), "asyncssh", "script"),
    (re.compile(r"JSCH", re.I), "JSch", "bruteforce"),
    (re.compile(r"ZGrab", re.I), "zgrab", "scanner"),
    (re.compile(r"Nmap", re.I), "nmap", "scanner"),
    (re.compile(r"PuTTY", re.I), "PuTTY", "manual-cli"),
    (re.compile(r"OpenSSH", re.I), "OpenSSH client", "manual-cli"),
]
EVASION_RX = re.compile(r"(%25[0-9a-f]{2}|/\*\*/|\bchar\(|0x[0-9a-f]{8,}|base64\s+-d|\|\s*base64|"
                        r"\$\{IFS\}|\\x[0-9a-f]{2}|unhex\(|concat\(0x)", re.I)
ANTI_FORENSICS_RX = re.compile(r"(history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|rm\s+.*(\.bash_history|/var/log)|"
                               r"shred\b|>\s*/var/log/|truncate\s+.*log)", re.I)
PERSISTENCE_RX = re.compile(r"(authorized_keys|crontab|/etc/cron|systemctl\s+enable|\.bashrc|/etc/rc\.local|"
                            r"useradd|adduser|passwd\s)", re.I)
RECON_CMD_RX = re.compile(r"^\s*(uname|id|whoami|cat\s+/etc/(passwd|os-release|issue)|ps\b|netstat|ss\b|ifconfig|ip\s+a|"
                          r"w\b|last\b|df\b|free\b|nproc|lscpu|crontab\s+-l|sudo\s+-l|ls\b)", re.I)
# One-liners bots fire right after login (Mirai & co.)
BOT_SHELL_RX = re.compile(r"(/bin/busybox\s+[A-Z]{3,}|cd\s+/tmp\s*\|\|\s*cd|echo\s+-e\s+['\"]\\x|"
                          r"enable\s*;\s*system|cat\s+/proc/cpuinfo\s*\|\s*grep\s+name\s*\|\s*wc)", re.I)


@dataclass
class Verdict:
    kind: str = "unknown"
    confidence: float = 0.0
    tool: str | None = None
    sophistication: int = 0
    reasons: list[str] = field(default_factory=list)


def _detect_tool(user_agents: list[str], ssh_versions: list[str]) -> tuple[str | None, str | None]:
    for ua in user_agents:
        for rx, name, family in TOOL_SIGNATURES:
            m = rx.search(ua or "")
            if m:
                version = m.group(1) if m.groups() and m.group(1) else ""
                return (f"{name} {version}".strip(), family)
    for v in ssh_versions:
        for rx, name, family in SSH_CLIENTS:
            if rx.search(v or ""):
                return name, family
    return None, None


def _intervals(ts: list[float]) -> list[float]:
    return [b - a for a, b in zip(ts, ts[1:]) if b >= a]


def profile_session(session: dict, events: list[dict], canary_hits: int = 0,
                    cred_attempts: int = 0, cred_success: int = 0) -> Verdict:
    """Pure function: session row + its events (chronological) -> Verdict."""
    v = Verdict()
    if not events:
        return v
    requests = [e for e in events if e.get("kind") == "request"]
    commands = [e for e in events if e.get("kind") == "command" and e.get("method") in ("shell", "exec")]
    uas = [session.get("user_agent") or ""]
    ssh_versions = []
    for e in events:
        if e.get("kind") == "connect" and e.get("headers"):
            try:
                for k, val in json.loads(e["headers"]):
                    if k == "client_version":
                        ssh_versions.append(val)
            except (ValueError, TypeError):
                pass
    tool, family = _detect_tool(uas, ssh_versions)
    v.tool = tool

    score_bot, score_human = 0.0, 0.0

    # -- timing ---------------------------------------------------------------
    ts = [e["ts"] for e in events if e.get("kind") in ("request", "command")]
    gaps = _intervals(ts)
    if len(gaps) >= 4:
        med = statistics.median(gaps)
        mean = statistics.fmean(gaps)
        cv = (statistics.pstdev(gaps) / mean) if mean > 0 else 0.0
        if med < 0.25:
            score_bot += 2.5
            v.reasons.append(f"fast cadence (median gap {med * 1000:.0f} ms)")
        elif med < 1.0 and cv < 0.6:
            score_bot += 1.5
            v.reasons.append(f"regular cadence (median {med:.2f}s, cv {cv:.2f})")
        long_pauses = sum(1 for g in gaps if 2.0 <= g <= 120.0)
        if long_pauses >= max(2, len(gaps) * 0.3) and cv > 0.8:
            score_human += 2.0
            v.reasons.append(f"irregular reading pauses ({long_pauses} gaps of 2-120 s)")

    # -- HTTP path pattern ---------------------------------------------------------
    if requests:
        statuses = [e.get("status") or 0 for e in requests]
        not_found = sum(1 for s in statuses if s == 404)
        ratio = not_found / len(requests)
        if len(requests) >= 15 and ratio > 0.6:
            score_bot += 2.5
            v.reasons.append(f"wordlist pattern ({not_found}/{len(requests)} 404s)")
        recon = sum(1 for e in requests if (e.get("attack_type") == "recon"))
        if recon and len(requests) <= 5 and not commands:
            score_bot += 1.0
            v.reasons.append("drive-by probe of known-sensitive paths")
        methods = {e.get("method") for e in requests}
        if "POST" in methods and len(requests) >= 3 and ratio < 0.3:
            score_human += 0.5

    # -- tool fingerprint ------------------------------------------------------------
    if family in ("scanner", "exploit", "bruteforce", "script"):
        score_bot += 3.0
        v.reasons.append(f"client looks like {tool}")
    elif family == "browser":
        score_human += 1.5
        v.reasons.append("browser user-agent")
    elif family in ("manual-cli", "manual-proxy"):
        score_human += 1.0
        v.reasons.append(f"hand-driven client ({tool})")

    # -- shell behaviour -----------------------------------------------------------------
    cmd_text = [str(e.get("path") or "") for e in commands]
    if commands:
        if any(BOT_SHELL_RX.search(c) for c in cmd_text):
            score_bot += 3.0
            v.reasons.append("botnet-style post-login one-liner")
        not_found_cmds = sum(1 for e in commands if (e.get("status") == 127))
        if not_found_cmds and len(commands) >= 3:
            score_human += 1.0
            v.reasons.append("typos / command-not-found followed by retries")
        if len(set(cmd_text)) >= 6 and len(gaps) >= 4 and statistics.median(gaps) > 1.5:
            score_human += 2.0
            v.reasons.append(f"interactive exploration ({len(set(cmd_text))} distinct commands)")

    # -- reaction to served content --------------------------------------------------------
    if canary_hits:
        score_human += 1.5
        v.reasons.append(f"reused {canary_hits} leaked credential(s) we served")

    # -- brute force -------------------------------------------------------------------------
    if cred_attempts >= 8 and cred_success == 0:
        score_bot += 2.0
        v.reasons.append(f"credential brute force ({cred_attempts} attempts)")

    # -- verdict ----------------------------------------------------------------------------
    total = score_bot + score_human
    if total == 0:
        v.kind, v.confidence = "unknown", 0.0
    elif score_bot and score_human and min(score_bot, score_human) / max(score_bot, score_human) > 0.5:
        v.kind = "hybrid"
        v.confidence = round(min(0.9, 0.4 + total / 20), 2)
    elif score_bot > score_human:
        scanner_like = family == "scanner" or any("wordlist" in r or "drive-by" in r for r in v.reasons)
        v.kind = "scanner" if scanner_like and not commands else "bot"
        v.confidence = round(min(0.98, 0.5 + (score_bot - score_human) / 10), 2)
    else:
        v.kind = "human"
        v.confidence = round(min(0.98, 0.5 + (score_human - score_bot) / 10), 2)

    v.sophistication = _sophistication(session, events, requests, commands, cmd_text, family, canary_hits,
                                       cred_success)
    return v


def _sophistication(session: dict, events: list[dict], requests: list[dict], commands: list[dict],
                    cmd_text: list[str], family: str | None, canary_hits: int, cred_success: int) -> int:
    attack_types = {e.get("attack_type") for e in events if e.get("attack_type")}
    exploit_types = attack_types - {"recon"}
    protocols = set((session.get("protocol") or "").split(",")) - {""}
    level = 0
    if requests or commands or events:
        level = 1 if attack_types or commands or cred_success or len(events) > 1 else 0
    if exploit_types or family in ("exploit", "bruteforce"):
        level = max(level, 2)
    successful_exploit = any(
        e.get("attack_type") in ("sqli", "lfi", "rce") and (e.get("status") or 0) == 200 and (e.get("response_len") or 0) > 0
        for e in requests)
    if (commands and not any(BOT_SHELL_RX.search(c) for c in cmd_text)) or (successful_exploit and family not in
                                                                             ("exploit", "scanner")):
        level = max(level, 3)
    if canary_hits and (len(protocols) > 1 or cred_success):
        level = max(level, 4)
    if len(exploit_types) >= 3 and commands:
        level = max(level, 4)
    hay = "\n".join(cmd_text + [str(e.get("query") or "") + str(e.get("path") or "") for e in requests])
    if level >= 3 and (ANTI_FORENSICS_RX.search(hay) or (PERSISTENCE_RX.search(hay) and EVASION_RX.search(hay))):
        level = 5
    elif level >= 3 and (PERSISTENCE_RX.search(hay) or EVASION_RX.search(hay)):
        level = max(level, 4)
    return min(level, 5)


class Profiler:
    """Background re-scoring of recently active sessions."""

    def __init__(self, db: Database, window_s: float = 6 * 3600):
        self.db = db
        self.window = window_s
        self._seen: dict[str, int] = {}

    def run_once(self, now: float | None = None) -> int:
        now = now or time.time()
        rows = self.db.query("SELECT * FROM sessions WHERE last_seen > ?", (now - self.window,))
        updated = 0
        for s in rows:
            if self._seen.get(s["id"]) == s["req_count"]:
                continue
            events = self.db.query(
                "SELECT ts, kind, method, path, query, headers, status, attack_type, response_len "
                "FROM events WHERE session_id = ? ORDER BY id LIMIT 5000", (s["id"],))
            hits = self.db.one("SELECT COUNT(*) AS n FROM canary_hits WHERE session_id = ?", (s["id"],))["n"]
            creds = self.db.one("SELECT COUNT(*) AS n, COALESCE(SUM(success), 0) AS ok FROM credentials "
                                "WHERE session_id = ?", (s["id"],))
            v = profile_session(s, events, hits, creds["n"], creds["ok"])
            self.db.execute("UPDATE sessions SET kind=?, kind_confidence=?, tool=?, sophistication=? WHERE id=?",
                            (v.kind, v.confidence, v.tool, v.sophistication, s["id"]))
            self._seen[s["id"]] = s["req_count"]
            updated += 1
        if len(self._seen) > 50_000:
            self._seen.clear()
        return updated
