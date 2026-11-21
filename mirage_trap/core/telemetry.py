"""Silent telemetry: everything is queued and written by a background thread.

Callers only do ``queue.put_nowait``; the response to the attacker never waits on
disk, GeoIP or canary scanning. If the writer dies, the trap keeps answering.
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import threading
import time
from typing import Any

from mirage_trap.core.db import Database, dumps
from mirage_trap.core.geo import GeoIP
from mirage_trap.core.state import Session

log = logging.getLogger("mirage.telemetry")


class Telemetry:
    def __init__(self, db: Database, geo: GeoIP | None = None, max_body: int = 65536):
        self.db = db
        self.geo = geo or GeoIP()
        self.max_body = max_body
        self.q: "queue.Queue[tuple[str, Any]]" = queue.Queue(maxsize=50_000)
        self._canaries: list[tuple[str, str]] = []
        self._geo_done: set[str] = set()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="mirage-telemetry", daemon=True)
        self._thread.start()

    # -- public, non-blocking API -------------------------------------------------
    def load_canaries(self, canaries: list[tuple[str, str, str]]) -> None:
        self.db.executemany("INSERT OR IGNORE INTO canaries(token, kind, label) VALUES (?,?,?)", canaries)
        self._canaries = [(t, label) for t, _, label in canaries if len(t) >= 6]

    def _put(self, kind: str, payload: Any) -> None:
        try:
            self.q.put_nowait((kind, payload))
        except queue.Full:
            log.warning("telemetry queue full, dropping %s", kind)

    def session(self, s: Session) -> None:
        self._put("session", {
            "id": s.id, "protocol": ",".join(sorted(s.protocols)), "first_seen": s.first_seen,
            "last_seen": s.last_seen, "ip": s.ip, "ips": sorted(s.ips), "cookie": s.cookie,
            "user_agent": s.user_agent, "ja3": s.ja3, "ja4": s.ja4, "req_count": s.req_count,
            "authenticated": s.web_user,
        })

    def event(self, session: Session, **fields: Any) -> None:
        session.req_count += 1
        body = fields.pop("body", None)
        if isinstance(body, (bytes, bytearray)):
            fields["body_len"] = len(body)
            fields["body_sha256"] = hashlib.sha256(body).hexdigest() if body else None
            body = body[: self.max_body].decode("utf-8", "replace")
        elif isinstance(body, str):
            fields["body_len"] = len(body)
        fields["body"] = body
        resp = fields.get("response")
        if isinstance(resp, (bytes, bytearray)):
            fields["response_len"] = len(resp)
            fields["response"] = resp[:8192].decode("utf-8", "replace")
        elif isinstance(resp, str):
            fields.setdefault("response_len", len(resp))
            fields["response"] = resp[:8192]
        if isinstance(fields.get("headers"), list):
            fields["headers"] = dumps(fields["headers"])
        fields.setdefault("ts", time.time())
        fields["session_id"] = session.id
        fields.setdefault("ip", session.ip)
        self._put("event", fields)
        self.session(session)

    def credential(self, session: Session, protocol: str, username: str, password: str, success: bool) -> None:
        self._put("credential", (session.id, time.time(), protocol, username, password, int(success)))
        self._put("scan", (session.id, f"{username}\n{password}", f"{protocol} login"))

    def ioc(self, session: Session, kind: str, value: str, context: str = "") -> None:
        self._put("ioc", (session.id, time.time(), kind, value[:2000], context[:2000]))

    def scan(self, session: Session, text: str, context: str) -> None:
        """Look for leaked canary credentials in attacker input."""
        if text:
            self._put("scan", (session.id, text[:20000], context))

    def flush(self, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while not self.q.empty() and time.time() < deadline:
            time.sleep(0.02)
        time.sleep(0.05)

    def close(self) -> None:
        self.flush()
        self._stop.set()
        self._thread.join(timeout=2)

    # -- writer thread ------------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            batch = []
            try:
                batch.append(self.q.get(timeout=0.2))
                while len(batch) < 500:
                    batch.append(self.q.get_nowait())
            except queue.Empty:
                pass
            if batch:
                try:
                    self._write(batch)
                except Exception:   # never let telemetry take the trap down
                    log.exception("telemetry write failed")

    def _write(self, batch: list[tuple[str, Any]]) -> None:
        sessions: dict[str, dict] = {}
        events, creds, iocs, hits = [], [], [], []
        for kind, p in batch:
            if kind == "session":
                sessions[p["id"]] = p
            elif kind == "event":
                events.append(p)
            elif kind == "credential":
                creds.append(p)
            elif kind == "ioc":
                iocs.append(p)
            elif kind == "scan":
                sid, text, ctx = p
                for token, label in self._canaries:
                    if token in text:
                        hits.append((token, sid, time.time(), f"{ctx}: {label}"))

        def tx(conn):
            for s in sessions.values():
                conn.execute(
                    "INSERT INTO sessions(id, protocol, first_seen, last_seen, ip, ips, cookie, user_agent, ja3, ja4, "
                    "req_count, authenticated) VALUES (:id,:protocol,:first_seen,:last_seen,:ip,:ips,:cookie,:user_agent,"
                    ":ja3,:ja4,:req_count,:authenticated) ON CONFLICT(id) DO UPDATE SET protocol=excluded.protocol, "
                    "last_seen=excluded.last_seen, ip=excluded.ip, ips=excluded.ips, cookie=COALESCE(excluded.cookie, cookie), "
                    "user_agent=COALESCE(excluded.user_agent, user_agent), ja3=COALESCE(excluded.ja3, ja3), "
                    "ja4=COALESCE(excluded.ja4, ja4), req_count=excluded.req_count, "
                    "authenticated=COALESCE(excluded.authenticated, authenticated)",
                    {**s, "ips": json.dumps(s["ips"])},
                )
            cols = ["session_id", "ts", "protocol", "ip", "port", "kind", "method", "path", "query", "headers", "body",
                    "body_len", "body_sha256", "attack_type", "attack_detail", "persona", "status", "response",
                    "response_len", "latency_sim_ms", "latency_real_ms", "provider"]
            for e in events:
                conn.execute(f"INSERT INTO events({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                             [e.get(c) for c in cols])
            conn.executemany("INSERT INTO credentials(session_id, ts, protocol, username, password, success) "
                             "VALUES (?,?,?,?,?,?)", creds)
            conn.executemany("INSERT INTO iocs(session_id, ts, kind, value, context) VALUES (?,?,?,?,?)", iocs)
            conn.executemany("INSERT INTO canary_hits(token, session_id, ts, context) VALUES (?,?,?,?)", hits)

        self.db.transaction(tx)
        for sid, s in sessions.items():
            if sid not in self._geo_done:
                self._geo_done.add(sid)
                g = self.geo.lookup(s["ip"])
                if any(g.values()):
                    self.db.execute("UPDATE sessions SET country=?, city=?, asn=?, as_org=? WHERE id=?",
                                    (g["country"], g["city"], g["asn"], g["as_org"], sid))
