"""Per-attacker session identity and persistent state.

A session is "one attacker": it is keyed by our session cookie when the client keeps
it (so proxy-rotating attackers stay one session) and otherwise by source IP within
an inactivity window. HTTP, SSH and Telnet activity from the same IP land in the
same session, so the dashboard shows a single story (e.g. creds stolen via the web,
then used over SSH) and the virtual machine state is shared across protocols, just
like a real host.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from mirage_trap.core.db import Database, dumps

SESSION_IDLE_SECONDS = 30 * 60
WORLD_SCOPE = "__world__"


@dataclass
class Session:
    id: str
    ip: str
    first_seen: float
    last_seen: float
    ips: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    cookie: str | None = None
    user_agent: str | None = None
    ja3: str | None = None
    ja4: str | None = None
    req_count: int = 0
    web_user: str | None = None          # authenticated web/app user, if any
    pma_user: str | None = None          # phpMyAdmin login
    api_tokens: set[str] = field(default_factory=set)
    # runtime caches, never persisted directly
    runtime: dict[str, Any] = field(default_factory=dict)
    dirty: bool = True


class StateStore:
    """Namespaced key/value persistence per session (VFS overlay, shell env, SQL db)."""

    def __init__(self, db: Database):
        self.db = db

    def load_ns(self, session_id: str, namespace: str) -> dict[str, Any]:
        rows = self.db.query(
            "SELECT key, value FROM state_kv WHERE session_id = ? AND namespace = ?", (session_id, namespace)
        )
        out: dict[str, Any] = {}
        for r in rows:
            v = r["value"]
            if isinstance(v, (bytes, bytearray)):
                out[r["key"]] = bytes(v)
            else:
                try:
                    out[r["key"]] = json.loads(v)
                except (TypeError, ValueError):
                    out[r["key"]] = v
        return out

    def save(self, session_id: str, namespace: str, items: dict[str, Any]) -> None:
        if not items:
            return
        now = time.time()
        rows = []
        for k, v in items.items():
            value = v if isinstance(v, (bytes, bytearray)) else dumps(v)
            rows.append((session_id, namespace, k, value, now))
        self.db.executemany(
            "INSERT INTO state_kv(session_id, namespace, key, value, updated) VALUES (?,?,?,?,?) "
            "ON CONFLICT(session_id, namespace, key) DO UPDATE SET value = excluded.value, updated = excluded.updated",
            rows,
        )

    async def asave(self, session_id: str, namespace: str, items: dict[str, Any]) -> None:
        await asyncio.to_thread(self.save, session_id, namespace, items)


class SessionManager:
    def __init__(self, db: Database, max_runtime: int = 512):
        self.db = db
        self.by_cookie: dict[str, Session] = {}
        self.by_ip: dict[str, Session] = {}
        self.by_id: "OrderedDict[str, Session]" = OrderedDict()
        self.max_runtime = max_runtime
        self._restore_recent()

    def _restore_recent(self) -> None:
        cutoff = time.time() - SESSION_IDLE_SECONDS
        for r in self.db.query("SELECT * FROM sessions WHERE last_seen > ?", (cutoff,)):
            s = Session(id=r["id"], ip=r["ip"], first_seen=r["first_seen"], last_seen=r["last_seen"],
                        ips=set(json.loads(r["ips"] or "[]")), protocols=set((r["protocol"] or "").split(",")) - {""},
                        cookie=r["cookie"], user_agent=r["user_agent"], ja3=r["ja3"], ja4=r["ja4"],
                        req_count=r["req_count"] or 0, web_user=r["authenticated"], dirty=False)
            self._index(s)

    def _index(self, s: Session) -> None:
        self.by_id[s.id] = s
        self.by_id.move_to_end(s.id)
        self.by_ip[s.ip] = s
        if s.cookie:
            self.by_cookie[s.cookie] = s
        while len(self.by_id) > self.max_runtime:
            old_id, old = self.by_id.popitem(last=False)
            if self.by_ip.get(old.ip) is old:
                del self.by_ip[old.ip]
            if old.cookie and self.by_cookie.get(old.cookie) is old:
                del self.by_cookie[old.cookie]

    def get(self, session_id: str) -> Session | None:
        return self.by_id.get(session_id)

    def resolve(self, ip: str, protocol: str, cookie: str | None = None, user_agent: str | None = None,
                ja3: str | None = None, ja4: str | None = None) -> tuple[Session, bool]:
        """Return (session, is_new)."""
        now = time.time()
        s = None
        if cookie:
            s = self.by_cookie.get(cookie)
            if s is None:
                row = self.db.one("SELECT id FROM sessions WHERE cookie = ?", (cookie,))
                if row:
                    s = self._load(row["id"])
        if s is None:
            cand = self.by_ip.get(ip)
            if cand and now - cand.last_seen < SESSION_IDLE_SECONDS:
                s = cand
        is_new = s is None
        if s is None:
            s = Session(id=secrets.token_hex(8), ip=ip, first_seen=now, last_seen=now)
        s.last_seen = now
        s.ips.add(ip)
        s.ip = ip
        s.protocols.add(protocol)
        if user_agent:
            s.user_agent = user_agent
        if ja3:
            s.ja3 = ja3
        if ja4:
            s.ja4 = ja4
        s.dirty = True
        self._index(s)
        return s, is_new

    def bind_cookie(self, s: Session, cookie: str) -> None:
        s.cookie = cookie
        s.dirty = True
        self.by_cookie[cookie] = s

    def _load(self, sid: str) -> Session | None:
        r = self.db.one("SELECT * FROM sessions WHERE id = ?", (sid,))
        if not r:
            return None
        return Session(id=r["id"], ip=r["ip"], first_seen=r["first_seen"], last_seen=r["last_seen"],
                       ips=set(json.loads(r["ips"] or "[]")), protocols=set((r["protocol"] or "").split(",")) - {""},
                       cookie=r["cookie"], user_agent=r["user_agent"], ja3=r["ja3"], ja4=r["ja4"],
                       req_count=r["req_count"] or 0, web_user=r["authenticated"], dirty=False)
