"""SQLite storage: schema, migrations and a small thread-safe wrapper.

A single connection guarded by a lock is plenty for a honeypot's write rate. Async
callers go through ``asyncio.to_thread`` so the event loop never blocks on disk.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    protocol        TEXT NOT NULL,
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    ip              TEXT NOT NULL,
    ips             TEXT NOT NULL DEFAULT '[]',
    cookie          TEXT,
    user_agent      TEXT,
    ja3             TEXT,
    ja4             TEXT,
    country         TEXT,
    city            TEXT,
    asn             INTEGER,
    as_org          TEXT,
    kind            TEXT DEFAULT 'unknown',
    kind_confidence REAL DEFAULT 0,
    tool            TEXT,
    sophistication  INTEGER DEFAULT 0,
    req_count       INTEGER DEFAULT 0,
    authenticated   TEXT
);
CREATE INDEX IF NOT EXISTS ix_sessions_last_seen ON sessions(last_seen);
CREATE INDEX IF NOT EXISTS ix_sessions_ip ON sessions(ip);
CREATE INDEX IF NOT EXISTS ix_sessions_cookie ON sessions(cookie);

CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL,
    ts               REAL NOT NULL,
    protocol         TEXT NOT NULL,
    ip               TEXT NOT NULL,
    port             INTEGER,
    kind             TEXT NOT NULL,            -- request | command | auth | download | connect
    method           TEXT,
    path             TEXT,
    query            TEXT,
    headers          TEXT,                     -- JSON list of [name, value], original order/case
    body             TEXT,
    body_len         INTEGER,
    body_sha256      TEXT,
    attack_type      TEXT,
    attack_detail    TEXT,
    persona          TEXT,
    status           INTEGER,
    response         TEXT,
    response_len     INTEGER,
    latency_sim_ms   REAL,
    latency_real_ms  REAL,
    provider         TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_id, id);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS state_kv (
    session_id TEXT NOT NULL,
    namespace  TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      BLOB,
    updated    REAL NOT NULL,
    PRIMARY KEY (session_id, namespace, key)
);

CREATE TABLE IF NOT EXISTS llm_cache (
    key     TEXT PRIMARY KEY,
    scope   TEXT NOT NULL,                     -- 'world' or a session id
    output  TEXT NOT NULL,
    created REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_usage (
    day   TEXT NOT NULL,
    ip    TEXT NOT NULL,
    calls INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, ip)
);

CREATE TABLE IF NOT EXISTS canaries (
    token   TEXT PRIMARY KEY,
    kind    TEXT NOT NULL,
    label   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS canary_hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ts         REAL NOT NULL,
    context    TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts         REAL NOT NULL,
    protocol   TEXT NOT NULL,
    username   TEXT,
    password   TEXT,
    success    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS iocs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts         REAL NOT NULL,
    kind       TEXT NOT NULL,                  -- url | ip | domain | hash
    value      TEXT NOT NULL,
    context    TEXT
);
"""


class Database:
    def __init__(self, path: str | Path, *, readonly: bool = False):
        self.path = Path(path)
        self.readonly = readonly
        if readonly:
            uri = f"file:{self.path.as_posix()}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(SCHEMA)
            self.conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self.conn.commit()
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()

    # -- sync API ---------------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self._lock:
            cur = self.conn.execute(sql, tuple(params))
            self.conn.commit()
            return cur.lastrowid or 0

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self.conn.executemany(sql, [tuple(r) for r in rows])
            self.conn.commit()

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(sql, tuple(params))
            return [dict(r) for r in cur.fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def transaction(self, fn):
        """Run ``fn(conn)`` atomically under the lock."""
        with self._lock:
            try:
                result = fn(self.conn)
                self.conn.commit()
                return result
            except Exception:
                self.conn.rollback()
                raise

    # -- async API --------------------------------------------------------
    async def aexecute(self, sql: str, params: Iterable[Any] = ()) -> int:
        return await asyncio.to_thread(self.execute, sql, params)

    async def aquery(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        return await asyncio.to_thread(self.query, sql, params)

    async def aone(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        return await asyncio.to_thread(self.one, sql, params)

    def meta_get(self, key: str) -> str | None:
        row = self.one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else None

    def meta_set(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def close(self) -> None:
        with self._lock:
            self.conn.close()


def dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
