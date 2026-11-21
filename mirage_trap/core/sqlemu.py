"""MySQL emulator backed by a sandboxed, per-session, in-memory SQLite database.

Attacker SQL never reaches a real database. It is translated from the MySQL dialect
and executed against an in-memory SQLite that only contains the world's fictitious
data, with an authorizer that blocks ATTACH/PRAGMA/SQLite-specific functions and a
progress handler that aborts runaway queries. SQLite errors are rewritten into the
exact MySQL error format, so UNION, boolean, error-based and time-based injection
behave like they would against a real MySQL server.
"""

from __future__ import annotations

import base64
import hashlib
import math
import random
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from mirage_trap.core.world import World

MYSQL_VERSION = "8.0.35-0ubuntu0.20.04.1"
MAX_SLEEP = 30.0
MAX_VM_STEPS = 400   # progress handler is called every 10k VM ops -> ~4M ops


class MySQLError(Exception):
    def __init__(self, code: int, state: str, message: str):
        super().__init__(message)
        self.code, self.state, self.message = code, state, message

    def cli(self) -> str:
        return f"ERROR {self.code} ({self.state}): {self.message}"


@dataclass
class SqlResult:
    columns: list[str] = field(default_factory=list)
    rows: list[tuple] = field(default_factory=list)
    affected: int = 0
    is_select: bool = False
    error: MySQLError | None = None
    sleep: float = 0.0
    modified: bool = False
    insert_id: int = 0


def _syntax(rest: str) -> MySQLError:
    return MySQLError(1064, "42000", "You have an error in your SQL syntax; check the manual that corresponds to "
                                     f"your MySQL server version for the right syntax to use near '{rest[:80]}' at line 1")


# ---------------------------------------------------------------------------
# Dialect translation
# ---------------------------------------------------------------------------

@dataclass
class Translated:
    statements: list[tuple[str, str]]     # (sqlite_sql, original_mysql_sql)
    unterminated_at: int | None = None


SYSVARS = {
    "version": f"'{MYSQL_VERSION}'", "version_comment": "'(Ubuntu)'", "version_compile_os": "'Linux'",
    "version_compile_machine": "'x86_64'", "datadir": "'/var/lib/mysql/'", "basedir": "'/usr/'",
    "port": "3306", "secure_file_priv": "'/var/lib/mysql-files/'", "max_allowed_packet": "67108864",
    "sql_mode": "'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'",
    "character_set_server": "'utf8mb4'", "collation_server": "'utf8mb4_0900_ai_ci'", "autocommit": "1",
    "tx_isolation": "'REPEATABLE-READ'", "transaction_isolation": "'REPEATABLE-READ'", "have_ssl": "'YES'",
    "server_id": "1", "log_bin": "1", "time_zone": "'SYSTEM'", "system_time_zone": "'UTC'",
}


def _sql_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def translate(sql: str, hostname: str, db_name: str) -> Translated:
    """Tokenize MySQL, rewrite into SQLite, split statements."""
    out: list[str] = []
    stmts: list[tuple[str, str]] = []
    i, n = 0, len(sql)
    stmt_start = 0
    unterminated = None

    def flush(end: int) -> None:
        nonlocal stmt_start
        text = "".join(out).strip()
        orig = sql[stmt_start:end].strip()
        if text:
            stmts.append((text, orig))
        out.clear()
        stmt_start = end + 1

    while i < n:
        c = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        # comments ---------------------------------------------------------
        if c == "#" or (c == "-" and nxt == "-" and (i + 2 >= n or sql[i + 2] in " \t\r\n")):
            j = sql.find("\n", i)
            i = n if j == -1 else j
            out.append(" ")
            continue
        if c == "/" and nxt == "*":
            if i + 2 < n and sql[i + 2] == "!":     # versioned comment: content is executed
                j = i + 3
                while j < n and sql[j].isdigit():
                    j += 1
                end = sql.find("*/", j)
                inner = sql[j:] if end == -1 else sql[j:end]
                sql = sql[:i] + " " + inner + " " + ("" if end == -1 else sql[end + 2:])
                n = len(sql)
                continue
            end = sql.find("*/", i + 2)
            if end == -1:
                unterminated = unterminated if unterminated is not None else i
                break
            i = end + 2
            out.append(" ")
            continue
        # strings -----------------------------------------------------------
        if c in ("'", '"'):
            j, buf, closed = i + 1, [], False
            while j < n:
                ch = sql[j]
                if ch == "\\" and j + 1 < n:
                    esc = sql[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0", "Z": "\x1a"}.get(esc, esc))
                    j += 2
                    continue
                if ch == c:
                    if j + 1 < n and sql[j + 1] == c:
                        buf.append(c)
                        j += 2
                        continue
                    closed = True
                    break
                buf.append(ch)
                j += 1
            if not closed:
                unterminated = i
                out.append(sql[i:])    # let sqlite choke; we report MySQL style
                i = n
                break
            out.append(_sql_quote("".join(buf)))
            i = j + 1
            continue
        if c == "`":
            j = sql.find("`", i + 1)
            if j == -1:
                unterminated = i
                out.append(sql[i:])
                i = n
                break
            out.append('"' + sql[i + 1:j].replace('"', '""') + '"')
            i = j + 1
            continue
        # hex literals 0x.. ------------------------------------------------------
        if c == "0" and nxt in "xX" and (i == 0 or not (sql[i - 1].isalnum() or sql[i - 1] == "_")):
            m = re.match(r"0[xX]([0-9a-fA-F]+)", sql[i:])
            if m:
                hexs = m.group(1)
                if len(hexs) % 2:
                    hexs = "0" + hexs
                raw = bytes.fromhex(hexs)
                try:
                    txt = raw.decode("utf-8")
                    out.append(_sql_quote(txt) if txt.isprintable() else f"X'{hexs}'")
                except UnicodeDecodeError:
                    out.append(f"X'{hexs}'")
                i += len(m.group(0))
                continue
        # system variables -----------------------------------------------------
        if c == "@" and nxt == "@":
            m = re.match(r"@@(?:global\.|session\.)?([A-Za-z_]+)", sql[i:])
            if m:
                var = m.group(1).lower()
                out.append(f"'{hostname}'" if var == "hostname" else SYSVARS.get(var, "NULL"))
                i += len(m.group(0))
                continue
        # operators ------------------------------------------------------------
        if c == "|" and nxt == "|":
            out.append(" OR ")
            i += 2
            continue
        if c == "&" and nxt == "&":
            out.append(" AND ")
            i += 2
            continue
        if c == ";":
            flush(i)
            i += 1
            continue
        out.append(c)
        i += 1
    if out:
        flush(n)
    # word-level rewrites, applied outside strings is guaranteed because strings were
    # normalized to '...' and those patterns cannot appear inside them meaningfully.
    rewritten = []
    for s, orig in stmts:
        s = re.sub(rf"(?i)\b{re.escape(db_name)}\s*\.", "main.", s)
        s = re.sub(r"(?i)\bSEPARATOR\s+", ", ", s)
        s = re.sub(r"(?i)\bLIMIT\s+(\d+)\s*,\s*(\d+)", r"LIMIT \2 OFFSET \1", s)
        s = re.sub(r"(?i)\bDIV\b", "/", s)
        s = re.sub(r"(?i)\bRLIKE\b", "REGEXP", s)
        rewritten.append((s, orig))
    return Translated(rewritten, unterminated)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

ALLOWED_FUNCS = {
    # sqlite built-ins that MySQL also has
    "abs", "coalesce", "count", "sum", "avg", "min", "max", "group_concat", "ifnull", "length", "lower",
    "upper", "ltrim", "rtrim", "trim", "replace", "round", "substr", "nullif", "instr", "like", "char",
    "date", "time", "datetime", "strftime", "quote",
    # our MySQL shims
    "version", "database", "schema", "user", "current_user", "session_user", "system_user", "connection_id",
    "sleep", "benchmark", "concat", "concat_ws", "mid", "substring", "ascii", "ord", "hex", "unhex", "if",
    "isnull", "floor", "ceil", "ceiling", "rand", "pow", "power", "now", "curdate", "sysdate", "md5", "sha1",
    "sha2", "lcase", "ucase", "load_file", "extractvalue", "updatexml", "regexp", "left", "right", "reverse",
    "lpad", "rpad", "repeat", "space", "locate", "position", "strcmp", "bin", "conv", "cast", "convert",
    "last_insert_id", "found_rows", "row_count", "uuid", "mod", "sign", "sqrt", "greatest", "least",
    "char_length", "character_length", "elt", "field", "make_set", "export_set", "json_extract", "exp", "ln",
    "log", "to_base64", "from_base64", "date_format", "unix_timestamp", "from_unixtime", "get_lock",
    "release_lock", "iif", "upper", "count",
}


class SqlEngine:
    """One instance per session. Holds an in-memory SQLite connection."""

    def __init__(self, world: World, base_image: bytes | None = None):
        self.world = world
        sec = world.data["secrets"]
        self.db_name = sec["db_name"]
        self.db_user = sec["db_user"]
        self.client_host = world.data["host"]["ip"]
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        if base_image:
            self.conn.deserialize(base_image)
        else:
            populate_base(self.conn, world)
        self.conn.execute("ATTACH ':memory:' AS information_schema")
        self.conn.execute("ATTACH ':memory:' AS mysql")
        self._mysql_schema()
        self._register_functions()
        self._sleep = 0.0
        self._pending: MySQLError | None = None
        self._steps = 0
        self._guard = False
        self.conn.set_authorizer(self._authorize)
        self.conn.set_progress_handler(self._progress, 10_000)
        self.last_insert_id = 0
        self.conn_id = random.Random(self.db_name).randint(1200, 98000)

    # -- sandbox ---------------------------------------------------------------
    def _authorize(self, action, arg1, arg2, dbname, source):
        if not self._guard:
            return sqlite3.SQLITE_OK
        if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA):
            self._pending = _syntax("")
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_READ and arg1 and arg1.lower().startswith("sqlite_"):
            self._pending = MySQLError(1146, "42S02", f"Table '{self.db_name}.{arg1}' doesn't exist")
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and arg2 and arg2.lower() not in ALLOWED_FUNCS:
            self._pending = MySQLError(1305, "42000", f"FUNCTION {self.db_name}.{arg2} does not exist")
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def _progress(self):
        self._steps += 1
        if self._steps > MAX_VM_STEPS:
            self._pending = MySQLError(3024, "HY000", "Query execution was interrupted, maximum statement "
                                                      "execution time exceeded")
            return 1
        return 0

    def _mysql_schema(self) -> None:
        c = self.conn
        c.execute("CREATE TABLE mysql.user (Host TEXT, User TEXT, authentication_string TEXT, plugin TEXT, "
                  "Super_priv TEXT, File_priv TEXT)")
        rng = random.Random(self.world.data["seed"])
        for host, user in [("localhost", "root"), ("%", self.db_user), ("localhost", "mysql.sys"),
                           ("localhost", "debian-sys-maint"), ("10.%", "backup")]:
            auth = "*" + "".join(rng.choice("0123456789ABCDEF") for _ in range(40))
            c.execute("INSERT INTO mysql.user VALUES (?,?,?,?,?,?)",
                      (host, user, auth, "mysql_native_password", "Y" if user == "root" else "N",
                       "Y" if user == "root" else "N"))

    def _refresh_information_schema(self) -> None:
        c = self.conn
        guard, self._guard = self._guard, False
        try:
            for t in ("SCHEMATA", "TABLES", "COLUMNS"):
                c.execute(f"DROP TABLE IF EXISTS information_schema.{t}")
            c.execute("CREATE TABLE information_schema.SCHEMATA (CATALOG_NAME TEXT, SCHEMA_NAME TEXT, "
                      "DEFAULT_CHARACTER_SET_NAME TEXT, DEFAULT_COLLATION_NAME TEXT, SQL_PATH TEXT)")
            c.execute("CREATE TABLE information_schema.TABLES (TABLE_CATALOG TEXT, TABLE_SCHEMA TEXT, TABLE_NAME TEXT, "
                      "TABLE_TYPE TEXT, ENGINE TEXT, VERSION INT, ROW_FORMAT TEXT, TABLE_ROWS INT, "
                      "AUTO_INCREMENT INT, CREATE_TIME TEXT, TABLE_COLLATION TEXT, TABLE_COMMENT TEXT)")
            c.execute("CREATE TABLE information_schema.COLUMNS (TABLE_CATALOG TEXT, TABLE_SCHEMA TEXT, TABLE_NAME TEXT, "
                      "COLUMN_NAME TEXT, ORDINAL_POSITION INT, COLUMN_DEFAULT TEXT, IS_NULLABLE TEXT, DATA_TYPE TEXT, "
                      "CHARACTER_MAXIMUM_LENGTH INT, COLUMN_TYPE TEXT, COLUMN_KEY TEXT, EXTRA TEXT, COLUMN_COMMENT TEXT)")
            for s in ("information_schema", "mysql", "performance_schema", "sys", self.db_name):
                c.execute("INSERT INTO information_schema.SCHEMATA VALUES ('def',?,'utf8mb4','utf8mb4_0900_ai_ci',NULL)", (s,))
            created = datetime.fromtimestamp(self.world.data["host"]["installed"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            for (name,) in c.execute("SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
                rows = c.execute(f'SELECT COUNT(*) FROM main."{name}"').fetchone()[0]
                c.execute("INSERT INTO information_schema.TABLES VALUES ('def',?,?,'BASE TABLE','InnoDB',10,'Dynamic',?,?,?,"
                          "'utf8mb4_0900_ai_ci','')", (self.db_name, name, rows, rows + 1, created))
                for cid, col, ctype, notnull, dflt, pk in c.execute(f'PRAGMA main.table_info("{name}")').fetchall():
                    dtype, ctype_full, maxlen = _mysql_type(ctype, col)
                    c.execute("INSERT INTO information_schema.COLUMNS VALUES ('def',?,?,?,?,?,?,?,?,?,?,?,'')",
                              (self.db_name, name, col, cid + 1, dflt, "NO" if notnull or pk else "YES", dtype, maxlen,
                               ctype_full, "PRI" if pk else "", "auto_increment" if pk and dtype == "int" else ""))
            for tbl, cols in (("user", ["Host", "User", "authentication_string", "plugin", "Super_priv", "File_priv"]),):
                c.execute("INSERT INTO information_schema.TABLES VALUES ('def','mysql',?,'BASE TABLE','InnoDB',10,"
                          "'Dynamic',5,NULL,?,'utf8mb3_bin','Users and global privileges')", (tbl, created))
                for i, col in enumerate(cols):
                    c.execute("INSERT INTO information_schema.COLUMNS VALUES ('def','mysql',?,?,?,NULL,'NO','char',255,"
                              "'char(255)','','','')", (tbl, col, i + 1))
        finally:
            self._guard = guard

    def _register_functions(self) -> None:
        c = self.conn
        eng = self

        def sleep(x):
            try:
                v = float(x)
            except (TypeError, ValueError):
                v = 0.0
            eng._sleep = min(MAX_SLEEP, eng._sleep + max(0.0, v))
            return 0

        def benchmark(count, _expr):
            try:
                eng._sleep = min(MAX_SLEEP, eng._sleep + int(count) * 2.5e-7)
            except (TypeError, ValueError):
                pass
            return 0

        def to_s(v):
            if v is None:
                return None
            if isinstance(v, bytes):
                return v.decode("utf-8", "replace")
            if isinstance(v, float) and v.is_integer() and abs(v) < 1e15:
                return str(v)
            return str(v)

        def concat(*args):
            if any(a is None for a in args):
                return None
            return "".join(to_s(a) for a in args)

        def concat_ws(sep, *args):
            if sep is None:
                return None
            return to_s(sep).join(to_s(a) for a in args if a is not None)

        def substring(s, pos, length=None):
            s = to_s(s)
            if s is None or pos is None:
                return None
            pos = int(pos)
            if pos == 0:
                return ""
            start = pos - 1 if pos > 0 else len(s) + pos
            if start < 0:
                return ""
            if length is None:
                return s[start:]
            return s[start:start + max(0, int(length))]

        def xpath_error(_xml, path, *_):
            text = to_s(path) or ""
            if re.fullmatch(r"[/A-Za-z0-9_@\[\]=.*'\" -]*", text) and not text.startswith(("~", ":", "!")):
                return None
            eng._pending = MySQLError(1105, "HY000", f"XPATH syntax error: '{text[1 if text[:1] in '~:!' else 0:][:32]}'")
            raise ValueError("xpath")

        def mysql_hex(v):
            if v is None:
                return None
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                return format(int(v), "X")
            b = v if isinstance(v, bytes) else str(v).encode()
            return b.hex().upper()

        def unhex(v):
            try:
                return bytes.fromhex(to_s(v)).decode("utf-8", "replace")
            except (ValueError, TypeError):
                return None

        def regexp(pattern, value):
            if pattern is None or value is None:
                return None
            try:
                return 1 if re.search(to_s(pattern), to_s(value), re.I) else 0
            except re.error:
                return 0

        now = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        funcs = {
            ("version", 0): lambda: MYSQL_VERSION,
            ("database", 0): lambda: eng.db_name,
            ("schema", 0): lambda: eng.db_name,
            ("user", 0): lambda: f"{eng.db_user}@{eng.client_host}",
            ("current_user", 0): lambda: f"{eng.db_user}@%",
            ("session_user", 0): lambda: f"{eng.db_user}@{eng.client_host}",
            ("system_user", 0): lambda: f"{eng.db_user}@{eng.client_host}",
            ("connection_id", 0): lambda: eng.conn_id,
            ("last_insert_id", 0): lambda: eng.last_insert_id,
            ("found_rows", 0): lambda: 0,
            ("row_count", 0): lambda: -1,
            ("sleep", 1): sleep,
            ("benchmark", 2): benchmark,
            ("concat", -1): concat,
            ("concat_ws", -1): concat_ws,
            ("mid", 2): substring, ("mid", 3): substring,
            ("substring", 2): substring, ("substring", 3): substring,
            ("ascii", 1): lambda s: (ord(to_s(s)[0]) if to_s(s) else 0) if s is not None else None,
            ("ord", 1): lambda s: (ord(to_s(s)[0]) if to_s(s) else 0) if s is not None else None,
            ("hex", 1): mysql_hex,
            ("unhex", 1): unhex,
            ("if", 3): lambda c_, a, b: a if c_ not in (None, 0, "0", "", 0.0) else b,
            ("isnull", 1): lambda v: 1 if v is None else 0,
            ("floor", 1): lambda v: None if v is None else math.floor(float(v)),
            ("ceil", 1): lambda v: None if v is None else math.ceil(float(v)),
            ("ceiling", 1): lambda v: None if v is None else math.ceil(float(v)),
            ("rand", 0): lambda: random.random(),
            ("rand", 1): lambda s: random.Random(s).random(),
            ("pow", 2): lambda a, b: None if a is None or b is None else float(a) ** float(b),
            ("power", 2): lambda a, b: None if a is None or b is None else float(a) ** float(b),
            ("sqrt", 1): lambda v: None if v is None or float(v) < 0 else math.sqrt(float(v)),
            ("mod", 2): lambda a, b: None if a is None or not b else float(a) % float(b),
            ("now", 0): now, ("sysdate", 0): now,
            ("curdate", 0): lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            ("unix_timestamp", 0): lambda: int(time.time()),
            ("md5", 1): lambda v: None if v is None else hashlib.md5(to_s(v).encode()).hexdigest(),
            ("sha1", 1): lambda v: None if v is None else hashlib.sha1(to_s(v).encode()).hexdigest(),
            ("sha2", 2): lambda v, b: None if v is None else hashlib.sha256(to_s(v).encode()).hexdigest(),
            ("lcase", 1): lambda v: None if v is None else to_s(v).lower(),
            ("ucase", 1): lambda v: None if v is None else to_s(v).upper(),
            ("load_file", 1): lambda v: None,          # secure_file_priv blocks it on MySQL 8
            ("extractvalue", 2): xpath_error,
            ("updatexml", 3): xpath_error,
            ("regexp", 2): regexp,
            ("left", 2): lambda s, k: None if s is None else to_s(s)[: max(0, int(k))],
            ("right", 2): lambda s, k: None if s is None else (to_s(s)[-int(k):] if int(k) > 0 else ""),
            ("reverse", 1): lambda s: None if s is None else to_s(s)[::-1],
            ("repeat", 2): lambda s, k: None if s is None else to_s(s) * min(int(k), 10000),
            ("space", 1): lambda k: " " * min(int(k), 10000),
            ("locate", 2): lambda sub, s: 0 if s is None else to_s(s).find(to_s(sub)) + 1,
            ("strcmp", 2): lambda a, b: (to_s(a) > to_s(b)) - (to_s(a) < to_s(b)),
            ("bin", 1): lambda v: None if v is None else format(int(v), "b"),
            ("char_length", 1): lambda s: None if s is None else len(to_s(s)),
            ("character_length", 1): lambda s: None if s is None else len(to_s(s)),
            ("greatest", -1): lambda *a: None if any(x is None for x in a) else max(a),
            ("least", -1): lambda *a: None if any(x is None for x in a) else min(a),
            ("elt", -1): lambda k, *a: a[int(k) - 1] if k and 0 < int(k) <= len(a) else None,
            ("uuid", 0): lambda: "%08x-%04x-11ee-%04x-%012x" % (random.getrandbits(32), random.getrandbits(16),
                                                                   random.getrandbits(16), random.getrandbits(48)),
            ("lpad", 3): lambda s, k, p: None if s is None else (to_s(p) * int(k) + to_s(s))[-int(k):] if int(k) > len(to_s(s)) else to_s(s)[: int(k)],
            ("rpad", 3): lambda s, k, p: None if s is None else (to_s(s) + to_s(p) * int(k))[: int(k)],
            ("to_base64", 1): lambda v: None if v is None else base64.b64encode(to_s(v).encode()).decode(),
            ("get_lock", 2): lambda *_: 1,
            ("release_lock", 1): lambda *_: 1,
        }
        for (name, nargs), fn in funcs.items():
            c.create_function(name, nargs, fn)

    # -- execution -------------------------------------------------------------
    def execute(self, sql: str, multi: bool = False) -> list[SqlResult]:
        """Run one (or, when ``multi``, several) MySQL statements. Never raises."""
        tr = translate(sql, self.world.hostname, self.db_name)
        if tr.unterminated_at is not None:
            return [SqlResult(error=_syntax(sql[tr.unterminated_at:]))]
        if not tr.statements:
            return [SqlResult(error=MySQLError(1065, "42000", "Query was empty"))]
        if len(tr.statements) > 1 and not multi:
            first_end = sql.find(";")
            return [SqlResult(error=_syntax(sql[first_end + 1:].lstrip()))]
        results = []
        for s, orig in tr.statements:
            r = self._run_one(s, orig)
            results.append(r)
            if r.error:
                break
        return results

    def _run_one(self, s: str, orig: str) -> SqlResult:
        self._sleep, self._pending, self._steps = 0.0, None, 0
        head = s.lstrip().split(None, 1)[0].lower() if s.strip() else ""
        special = self._special(s, head)
        if special is not None:
            return special
        if head in ("drop",) and re.match(r"(?i)\s*drop\s+(database|schema)", s):
            return SqlResult(error=MySQLError(1044, "42000", f"Access denied for user '{self.db_user}'@'%' to database "
                                                             f"'{re.split(r'\s+', s.strip())[-1].strip(chr(34))}'"))
        if re.search(r"(?i)\binto\s+(out|dump)file\b", s):
            return SqlResult(error=MySQLError(1290, "HY000", "The MySQL server is running with the --secure-file-priv "
                                                             "option so it cannot execute this statement"))
        if head in ("grant", "revoke", "create") and re.match(r"(?i)\s*(grant|revoke|create\s+user)", s):
            return SqlResult(error=MySQLError(1227, "42000", "Access denied; you need (at least one of) the CREATE USER "
                                                             "privilege(s) for this operation"))
        if "information_schema" in s.lower():
            self._refresh_information_schema()
        self._guard = True
        try:
            cur = self.conn.execute(s)
            rows = cur.fetchall() if cur.description else []
            cols = [d[0] for d in cur.description] if cur.description else []
            res = SqlResult(columns=cols, rows=rows, is_select=bool(cur.description), sleep=self._sleep)
            if head in ("insert", "update", "delete", "replace", "create", "drop", "alter"):
                res.affected = max(cur.rowcount, 0)
                res.modified = True
                if head in ("insert", "replace"):
                    self.last_insert_id = cur.lastrowid or 0
                    res.insert_id = self.last_insert_id
            return res
        except sqlite3.Error as exc:
            return SqlResult(error=self._map_error(exc, s, orig), sleep=self._sleep)
        except (ValueError, OverflowError, TypeError):
            return SqlResult(error=self._pending or _syntax(orig[:80]), sleep=self._sleep)
        finally:
            self._guard = False

    def _special(self, s: str, head: str) -> SqlResult | None:
        st = s.strip().rstrip(";")
        low = st.lower()
        if head == "show":
            if re.fullmatch(r"show\s+(full\s+)?tables(\s+from\s+\S+)?", low):
                names = [r[0] for r in self.conn.execute(
                    "SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
                return SqlResult([f"Tables_in_{self.db_name}"], [(n,) for n in names], is_select=True)
            if re.fullmatch(r"show\s+(databases|schemas)", low):
                return SqlResult(["Database"], [("information_schema",), (self.db_name,), ("mysql",),
                                                ("performance_schema",), ("sys",)], is_select=True)
            m = re.fullmatch(r"show\s+(?:full\s+)?columns\s+from\s+\"?(\w+)\"?", st, re.I)
            if m:
                return self._describe(m.group(1))
            if re.fullmatch(r"show\s+grants.*", low):
                return SqlResult([f"Grants for {self.db_user}@%"], [
                    (f"GRANT USAGE ON *.* TO `{self.db_user}`@`%`",),
                    (f"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER ON `{self.db_name}`.* TO `{self.db_user}`@`%`",)],
                    is_select=True)
            if re.fullmatch(r"show\s+(global\s+|session\s+)?variables.*", low):
                return SqlResult(["Variable_name", "Value"], [(k, v.strip("'")) for k, v in SYSVARS.items()],
                                 is_select=True)
            if re.fullmatch(r"show\s+(full\s+)?processlist", low):
                return SqlResult(["Id", "User", "Host", "db", "Command", "Time", "State", "Info"], [
                    (self.conn_id, self.db_user, f"{self.client_host}:51234", self.db_name, "Query", 0, "init",
                     "SHOW PROCESSLIST")], is_select=True)
            return SqlResult(error=_syntax(st[5:].strip()))
        m = re.fullmatch(r"(?:describe|desc|explain)\s+\"?(\w+)\"?", st, re.I)
        if m:
            return self._describe(m.group(1))
        if head == "use":
            target = st.split(None, 1)[1].strip('"') if len(st.split()) > 1 else ""
            if target.lower() in (self.db_name.lower(), "information_schema", "mysql"):
                return SqlResult()
            return SqlResult(error=MySQLError(1044, "42000", f"Access denied for user '{self.db_user}'@'%' to database '{target}'"))
        if head in ("set", "begin", "commit", "rollback", "start", "flush", "lock", "unlock"):
            return SqlResult()
        return None

    def _describe(self, table: str) -> SqlResult:
        info = self.conn.execute(f'PRAGMA main.table_info("{table}")').fetchall()
        if not info:
            return SqlResult(error=MySQLError(1146, "42S02", f"Table '{self.db_name}.{table}' doesn't exist"))
        rows = []
        for cid, col, ctype, notnull, dflt, pk in info:
            _, full, _ = _mysql_type(ctype, col)
            rows.append((col, full, "NO" if notnull or pk else "YES", "PRI" if pk else "", dflt,
                         "auto_increment" if pk and full.startswith("int") else ""))
        return SqlResult(["Field", "Type", "Null", "Key", "Default", "Extra"], rows, is_select=True)

    def _map_error(self, exc: sqlite3.Error, s: str, orig: str) -> MySQLError:
        if self._pending:
            return self._pending
        msg = str(exc)
        m = re.match(r'near "(.*)": syntax error', msg, re.S)
        if m:
            tok = m.group(1)
            pos = _find_token(orig, tok)
            return _syntax(orig[pos:] if pos >= 0 else tok)
        if "incomplete input" in msg:
            return _syntax("")
        m = re.match(r"unrecognized token: \"(.*)\"", msg, re.S)
        if m:
            pos = orig.find(m.group(1))
            return _syntax(orig[pos:] if pos >= 0 else m.group(1))
        m = re.match(r"no such table: (?:\w+\.)?(\S+)", msg)
        if m:
            return MySQLError(1146, "42S02", f"Table '{self.db_name}.{m.group(1)}' doesn't exist")
        m = re.match(r"no such column: (\S+)", msg)
        if m:
            clause = "where clause" if re.search(r"(?i)\bwhere\b.*" + re.escape(m.group(1).split(".")[-1]), s) else "field list"
            return MySQLError(1054, "42S22", f"Unknown column '{m.group(1)}' in '{clause}'")
        m = re.match(r"no such function: (\S+)", msg)
        if m:
            return MySQLError(1305, "42000", f"FUNCTION {self.db_name}.{m.group(1)} does not exist")
        m = re.match(r"wrong number of arguments to function (\w+)", msg)
        if m:
            return MySQLError(1582, "42000", f"Incorrect parameter count in the call to native function '{m.group(1).upper()}'")
        if "do not have the same number of result columns" in msg:
            return MySQLError(1222, "21000", "The used SELECT statements have a different number of columns")
        m = re.search(r"(\d+)\w* ORDER BY term out of range", msg)
        if m:
            num = re.search(r"(?i)order\s+by\s+.*?(\d+)", s)
            return MySQLError(1054, "42S22", f"Unknown column '{num.group(1) if num else m.group(1)}' in 'order clause'")
        m = re.search(r"GROUP BY term out of range", msg)
        if m:
            num = re.search(r"(?i)group\s+by\s+.*?(\d+)", s)
            return MySQLError(1054, "42S22", f"Unknown column '{num.group(1) if num else '?'}' in 'group statement'")
        m = re.match(r"UNIQUE constraint failed: (\w+)\.(\w+)", msg)
        if m:
            return MySQLError(1062, "23000", f"Duplicate entry for key '{m.group(1)}.{m.group(2)}'")
        m = re.match(r"table (\S+) already exists", msg)
        if m:
            return MySQLError(1050, "42S01", f"Table '{m.group(1)}' already exists")
        if "not authorized" in msg:
            return _syntax(orig[:80])
        if "interrupted" in msg:
            return MySQLError(3024, "HY000", "Query execution was interrupted, maximum statement execution time exceeded")
        if "user-defined function raised exception" in msg:
            return _syntax(orig[:80])
        return _syntax(orig[:80])

    def image(self) -> bytes:
        # MySQL runs with autocommit=1, but Python's sqlite3 keeps DML in an implicit
        # transaction, and serialize() only sees committed pages.
        if self.conn.in_transaction:
            self.conn.commit()
        return self.conn.serialize()

    def close(self) -> None:
        self.conn.close()


def _find_token(sql: str, tok: str) -> int:
    if not tok:
        return -1
    m = re.search(r"(?i)(?<![\w])" + re.escape(tok), sql)
    return m.start() if m else sql.lower().find(tok.lower())


def _mysql_type(sqlite_type: str, col: str) -> tuple[str, str, int | None]:
    t = (sqlite_type or "").upper()
    if t.startswith("INT"):
        return "int", "int", None
    if t.startswith(("REAL", "DECIMAL", "NUMERIC")):
        return "decimal", "decimal(10,2)", None
    if t.startswith("DATETIME"):
        return "datetime", "datetime", None
    if t.startswith("TINYINT"):
        return "tinyint", "tinyint(1)", None
    if t.startswith("TEXT"):
        return "text", "text", 65535
    m = re.match(r"VARCHAR\((\d+)\)", t)
    if m:
        return "varchar", f"varchar({m.group(1)})", int(m.group(1))
    return "varchar", "varchar(255)", 255


def _dt(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def populate_base(conn: sqlite3.Connection, world: World) -> None:
    d = world.data
    node = world.profile == "node-express-api"
    c = conn
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(64) NOT NULL UNIQUE, "
              "email VARCHAR(128) NOT NULL, password VARCHAR(255) NOT NULL, first_name VARCHAR(64), "
              "last_name VARCHAR(64), role VARCHAR(16) DEFAULT 'user', department VARCHAR(64), phone VARCHAR(32), "
              "active TINYINT DEFAULT 1, created_at DATETIME, last_login DATETIME)")
    for e in d["employees"]:
        c.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                  (e["id"], e["username"], e["email"], e["bcrypt"] if node else e["md5"], e["first"], e["last"],
                   e["role"], e["department"], e["phone"], e["active"], _dt(e["created_at"]), _dt(e["last_login"])))
    c.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, sku VARCHAR(32), name VARCHAR(128), "
              "price DECIMAL(10,2), stock INT, description TEXT)")
    for p in d["products"]:
        c.execute("INSERT INTO products VALUES (?,?,?,?,?,?)",
                  (p["id"], p["sku"], p["name"], p["price"], p["stock"], p["description"]))
    c.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name VARCHAR(128), email VARCHAR(128), "
              "phone VARCHAR(32), city VARCHAR(64), card_last4 VARCHAR(4), created_at DATETIME)")
    for cu in d["customers"]:
        c.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?)",
                  (cu["id"], cu["name"], cu["email"], cu["phone"], cu["city"], cu["card_last4"], _dt(cu["created_at"])))
    c.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INT, product_id INT, qty INT, "
              "total DECIMAL(10,2), status VARCHAR(16), created_at DATETIME)")
    for o in d["orders"]:
        c.execute("INSERT INTO orders VALUES (?,?,?,?,?,?,?)",
                  (o["id"], o["customer_id"], o["product_id"], o["qty"], o["total"], o["status"], _dt(o["created_at"])))
    c.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, name VARCHAR(64), value TEXT)")
    sec = d["secrets"]
    for i, (k, v) in enumerate([("site_name", d["company"]["name"]), ("smtp_host", sec["smtp_host"]),
                                ("smtp_user", sec["smtp_user"]), ("smtp_pass", sec["smtp_password"]),
                                ("maintenance", "0"), ("s3_bucket", sec["aws_bucket"])]):
        c.execute("INSERT INTO settings VALUES (?,?,?)", (i + 1, k, v))
    c.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, user_id INT, action VARCHAR(64), ip VARCHAR(45), "
              "created_at DATETIME)")
    rng = random.Random(d["seed"] + 7)
    for i in range(60):
        e = rng.choice(d["employees"])
        c.execute("INSERT INTO audit_log VALUES (?,?,?,?,?)",
                  (i + 1, e["id"], rng.choice(["login", "logout", "update_order", "export_customers", "password_change"]),
                   f"10.{rng.randint(10, 60)}.{rng.randint(1, 30)}.{rng.randint(2, 250)}",
                   _dt(time.time() - (60 - i) * rng.randint(3000, 9000))))
    conn.commit()


_BASE_IMAGES: dict[int, bytes] = {}


def base_image(world: World) -> bytes:
    key = world.data["seed"]
    if key not in _BASE_IMAGES:
        conn = sqlite3.connect(":memory:")
        populate_base(conn, world)
        _BASE_IMAGES[key] = conn.serialize()
        conn.close()
    return _BASE_IMAGES[key]


def format_table(res: SqlResult) -> str:
    """mysql CLI-style table output."""
    if not res.columns:
        return f"Query OK, {res.affected} row{'s' if res.affected != 1 else ''} affected (0.01 sec)\n"
    cells = [[("NULL" if v is None else _cell(v)) for v in row] for row in res.rows]
    widths = [max([len(c)] + [len(r[i]) for r in cells]) for i, c in enumerate(res.columns)]
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [sep, "| " + " | ".join(c.ljust(w) for c, w in zip(res.columns, widths)) + " |", sep]
    for r in cells:
        lines.append("| " + " | ".join(v.ljust(w) for v, w in zip(r, widths)) + " |")
    lines.append(sep)
    n = len(res.rows)
    if n == 0:
        return "Empty set (0.00 sec)\n"
    return "\n".join(lines) + f"\n{n} row{'s' if n != 1 else ''} in set (0.00 sec)\n"


def _cell(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    if isinstance(v, float):
        return f"{v:.2f}" if not v.is_integer() else str(int(v)) if abs(v) < 1e15 else str(v)
    return str(v)
