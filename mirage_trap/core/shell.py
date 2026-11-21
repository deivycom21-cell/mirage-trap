"""Deterministic Linux shell emulator over the virtual filesystem.

Shared by SSH, Telnet and web command injection. Nothing is ever executed: every
command is implemented in Python against the VFS and the world. Commands that
exist on the box (present in the VFS PATH) but are not implemented here are handed
to the LLM (with the shell context); commands that do not exist get the exact
"command not found" message of the shell being emulated.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import posixpath
import random
import re
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

from mirage_trap.core.sqlemu import SqlEngine, format_table
from mirage_trap.core.vfs import FS_ERR_TEXT, FsError, Node, VirtualFS, fmt_mode, node_size
from mirage_trap.core.world import World

PATH_DIRS = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
BUILTINS = {"cd", "pwd", "echo", "export", "unset", "exit", "logout", "history", "type", "alias", "clear",
            "true", "false", "printf", "set", "source", ".", "read", "umask", "jobs", "wait", "kill", "test", "["}


@dataclass
class ShellContext:
    user: str = "www-data"
    cwd: str = "/var/www/html"
    interactive: bool = False      # SSH/Telnet TTY (bash) vs. sh -c from a web app (dash)
    tty: bool = False
    env: dict = field(default_factory=dict)
    history: list = field(default_factory=list)
    last_status: int = 0
    pending: dict | None = None     # multi-step interactions: sudo password, mysql REPL
    mysql: dict | None = None       # active mysql client session
    exited: bool = False

    def to_json(self) -> dict:
        return {"user": self.user, "cwd": self.cwd, "env": self.env, "history": self.history[-500:],
                "last_status": self.last_status}

    @classmethod
    def from_json(cls, d: dict, **kw) -> "ShellContext":
        ctx = cls(**kw)
        ctx.user = d.get("user", ctx.user)
        ctx.cwd = d.get("cwd", ctx.cwd)
        ctx.env.update(d.get("env", {}))
        ctx.history = d.get("history", [])
        ctx.last_status = d.get("last_status", 0)
        return ctx


@dataclass
class Out:
    out: str = ""
    err: str = ""
    code: int = 0


LlmShellFn = Callable[[str, "Shell", str], Awaitable[str | None]]
LlmFileFn = Callable[[str], Awaitable[str | None]]


class Shell:
    def __init__(self, world: World, vfs: VirtualFS, ctx: ShellContext, *,
                 sql: Callable[[], SqlEngine] | None = None,
                 llm_command: LlmShellFn | None = None,
                 llm_file: LlmFileFn | None = None,
                 on_ioc: Callable[[str, str, str], None] | None = None,
                 on_credential: Callable[[str, str, bool], None] | None = None,
                 client_ip: str = "203.0.113.10"):
        self.world = world
        self.vfs = vfs
        self.ctx = ctx
        self.sql_factory = sql
        self.llm_command = llm_command
        self.llm_file = llm_file
        self.on_ioc = on_ioc or (lambda *a: None)
        self.on_credential = on_credential or (lambda *a: None)
        self.client_ip = client_ip
        self.sleep_total = 0.0
        self.sql_modified = False
        if not ctx.env:
            ctx.env.update(self._default_env())

    # -- identity --------------------------------------------------------------
    @property
    def user(self) -> str:
        return self.ctx.user

    @property
    def groups(self) -> tuple[str, ...]:
        groups = [self.user]
        for line in self._read_quiet("/etc/group").splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and self.user in parts[3].split(","):
                groups.append(parts[0])
        return tuple(groups)

    def uid_gid(self, user: str | None = None) -> tuple[int, int, str]:
        user = user or self.user
        for line in self._read_quiet("/etc/passwd").splitlines():
            p = line.split(":")
            if p and p[0] == user:
                return int(p[2]), int(p[3]), p[5]
        return 1000, 1000, f"/home/{user}"

    def home(self) -> str:
        return self.uid_gid()[2]

    def _default_env(self) -> dict:
        home = self.home()
        env = {"PATH": ":".join(PATH_DIRS), "HOME": home, "USER": self.user, "LOGNAME": self.user,
               "SHELL": "/bin/bash" if self.ctx.interactive else "/bin/sh", "LANG": "C.UTF-8",
               "PWD": self.ctx.cwd}
        if self.ctx.interactive:
            env.update({"TERM": "xterm-256color", "SSH_CONNECTION": f"{self.client_ip} 51022 {self.world['host']['ip']} 22",
                        "SSH_CLIENT": f"{self.client_ip} 51022 22", "HISTSIZE": "1000", "SHLVL": "1"})
        return env

    def prompt(self) -> str:
        if self.ctx.pending:
            return ""
        if self.ctx.mysql:
            return "    -> " if self.ctx.mysql.get("buffer") else "mysql> "
        cwd = self.ctx.cwd
        home = self.home()
        if cwd == home:
            cwd = "~"
        elif cwd.startswith(home + "/"):
            cwd = "~" + cwd[len(home):]
        sign = "#" if self.user == "root" else "$"
        if self.ctx.tty:
            color = "\x1b[01;31m" if self.user == "root" else "\x1b[01;32m"
            return f"{color}{self.user}@{self.world.hostname}\x1b[00m:\x1b[01;34m{cwd}\x1b[00m{sign} "
        return f"{self.user}@{self.world.hostname}:{cwd}{sign} "

    # -- error formats ---------------------------------------------------------
    def not_found(self, cmd: str) -> str:
        if self.ctx.interactive:
            return f"{cmd}: command not found\n"
        return f"sh: 1: {cmd}: not found\n"

    def builtin_err(self, builtin: str, msg: str) -> str:
        if self.ctx.interactive:
            return f"-bash: {builtin}: {msg}\n"
        return f"sh: 1: {builtin}: {msg}\n"

    # -- entry point -------------------------------------------------------------
    async def run(self, line: str) -> tuple[str, int]:
        """Run one input line; returns (terminal output, exit status)."""
        if self.ctx.pending:
            return await self._continue_pending(line)
        if self.ctx.mysql is not None:
            return self._mysql_line(line), 0
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return "", self.ctx.last_status
        if self.ctx.interactive:
            self.ctx.history.append(stripped)
        try:
            out, code = await self._run_list(stripped)
        except _ParseError as e:
            out, code = (f"-bash: syntax error near unexpected token `{e}'\n" if self.ctx.interactive
                         else f"sh: 1: Syntax error: \"{e}\" unexpected\n"), 2
        self.ctx.last_status = code
        self.ctx.env["PWD"] = self.ctx.cwd
        return out, code

    # -- parsing -------------------------------------------------------------------
    async def _expand(self, text: str) -> str:
        """Command substitution and variable expansion outside single quotes."""
        out, i, n, in_sq, in_dq = [], 0, len(text), False, False
        while i < n:
            c = text[i]
            if c == "'" and not in_dq:
                in_sq = not in_sq
                out.append(c)
                i += 1
                continue
            if c == '"' and not in_sq:
                in_dq = not in_dq
                out.append(c)
                i += 1
                continue
            if in_sq:
                out.append(c)
                i += 1
                continue
            if c == "\\" and i + 1 < n:
                out.append(text[i:i + 2])
                i += 2
                continue
            if c == "$" and i + 1 < n and text[i + 1] == "(":
                depth, j = 1, i + 2
                while j < n and depth:
                    depth += {"(": 1, ")": -1}.get(text[j], 0)
                    j += 1
                inner = text[i + 2:j - 1]
                sub, _ = await self._run_list(inner, capture=True)
                out.append(sub.rstrip("\n"))
                i = j
                continue
            if c == "`":
                j = text.find("`", i + 1)
                if j == -1:
                    raise _ParseError("`")
                sub, _ = await self._run_list(text[i + 1:j], capture=True)
                out.append(sub.rstrip("\n"))
                i = j + 1
                continue
            if c == "$" and i + 1 < n:
                m = re.match(r"\$(?:\{(\w+)\}|(\w+)|([?$#!0]))", text[i:])
                if m:
                    name = m.group(1) or m.group(2)
                    special = m.group(3)
                    if special == "?":
                        val = str(self.ctx.last_status)
                    elif special == "$":
                        val = str(self._pid())
                    elif special == "0":
                        val = "-bash" if self.ctx.interactive else "sh"
                    elif special:
                        val = "0"
                    else:
                        val = self.ctx.env.get(name, "")
                    out.append(val)
                    i += len(m.group(0))
                    continue
            out.append(c)
            i += 1
        return "".join(out)

    def _tokens(self, text: str) -> list[str]:
        lex = shlex.shlex(text, posix=True, punctuation_chars=";&|<>")
        lex.whitespace_split = True
        lex.commenters = ""
        try:
            return list(lex)
        except ValueError as e:
            raise _ParseError("newline") from e

    @staticmethod
    def _split_list(text: str) -> list[tuple[str, str]]:
        """Split a command line on top-level ``;``, ``&&``, ``||`` and ``&`` (outside
        quotes, backticks and ``$( )``). Expansion happens per segment afterwards, so
        ``false; echo $?`` sees the status of ``false`` like bash does."""
        parts: list[tuple[str, str]] = []
        cur: list[str] = []
        i, n = 0, len(text)
        in_sq = in_dq = in_bt = False
        depth = 0
        while i < n:
            c = text[i]
            if c == "\\" and not in_sq and i + 1 < n:
                cur.append(text[i:i + 2])
                i += 2
                continue
            if c == "'" and not in_dq and not in_bt:
                in_sq = not in_sq
            elif c == '"' and not in_sq:
                in_dq = not in_dq
            elif not in_sq:
                if c == "`":
                    in_bt = not in_bt
                elif c == "$" and i + 1 < n and text[i + 1] == "(":
                    depth += 1
                    cur.append("$(")
                    i += 2
                    continue
                elif c == "(" and depth:
                    depth += 1
                elif c == ")" and depth:
                    depth -= 1
            if not (in_sq or in_dq or in_bt or depth):
                two = text[i:i + 2]
                if two in ("&&", "||"):
                    parts.append(("".join(cur), two))
                    cur, i = [], i + 2
                    continue
                if c == ";":
                    parts.append(("".join(cur), ";"))
                    cur, i = [], i + 1
                    continue
                if c == "&" and (i == 0 or text[i - 1] not in "<>") and text[i + 1:i + 2] != ">":
                    parts.append(("".join(cur), "&"))
                    cur, i = [], i + 1
                    continue
            cur.append(c)
            i += 1
        if "".join(cur).strip():
            parts.append(("".join(cur), ";"))
        return parts

    async def _run_list(self, text: str, capture: bool = False) -> tuple[str, int]:
        chain = self._split_list(text)
        for seg, conn in chain:
            if not seg.strip() and conn != ";":
                raise _ParseError(conn)
        output, status = [], self.ctx.last_status
        prev_conn = ";"
        for seg, conn in chain:
            if not seg.strip():
                prev_conn = conn
                continue
            run_it = True
            if prev_conn == "&&" and status != 0:
                run_it = False
            if prev_conn == "||" and status == 0:
                run_it = False
            if run_it:
                seg = await self._expand(seg)
                stderr_null = bool(re.search(r"(^|\s)2>\s*/dev/null", seg))
                seg = re.sub(r"(^|\s)2>\s*/dev/null", " ", seg)
                seg = re.sub(r"(^|\s)2>&1", " ", seg)
                toks = [t for t in self._tokens(seg)]
                if not toks:
                    prev_conn = conn
                    continue
                o, status = await self._run_pipeline(toks, stderr_null)
                self.ctx.last_status = status
                if conn == "&" and self.ctx.interactive and not capture:
                    o = f"[1] {self._pid() + 3}\n" + o
                output.append(o)
                if self.ctx.exited:
                    break
            prev_conn = conn
        return "".join(output), status

    async def _run_pipeline(self, toks: list[str], stderr_null: bool) -> tuple[str, int]:
        joined = " ".join(toks)
        m = re.search(r"/dev/(tcp|udp)/([\w.\-]+)/(\d+)", joined)
        if m:   # bash reverse shell: egress to non-web ports is filtered on this box
            self.on_ioc("reverse_shell", f"{m.group(2)}:{m.group(3)}", joined[:300])
            self.sleep_total = min(30.0, self.sleep_total + 15)
            name = "-bash" if self.ctx.interactive else "sh: 1"
            return (f"{name}: connect: Connection timed out\n{name}: /dev/{m.group(1)}/{m.group(2)}/{m.group(3)}: "
                    "Connection timed out\n"), 1
        cmds: list[list[str]] = [[]]
        for t in toks:
            if t == "|":
                cmds.append([])
            elif t == "||":
                raise _ParseError("||")
            else:
                cmds[-1].append(t)
        stdin = ""
        terminal = []
        res = Out()
        for idx, argv in enumerate(cmds):
            if not argv:
                raise _ParseError("|")
            argv, redirects = self._split_redirects(argv)
            for kind, target in redirects:
                if kind == "<":
                    try:
                        stdin = self.vfs.read(target, self.ctx.cwd, self.user, self.groups)
                    except FsError as e:
                        msg = FS_ERR_TEXT.get(e.kind, e.kind)
                        if self.ctx.interactive:
                            return f"-bash: {target}: {msg}\n", 1
                        return f"sh: 1: cannot open {target}: {msg}\n", 2
            last = idx == len(cmds) - 1
            res = await self._dispatch(argv, stdin, piped_out=not last or any(k in (">", ">>") for k, _ in redirects))
            out = res.out
            wrote = False
            for kind, target in redirects:
                if kind in (">", ">>"):
                    if target == "/dev/null":
                        out, wrote = "", True
                        continue
                    try:
                        self.vfs.write(target, out, self.ctx.cwd, self.user, self.groups, append=kind == ">>")
                        out, wrote = "", True
                    except FsError as e:
                        res.err += (f"-bash: {target}: {FS_ERR_TEXT.get(e.kind)}\n" if self.ctx.interactive
                                    else f"sh: 1: cannot create {target}: {FS_ERR_TEXT.get(e.kind)}\n")
                        res.code = 1
                        out = ""
            if not stderr_null:
                terminal.append(res.err)
            if last:
                terminal.append(out)
            else:
                stdin = out
        return "".join(terminal), res.code

    @staticmethod
    def _split_redirects(argv: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
        clean, redirects, i = [], [], 0
        while i < len(argv):
            a = argv[i]
            if a in (">", ">>", "<", ">|") and i + 1 < len(argv):
                redirects.append((">" if a == ">|" else a, argv[i + 1]))
                i += 2
                continue
            if a == ">&":
                i += 2
                continue
            clean.append(a)
            i += 1
        return clean, redirects

    # -- dispatch ------------------------------------------------------------------
    async def _dispatch(self, argv: list[str], stdin: str, piped_out: bool) -> Out:
        # leading VAR=value assignments
        while argv and re.fullmatch(r"[A-Za-z_]\w*=.*", argv[0]):
            k, _, v = argv[0].partition("=")
            if len(argv) == 1:
                self.ctx.env[k] = v
            argv = argv[1:]
        if not argv:
            return Out()
        argv = [self._tilde(a) for a in argv]
        name = argv[0]
        base = posixpath.basename(name)
        if "/" in name:
            node = self.vfs.get(name, self.ctx.cwd)
            if node is None:
                return Out(err=(f"-bash: {name}: No such file or directory\n" if self.ctx.interactive
                                else f"sh: 1: {name}: not found\n"), code=127)
            if node.kind == "dir":
                return Out(err=self.builtin_err(name, "Is a directory"), code=126)
            if not self.vfs.can(node, self.user, self.groups, 1):
                return Out(err=self.builtin_err(name, "Permission denied"), code=126)
            if base not in COMMANDS and base not in BUILTINS:
                return await self._exec_file(name, node, argv)
        handler = COMMANDS.get(base)
        if handler and (base in BUILTINS or self._in_path(base)):
            try:
                result = handler(self, argv, stdin, piped_out)
                if asyncio.iscoroutine(result):
                    result = await result
                return result
            except FsError as e:
                return Out(err=f"{base}: {e.path}: {FS_ERR_TEXT.get(e.kind, e.kind)}\n", code=1)
        if self._in_path(base):
            return await self._llm_command(" ".join(shlex.quote(a) for a in argv), stdin)
        return Out(err=self.not_found(name), code=127)

    def _in_path(self, name: str) -> bool:
        if name in BUILTINS:
            return True
        return any(self.vfs.exists(f"{d}/{name}") for d in ("/usr/local/bin", "/usr/bin", "/usr/sbin"))

    def _tilde(self, a: str) -> str:
        if a == "~" or a.startswith("~/"):
            return self.home() + a[1:]
        return a

    async def _llm_command(self, cmdline: str, stdin: str) -> Out:
        if self.llm_command:
            text = await self.llm_command(cmdline, self, stdin)
            if text is not None:
                return Out(out=text)
        name = shlex.split(cmdline)[0] if cmdline else ""
        return Out(err=f"{name}: {'missing operand' if len(cmdline.split()) == 1 else 'invalid option'}\n"
                       f"Try '{name} --help' for more information.\n", code=1)

    async def _exec_file(self, path: str, node: Node, argv: list[str]) -> Out:
        self.on_ioc("exec", path, " ".join(argv)[:300])
        if node.content and (node.content.startswith("#!") or path.endswith(".sh")):
            return await self.run_script(node.content, path)
        if node.size and not node.content:
            return Out(err="Segmentation fault (core dumped)\n", code=139)
        return Out()

    async def run_script(self, content: str, name: str) -> Out:
        """Emulate a shell script line by line (attacker-dropped scripts included)."""
        self._depth = getattr(self, "_depth", 0) + 1
        try:
            if self._depth > 4:
                return Out(err=f"{name}: fork: retry: Resource temporarily unavailable\n", code=254)
            out, code = [], 0
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                self.on_ioc("exec", f"{name}: {line[:200]}", "script line")
                try:
                    o, code = await self._run_list(line, capture=True)
                except _ParseError as e:
                    o, code = f"{name}: line 1: syntax error near unexpected token `{e}'\n", 2
                out.append(o)
                if self.ctx.exited:
                    self.ctx.exited = False
                    break
            return Out("".join(out), code=code)
        finally:
            self._depth -= 1

    # -- helpers -------------------------------------------------------------------
    def _read_quiet(self, path: str) -> str:
        try:
            return self.vfs.read(path, "/", "root", ())
        except FsError:
            return ""

    def _pid(self) -> int:
        return 1000 + int(self.world.uptime_seconds()) % 30000

    def read_file(self, path: str) -> str:
        return self.vfs.read(path, self.ctx.cwd, self.user, self.groups, ctx={"user": self.user})

    async def read_file_or_llm(self, path: str) -> str:
        try:
            return self.read_file(path)
        except FsError as e:
            if e.kind != "ENOENT" or not self.llm_file:
                raise
            full = self.vfs.resolve(path, self.ctx.cwd)
            content = await self.llm_file(full)
            if content is None:
                raise
            return self.read_file(path)

    # -- multi-step interactions -----------------------------------------------------
    async def _continue_pending(self, line: str) -> tuple[str, int]:
        p = self.ctx.pending
        self.ctx.pending = None
        if p["kind"] == "sudo":
            password = line.rstrip("\r\n")
            ok = self._sudo_allowed() and self._password_ok(self.user, password)
            self.on_credential(self.user, password, ok)
            if not self._sudo_allowed():
                return f"\n{self.user} is not in the sudoers file.  This incident will be reported.\n", 1
            if not ok:
                tries = p.get("tries", 1)
                if tries >= 3:
                    return "\nsudo: 3 incorrect password attempts\n", 1
                self.ctx.pending = {"kind": "sudo", "argv": p["argv"], "tries": tries + 1}
                return f"\nSorry, try again.\n[sudo] password for {self.user}: ", 1
            self.ctx.env["_SUDO_TS"] = str(time.time())
            return "\n" + await self._as_root(p["argv"]), 0
        if p["kind"] == "su":
            password = line.rstrip("\r\n")
            ok = self._password_ok(p["target"], password)
            self.on_credential(f"su:{p['target']}", password, ok)
            await asyncio.sleep(0 if ok else 2)
            if not ok:
                return "\nsu: Authentication failure\n", 1
            self.ctx.user = p["target"]
            self.ctx.cwd = self.home() if p["target"] != "root" else self.ctx.cwd
            return "\n", 0
        return "", 0

    def _sudo_allowed(self) -> bool:
        return "sudo" in self.groups or self.user == "root"

    def _password_ok(self, user: str, password: str) -> bool:
        return self.world.system_password_ok(user, password)

    def sudo_listing(self) -> str:
        host = self.world.hostname
        return (f"Matching Defaults entries for {self.user} on {host}:\n"
                "    env_reset, mail_badpass,\n"
                "    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\n\n"
                f"User {self.user} may run the following commands on {host}:\n    (ALL : ALL) ALL\n")

    async def _as_root(self, argv: list[str]) -> str:
        if argv and argv[0] == "-l":
            return self.sudo_listing()
        if argv and argv[0] in ("-i", "-s", "su", "bash", "sh", "/bin/bash", "/bin/sh") and len(argv) == 1:
            self.ctx.user = "root"          # interactive root shell from here on
            if argv[0] == "-i" or argv[0] == "su":
                self.ctx.cwd = "/root"
            self.ctx.env.update({"USER": "root", "LOGNAME": "root", "HOME": "/root"})
            return ""
        saved = self.ctx.user
        self.ctx.user = "root"
        try:
            out, _ = await self._run_list(" ".join(shlex.quote(a) for a in argv))
            return out
        finally:
            self.ctx.user = saved

    def _mysql_line(self, line: str) -> str:
        m = self.ctx.mysql
        stripped = line.strip()
        if not m.get("buffer") and stripped.lower() in ("exit", "quit", "\\q", "exit;", "quit;"):
            self.ctx.mysql = None
            return "Bye\n"
        m["buffer"] = (m.get("buffer", "") + " " + stripped).strip()
        if not m["buffer"].endswith((";", "\\G")):
            return ""
        query, m["buffer"] = m["buffer"].rstrip(";").removesuffix("\\G"), ""
        return self.run_sql(query) + "\n"

    def run_sql(self, query: str) -> str:
        if not self.sql_factory:
            return "ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)\n"
        eng = self.sql_factory()
        out = []
        for r in eng.execute(query, multi=True):
            self.sleep_total += r.sleep
            if r.modified:
                self.sql_modified = True
            out.append(r.error.cli() + "\n" if r.error else format_table(r))
        return "".join(out)


class _ParseError(Exception):
    pass


# ---------------------------------------------------------------------------
# Command implementations: fn(shell, argv, stdin, piped_out) -> Out
# ---------------------------------------------------------------------------

COMMANDS: dict[str, Callable] = {}


def cmd(*names):
    def deco(fn):
        for n in names:
            COMMANDS[n] = fn
        return fn
    return deco


def _flags(argv: list[str]) -> tuple[set[str], list[str]]:
    flags, args = set(), []
    for a in argv[1:]:
        if a.startswith("--"):
            flags.add(a)
        elif a.startswith("-") and len(a) > 1 and not a[1:].isdigit():
            flags.update(a[1:])
        else:
            args.append(a)
    return flags, args


def _now_str(fmt: str = "%a %b %e %H:%M:%S UTC %Y") -> str:
    return datetime.now(timezone.utc).strftime(fmt)


@cmd("true", ":")
def _true(sh, argv, stdin, piped):
    return Out()


@cmd("false")
def _false(sh, argv, stdin, piped):
    return Out(code=1)


@cmd("clear")
def _clear(sh, argv, stdin, piped):
    return Out("\x1b[H\x1b[2J\x1b[3J" if sh.ctx.tty else "")


@cmd("exit", "logout")
def _exit(sh, argv, stdin, piped):
    sh.ctx.exited = True
    return Out("logout\n" if sh.ctx.interactive and argv[0] == "logout" else "")


@cmd("pwd")
def _pwd(sh, argv, stdin, piped):
    return Out(sh.ctx.cwd + "\n")


@cmd("cd")
def _cd(sh, argv, stdin, piped):
    target = argv[1] if len(argv) > 1 else sh.home()
    if target == "-":
        target = sh.ctx.env.get("OLDPWD", sh.ctx.cwd)
    path = sh.vfs.resolve(target, sh.ctx.cwd)
    node = sh.vfs.get(path)
    if node is None:
        msg = "No such file or directory"
    elif node.kind != "dir":
        msg = "Not a directory"
    elif not sh.vfs.can(node, sh.user, sh.groups, 1):
        msg = "Permission denied"
    else:
        sh.ctx.env["OLDPWD"] = sh.ctx.cwd
        sh.ctx.cwd = path
        return Out()
    if sh.ctx.interactive:
        return Out(err=f"-bash: cd: {target}: {msg}\n", code=1)
    return Out(err=f"sh: 1: cd: can't cd to {target}\n", code=2)


@cmd("echo")
def _echo(sh, argv, stdin, piped):
    args = argv[1:]
    newline, escapes = True, False
    while args and re.fullmatch(r"-[neE]+", args[0]):
        newline = newline and "n" not in args[0]
        escapes = "e" in args[0]
        args = args[1:]
    text = " ".join(args)
    if escapes or not sh.ctx.interactive:   # dash's echo interprets escapes
        try:
            text = text.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except UnicodeDecodeError:
            pass
    return Out(text + ("\n" if newline else ""))


@cmd("printf")
def _printf(sh, argv, stdin, piped):
    if len(argv) < 2:
        return Out(err="printf: usage: printf [-v var] format [arguments]\n", code=2)
    fmt = argv[1].encode("latin-1", "backslashreplace").decode("unicode_escape")
    try:
        return Out(fmt.replace("%s", "{}").format(*argv[2:]) if "%s" in fmt else fmt % tuple(argv[2:]))
    except (TypeError, ValueError, IndexError):
        return Out(fmt)


@cmd("export")
def _export(sh, argv, stdin, piped):
    if len(argv) == 1:
        return Out("".join(f'declare -x {k}="{v}"\n' for k, v in sorted(sh.ctx.env.items()) if not k.startswith("_")))
    for a in argv[1:]:
        k, _, v = a.partition("=")
        if v or "=" in a:
            sh.ctx.env[k] = v
    return Out()


@cmd("unset")
def _unset(sh, argv, stdin, piped):
    for a in argv[1:]:
        sh.ctx.env.pop(a, None)
    return Out()


@cmd("env", "printenv")
def _env(sh, argv, stdin, piped):
    if argv[0] == "printenv" and len(argv) > 1:
        v = sh.ctx.env.get(argv[1])
        return Out(v + "\n" if v is not None else "", code=0 if v is not None else 1)
    return Out("".join(f"{k}={v}\n" for k, v in sh.ctx.env.items() if not k.startswith("_")))


@cmd("history")
def _history(sh, argv, stdin, piped):
    return Out("".join(f"{i + 1:>5}  {c}\n" for i, c in enumerate(sh.ctx.history)))


@cmd("alias")
def _alias(sh, argv, stdin, piped):
    return Out("alias egrep='egrep --color=auto'\nalias fgrep='fgrep --color=auto'\nalias grep='grep --color=auto'\n"
               "alias l='ls -CF'\nalias la='ls -A'\nalias ll='ls -alF'\nalias ls='ls --color=auto'\n")


@cmd("type")
def _type(sh, argv, stdin, piped):
    out, code = [], 0
    for a in argv[1:]:
        if a in BUILTINS:
            out.append(f"{a} is a shell builtin\n")
        elif sh._in_path(a):
            d = next(d for d in ("/usr/local/bin", "/usr/bin", "/usr/sbin") if sh.vfs.exists(f"{d}/{a}"))
            out.append(f"{a} is {d}/{a}\n")
        else:
            out.append(sh.builtin_err("type", f"{a}: not found"))
            code = 1
    return Out("".join(out), code=code)


@cmd("which")
def _which(sh, argv, stdin, piped):
    out, code = [], 0
    for a in argv[1:]:
        for d in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin"):
            if sh.vfs.exists(f"{d}/{a}"):
                out.append(f"{d}/{a}\n")
                break
        else:
            code = 1
    return Out("".join(out), code=code)


@cmd("whoami")
def _whoami(sh, argv, stdin, piped):
    return Out(sh.user + "\n")


@cmd("id")
def _id(sh, argv, stdin, piped):
    flags = set("".join(a[1:] for a in argv[1:] if a.startswith("-") and len(a) > 1))
    names = [a for a in argv[1:] if not a.startswith("-")]
    user = names[0] if names else sh.user
    if names and not any(l.split(":")[0] == user for l in sh._read_quiet("/etc/passwd").splitlines()) \
            and user != sh.user:
        return Out(err=f"id: ‘{user}’: no such user\n", code=1)
    uid, gid, _ = sh.uid_gid(user)
    groups = [user] + [g for g in sh.groups if g != user] if user == sh.user else [user]
    gids = []
    for g in groups:
        for line in sh._read_quiet("/etc/group").splitlines():
            p = line.split(":")
            if p[0] == g:
                gids.append((p[2], g))
    gids = gids or [(str(gid), user)]
    if "u" in flags:
        return Out(f"{user if 'n' in flags else uid}\n")
    if "g" in flags:
        return Out(f"{user if 'n' in flags else gid}\n")
    if "G" in flags:
        return Out(" ".join(g if "n" in flags else n for n, g in gids) + "\n")
    return Out(f"uid={uid}({user}) gid={gid}({user}) groups={','.join(f'{n}({g})' for n, g in gids)}\n")


@cmd("groups")
def _groups(sh, argv, stdin, piped):
    return Out(" ".join(sh.groups) + "\n")


@cmd("hostname")
def _hostname(sh, argv, stdin, piped):
    if "-I" in argv or "-i" in argv:
        return Out(sh.world["host"]["ip"] + " \n")
    if "-f" in argv:
        return Out(f"{sh.world.hostname}.{sh.world['company']['domain']}\n")
    return Out(sh.world.hostname + "\n")


@cmd("uname")
def _uname(sh, argv, stdin, piped):
    osd = sh.world["os"]
    flags, _ = _flags(argv)
    parts = {"s": "Linux", "n": sh.world.hostname, "r": osd["kernel"], "v": osd["kernel_build"],
             "m": "x86_64", "p": "x86_64", "i": "x86_64", "o": "GNU/Linux"}
    if not flags or flags == {"s"}:
        return Out("Linux\n")
    if "a" in flags or "--all" in flags:
        keys = "snrvmpio"
    else:
        keys = [k for k in "snrvmpio" if k in flags]
    return Out(" ".join(parts[k] for k in keys) + "\n")


def _uptime_str(sh) -> tuple[str, str]:
    up = sh.world.uptime_seconds()
    days, rem = divmod(int(up), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    load = sh.vfs.read("/proc/loadavg").split()[:3]
    users = 1 if sh.ctx.interactive else 0
    up_s = f"up {days} days, {h:2d}:{m:02d}" if days else f"up {h:2d}:{m:02d}"
    return up_s, f"{users} user{'s' if users != 1 else ''},  load average: {', '.join(load)}"


@cmd("uptime")
def _uptime(sh, argv, stdin, piped):
    up, rest = _uptime_str(sh)
    if "-p" in argv:
        days = int(sh.world.uptime_seconds() // 86400)
        return Out(f"up {days // 7} weeks, {days % 7} days\n")
    return Out(f" {_now_str('%H:%M:%S')} {up},  {rest}\n")


@cmd("w")
def _w(sh, argv, stdin, piped):
    up, rest = _uptime_str(sh)
    lines = [f" {_now_str('%H:%M:%S')} {up},  {rest}",
             "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"]
    if sh.ctx.interactive:
        lines.append(f"{sh.user:<8} pts/0    {sh.client_ip:<16} {_now_str('%H:%M')}    0.00s  0.03s  0.00s w")
    return Out("\n".join(lines) + "\n")


@cmd("who")
def _who(sh, argv, stdin, piped):
    if not sh.ctx.interactive:
        return Out()
    return Out(f"{sh.user:<8} pts/0        {_now_str('%Y-%m-%d %H:%M')} ({sh.client_ip})\n")


@cmd("last")
def _last(sh, argv, stdin, piped):
    rng = random.Random(sh.world["seed"])
    admins = [e["username"] for e in sh.world["employees"] if e["shell_access"]] or ["deploy"]
    lines = []
    for i in range(8):
        ts = time.time() - (i + 1) * rng.randint(20000, 90000)
        lines.append(f"{rng.choice(admins + ['deploy']):<8} pts/{rng.randint(0, 2)}        "
                     f"10.{rng.randint(10, 60)}.{rng.randint(1, 30)}.{rng.randint(2, 250):<5} "
                     f"{datetime.fromtimestamp(ts, timezone.utc):%a %b %e %H:%M} - "
                     f"{datetime.fromtimestamp(ts + rng.randint(300, 7200), timezone.utc):%H:%M}  (00:{rng.randint(5, 59):02d})")
    boot = datetime.fromtimestamp(sh.world["host"]["boot_time"], timezone.utc)
    lines.append(f"reboot   system boot  {sh.world['os']['kernel']:<16} {boot:%a %b %e %H:%M}   still running")
    return Out("\n".join(lines) + f"\n\nwtmp begins {boot:%a %b %e %H:%M:%S %Y}\n")


@cmd("date")
def _date(sh, argv, stdin, piped):
    for a in argv[1:]:
        if a.startswith("+"):
            fmt = a[1:].replace("%N", "000000000")
            try:
                return Out(datetime.now(timezone.utc).strftime(fmt) + "\n")
            except ValueError:
                return Out(fmt + "\n")
    return Out(_now_str() + "\n")


@cmd("sleep")
def _sleep(sh, argv, stdin, piped):
    try:
        sh.sleep_total = min(30.0, sh.sleep_total + float(argv[1].rstrip("s")))
    except (IndexError, ValueError):
        return Out(err="sleep: missing operand\nTry 'sleep --help' for more information.\n", code=1)
    return Out()


def _ls_color(name: str, node: Node) -> str:
    if node.kind == "dir":
        return f"\x1b[01;34m{name}\x1b[0m" if not node.mode & 0o002 else f"\x1b[30;42m{name}\x1b[0m"
    if node.kind == "link":
        return f"\x1b[01;36m{name}\x1b[0m"
    if node.mode & 0o111:
        return f"\x1b[01;32m{name}\x1b[0m"
    if name.endswith((".gz", ".zip", ".tar", ".tgz")):
        return f"\x1b[01;31m{name}\x1b[0m"
    return name


def _columns(names: list[str], plain: list[str], width: int = 80) -> str:
    if not names:
        return ""
    colw = max(len(p) for p in plain) + 2
    ncols = max(1, width // colw)
    nrows = (len(names) + ncols - 1) // ncols
    lines = []
    for r in range(nrows):
        row = []
        for c in range(ncols):
            i = c * nrows + r
            if i < len(names):
                pad = colw - len(plain[i]) if (c + 1) * nrows + r < len(names) else 0
                row.append(names[i] + " " * pad)
        lines.append("".join(row).rstrip())
    return "\n".join(lines) + "\n"


@cmd("ls", "dir", "ll", "la")
def _ls(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    if argv[0] == "ll":
        flags |= {"a", "l", "F"}
    if argv[0] == "la":
        flags |= {"A"}
    long_ = "l" in flags
    all_ = "a" in flags
    almost = "A" in flags
    human = "h" in flags
    one = "1" in flags or piped or not sh.ctx.tty
    color = sh.ctx.tty and not piped
    targets = args or ["."]
    out, err, code = [], [], 0
    for t in targets:
        path = sh.vfs.resolve(t, sh.ctx.cwd)
        node = sh.vfs.get(path)
        if node is None:
            err.append(f"ls: cannot access '{t}': No such file or directory\n")
            code = 2
            continue
        try:
            if node.kind == "dir" and "d" not in flags:
                entries = sh.vfs.listdir(path, "/", sh.user, sh.groups)
            else:
                entries = [(t, node)]
        except FsError:
            err.append(f"ls: cannot open directory '{t}': Permission denied\n")
            code = 2
            continue
        if node.kind == "dir" and "d" not in flags:
            if all_:
                parent = sh.vfs.get(posixpath.dirname(path)) or node
                entries = [(".", node), ("..", parent)] + entries
            elif not almost:
                entries = [(n, e) for n, e in entries if not n.startswith(".")]
        if "t" in flags:
            entries.sort(key=lambda kv: -kv[1].mtime)
        if "r" in flags:
            entries.reverse()
        if len(targets) > 1:
            out.append(f"{t}:\n")
        if long_:
            total = sum(max(4, (node_size(e) + 1023) // 1024 * 1) for _, e in entries)
            if node.kind == "dir":
                out.append(f"total {total}\n")
            rows = []
            for name, e in entries:
                size = node_size(e)
                size_s = _human(size) if human else str(size)
                mt = datetime.fromtimestamp(e.mtime or sh.world["host"]["installed"], timezone.utc)
                when = mt.strftime("%b %e %H:%M") if time.time() - mt.timestamp() < 180 * 86400 else mt.strftime("%b %e  %Y")
                disp = _ls_color(name, e) if color else name
                if e.kind == "link":
                    disp += f" -> {e.target}"
                elif "F" in flags and e.kind == "dir":
                    disp += "/"
                nlink = 2 if e.kind == "dir" else 1
                rows.append((fmt_mode(e), str(nlink), e.owner, e.group, size_s, when, disp))
            if rows:
                w = [max(len(r[i]) for r in rows) for i in range(5)]
                for r in rows:
                    out.append(f"{r[0]} {r[1]:>{w[1]}} {r[2]:<{w[2]}} {r[3]:<{w[3]}} {r[4]:>{w[4]}} {r[5]} {r[6]}\n")
        else:
            names = [n for n, _ in entries]
            if one:
                out.append("".join(n + "\n" for n in names))
            else:
                shown = [_ls_color(n, e) if color else n for n, e in entries]
                out.append(_columns(shown, names))
        if len(targets) > 1:
            out.append("\n")
    return Out("".join(out).rstrip("\n") + "\n" if out and "".join(out).strip() else "".join(out), "".join(err), code)


def _human(n: int) -> str:
    for unit in ("", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n}{unit}" if unit == "" else (f"{n:.1f}{unit}" if n < 10 else f"{int(round(n))}{unit}")
        n /= 1024
    return f"{n:.1f}P"


@cmd("cat", "more", "less")
async def _cat(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    if not args:
        return Out(stdin)
    out, err, code = [], [], 0
    for a in args:
        try:
            content = await sh.read_file_or_llm(a)
            if "n" in flags:
                content = "".join(f"{i + 1:>6}\t{l}\n" for i, l in enumerate(content.splitlines()))
            out.append(content)
        except FsError as e:
            err.append(f"{argv[0]}: {a}: {FS_ERR_TEXT.get(e.kind, e.kind)}\n")
            code = 1
    return Out("".join(out), "".join(err), code)


def _input_text(sh, args: list[str], stdin: str, name: str) -> tuple[str, str, int]:
    if not args:
        return stdin, "", 0
    text, err, code = [], [], 0
    for a in args:
        try:
            text.append(sh.read_file(a))
        except FsError as e:
            err.append(f"{name}: {a}: {FS_ERR_TEXT.get(e.kind, e.kind)}\n" if name != "head" and name != "tail"
                       else f"{name}: cannot open '{a}' for reading: {FS_ERR_TEXT.get(e.kind, e.kind)}\n")
            code = 1
    return "".join(text), "".join(err), code


def _count_arg(argv: list[str], default: int = 10) -> tuple[int, list[str]]:
    n, rest, i = default, [], 1
    while i < len(argv):
        a = argv[i]
        if a == "-n" and i + 1 < len(argv):
            try:
                n = int(argv[i + 1].lstrip("+-"))
            except ValueError:
                pass
            i += 2
            continue
        if re.fullmatch(r"-n?\d+", a):
            n = int(re.sub(r"\D", "", a))
        elif a in ("-f", "-F", "-q"):
            pass
        else:
            rest.append(a)
        i += 1
    return n, rest


@cmd("head")
def _head(sh, argv, stdin, piped):
    n, args = _count_arg(argv)
    text, err, code = _input_text(sh, args, stdin, "head")
    lines = text.splitlines(keepends=True)
    return Out("".join(lines[:n]), err, code)


@cmd("tail")
def _tail(sh, argv, stdin, piped):
    n, args = _count_arg(argv)
    text, err, code = _input_text(sh, args, stdin, "tail")
    lines = text.splitlines(keepends=True)
    return Out("".join(lines[-n:] if n else []), err, code)


@cmd("wc")
def _wc(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    text, err, code = _input_text(sh, args, stdin, "wc")
    l, w, c = text.count("\n"), len(text.split()), len(text.encode("utf-8", "surrogateescape"))
    suffix = f" {args[0]}" if args else ""
    if flags & {"l", "w", "c", "m"}:
        vals = [str(v) for f_, v in (("l", l), ("w", w), ("c", c)) if f_ in flags or (f_ == "c" and "m" in flags)]
        return Out(" ".join(vals) + suffix + "\n", err, code)
    return Out(f"{l:>7} {w:>7} {c:>7}{suffix}\n" if not args else f" {l} {w} {c}{suffix}\n", err, code)


@cmd("grep", "egrep", "fgrep")
def _grep(sh, argv, stdin, piped):
    flags, args = set(), []
    i = 1
    pattern = None
    while i < len(argv):
        a = argv[i]
        if a in ("-e",) and i + 1 < len(argv):
            pattern = argv[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        if a.startswith("-") and len(a) > 1:
            flags.update(a[1:])
        elif pattern is None:
            pattern = a
        else:
            args.append(a)
        i += 1
    if pattern is None:
        return Out(err="Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", code=2)
    re_flags = re.I if "i" in flags else 0
    try:
        rx = re.compile(re.escape(pattern) if argv[0] == "fgrep" or "F" in flags else
                        pattern.replace("\\|", "|").replace("\\(", "(").replace("\\)", ")"), re_flags)
    except re.error:
        rx = re.compile(re.escape(pattern), re_flags)
    sources: list[tuple[str, str]] = []
    err = []
    if not args:
        sources.append(("(standard input)", stdin))
    for a in args:
        try:
            if "r" in flags or "R" in flags:
                for path in _walk(sh, a):
                    try:
                        sources.append((path, sh.read_file(path)))
                    except FsError:
                        pass
            else:
                sources.append((a, sh.read_file(a)))
        except FsError as e:
            err.append(f"grep: {a}: {FS_ERR_TEXT.get(e.kind, e.kind)}\n")
    out, matched = [], False
    multi = len(sources) > 1 or "r" in flags or "R" in flags
    for name, text in sources:
        count = 0
        for n, line in enumerate(text.splitlines(), 1):
            hit = bool(rx.search(line))
            if "v" in flags:
                hit = not hit
            if hit:
                matched = True
                count += 1
                if "l" in flags or "c" in flags or "q" in flags:
                    continue
                prefix = (f"{name}:" if multi and "h" not in flags else "") + (f"{n}:" if "n" in flags else "")
                out.append(f"{prefix}{line}\n")
        if "l" in flags and count:
            out.append(name + "\n")
        if "c" in flags:
            out.append((f"{name}:" if multi else "") + f"{count}\n")
    if "q" in flags:
        out = []
    return Out("".join(out), "".join(err) if "s" not in flags else "", 0 if matched else (2 if err else 1))


def _walk(sh, path: str) -> list[str]:
    root = sh.vfs.resolve(path, sh.ctx.cwd)
    node = sh.vfs.get(root)
    if node is None:
        raise FsError("ENOENT", path)
    if node.kind != "dir":
        return [root]
    out = []
    stack = [root]
    while stack and len(out) < 2000:
        cur = stack.pop()
        try:
            entries = sh.vfs.listdir(cur, "/", sh.user, sh.groups)
        except FsError:
            continue
        for name, e in entries:
            full = posixpath.join(cur, name)
            if e.kind == "dir":
                stack.append(full)
            elif e.kind == "file":
                out.append(full)
    return sorted(out)


@cmd("find")
def _find(sh, argv, stdin, piped):
    args = argv[1:]
    roots = []
    while args and not args[0].startswith("-"):
        roots.append(args.pop(0))
    roots = roots or ["."]
    name_rx, ftype, perm_suid, user_filter = None, None, False, None
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a in ("-name", "-iname"):
            pat = re.escape(nxt).replace(r"\*", ".*").replace(r"\?", ".")
            name_rx = re.compile(f"^{pat}$", re.I if a == "-iname" else 0)
            i += 2
        elif a == "-type":
            ftype = nxt
            i += 2
        elif a == "-perm":
            perm_suid = "4000" in nxt or "u=s" in nxt
            i += 2
        elif a == "-user":
            user_filter = nxt
            i += 2
        elif a in ("-maxdepth", "-mindepth", "-mtime", "-size", "-newer", "-exec"):
            i += 2 if a != "-exec" else len(args)
        else:
            i += 1
    out, err = [], []
    for r in roots:
        base = sh.vfs.resolve(r, sh.ctx.cwd)
        if sh.vfs.get(base) is None:
            err.append(f"find: '{r}': No such file or directory\n")
            continue
        stack = [base]
        seen = 0
        while stack and seen < 3000:
            cur = stack.pop(0)
            node = sh.vfs.get(cur)
            seen += 1
            if node is None:
                continue
            rel = cur if r.startswith("/") else (r.rstrip("/") + cur[len(base):] if cur != base else r)
            ok = True
            if name_rx and not name_rx.match(posixpath.basename(cur)):
                ok = False
            if ftype and ((ftype == "f") != (node.kind == "file") if ftype in "fd" else False):
                ok = False
            if perm_suid:
                ok = ok and node.kind == "file" and posixpath.basename(cur) in ("sudo", "passwd", "su", "mount", "umount", "chsh", "gpasswd", "newgrp", "pkexec")
            if user_filter and node.owner != user_filter:
                ok = False
            if ok:
                out.append(rel + "\n")
            if node.kind == "dir":
                try:
                    for name, _ in sh.vfs.listdir(cur, "/", sh.user, sh.groups):
                        stack.append(posixpath.join(cur, name))
                except FsError:
                    err.append(f"find: '{rel}': Permission denied\n")
    return Out("".join(out), "".join(err), 1 if err else 0)


@cmd("touch")
def _touch(sh, argv, stdin, piped):
    _, args = _flags(argv)
    for a in args:
        try:
            if not sh.vfs.exists(a, sh.ctx.cwd):
                sh.vfs.write(a, "", sh.ctx.cwd, sh.user, sh.groups)
        except FsError as e:
            return Out(err=f"touch: cannot touch '{a}': {FS_ERR_TEXT.get(e.kind)}\n", code=1)
    return Out()


@cmd("mkdir")
def _mkdir(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    err = []
    for a in args:
        try:
            if "p" in flags:
                parts = sh.vfs.resolve(a, sh.ctx.cwd).strip("/").split("/")
                cur = ""
                for p in parts:
                    cur += "/" + p
                    if not sh.vfs.exists(cur):
                        sh.vfs.mkdir(cur, "/", sh.user, sh.groups)
            else:
                sh.vfs.mkdir(a, sh.ctx.cwd, sh.user, sh.groups)
        except FsError as e:
            err.append(f"mkdir: cannot create directory ‘{a}’: {FS_ERR_TEXT.get(e.kind)}\n")
    return Out(err="".join(err), code=1 if err else 0)


@cmd("rm", "rmdir", "unlink")
def _rm(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    err = []
    for a in args:
        try:
            sh.vfs.delete(a, sh.ctx.cwd, sh.user, sh.groups, recursive="r" in flags or "R" in flags or argv[0] == "rmdir")
        except FsError as e:
            if e.kind == "ENOENT" and "f" in flags:
                continue
            msg = "Is a directory" if e.kind == "EISDIR" else FS_ERR_TEXT.get(e.kind)
            err.append(f"rm: cannot remove '{a}': {msg}\n")
    return Out(err="".join(err), code=1 if err else 0)


@cmd("cp", "mv")
def _cp(sh, argv, stdin, piped):
    _, args = _flags(argv)
    if len(args) < 2:
        return Out(err=f"{argv[0]}: missing destination file operand after '{args[0] if args else ''}'\n", code=1)
    *srcs, dst = args
    for s in srcs:
        try:
            content = sh.read_file(s)
            target = dst
            if sh.vfs.is_dir(dst, sh.ctx.cwd):
                target = posixpath.join(sh.vfs.resolve(dst, sh.ctx.cwd), posixpath.basename(s))
            sh.vfs.write(target, content, sh.ctx.cwd, sh.user, sh.groups)
            if argv[0] == "mv":
                sh.vfs.delete(s, sh.ctx.cwd, sh.user, sh.groups)
        except FsError as e:
            return Out(err=f"{argv[0]}: cannot stat '{s}': {FS_ERR_TEXT.get(e.kind)}\n", code=1)
    return Out()


@cmd("chmod")
def _chmod(sh, argv, stdin, piped):
    _, args = _flags(argv)
    if len(args) < 2:
        return Out(err="chmod: missing operand\n", code=1)
    mode_s, files = args[0], args[1:]
    for f in files:
        node = sh.vfs.get(f, sh.ctx.cwd)
        if node is None:
            return Out(err=f"chmod: cannot access '{f}': No such file or directory\n", code=1)
        if re.fullmatch(r"[0-7]{3,4}", mode_s):
            mode = int(mode_s, 8)
        else:
            mode = node.mode | (0o111 if "x" in mode_s and "+" in mode_s else 0)
        try:
            sh.vfs.chmod(f, mode, sh.ctx.cwd, sh.user)
        except FsError:
            return Out(err=f"chmod: changing permissions of '{f}': Operation not permitted\n", code=1)
    return Out()


@cmd("chown", "chgrp")
def _chown(sh, argv, stdin, piped):
    if sh.user == "root":
        return Out()
    _, args = _flags(argv)
    f = args[1] if len(args) > 1 else ""
    return Out(err=f"{argv[0]}: changing ownership of '{f}': Operation not permitted\n", code=1)


@cmd("ln")
def _ln(sh, argv, stdin, piped):
    return Out()


@cmd("file")
def _file(sh, argv, stdin, piped):
    out = []
    for a in argv[1:]:
        node = sh.vfs.get(a, sh.ctx.cwd)
        if node is None:
            out.append(f"{a}: cannot open `{a}' (No such file or directory)\n")
        elif node.kind == "dir":
            out.append(f"{a}: directory\n")
        elif node.size and not node.content:
            kind = ("gzip compressed data" if a.endswith(".gz") else "PDF document, version 1.4" if a.endswith(".pdf")
                    else "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, "
                         "interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped")
            out.append(f"{a}: {kind}\n")
        elif node.content.startswith("#!/bin/bash") or node.content.startswith("#!/bin/sh"):
            out.append(f"{a}: Bourne-Again shell script, ASCII text executable\n")
        elif node.content.startswith("<?php"):
            out.append(f"{a}: PHP script, ASCII text\n")
        else:
            out.append(f"{a}: {'ASCII text' if node.content else 'empty'}\n")
    return Out("".join(out))


@cmd("stat")
def _stat(sh, argv, stdin, piped):
    _, args = _flags(argv)
    out = []
    for a in args:
        node = sh.vfs.get(a, sh.ctx.cwd)
        if node is None:
            return Out(err=f"stat: cannot stat '{a}': No such file or directory\n", code=1)
        t = datetime.fromtimestamp(node.mtime or sh.world["host"]["installed"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000000000 +0000")
        out.append(f"  File: {a}\n  Size: {node_size(node):<15}Blocks: {max(8, node_size(node) // 512)}      IO Block: 4096   "
                   f"{'directory' if node.kind == 'dir' else 'regular file'}\nAccess: ({node.mode:04o}/{fmt_mode(node)})  "
                   f"Uid: ({sh.uid_gid(node.owner)[0]:>5}/{node.owner:>8})   Gid: ({sh.uid_gid(node.owner)[1]:>5}/{node.group:>8})\n"
                   f"Access: {t}\nModify: {t}\nChange: {t}\n Birth: -\n")
    return Out("".join(out))


@cmd("base64")
def _base64(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    text, err, code = _input_text(sh, args, stdin, "base64")
    if "d" in flags or "--decode" in flags:
        try:
            return Out(base64.b64decode(text.strip() + "===", validate=False).decode("utf-8", "replace"))
        except ValueError:
            return Out(err="base64: invalid input\n", code=1)
    enc = base64.b64encode(text.encode()).decode()
    return Out("\n".join(enc[i:i + 76] for i in range(0, len(enc), 76)) + "\n", err, code)


def _hash_cmd(algo):
    def fn(sh, argv, stdin, piped):
        _, args = _flags(argv)
        if not args:
            return Out(hashlib.new(algo, stdin.encode()).hexdigest() + "  -\n")
        out, err = [], []
        for a in args:
            try:
                out.append(f"{hashlib.new(algo, sh.read_file(a).encode('utf-8', 'surrogateescape')).hexdigest()}  {a}\n")
            except FsError as e:
                err.append(f"{argv[0]}: {a}: {FS_ERR_TEXT.get(e.kind)}\n")
        return Out("".join(out), "".join(err), 1 if err else 0)
    return fn


COMMANDS["md5sum"] = _hash_cmd("md5")
COMMANDS["sha1sum"] = _hash_cmd("sha1")
COMMANDS["sha256sum"] = _hash_cmd("sha256")


@cmd("sort")
def _sort(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    text, err, code = _input_text(sh, args, stdin, "sort")
    lines = text.splitlines()
    key = (lambda s: float(re.match(r"\s*(-?\d+(\.\d+)?)", s).group(1)) if re.match(r"\s*-?\d", s) else 0) if "n" in flags else None
    lines.sort(key=key, reverse="r" in flags)
    if "u" in flags:
        lines = list(dict.fromkeys(lines))
    return Out("".join(l + "\n" for l in lines), err, code)


@cmd("uniq")
def _uniq(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    text, err, code = _input_text(sh, args, stdin, "uniq")
    out, prev, count = [], None, 0
    for line in text.splitlines() + [None]:
        if line == prev:
            count += 1
            continue
        if prev is not None:
            out.append(f"{count:>7} {prev}\n" if "c" in flags else prev + "\n")
        prev, count = line, 1
    return Out("".join(out), err, code)


@cmd("cut")
def _cut(sh, argv, stdin, piped):
    delim, fields, files, i = "\t", None, [], 1
    while i < len(argv):
        a = argv[i]
        if a.startswith("-d"):
            delim = a[2:] or (argv[i + 1] if i + 1 < len(argv) else "\t")
            i += 1 if a[2:] else 2
            continue
        if a.startswith("-f"):
            spec = a[2:] or (argv[i + 1] if i + 1 < len(argv) else "1")
            fields = []
            for part in spec.split(","):
                if "-" in part:
                    lo, _, hi = part.partition("-")
                    fields.extend(range(int(lo or 1), int(hi or 50) + 1))
                elif part.isdigit():
                    fields.append(int(part))
            i += 1 if a[2:] else 2
            continue
        files.append(a)
        i += 1
    text, err, code = _input_text(sh, files, stdin, "cut")
    if not fields:
        return Out(err="cut: you must specify a list of bytes, characters, or fields\n", code=1)
    out = []
    for line in text.splitlines():
        parts = line.split(delim)
        out.append(delim.join(parts[f - 1] for f in fields if f - 1 < len(parts)) + "\n" if delim in line else line + "\n")
    return Out("".join(out), err, code)


@cmd("awk")
def _awk(sh, argv, stdin, piped):
    fs, prog, files, i = None, None, [], 1
    while i < len(argv):
        a = argv[i]
        if a.startswith("-F"):
            fs = a[2:] or argv[i + 1]
            i += 1 if a[2:] else 2
            continue
        if prog is None:
            prog = a
        else:
            files.append(a)
        i += 1
    text, err, code = _input_text(sh, files, stdin, "awk")
    m = re.fullmatch(r"\s*(?:/(.*?)/\s*)?\{\s*print\s+([$\d\w\s,\"':-]+?)\s*;?\s*\}\s*", prog or "")
    if not m:
        return Out(text, err, code)
    pat, fields = m.group(1), [f.strip() for f in m.group(2).split(",")]
    out = []
    for line in text.splitlines():
        if pat and not re.search(pat, line):
            continue
        parts = line.split(fs) if fs else line.split()
        vals = []
        for f in fields:
            if f == "$0":
                vals.append(line)
            elif f.startswith("$") and f[1:].isdigit():
                k = int(f[1:])
                vals.append(parts[k - 1] if 0 < k <= len(parts) else "")
            elif f == "$NF":
                vals.append(parts[-1] if parts else "")
            else:
                vals.append(f.strip("\"'"))
        out.append(" ".join(vals) + "\n")
    return Out("".join(out), err, code)


@cmd("tr")
def _tr(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    if "d" in flags and args:
        chars = args[0].encode().decode("unicode_escape")
        return Out("".join(c for c in stdin if c not in chars))
    if len(args) >= 2:
        a, b = args[0], args[1]
        if a in ("a-z", "[:lower:]") and b in ("A-Z", "[:upper:]"):
            return Out(stdin.upper())
        if a in ("A-Z", "[:upper:]") and b in ("a-z", "[:lower:]"):
            return Out(stdin.lower())
        table = str.maketrans(a[: len(b)], b[: len(a)])
        return Out(stdin.translate(table))
    return Out(stdin)


@cmd("tee")
def _tee(sh, argv, stdin, piped):
    flags, args = _flags(argv)
    for a in args:
        try:
            sh.vfs.write(a, stdin, sh.ctx.cwd, sh.user, sh.groups, append="a" in flags)
        except FsError as e:
            return Out(stdin, f"tee: {a}: {FS_ERR_TEXT.get(e.kind)}\n", 1)
    return Out(stdin)


@cmd("xargs")
async def _xargs(sh, argv, stdin, piped):
    rest = argv[1:] or ["echo"]
    items = stdin.split()
    line = " ".join(shlex.quote(a) for a in rest + items)
    out, code = await sh._run_list(line, capture=True)
    return Out(out, code=code)


@cmd("ps")
def _ps(sh, argv, stdin, piped):
    rng = random.Random(sh.world["seed"])
    boot = datetime.fromtimestamp(sh.world["host"]["boot_time"], timezone.utc)
    start = boot.strftime("%b%d") if (time.time() - boot.timestamp()) > 86400 else boot.strftime("%H:%M")
    prof = sh.world.profile
    procs = [("root", 1, "/sbin/init"), ("root", 2, "[kthreadd]"), ("root", 3, "[rcu_gp]"),
             ("root", 412, "/lib/systemd/systemd-journald"), ("root", 446, "/lib/systemd/systemd-udevd"),
             ("systemd+", 590, "/lib/systemd/systemd-networkd"), ("systemd+", 612, "/lib/systemd/systemd-resolved"),
             ("root", 701, "/usr/lib/accountsservice/accounts-daemon"), ("message+", 705, "/usr/bin/dbus-daemon --system"),
             ("syslog", 733, "/usr/sbin/rsyslogd -n -iNONE"), ("root", 741, "/lib/systemd/systemd-logind"),
             ("root", 802, "/usr/sbin/cron -f"), ("root", 811, "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
             ("root", 830, "/sbin/agetty -o -p -- \\u --noclear tty1 linux")]
    if prof == "nginx-php-legacy":
        procs += [("root", 905, "php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)"),
                  ("www-data", 921, "php-fpm: pool www"), ("www-data", 922, "php-fpm: pool www"),
                  ("root", 960, "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
                  ("www-data", 961, "nginx: worker process"), ("www-data", 962, "nginx: worker process")]
    elif prof == "ubuntu-admin-panel":
        procs += [("root", 955, "/usr/sbin/apache2 -k start")] + [("www-data", 980 + k, "/usr/sbin/apache2 -k start") for k in range(5)]
    else:
        procs += [("node", 990, "PM2 v5.3.0: God Daemon (/srv/app/.pm2)"), ("node", 1004, "node /srv/app/server.js")]
    if sh.ctx.interactive:
        procs += [("root", 21544, f"sshd: {sh.user} [priv]"), (sh.user, 21630, f"sshd: {sh.user}@pts/0"),
                  (sh.user, 21631, "-bash"), (sh.user, 21702, "ps " + " ".join(argv[1:]))]
    else:
        procs += [(sh.user, 21702, "sh -c " + "ps"), (sh.user, 21703, "ps " + " ".join(argv[1:]))]
    if any(a in argv for a in ("aux", "-aux", "auxf", "-ef", "-e", "ax", "-A")):
        if "-ef" in argv:
            lines = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
            for u, pid, c in procs:
                lines.append(f"{u:<8} {pid:>7} {1 if pid > 2 else 0:>7}  0 {start:<5} ?        00:00:{rng.randint(0, 59):02d} {c}")
            return Out("\n".join(lines) + "\n")
        lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for u, pid, c in procs:
            lines.append(f"{u:<8} {pid:>7}  0.{rng.randint(0, 9)}  {rng.randint(0, 4)}.{rng.randint(0, 9)} "
                         f"{rng.randint(5000, 900000):>6} {rng.randint(900, 90000):>5} ?        S{'s' if pid < 1000 else ''}   "
                         f"{start:<6}  0:{rng.randint(0, 59):02d} {c}")
        return Out("\n".join(lines) + "\n")
    lines = ["    PID TTY          TIME CMD"]
    mine = [p for p in procs if p[0] == sh.user][-2:]
    for _, pid, c in mine:
        lines.append(f"{pid:>7} pts/0    00:00:00 {c.split()[0].lstrip('-')}")
    return Out("\n".join(lines) + "\n")


@cmd("kill", "pkill", "killall", "nohup", "disown", "wait", "jobs", "umask", "set", "source", ".", "read",
     "sync", "renice", "ulimit", "hash", "test", "[")
def _noop(sh, argv, stdin, piped):
    if argv[0] in ("kill", "pkill", "killall") and len(argv) > 1 and sh.user != "root":
        target = argv[-1]
        if target.isdigit() and int(target) < 20000:
            return Out(err=sh.builtin_err("kill", f"({target}) - Operation not permitted") if argv[0] == "kill"
                       else "", code=1)
    return Out()


@cmd("df")
def _df(sh, argv, stdin, piped):
    h = sh.world["host"]
    total = h["disk_gb"] * 1024 * 1024
    used = int(total * h["disk_used_pct"] / 100)
    human = "h" in _flags(argv)[0]
    def fmt(k):
        return _human(k * 1024) if human else str(k)
    rows = [("udev", h["mem_mb"] * 512, 0, "/dev"), ("tmpfs", h["mem_mb"] * 102, 1100, "/run"),
            ("/dev/nvme0n1p1", total, used, "/"), ("tmpfs", h["mem_mb"] * 512, 0, "/dev/shm"),
            ("tmpfs", 5120, 0, "/run/lock"), ("/dev/loop0", 56832, 56832, "/snap/core18/2812")]
    lines = [f"Filesystem     {'Size' if human else '1K-blocks':>9} {'Used':>6} {'Avail':>6} Use% Mounted on"]
    for fs_, size, u, mnt in rows:
        pct = f"{int(u * 100 / size) if size else 0}%"
        lines.append(f"{fs_:<14} {fmt(size):>9} {fmt(u):>6} {fmt(size - u):>6} {pct:>4} {mnt}")
    return Out("\n".join(lines) + "\n")


@cmd("free")
def _free(sh, argv, stdin, piped):
    mb = sh.world["host"]["mem_mb"]
    flags = _flags(argv)[0]
    k = mb * 1024
    used, free, shared, buff = int(k * 0.41), int(k * 0.18), int(k * 0.02), int(k * 0.41)
    if "h" in flags:
        f = lambda v: f"{v / 1024 / 1024:.1f}Gi" if v > 1024 * 1024 else f"{v // 1024}Mi"
    elif "m" in flags:
        f = lambda v: str(v // 1024)
    else:
        f = str
    return Out(f"{'':15}total        used        free      shared  buff/cache   available\n"
               f"Mem:    {f(k):>11} {f(used):>11} {f(free):>11} {f(shared):>11} {f(buff):>11} {f(int(k * 0.52)):>11}\n"
               f"Swap:   {f(0):>11} {f(0):>11} {f(0):>11}\n")


def _ifaces(sh) -> str:
    h = sh.world["host"]
    return (f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            f"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n"
            f"       valid_lft forever preferred_lft forever\n    inet6 ::1/128 scope host \n"
            f"       valid_lft forever preferred_lft forever\n"
            f"2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000\n"
            f"    link/ether {h['mac']} brd ff:ff:ff:ff:ff:ff\n"
            f"    inet {h['ip']}/24 brd {h['ip'].rsplit('.', 1)[0]}.255 scope global dynamic ens5\n"
            f"       valid_lft 2843sec preferred_lft 2843sec\n")


@cmd("ip")
def _ip(sh, argv, stdin, piped):
    sub = argv[1] if len(argv) > 1 else ""
    h = sh.world["host"]
    if sub.startswith("a"):
        return Out(_ifaces(sh))
    if sub.startswith("r"):
        net = h["ip"].rsplit(".", 1)[0]
        return Out(f"default via {h['gateway']} dev ens5 proto dhcp src {h['ip']} metric 100 \n"
                   f"{net}.0/24 dev ens5 proto kernel scope link src {h['ip']} \n")
    return Out(err="Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n", code=255)


@cmd("ifconfig")
def _ifconfig(sh, argv, stdin, piped):
    h = sh.world["host"]
    return Out(f"ens5: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n        inet {h['ip']}  netmask 255.255.255.0  "
               f"broadcast {h['ip'].rsplit('.', 1)[0]}.255\n        ether {h['mac']}  txqueuelen 1000  (Ethernet)\n"
               "        RX packets 48211873  bytes 21958877211 (21.9 GB)\n        TX packets 39017641  bytes 33876501120 (33.8 GB)\n\n"
               "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n"
               "        loop  txqueuelen 1000  (Local Loopback)\n\n")


@cmd("netstat", "ss")
def _netstat(sh, argv, stdin, piped):
    prof = sh.world.profile
    web = {"nginx-php-legacy": ("nginx", 960), "ubuntu-admin-panel": ("apache2", 955), "node-express-api": ("node", 1004)}[prof]
    port = "3000" if prof == "node-express-api" else "80"
    show_p = sh.user == "root"
    rows = [("tcp", "127.0.0.53:53", "LISTEN", "systemd-resolve", 612), ("tcp", "0.0.0.0:22", "LISTEN", "sshd", 811),
            ("tcp", f"0.0.0.0:{port}", "LISTEN", web[0], web[1]), ("tcp", "127.0.0.1:6379", "LISTEN", "redis-server", 880)]
    if prof != "node-express-api":
        rows.append(("tcp", "0.0.0.0:443", "LISTEN", web[0], web[1]))
    if argv[0] == "ss":
        lines = ["Netid State  Recv-Q Send-Q  Local Address:Port   Peer Address:Port Process"]
        for proto, addr, st, prog, pid in rows:
            proc = f'users:(("{prog}",pid={pid},fd=6))' if show_p else ""
            lines.append(f"{proto:<5} {st:<6} 0      128     {addr:>18}      0.0.0.0:*     {proc}")
        return Out("\n".join(lines) + "\n")
    lines = ["Active Internet connections (only servers)" if "l" in "".join(argv) else "Active Internet connections (servers and established)",
             "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"]
    for proto, addr, st, prog, pid in rows:
        lines.append(f"{proto:<5}      0      0 {addr:<23} 0.0.0.0:*               {st:<11} {f'{pid}/{prog}' if show_p else '-'}")
    return Out("\n".join(lines) + "\n")


def _fake_ip(host: str) -> str:
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        return host
    h = hashlib.sha256(host.encode()).digest()
    return f"{h[0] % 200 + 20}.{h[1]}.{h[2]}.{h[3] % 250 + 2}"


@cmd("ping")
def _ping(sh, argv, stdin, piped):
    flags, args = set(), []
    count, i = 4, 1
    while i < len(argv):
        a = argv[i]
        if a == "-c" and i + 1 < len(argv):
            try:
                count = max(1, min(int(argv[i + 1]), 10))
            except ValueError:
                return Out(err=f"ping: invalid argument: '{argv[i + 1]}'\n", code=1)
            i += 2
            continue
        if a.startswith("-"):
            if a in ("-W", "-i", "-s", "-t", "-w"):
                i += 2
                continue
            i += 1
            continue
        args.append(a)
        i += 1
    if not args:
        return Out(err="ping: usage error: Destination address required\n", code=1)
    host = args[0]
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
        return Out(err=f"ping: {host}: Name or service not known\n", code=2)
    ip = _fake_ip(host)
    rng = random.Random(host)
    base = 0.3 if ip.startswith(("10.", "127.", "192.168.")) else rng.uniform(4, 60)
    lines = [f"PING {host} ({ip}) 56(84) bytes of data."]
    times = []
    for seq in range(1, count + 1):
        t = base * random.uniform(0.85, 1.25)
        times.append(t)
        lines.append(f"64 bytes from {ip}: icmp_seq={seq} ttl={64 if ip.startswith(('10.', '127.')) else rng.randint(48, 118)} time={t:.{3 if t < 1 else 1}f} ms")
    sh.sleep_total = min(30.0, sh.sleep_total + count - 1)
    mdev = (max(times) - min(times)) / 2
    lines += ["", f"--- {host} ping statistics ---",
              f"{count} packets transmitted, {count} received, 0% packet loss, time {int((count - 1) * 1003)}ms",
              f"rtt min/avg/max/mdev = {min(times):.3f}/{sum(times) / len(times):.3f}/{max(times):.3f}/{mdev:.3f} ms"]
    return Out("\n".join(lines) + "\n")


@cmd("dig", "nslookup", "host")
def _dig(sh, argv, stdin, piped):
    names = [a for a in argv[1:] if not a.startswith(("-", "+", "@"))]
    if not names:
        return Out()
    name = names[0]
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", name):
        return Out(err=f"{argv[0]}: '{name}' is not a legal name (unexpected end of input)\n", code=1)
    ip = _fake_ip(name)
    if argv[0] == "dig":
        return Out(ip + "\n" if "+short" in argv else
                   f"\n; <<>> DiG 9.16.1-Ubuntu <<>> {name}\n;; global options: +cmd\n;; Got answer:\n"
                   f";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {random.randint(1000, 65000)}\n\n"
                   f";; ANSWER SECTION:\n{name}.\t\t300\tIN\tA\t{ip}\n\n;; Query time: 4 msec\n"
                   f";; SERVER: 127.0.0.53#53(127.0.0.53)\n;; WHEN: {_now_str()}\n;; MSG SIZE  rcvd: 56\n\n")
    if argv[0] == "host":
        return Out(f"{name} has address {ip}\n")
    return Out(f"Server:\t\t127.0.0.53\nAddress:\t127.0.0.53#53\n\nNon-authoritative answer:\nName:\t{name}\nAddress: {ip}\n\n")


@cmd("traceroute")
def _traceroute(sh, argv, stdin, piped):
    names = [a for a in argv[1:] if not a.startswith("-") and not a.isdigit()]
    if not names:
        return Out(err="Usage: traceroute [ -46dFITnreAUDV ] host\n", code=2)
    ip = _fake_ip(names[0])
    gw = sh.world["host"]["gateway"]
    rng = random.Random(names[0])
    lines = [f"traceroute to {names[0]} ({ip}), 30 hops max, 60 byte packets", f" 1  {gw} ({gw})  0.412 ms  0.388 ms  0.371 ms"]
    for hop in range(2, rng.randint(5, 9)):
        lines.append(f" {hop}  * * *" if rng.random() < 0.3 else
                     f" {hop}  {_fake_ip(names[0] + str(hop))}  {hop * 1.7:.3f} ms  {hop * 1.8:.3f} ms  {hop * 1.75:.3f} ms")
    lines.append(f" {len(lines)}  {ip} ({ip})  {rng.uniform(8, 60):.3f} ms  {rng.uniform(8, 60):.3f} ms  {rng.uniform(8, 60):.3f} ms")
    return Out("\n".join(lines) + "\n")


def _download_name(url: str) -> str:
    name = posixpath.basename(url.split("?", 1)[0].rstrip("/")) or "index.html"
    return name


@cmd("wget")
def _wget(sh, argv, stdin, piped):
    urls = [a for a in argv[1:] if re.match(r"(?i)^(https?|ftp)://", a) or (not a.startswith("-") and "." in a and "/" in a)]
    out_name, quiet, to_stdout = None, "-q" in argv or "-qO-" in argv, False
    for i, a in enumerate(argv):
        if a in ("-O", "--output-document") and i + 1 < len(argv):
            out_name = argv[i + 1]
        if a in ("-qO-", "-O-") or (a == "-O" and i + 1 < len(argv) and argv[i + 1] == "-"):
            to_stdout = True
    if not urls:
        return Out(err="wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n", code=1)
    url = urls[0] if "://" in urls[0] else "http://" + urls[0]
    sh.on_ioc("url", url, " ".join(argv)[:300])
    host = re.sub(r"^\w+://", "", url).split("/", 1)[0].split(":")[0]
    ip = _fake_ip(host)
    port = 443 if url.startswith("https") else 80
    name = out_name or _download_name(url)
    size = random.Random(url).randint(900, 2_400_000)
    if to_stdout:
        return Out("")
    try:
        sh.vfs.write(name, "", sh.ctx.cwd, sh.user, sh.groups)
        node = sh.vfs.get(name, sh.ctx.cwd)
        if node:
            node.size = size
            sh.vfs._set(sh.vfs.resolve(name, sh.ctx.cwd), node.to_json())
    except FsError as e:
        return Out(err=f"{name}: {FS_ERR_TEXT.get(e.kind)}\n", code=3)
    sh.sleep_total = min(30.0, sh.sleep_total + 1.2)
    if quiet:
        return Out()
    ts = _now_str("%Y-%m-%d %H:%M:%S")
    return Out(err=f"--{ts}--  {url}\nResolving {host} ({host})... {ip}\nConnecting to {host} ({host})|{ip}|:{port}... connected.\n"
                   f"HTTP request sent, awaiting response... 200 OK\nLength: {size} ({_human(size)}) [application/octet-stream]\n"
                   f"Saving to: ‘{name}’\n\n{name:<20}100%[===================>] {_human(size):>7}  {random.uniform(1, 9):.2f}MB/s    in 0.{random.randint(1, 9)}s\n\n"
                   f"{ts} ({random.uniform(1, 9):.2f} MB/s) - ‘{name}’ saved [{size}/{size}]\n\n")


@cmd("curl")
def _curl(sh, argv, stdin, piped):
    urls = [a for a in argv[1:] if re.match(r"(?i)^(https?|ftp)://", a) or (not a.startswith("-") and "." in a and "/" in a)]
    if not urls:
        return Out(err="curl: try 'curl --help' or 'curl --manual' for more information\n", code=2)
    url = urls[0]
    sh.on_ioc("url", url, " ".join(argv)[:300])
    out_name = None
    for i, a in enumerate(argv):
        if a in ("-o", "--output") and i + 1 < len(argv):
            out_name = argv[i + 1]
        if a in ("-O", "--remote-name"):
            out_name = _download_name(url)
    sh.sleep_total = min(30.0, sh.sleep_total + 0.8)
    if out_name:
        try:
            sh.vfs.write(out_name, "", sh.ctx.cwd, sh.user, sh.groups)
            node = sh.vfs.get(out_name, sh.ctx.cwd)
            if node:
                node.size = random.Random(url).randint(900, 2_400_000)
                sh.vfs._set(sh.vfs.resolve(out_name, sh.ctx.cwd), node.to_json())
        except FsError:
            return Out(err=f"curl: (23) Failed writing body (0 != 1)\n", code=23)
        return Out() if "-s" in argv or "-sS" in argv or piped else Out(
            err="  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                "                                 Dload  Upload   Total   Spent    Left  Speed\n"
                "100  1532  100  1532    0     0   9871      0 --:--:-- --:--:-- --:--:--  9883\n")
    if piped:
        return Out("")
    return Out("<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
               "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")


@cmd("nc", "ncat", "netcat", "telnet", "socat")
def _nc(sh, argv, stdin, piped):
    hosts = [a for a in argv[1:] if not a.startswith("-")]
    if len(hosts) >= 2:
        sh.on_ioc("connect", f"{hosts[0]}:{hosts[1]}", " ".join(argv)[:300])
        sh.sleep_total = min(30.0, sh.sleep_total + 10)
        if argv[0] == "telnet":
            return Out(f"Trying {_fake_ip(hosts[0])}...\n", "telnet: Unable to connect to remote host: Connection timed out\n", 1)
        return Out(code=1)
    if "-l" in "".join(argv[1:]):
        return Out()
    return Out(err="usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n", code=1)


@cmd("ssh", "scp", "sftp", "rsync")
def _ssh(sh, argv, stdin, piped):
    target = next((a for a in argv[1:] if not a.startswith("-") and ("@" in a or "." in a)), None)
    if not target:
        return Out(err="usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n", code=255)
    host = target.split("@")[-1].split(":")[0]
    sh.on_ioc("connect", f"{host}:22", " ".join(argv)[:300])
    sh.sleep_total = min(30.0, sh.sleep_total + 8)
    return Out(err=f"ssh: connect to host {host} port 22: Connection timed out\n", code=255)


@cmd("bash", "sh", "dash")
async def _bash(sh, argv, stdin, piped):
    if "-c" in argv:
        i = argv.index("-c")
        if i + 1 < len(argv):
            out, code = await sh._run_list(argv[i + 1])
            return Out(out, code=code)
    rest = [a for a in argv[1:] if not a.startswith("-")]
    joined = " ".join(argv)
    m = re.search(r"/dev/(tcp|udp)/([\w.\-]+)/(\d+)", joined + " " + stdin)
    if m:
        sh.on_ioc("reverse_shell", f"{m.group(2)}:{m.group(3)}", joined[:300])
        sh.sleep_total = min(30.0, sh.sleep_total + 15)
        return Out(err=f"{argv[0]}: connect: Connection timed out\n{argv[0]}: /dev/{m.group(1)}/{m.group(2)}/{m.group(3)}: "
                       "Connection timed out\n", code=1)
    if stdin and not rest:
        return await sh.run_script(stdin, argv[0])
    if rest:
        try:
            content = sh.read_file(rest[0])
        except FsError:
            return Out(err=f"{argv[0]}: {rest[0]}: No such file or directory\n" if argv[0] == "bash"
                       else f"{argv[0]}: 0: Can't open {rest[0]}\n", code=127 if argv[0] == "bash" else 2)
        return await sh.run_script(content, rest[0])
    return Out()


@cmd("python", "python3", "perl", "php", "ruby")
async def _interp(sh, argv, stdin, piped):
    code_arg = None
    for flag in ("-c", "-e", "-r"):
        if flag in argv:
            i = argv.index(flag)
            code_arg = argv[i + 1] if i + 1 < len(argv) else ""
    if argv[0] == "python":
        return Out(err=sh.not_found("python"), code=127)
    if argv[0] == "ruby":
        return Out(err=sh.not_found("ruby"), code=127)
    if code_arg is None:
        if "-V" in argv or "--version" in argv:
            return Out({"python3": "Python 3.8.10\n", "perl": "\nThis is perl 5, version 30, subversion 0 (v5.30.0)\n",
                        "php": "PHP 7.4.3-4ubuntu2.19 (cli) (built: Jun 27 2023 15:49:59) ( NTS )\n"}.get(argv[0], ""))
        return Out()
    m = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})\D{1,12}?(\d{2,5})", code_arg)
    if m and re.search(r"socket|connect|fsockopen|TCPSocket|pty", code_arg):
        sh.on_ioc("reverse_shell", f"{m.group(1)}:{m.group(2)}", code_arg[:300])
        sh.sleep_total = min(30.0, sh.sleep_total + 15)
        return Out(err="", code=1)
    if re.search(r"pty\.spawn", code_arg):
        return Out()
    m = re.fullmatch(r"\s*(?:print\s*\(?|echo\s+)\s*['\"](.*?)['\"]\s*\)?\s*;?\s*", code_arg)
    if m:
        return Out(m.group(1) + ("\n" if argv[0] == "python3" else ""))
    m = re.fullmatch(r"\s*(?:echo|print)\s+(system|shell_exec|passthru|exec)\s*\(\s*['\"](.*?)['\"]\s*\)\s*;?\s*", code_arg)
    if m:
        out, code = await sh._run_list(m.group(2))
        return Out(out, code=code)
    return await sh._llm_command(" ".join(shlex.quote(a) for a in argv), stdin)


@cmd("sudo")
async def _sudo(sh, argv, stdin, piped):
    args = [a for a in argv[1:]]
    while args and args[0].startswith("-") and args[0] not in ("-l", "-i", "-s"):
        args = args[1:] if args[0] not in ("-u",) else args[2:]
    if sh.user == "root":
        if not args or args[0] in ("-i", "-s", "su"):
            return Out()
        if args[0] == "-l":
            return Out(sh.sudo_listing())
        out, code = await sh._run_list(" ".join(shlex.quote(a) for a in args))
        return Out(out, code=code)
    if not sh.ctx.interactive:
        return Out(err="sudo: a terminal is required to read the password; either use the -S option to read from "
                       "standard input or configure an askpass helper\n", code=1)
    if "-S" in argv and stdin:
        pw = stdin.splitlines()[0] if stdin else ""
        ok = sh._sudo_allowed() and sh._password_ok(sh.user, pw)
        sh.on_credential(sh.user, pw, ok)
        if ok:
            return Out(await sh._as_root(args))
        return Out(err=f"[sudo] password for {sh.user}: Sorry, try again.\n", code=1)
    sh.ctx.pending = {"kind": "sudo", "argv": args or ["true"], "tries": 1}
    return Out(f"[sudo] password for {sh.user}: ")


@cmd("su")
def _su(sh, argv, stdin, piped):
    if not sh.ctx.interactive:
        return Out(err="su: must be run from a terminal\n", code=1)
    target = next((a for a in argv[1:] if not a.startswith("-")), "root")
    if sh.user == "root":
        sh.ctx.user = target
        return Out()
    sh.ctx.pending = {"kind": "su", "target": target}
    return Out("Password: ")


@cmd("crontab")
def _crontab(sh, argv, stdin, piped):
    if "-l" in argv:
        if sh.user == "root":
            return Out("# m h  dom mon dow   command\n30 2 * * * /opt/backup/db_backup.sh >> /var/log/db_backup.log 2>&1\n")
        return Out(err=f"no crontab for {sh.user}\n", code=1)
    if "-r" in argv:
        return Out()
    if sh.user == "www-data":
        return Out(err="You (www-data) are not allowed to use this program (crontab)\nSee crontab(1) for more information\n",
                   code=1)
    sh.on_ioc("persistence", "crontab " + " ".join(argv[1:]), stdin[:300])
    return Out()


@cmd("useradd", "adduser", "usermod", "passwd", "chpasswd", "apt", "apt-get", "dpkg", "systemctl", "service",
     "iptables", "reboot", "shutdown", "mount")
async def _privileged(sh, argv, stdin, piped):
    name = argv[0]
    if sh.user != "root":
        msgs = {
            "useradd": "useradd: Permission denied.\nuseradd: cannot lock /etc/passwd; try again later.\n",
            "adduser": "adduser: Only root may add a user or group to the system.\n",
            "usermod": "usermod: Permission denied.\nusermod: cannot lock /etc/passwd; try again later.\n",
            "apt": "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                   "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n",
            "apt-get": "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                       "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n",
            "iptables": "iptables v1.8.4 (legacy): can't initialize iptables table `filter': Permission denied (you must be root)\n"
                        "Perhaps iptables or your kernel needs to be upgraded.\n",
            "reboot": "Failed to set wall message, ignoring: Interactive authentication required.\n"
                      "Failed to reboot system via logind: Interactive authentication required.\n",
            "shutdown": "Failed to set wall message, ignoring: Interactive authentication required.\n",
            "mount": "mount: only root can do that\n",
        }
        if name == "passwd":
            return Out(err="passwd: Authentication token manipulation error\npasswd: password unchanged\n", code=10)
        if name in ("systemctl", "service") and any(a in argv for a in ("status", "list-units", "--status-all", "is-active")):
            return await sh._llm_command(" ".join(shlex.quote(a) for a in argv), stdin)
        if name in msgs:
            return Out(err=msgs[name], code=1)
        if name in ("systemctl", "service"):
            return Out(err="Failed to restart: Interactive authentication required.\nSee system logs and 'systemctl status' for details.\n"
                       if name == "systemctl" else "Failed to restart: Access denied\n", code=1)
    if name in ("useradd", "adduser", "usermod", "chpasswd", "passwd"):
        sh.on_ioc("persistence", " ".join(argv)[:300], "account change")
        return Out()
    if name in ("reboot", "shutdown"):
        sh.ctx.exited = True
        return Out()
    return await sh._llm_command(" ".join(shlex.quote(a) for a in argv), stdin)


@cmd("mysql")
def _mysql(sh, argv, stdin, piped):
    user, password, query, i = sh.user, None, None, 1
    host = "localhost"
    while i < len(argv):
        a = argv[i]
        if a in ("-u", "--user") and i + 1 < len(argv):
            user = argv[i + 1]; i += 2; continue
        if a.startswith("-u") and len(a) > 2:
            user = a[2:]
        elif a.startswith("--user="):
            user = a.split("=", 1)[1]
        elif a == "-p":
            password = ""
        elif a.startswith("-p"):
            password = a[2:]
        elif a.startswith("--password="):
            password = a.split("=", 1)[1]
        elif a in ("-h", "--host") and i + 1 < len(argv):
            host = argv[i + 1]; i += 2; continue
        elif a.startswith("-h") and len(a) > 2:
            host = a[2:]
        elif a in ("-e", "--execute") and i + 1 < len(argv):
            query = argv[i + 1]; i += 2; continue
        i += 1
    sec = sh.world["secrets"]
    db_host = sh.world["host"]["db_hostname"]
    if host in ("localhost", "127.0.0.1"):
        return Out(err="ERROR 2002 (HY000): Can't connect to local MySQL server through socket "
                       "'/var/run/mysqld/mysqld.sock' (2)\n", code=1)
    if host not in (db_host, sh.world["host"]["db_host"], f"{db_host}.{sh.world['company']['domain']}"):
        sh.sleep_total = min(30.0, sh.sleep_total + 10)
        return Out(err=f"ERROR 2003 (HY000): Can't connect to MySQL server on '{host}:3306' (110)\n", code=1)
    if password == "" and sh.ctx.interactive:
        return Out(err="Enter password: \nERROR 1045 (28000): Access denied for user "
                       f"'{user}'@'{sh.world['host']['ip']}' (using password: NO)\n", code=1)
    ok = (user == sec["db_user"] and password == sec["db_password"]) or (user == "root" and password == sec["db_root_password"])
    sh.on_credential(f"mysql:{user}", password or "", ok)
    if not ok:
        return Out(err=f"ERROR 1045 (28000): Access denied for user '{user}'@'{sh.world['host']['ip']}' "
                       f"(using password: {'YES' if password else 'NO'})\n", code=1)
    if query is None and stdin:
        query = stdin
    if query is not None:
        # batch mode (-e / stdin): stops at the first error, reports its line, exits 1
        text = sh.run_sql(query)
        m = re.search(r"(?m)^ERROR (\d+) \((\w+)\): ", text)
        if m:
            return Out(text[:m.start()], err=f"ERROR {m.group(1)} ({m.group(2)}) at line 1: "
                                             + text[m.end():].split("\n", 1)[0] + "\n", code=1)
        return Out(text)
    if not sh.ctx.interactive:
        return Out()
    sh.ctx.mysql = {"user": user, "buffer": ""}
    return Out("mysql: [Warning] Using a password on the command line interface can be insecure.\n"
               f"Welcome to the MySQL monitor.  Commands end with ; or \\g.\nYour MySQL connection id is {random.randint(1200, 90000)}\n"
               "Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)\n\nCopyright (c) 2000, 2023, Oracle and/or its affiliates.\n\n"
               "Oracle is a registered trademark of Oracle Corporation and/or its\naffiliates. Other names may be trademarks "
               "of their respective\nowners.\n\nType 'help;' or '\\h' for help. Type '\\c' to clear the current input statement.\n\n")


@cmd("lsb_release")
def _lsb(sh, argv, stdin, piped):
    return Out("No LSB modules are available.\nDistributor ID:\tUbuntu\nDescription:\tUbuntu 20.04.6 LTS\n"
               "Release:\t20.04\nCodename:\tfocal\n" if "-a" in argv else "No LSB modules are available.\n")


@cmd("seq")
def _seq(sh, argv, stdin, piped):
    try:
        nums = [int(a) for a in argv[1:]]
    except ValueError:
        return Out(err=f"seq: invalid floating point argument: '{argv[-1]}'\n", code=1)
    if len(nums) == 1:
        rng_ = range(1, nums[0] + 1)
    elif len(nums) == 2:
        rng_ = range(nums[0], nums[1] + 1)
    else:
        rng_ = range(nums[0], nums[2] + 1, nums[1] or 1)
    return Out("".join(f"{n}\n" for n in list(rng_)[:10000]))


@cmd("git")
async def _git(sh, argv, stdin, piped):
    if len(argv) > 1 and argv[1] == "--version":
        return Out("git version 2.25.1\n")
    return await sh._llm_command(" ".join(shlex.quote(a) for a in argv), stdin)


@cmd("diff", "dirname", "readlink", "whereis", "du", "top", "journalctl", "tar", "gzip", "unzip", "zip", "sed",
     "openssl", "nano", "vi", "vim", "dd", "lsblk", "lscpu", "lsof", "getent")
async def _llm_backed(sh, argv, stdin, piped):
    name = argv[0]
    if name == "dirname" and len(argv) > 1:
        return Out(posixpath.dirname(argv[1]) or ".")
    if name == "readlink" and len(argv) > 1:
        return Out(sh.vfs.resolve(argv[-1], sh.ctx.cwd) + "\n")
    if name == "whereis" and len(argv) > 1:
        a = argv[1]
        paths = [f"{d}/{a}" for d in ("/usr/bin", "/usr/sbin") if sh.vfs.exists(f"{d}/{a}")]
        return Out(f"{a}: {' '.join(paths)}\n")
    if name in ("vi", "vim", "nano", "top", "less") and sh.ctx.interactive:
        return Out("" if not piped else "", err="" if name != "top" else "", code=0)
    if name == "getent" and len(argv) > 2 and argv[1] == "passwd":
        lines = [l for l in sh._read_quiet("/etc/passwd").splitlines() if l.split(":")[0] == argv[2]]
        return Out("".join(l + "\n" for l in lines), code=0 if lines else 2)
    if name == "sed" and len(argv) >= 2:
        m = re.fullmatch(r"s(.)(.*?)\1(.*?)\1(g?)", argv[-1] if len(argv) == 2 else argv[1])
        if m:
            text = stdin if len(argv) == 2 else _input_text(sh, argv[2:], stdin, "sed")[0]
            try:
                return Out(re.sub(m.group(2), m.group(3), text, count=0 if m.group(4) else 1))
            except re.error:
                return Out(text)
    return await sh._llm_command(" ".join(shlex.quote(a) for a in argv), stdin)
