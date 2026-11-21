"""Virtual filesystem: a base tree derived from the world + per-session overlay.

Nothing here touches the real filesystem. The base tree is rebuilt from the world
seed; files generated later (by the LLM, for paths the base tree does not cover)
are stored in a shared "world overlay" so every attacker sees the same content;
writes made by an attacker live only in that attacker's session overlay.
"""

from __future__ import annotations

import posixpath
import random
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable

from mirage_trap.core.world import World


@dataclass
class Node:
    kind: str = "file"           # file | dir | link
    content: str = ""
    mode: int = 0o644
    owner: str = "root"
    group: str = "root"
    mtime: float = 0.0
    target: str = ""             # for links
    size: int | None = None      # override (binaries)
    dynamic: str = ""            # name of a dynamic generator (proc files)

    def to_json(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in ("", None)}

    @classmethod
    def from_json(cls, d: dict) -> "Node":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


BIN_NAMES = (
    "[ awk base64 bash cat chgrp chmod chown cp crontab curl cut dash date dd df diff dig dirname du "
    "echo egrep env false fgrep file find free getent git grep groups gzip head host hostname id ip "
    "journalctl kill killall last less ln ls lsb_release lsblk lscpu lsof md5sum mkdir more mount mv "
    "mysql mysqldump nano nc netcat netstat nohup nslookup openssl passwd perl pgrep ping pkill printenv "
    "printf ps pwd python3 readlink rm rmdir rsync scp sed seq sftp sh sha1sum sha256sum sleep sort ss ssh "
    "stat su sudo sync systemctl tail tar tee telnet test top touch tr traceroute true uname uniq unlink "
    "unzip uptime vi vim w wc wget whereis which who whoami xargs zip apt apt-get dpkg service"
).split()
SBIN_NAMES = ("adduser chpasswd ifconfig iptables reboot route shutdown sshd useradd usermod").split()
PROFILE_BINS = {
    "nginx-php-legacy": (["php", "php7.4"], ["nginx", "php-fpm7.4"]),
    "ubuntu-admin-panel": (["php", "php7.4"], ["apache2", "apachectl"]),
    "node-express-api": (["node", "npm", "npx", "pm2"], []),
}


def _ts(world: World, days_after_install: float) -> float:
    return world.data["host"]["installed"] + days_after_install * 86400


def _fmt_syslog(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%b %e %H:%M:%S")


def build_base_vfs(world: World) -> dict[str, Node]:
    d = world.data
    rng = random.Random(f"{d['seed']}-{d['fs_salt']}")
    host, sec, comp, osd = d["host"], d["secrets"], d["company"], d["os"]
    stack = world.stack
    profile = world.profile
    inst = host["installed"]
    fs: dict[str, Node] = {}

    def f(path: str, content: str = "", mode: int = 0o644, owner: str = "root", group: str | None = None,
          mtime: float | None = None, **kw) -> None:
        fs[path] = Node("file", content, mode, owner, group or owner, mtime or inst + rng.randint(0, 200) * 86400, **kw)

    def dr(path: str, mode: int = 0o755, owner: str = "root", group: str | None = None) -> None:
        fs[path] = Node("dir", "", mode, owner, group or owner, inst + rng.randint(0, 300) * 86400)

    def ln(path: str, target: str) -> None:
        fs[path] = Node("link", "", 0o777, "root", "root", inst, target=target)

    # -- skeleton ------------------------------------------------------------
    for p in ["/", "/etc", "/home", "/opt", "/srv", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib",
              "/usr/local", "/usr/local/bin", "/usr/share", "/var", "/var/log", "/var/www", "/var/lib",
              "/var/backups", "/var/tmp", "/proc", "/dev", "/run", "/boot", "/mnt", "/media", "/snap",
              "/etc/ssh", "/etc/cron.d", "/etc/cron.daily", "/etc/systemd", "/etc/systemd/system", "/sys"]:
        dr(p)
    dr("/root", 0o700)
    dr("/tmp", 0o1777)
    for name, target in [("/bin", "usr/bin"), ("/sbin", "usr/sbin"), ("/lib", "usr/lib"), ("/lib64", "usr/lib64")]:
        ln(name, target)
    for b in BIN_NAMES:
        f(f"/usr/bin/{b}", "", 0o755, size=rng.randint(30_000, 1_400_000), mtime=inst)
    for b in SBIN_NAMES:
        f(f"/usr/sbin/{b}", "", 0o755, size=rng.randint(40_000, 900_000), mtime=inst)
    extra_bin, extra_sbin = PROFILE_BINS[profile]
    for b in extra_bin:
        f(f"/usr/bin/{b}", "", 0o755, size=rng.randint(40_000, 900_000), mtime=inst)
    for b in extra_sbin:
        f(f"/usr/sbin/{b}", "", 0o755, size=rng.randint(40_000, 900_000), mtime=inst)
    fs["/usr/bin/sudo"].mode = 0o4755
    fs["/usr/bin/passwd"].mode = 0o4755
    fs["/usr/bin/su"].mode = 0o4755
    fs["/usr/bin/mount"].mode = 0o4755
    f("/boot/vmlinuz-" + osd["kernel"], "", 0o600, size=11_731_712)

    # -- identity --------------------------------------------------------------
    sys_users = [
        ("root", 0, 0, "root", "/root", "/bin/bash"),
        ("daemon", 1, 1, "daemon", "/usr/sbin", "/usr/sbin/nologin"),
        ("bin", 2, 2, "bin", "/bin", "/usr/sbin/nologin"),
        ("sys", 3, 3, "sys", "/dev", "/usr/sbin/nologin"),
        ("sync", 4, 65534, "sync", "/bin", "/bin/sync"),
        ("games", 5, 60, "games", "/usr/games", "/usr/sbin/nologin"),
        ("man", 6, 12, "man", "/var/cache/man", "/usr/sbin/nologin"),
        ("lp", 7, 7, "lp", "/var/spool/lpd", "/usr/sbin/nologin"),
        ("mail", 8, 8, "mail", "/var/mail", "/usr/sbin/nologin"),
        ("news", 9, 9, "news", "/var/spool/news", "/usr/sbin/nologin"),
        ("uucp", 10, 10, "uucp", "/var/spool/uucp", "/usr/sbin/nologin"),
        ("proxy", 13, 13, "proxy", "/bin", "/usr/sbin/nologin"),
        ("www-data", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin"),
        ("backup", 34, 34, "backup", "/var/backups", "/usr/sbin/nologin"),
        ("list", 38, 38, "Mailing List Manager", "/var/list", "/usr/sbin/nologin"),
        ("irc", 39, 39, "ircd", "/var/run/ircd", "/usr/sbin/nologin"),
        ("gnats", 41, 41, "Gnats Bug-Reporting System (admin)", "/var/lib/gnats", "/usr/sbin/nologin"),
        ("nobody", 65534, 65534, "nobody", "/nonexistent", "/usr/sbin/nologin"),
        ("systemd-network", 100, 102, "systemd Network Management,,,", "/run/systemd", "/usr/sbin/nologin"),
        ("systemd-resolve", 101, 103, "systemd Resolver,,,", "/run/systemd", "/usr/sbin/nologin"),
        ("systemd-timesync", 102, 104, "systemd Time Synchronization,,,", "/run/systemd", "/usr/sbin/nologin"),
        ("messagebus", 103, 106, "", "/nonexistent", "/usr/sbin/nologin"),
        ("syslog", 104, 110, "", "/home/syslog", "/usr/sbin/nologin"),
        ("_apt", 105, 65534, "", "/nonexistent", "/usr/sbin/nologin"),
        ("tss", 106, 111, "TPM software stack,,,", "/var/lib/tpm", "/bin/false"),
        ("uuidd", 107, 112, "", "/run/uuidd", "/usr/sbin/nologin"),
        ("tcpdump", 108, 113, "", "/nonexistent", "/usr/sbin/nologin"),
        ("sshd", 109, 65534, "", "/run/sshd", "/usr/sbin/nologin"),
        ("landscape", 110, 115, "", "/var/lib/landscape", "/usr/sbin/nologin"),
        ("pollinate", 111, 1, "", "/var/cache/pollinate", "/bin/false"),
        ("ubuntu", 1000, 1000, "Ubuntu", "/home/ubuntu", "/bin/bash"),
        ("deploy", 1100, 1100, "Deploy user,,,", "/home/deploy", "/bin/bash"),
    ]
    if profile == "node-express-api":
        sys_users.append(("node", 1101, 1101, "", "/srv/app", "/bin/bash"))
    admins = [e for e in d["employees"] if e["shell_access"]]
    for e in admins:
        sys_users.append((e["username"], e["uid"], e["uid"], f"{e['first']} {e['last']},,,",
                          f"/home/{e['username']}", "/bin/bash"))
    f("/etc/passwd", "".join(f"{u}:x:{uid}:{gid}:{g}:{h}:{s}\n" for u, uid, gid, g, h, s in sys_users))
    adm = "syslog,ubuntu" + (",www-data" if profile == "ubuntu-admin-panel" else "")   # log viewer needs it
    groups = ["root:x:0:", "daemon:x:1:", "bin:x:2:", "sys:x:3:", f"adm:x:4:{adm}",
              "tty:x:5:", "disk:x:6:", "www-data:x:33:", "backup:x:34:", "shadow:x:42:",
              "sudo:x:27:ubuntu," + ",".join(e["username"] for e in admins),
              "users:x:100:", "ubuntu:x:1000:", "deploy:x:1100:"]
    f("/etc/group", "\n".join(groups) + "\n")
    shadow = []
    for u, *_ in sys_users:
        h = d["fake_shadow"].get(u, "*" if u not in [e["username"] for e in admins] else "")
        if not h:
            h = "$6$" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEF0123456789./") for _ in range(102))
        shadow.append(f"{u}:{h}:{int(inst // 86400)}:0:99999:7:::")
    f("/etc/shadow", "\n".join(shadow) + "\n", 0o640, "root", "shadow")
    f("/etc/hostname", host["hostname"] + "\n")
    f("/etc/hosts", f"127.0.0.1 localhost\n127.0.1.1 {host['hostname']}\n{host['db_host']} "
                    f"{host['db_hostname']} {host['db_hostname']}.{comp['domain']}\n\n"
                    "# The following lines are desirable for IPv6 capable hosts\n"
                    "::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\n"
                    "ff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n")
    f("/etc/os-release", 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nID_LIKE=debian\n'
                         f'PRETTY_NAME="{osd["pretty"]}"\nVERSION_ID="20.04"\nHOME_URL="https://www.ubuntu.com/"\n'
                         'SUPPORT_URL="https://help.ubuntu.com/"\nBUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
                         'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
                         'VERSION_CODENAME=focal\nUBUNTU_CODENAME=focal\n')
    f("/etc/issue", f"{osd['pretty']} \\n \\l\n\n")
    f("/etc/issue.net", f"{osd['pretty']}\n")
    f("/etc/lsb-release", f"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=20.04\nDISTRIB_CODENAME=focal\n"
                          f'DISTRIB_DESCRIPTION="{osd["pretty"]}"\n')
    f("/etc/debian_version", "bullseye/sid\n")
    f("/etc/resolv.conf", "# This file is managed by man:systemd-resolved(8). Do not edit.\n#\n"
                          "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch "
                          f"{comp['domain']}\n")
    f("/etc/timezone", "Etc/UTC\n")
    f("/etc/shells", "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/rbash\n"
                     "/usr/bin/rbash\n/bin/dash\n/usr/bin/dash\n/usr/bin/tmux\n/usr/bin/screen\n")
    f("/etc/sudoers", "#\n# This file MUST be edited with the 'visudo' command as root.\n#\nDefaults\tenv_reset\n"
                      "Defaults\tmail_badpass\nDefaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                      "/usr/bin:/sbin:/bin:/snap/bin\"\n\nroot\tALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n"
                      "%sudo\tALL=(ALL:ALL) ALL\n\n#includedir /etc/sudoers.d\n", 0o440)
    f("/etc/crontab", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                      "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"
                      "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
                      "47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
                      "52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
                      "30 2\t* * *\troot\t/opt/backup/db_backup.sh >> /var/log/db_backup.log 2>&1\n#\n")
    f("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n\n#Port 22\n#PermitRootLogin prohibit-password\n"
                              "PasswordAuthentication yes\nChallengeResponseAuthentication no\nUsePAM yes\n"
                              "X11Forwarding yes\nPrintMotd no\nAcceptEnv LANG LC_*\n"
                              "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n", 0o644)

    # -- /opt backup script: root DB password canary --------------------------
    dr("/opt/backup", 0o755)
    f("/opt/backup/db_backup.sh",
      "#!/bin/bash\n# nightly dump -> s3\nset -e\nTS=$(date +%F)\n"
      f"mysqldump -h {host['db_hostname']} -u root -p'{sec['db_root_password']}' --single-transaction "
      f"{sec['db_name']} | gzip > /var/backups/{sec['db_name']}_$TS.sql.gz\n"
      f"AWS_ACCESS_KEY_ID={sec['aws_access_key_id']} AWS_SECRET_ACCESS_KEY={sec['aws_secret_access_key']} \\\n"
      f"  aws s3 cp /var/backups/{sec['db_name']}_$TS.sql.gz s3://{sec['aws_bucket']}/db/ --region {sec['aws_region']}\n"
      "find /var/backups -name '*.sql.gz' -mtime +7 -delete\n", 0o750, "root", "deploy")
    for i in range(3):
        f(f"/var/backups/{sec['db_name']}_{datetime.fromtimestamp(time.time() - (i + 1) * 86400, timezone.utc):%Y-%m-%d}.sql.gz",
          "", 0o640, "root", "root", size=rng.randint(4_000_000, 9_000_000))

    # -- homes -----------------------------------------------------------------
    for u, uid, *_ in [x for x in sys_users if x[1] >= 1000]:
        home = f"/home/{u}" if u != "node" else None
        if not home:
            continue
        dr(home, 0o750, u)
        f(f"{home}/.bashrc", "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
                             "case $- in\n    *i*) ;;\n      *) return;;\nesac\nHISTCONTROL=ignoreboth\n"
                             "HISTSIZE=1000\nHISTFILESIZE=2000\nalias ll='ls -alF'\nalias la='ls -A'\n", 0o644, u)
        f(f"{home}/.profile", "# ~/.profile: executed by the command interpreter for login shells.\n"
                              'if [ -n "$BASH_VERSION" ]; then\n    if [ -f "$HOME/.bashrc" ]; then\n'
                              '\t. "$HOME/.bashrc"\n    fi\nfi\n', 0o644, u)
        dr(f"{home}/.ssh", 0o700, u)
        f(f"{home}/.ssh/authorized_keys",
          f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{''.join(rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/') for _ in range(43))} {u}@laptop\n",
          0o600, u)
    f("/home/deploy/.bash_history", "\n".join([
        "cd /var/www", "git pull origin master", "ls -la", f"mysql -h {host['db_hostname']} -u {sec['db_user']} -p",
        "sudo systemctl restart php7.4-fpm" if profile != "node-express-api" else "pm2 restart api",
        f"echo '{sec['deploy_password']}' | sudo -S systemctl reload nginx",
        "tail -f /var/log/nginx/error.log", "df -h", "crontab -l", "sudo /opt/backup/db_backup.sh",
        f"scp backup.sql.gz deploy@{host['db_hostname']}:/tmp/", "exit",
    ]) + "\n", 0o600, "deploy")
    f("/home/ubuntu/.bash_history", "sudo apt update\nsudo apt upgrade -y\nsudo reboot\nuptime\nexit\n", 0o600, "ubuntu")
    f("/root/.bash_history", "ls\ncat /opt/backup/db_backup.sh\nexit\n", 0o600)
    f("/root/.bashrc", "# ~/.bashrc\n", 0o644)

    # -- proc (dynamic) --------------------------------------------------------
    f("/proc/version", f"Linux version {osd['kernel']} (buildd@lcy02-amd64-001) ({osd['gcc']}, GNU ld "
                       f"(GNU Binutils for Ubuntu) 2.34) {osd['kernel_build']}\n", 0o444)
    f("/proc/cpuinfo", "", 0o444, dynamic="cpuinfo")
    f("/proc/meminfo", "", 0o444, dynamic="meminfo")
    f("/proc/uptime", "", 0o444, dynamic="uptime")
    f("/proc/loadavg", "", 0o444, dynamic="loadavg")
    dr("/proc/self")
    f("/proc/self/environ", "", 0o400, dynamic="environ")
    f("/proc/self/cmdline", "", 0o444, dynamic="cmdline")

    # -- logs ------------------------------------------------------------------
    now = time.time()
    auth_lines = []
    for i in range(24):
        ts = now - (24 - i) * rng.randint(1800, 7200)
        e = rng.choice(admins) if admins else None
        who = e["username"] if e and rng.random() < 0.7 else "deploy"
        src = f"10.{rng.randint(10, 60)}.{rng.randint(1, 30)}.{rng.randint(2, 250)}"
        pid = rng.randint(1000, 40000)
        auth_lines.append(f"{_fmt_syslog(ts)} {host['hostname']} sshd[{pid}]: Accepted publickey for {who} from "
                          f"{src} port {rng.randint(40000, 65000)} ssh2: ED25519 SHA256:"
                          + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                                    for _ in range(43)))
        auth_lines.append(f"{_fmt_syslog(ts)} {host['hostname']} sshd[{pid}]: pam_unix(sshd:session): session "
                          f"opened for user {who} by (uid=0)")
    f("/var/log/auth.log", "\n".join(auth_lines) + "\n", 0o640, "syslog", "adm")
    f("/var/log/syslog", "\n".join(
        f"{_fmt_syslog(now - (40 - i) * 900)} {host['hostname']} {rng.choice(['systemd[1]', 'CRON[%d]' % rng.randint(1000, 60000), 'kernel'])}: "
        f"{rng.choice(['Started Session of user deploy.', 'Starting Daily apt download activities...', '(root) CMD (cd / && run-parts --report /etc/cron.hourly)', 'Finished Message of the Day.', 'Started Rotate log files.'])}"
        for i in range(40)) + "\n", 0o640, "syslog", "adm")
    f("/var/log/db_backup.log", "", 0o644, size=rng.randint(2000, 9000))
    dr("/var/log/apt")

    # -- web stack -------------------------------------------------------------
    if profile == "nginx-php-legacy":
        _nginx_php_files(fs, f, dr, world, rng)
    elif profile == "ubuntu-admin-panel":
        _apache_ops_files(fs, f, dr, world, rng)
    else:
        _node_api_files(fs, f, dr, world, rng)
    return fs


def _env_file(world: World, app_env: str = "production") -> str:
    d, sec, comp = world.data, world.data["secrets"], world.data["company"]
    return (
        f"APP_NAME=\"{comp['name']}\"\nAPP_ENV={app_env}\nAPP_KEY={sec['app_key']}\nAPP_DEBUG=false\n"
        f"APP_URL=https://{'portal' if world.profile != 'node-express-api' else 'api'}.{comp['domain']}\n\n"
        f"DB_CONNECTION=mysql\nDB_HOST={d['host']['db_hostname']}\nDB_PORT=3306\nDB_DATABASE={sec['db_name']}\n"
        f"DB_USERNAME={sec['db_user']}\nDB_PASSWORD={sec['db_password']}\n\n"
        f"REDIS_HOST=127.0.0.1\nREDIS_PASSWORD={sec['redis_password']}\nREDIS_PORT=6379\n\n"
        f"MAIL_MAILER=smtp\nMAIL_HOST={sec['smtp_host']}\nMAIL_PORT=587\nMAIL_USERNAME={sec['smtp_user']}\n"
        f"MAIL_PASSWORD={sec['smtp_password']}\nMAIL_ENCRYPTION=tls\n\n"
        f"AWS_ACCESS_KEY_ID={sec['aws_access_key_id']}\nAWS_SECRET_ACCESS_KEY={sec['aws_secret_access_key']}\n"
        f"AWS_DEFAULT_REGION={sec['aws_region']}\nAWS_BUCKET={sec['aws_bucket']}\n\n"
        f"STRIPE_SECRET={sec['stripe_key']}\nJWT_SECRET={sec['jwt_secret']}\nSENTRY_DSN={sec['sentry_dsn']}\n"
    )


def env_file(world: World) -> str:
    return _env_file(world)


def _git(f, dr, root: str, world: World, repo: str, owner: str) -> None:
    sec = world.data["secrets"]
    dr(f"{root}/.git", 0o755, owner)
    f(f"{root}/.git/HEAD", "ref: refs/heads/master\n", owner=owner)
    f(f"{root}/.git/config", "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
                             "\tlogallrefupdates = true\n[remote \"origin\"]\n"
                             f"\turl = git@{sec['gitlab']}:web/{repo}.git\n"
                             "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"master\"]\n"
                             "\tremote = origin\n\tmerge = refs/heads/master\n", owner=owner)
    f(f"{root}/.git/description", "Unnamed repository; edit this file 'description' to name the repository.\n",
      owner=owner)


def _nginx_php_files(fs, f, dr, world: World, rng: random.Random) -> None:
    w = "/var/www/html"
    d, sec, host = world.data, world.data["secrets"], world.data["host"]
    dr("/etc/nginx")
    dr("/etc/nginx/sites-enabled")
    dr("/var/log/nginx", 0o755, "root", "adm")
    f("/etc/nginx/nginx.conf", "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\n"
                               "include /etc/nginx/modules-enabled/*.conf;\n\nevents {\n\tworker_connections 768;\n}\n\n"
                               "http {\n\tsendfile on;\n\ttcp_nopush on;\n\ttypes_hash_max_size 2048;\n"
                               "\tinclude /etc/nginx/mime.types;\n\tdefault_type application/octet-stream;\n"
                               "\tssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n\tssl_prefer_server_ciphers on;\n"
                               "\taccess_log /var/log/nginx/access.log;\n\terror_log /var/log/nginx/error.log;\n"
                               "\tgzip on;\n\tinclude /etc/nginx/conf.d/*.conf;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n")
    f("/etc/nginx/sites-enabled/default", "server {\n\tlisten 80 default_server;\n\tlisten [::]:80 default_server;\n"
                                          f"\troot {w};\n\tindex index.php index.html;\n\tserver_name _;\n\n"
                                          "\tlocation / {\n\t\ttry_files $uri $uri/ =404;\n\t}\n\n"
                                          "\tlocation ~ \\.php$ {\n\t\tinclude snippets/fastcgi-php.conf;\n"
                                          "\t\tfastcgi_pass unix:/run/php/php7.4-fpm.sock;\n\t}\n}\n")
    f("/var/log/nginx/access.log", "", 0o640, "www-data", "adm", size=rng.randint(200_000, 900_000))
    f("/var/log/nginx/error.log", "", 0o640, "www-data", "adm", size=rng.randint(5_000, 40_000))
    _php_app(f, dr, w, world, rng)


def _apache_ops_files(fs, f, dr, world: World, rng: random.Random) -> None:
    w = "/var/www/ops"
    dr("/etc/apache2")
    dr("/etc/apache2/sites-enabled")
    dr("/var/log/apache2", 0o750, "root", "adm")
    f("/etc/apache2/sites-enabled/000-default.conf",
      f"<VirtualHost *:80>\n\tServerAdmin webmaster@localhost\n\tDocumentRoot {w}\n\n"
      "\t<Directory /var/www/ops/>\n\t\tOptions -Indexes +FollowSymLinks\n\t\tAllowOverride All\n"
      "\t\tRequire all granted\n\t</Directory>\n\n\tErrorLog ${APACHE_LOG_DIR}/error.log\n"
      "\tCustomLog ${APACHE_LOG_DIR}/access.log combined\n</VirtualHost>\n")
    f("/etc/apache2/apache2.conf", "DefaultRuntimeDir ${APACHE_RUN_DIR}\nPidFile ${APACHE_PID_FILE}\n"
                                   "Timeout 300\nKeepAlive On\nMaxKeepAliveRequests 100\nKeepAliveTimeout 5\n"
                                   "User ${APACHE_RUN_USER}\nGroup ${APACHE_RUN_GROUP}\nHostnameLookups Off\n"
                                   "ErrorLog ${APACHE_LOG_DIR}/error.log\nLogLevel warn\n"
                                   "IncludeOptional mods-enabled/*.load\nIncludeOptional mods-enabled/*.conf\n"
                                   "Include ports.conf\nAccessFileName .htaccess\n"
                                   "IncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n")
    f("/var/log/apache2/access.log", "", 0o640, "root", "adm", size=rng.randint(200_000, 900_000))
    _php_app(f, dr, w, world, rng, ops=True)


def _php_app(f, dr, w: str, world: World, rng: random.Random, ops: bool = False) -> None:
    d, sec, host = world.data, world.data["secrets"], world.data["host"]
    dr(w, 0o755, "www-data")
    _git(f, dr, w, world, "ops-console" if ops else "portal", "www-data")
    f(f"{w}/.env", _env_file(world), 0o644, "www-data")
    cfg = ("<?php\n// Database configuration\n"
           f"define('DB_HOST', '{host['db_hostname']}');\ndefine('DB_USER', '{sec['db_user']}');\n"
           f"define('DB_PASS', '{sec['db_password']}');\ndefine('DB_NAME', '{sec['db_name']}');\n\n"
           "$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);\nif (!$conn) {\n"
           "    die('Connection failed: ' . mysqli_connect_error());\n}\nsession_start();\n")
    f(f"{w}/config.php", cfg, 0o640, "www-data")
    f(f"{w}/config.php.bak", cfg.replace("session_start();\n", ""), 0o644, "www-data",
      mtime=host["installed"] + 120 * 86400)
    dr(f"{w}/assets", 0o755, "www-data")
    f(f"{w}/assets/style.css", "body{font-family:Arial,Helvetica,sans-serif;margin:0;background:#f4f6f8;color:#222}\n",
      owner="www-data")
    f(f"{w}/robots.txt", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /uploads/\n" if not ops
      else "User-agent: *\nDisallow: /\n", owner="www-data")
    f(f"{w}/info.php", "<?php phpinfo(); ?>\n", owner="www-data")
    if ops:
        f(f"{w}/index.php", "<?php\nrequire 'config.php';\nif (isset($_SESSION['user'])) { header('Location: dashboard.php'); exit; }\n"
                            "include 'templates/login.php';\n", owner="www-data")
        f(f"{w}/login.php", "<?php\nrequire 'config.php';\n$u = $_POST['username'];\n$p = md5($_POST['password']);\n"
                            "$r = mysqli_query($conn, \"SELECT * FROM users WHERE username='$u' AND password='$p' AND role='admin'\");\n"
                            "if ($row = mysqli_fetch_assoc($r)) { $_SESSION['user'] = $row['username']; header('Location: dashboard.php'); }\n"
                            "else { header('Location: index.php?error=1'); }\n", owner="www-data")
        f(f"{w}/dashboard.php", "<?php\nrequire 'config.php';\nrequire 'auth.php';\ninclude 'templates/dashboard.php';\n",
          owner="www-data")
        dr(f"{w}/tools", 0o755, "www-data")
        f(f"{w}/tools/diagnostics.php", "<?php\nrequire '../config.php';\nrequire '../auth.php';\n"
                                        "$host = $_GET['host'] ?? '';\n$tool = $_GET['tool'] ?? 'ping';\nif ($host) {\n"
                                        "    if ($tool == 'ping') { $out = shell_exec('ping -c 4 ' . $host); }\n"
                                        "    elseif ($tool == 'dig') { $out = shell_exec('dig +short ' . $host); }\n"
                                        "    else { $out = shell_exec('traceroute -m 10 ' . $host); }\n}\n"
                                        "include '../templates/diagnostics.php';\n", owner="www-data")
        f(f"{w}/logs.php", "<?php\nrequire 'config.php';\nrequire 'auth.php';\n$file = $_GET['file'] ?? 'syslog';\n"
                           "$content = file_get_contents('/var/log/' . $file);\ninclude 'templates/logs.php';\n",
          owner="www-data")
    else:
        f(f"{w}/index.php", "<?php\nrequire 'config.php';\n$r = mysqli_query($conn, 'SELECT id, name, price FROM products');\n"
                            "include 'templates/home.php';\n", owner="www-data")
        f(f"{w}/product.php", "<?php\nrequire 'config.php';\n$id = $_GET['id'];\n"
                              "$r = mysqli_query($conn, \"SELECT id, name, price, description FROM products WHERE id = $id\")\n"
                              "    or die(mysqli_error($conn));\n$p = mysqli_fetch_assoc($r);\ninclude 'templates/product.php';\n",
          owner="www-data")
        f(f"{w}/login.php", "<?php\nrequire 'config.php';\nif ($_SERVER['REQUEST_METHOD'] == 'POST') {\n"
                            "    $u = $_POST['username'];\n    $p = md5($_POST['password']);\n"
                            "    $r = mysqli_query($conn, \"SELECT * FROM users WHERE username='$u' AND password='$p'\");\n"
                            "    if ($row = mysqli_fetch_assoc($r)) {\n        $_SESSION['user'] = $row;\n"
                            "        header('Location: /admin/');\n        exit;\n    }\n    $error = 'Invalid username or password';\n}\n"
                            "include 'templates/login.php';\n", owner="www-data")
        f(f"{w}/download.php", "<?php\n$file = $_GET['file'];\n$path = 'uploads/' . $file;\n"
                               "header('Content-Type: application/octet-stream');\n"
                               "readfile($path);\n", owner="www-data")
        dr(f"{w}/admin", 0o755, "www-data")
        f(f"{w}/admin/index.php", "<?php\nrequire '../config.php';\nif (!isset($_SESSION['user'])) { header('Location: /login.php'); exit; }\n"
                                  "include '../templates/admin.php';\n", owner="www-data")
        f(f"{w}/admin/users.php", "<?php\nrequire '../config.php';\nif (!isset($_SESSION['user'])) { header('Location: /login.php'); exit; }\n"
                                  "$r = mysqli_query($conn, 'SELECT id, username, email, role, active FROM users');\n"
                                  "include '../templates/users.php';\n", owner="www-data")
        f(f"{w}/admin/tools.php", "<?php\nrequire '../config.php';\nif (!isset($_SESSION['user'])) { header('Location: /login.php'); exit; }\n"
                                  "if (isset($_POST['host'])) {\n    $output = shell_exec('ping -c 4 ' . $_POST['host']);\n}\n"
                                  "include '../templates/tools.php';\n", owner="www-data")
        dr(f"{w}/uploads", 0o755, "www-data")
        for i in range(6):
            f(f"{w}/uploads/invoice_{rng.randint(10000, 19999)}.pdf", "", 0o644, "www-data",
              size=rng.randint(30_000, 220_000))
        dr(f"{w}/backup", 0o755, "www-data")
    dr(f"{w}/templates", 0o755, "www-data")


def _node_api_files(fs, f, dr, world: World, rng: random.Random) -> None:
    w = "/srv/app"
    d, sec, comp = world.data, world.data["secrets"], world.data["company"]
    dr(w, 0o755, "node")
    _git(f, dr, w, world, "api", "node")
    f(f"{w}/.env", _env_file(world).replace("DB_CONNECTION=mysql\n", "") + "PORT=3000\nNODE_ENV=production\n",
      0o600, "node")
    f(f"{w}/package.json", "{\n" f'  "name": "{comp["slug"]}-api",\n  "version": "2.3.1",\n  "private": true,\n'
                           '  "main": "server.js",\n  "scripts": {\n    "start": "node server.js"\n  },\n'
                           '  "dependencies": {\n    "bcryptjs": "^2.4.3",\n    "dotenv": "^16.0.3",\n'
                           '    "express": "^4.18.2",\n    "express-graphql": "^0.12.0",\n    "graphql": "^15.8.0",\n'
                           '    "jsonwebtoken": "^9.0.0",\n    "mysql2": "^3.2.0"\n  }\n}\n', owner="node")
    f(f"{w}/server.js", "require('dotenv').config();\nconst express = require('express');\nconst app = express();\n"
                        "app.use(express.json());\napp.use(express.static(__dirname, { dotfiles: 'allow' }));\n"
                        "app.use('/api/v1', require('./src/routes'));\napp.use('/graphql', require('./src/graphql'));\n"
                        "app.listen(process.env.PORT || 3000);\n", owner="node")
    dr(f"{w}/src", 0o755, "node")
    dr(f"{w}/src/routes", 0o755, "node")
    f(f"{w}/src/routes/index.js", "const router = require('express').Router();\nrouter.use('/auth', require('./auth'));\n"
                                  "router.use('/users', require('./users'));\nrouter.use('/orders', require('./orders'));\n"
                                  "router.use('/backups', require('./backups'));\nmodule.exports = router;\n", owner="node")
    f(f"{w}/src/routes/users.js", "const db = require('../db');\nconst router = require('express').Router();\n"
                                  "const auth = require('../middleware/auth');\n"
                                  "router.get('/', auth, async (req, res) => {\n  const q = req.query.search || '';\n  try {\n"
                                  "    const [rows] = await db.query(`SELECT id, username, email, first_name, last_name, role, "
                                  "department, active, created_at FROM users WHERE username LIKE '%${q}%'`);\n"
                                  "    res.json(rows);\n  } catch (err) {\n"
                                  "    res.status(500).json({ error: err.message, code: err.code, errno: err.errno, sqlState: err.sqlState });\n"
                                  "  }\n});\nmodule.exports = router;\n", owner="node")
    f(f"{w}/src/routes/backups.js", "const fs = require('fs');\nconst path = require('path');\n"
                                    "const router = require('express').Router();\nrouter.get('/download', (req, res) => {\n"
                                    "  const p = path.join('/srv/app/backups', req.query.file);\n"
                                    "  res.send(fs.readFileSync(p, 'utf8'));\n});\nmodule.exports = router;\n", owner="node")
    dr(f"{w}/backups", 0o755, "node")
    f(f"{w}/backups/README.txt", "Nightly exports are pushed to S3. Local copies are kept for 7 days.\n", owner="node")
    dr(f"{w}/node_modules", 0o755, "node")
    dr(f"{w}/logs", 0o755, "node")


# ---------------------------------------------------------------------------
# Dynamic /proc content
# ---------------------------------------------------------------------------

def render_dynamic(world: World, name: str, ctx: dict) -> str:
    host = world.data["host"]
    up = world.uptime_seconds()
    if name == "uptime":
        return f"{up:.2f} {up * host['cpus'] * 0.93:.2f}\n"
    if name == "loadavg":
        return f"0.{int(up) % 40 + 5:02d} 0.{int(up) % 30 + 8:02d} 0.{int(up) % 25 + 11:02d} 1/{180 + int(up) % 60} {int(up) % 32000 + 1000}\n"
    if name == "meminfo":
        total = host["mem_mb"] * 1024
        free = int(total * 0.18)
        return (f"MemTotal:       {total:>8} kB\nMemFree:        {free:>8} kB\nMemAvailable:   {int(total * 0.52):>8} kB\n"
                f"Buffers:        {int(total * 0.03):>8} kB\nCached:         {int(total * 0.29):>8} kB\n"
                f"SwapCached:            0 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n")
    if name == "cpuinfo":
        blocks = []
        for i in range(host["cpus"]):
            blocks.append(f"processor\t: {i}\nvendor_id\t: {'AuthenticAMD' if 'AMD' in host['cpu_model'] else 'GenuineIntel'}\n"
                          f"model name\t: {host['cpu_model']}\ncpu MHz\t\t: 2499.998\ncache size\t: 36608 KB\n"
                          f"physical id\t: 0\ncpu cores\t: {host['cpus']}\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic "
                          "sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm "
                          "constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq "
                          "ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand "
                          "hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 avx2 smep bmi2 "
                          "erms invpcid mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl "
                          "xsaveopt xsavec xgetbv1 xsaves ida arat pku ospke\n")
        return "\n".join(blocks) + "\n"
    if name == "environ":
        user = ctx.get("user", "www-data")
        if world.profile == "node-express-api":
            env = {"NODE_ENV": "production", "PORT": "3000", "HOME": "/srv/app", "USER": "node",
                   "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD": "/srv/app"}
        else:
            env = {"USER": user, "HOME": "/var/www", "PATH": "/usr/local/bin:/usr/bin:/bin"}
        return "\0".join(f"{k}={v}" for k, v in env.items()) + "\0"
    if name == "cmdline":
        if world.profile == "node-express-api":
            return "node\0/srv/app/server.js\0"
        if world.profile == "ubuntu-admin-panel":
            return "/usr/sbin/apache2\0-k\0start\0"
        return "php-fpm: pool www\0\0\0\0\0\0"
    return ""


# ---------------------------------------------------------------------------
# Runtime view: base + world overlay + session overlay
# ---------------------------------------------------------------------------

class FsError(Exception):
    def __init__(self, kind: str, path: str):
        super().__init__(kind)
        self.kind = kind      # ENOENT | EACCES | EISDIR | ENOTDIR
        self.path = path


class VirtualFS:
    def __init__(self, world: World, world_overlay: dict[str, dict], session_overlay: dict[str, dict]):
        self.world = world
        self.base = world.vfs
        self.world_overlay = world_overlay
        self.overlay = session_overlay
        self.dirty: dict[str, dict] = {}

    # -- lookup ----------------------------------------------------------------
    def _raw(self, path: str) -> Node | None:
        if path in self.overlay:
            entry = self.overlay[path]
            return None if entry.get("deleted") else Node.from_json(entry)
        if path in self.world_overlay:
            return Node.from_json(self.world_overlay[path])
        return self.base.get(path)

    def normalize(self, path: str, cwd: str = "/") -> str:
        if not path:
            return cwd
        if not path.startswith("/"):
            path = posixpath.join(cwd, path)
        norm = posixpath.normpath(path)
        if norm.startswith("//"):
            norm = "/" + norm.lstrip("/")
        return norm

    def resolve(self, path: str, cwd: str = "/", depth: int = 0) -> str:
        """Normalize and resolve symlinks in each component."""
        path = self.normalize(path, cwd)
        if depth > 8:
            return path
        parts = [p for p in path.split("/") if p]
        cur = "/"
        for i, part in enumerate(parts):
            nxt = posixpath.join(cur, part)
            node = self._raw(nxt)
            if node and node.kind == "link":
                target = node.target if node.target.startswith("/") else posixpath.join(cur, node.target)
                rest = "/".join(parts[i + 1:])
                return self.resolve(posixpath.join(target, rest) if rest else target, "/", depth + 1)
            cur = nxt
        return cur

    def get(self, path: str, cwd: str = "/") -> Node | None:
        p = self.resolve(path, cwd)
        node = self._raw(p)
        if node is None and self._has_children(p):
            return Node("dir", "", 0o755, "root", "root", self.world.data["host"]["installed"])
        return node

    def _all_paths(self) -> set[str]:
        paths = set(self.base) | set(self.world_overlay)
        for p, e in self.overlay.items():
            if e.get("deleted"):
                paths.discard(p)
            else:
                paths.add(p)
        return paths

    def _has_children(self, path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        return any(p.startswith(prefix) for p in self._all_paths())

    def exists(self, path: str, cwd: str = "/") -> bool:
        return self.get(path, cwd) is not None

    def is_dir(self, path: str, cwd: str = "/") -> bool:
        n = self.get(path, cwd)
        return bool(n and n.kind == "dir")

    # -- permissions -------------------------------------------------------------
    @staticmethod
    def can(node: Node, user: str, groups: tuple[str, ...], want: int) -> bool:
        """want: 4 read, 2 write, 1 exec."""
        if user == "root":
            return True
        if node.owner == user:
            return bool((node.mode >> 6) & want)
        if node.group in groups:
            return bool((node.mode >> 3) & want)
        return bool(node.mode & want)

    def _check_parents(self, path: str, user: str, groups: tuple[str, ...]) -> None:
        cur = "/"
        for part in [p for p in path.split("/") if p][:-1]:
            cur = posixpath.join(cur, part)
            n = self.get(cur)
            if n is None:
                raise FsError("ENOENT", path)
            if n.kind != "dir":
                raise FsError("ENOTDIR", path)
            if not self.can(n, user, groups, 1):
                raise FsError("EACCES", path)

    # -- operations ------------------------------------------------------------
    def read(self, path: str, cwd: str = "/", user: str = "root", groups: tuple[str, ...] = (),
             ctx: dict | None = None) -> str:
        p = self.resolve(path, cwd)
        self._check_parents(p, user, groups)
        node = self.get(p)
        if node is None:
            raise FsError("ENOENT", p)
        if node.kind == "dir":
            raise FsError("EISDIR", p)
        if not self.can(node, user, groups, 4):
            raise FsError("EACCES", p)
        if node.dynamic:
            return render_dynamic(self.world, node.dynamic, ctx or {"user": user})
        if node.size and not node.content:
            return binary_blob(p, node.size)
        return node.content

    def listdir(self, path: str, cwd: str = "/", user: str = "root", groups: tuple[str, ...] = ()) -> list[tuple[str, Node]]:
        p = self.resolve(path, cwd)
        node = self.get(p)
        if node is None:
            raise FsError("ENOENT", p)
        if node.kind != "dir":
            return [(posixpath.basename(p), node)]
        if not self.can(node, user, groups, 4):
            raise FsError("EACCES", p)
        prefix = p.rstrip("/") + "/"
        names: dict[str, Node] = {}
        for full in self._all_paths():
            if full.startswith(prefix) and full != p:
                rest = full[len(prefix):]
                name = rest.split("/", 1)[0]
                if name not in names:
                    names[name] = self.get(prefix + name) or Node("dir")
        return sorted(names.items(), key=lambda kv: kv[0].lower().lstrip("."))

    def write(self, path: str, content: str, cwd: str = "/", user: str = "root", groups: tuple[str, ...] = (),
              append: bool = False, mode: int = 0o644) -> None:
        p = self.resolve(path, cwd)
        self._check_parents(p, user, groups)
        parent = self.get(posixpath.dirname(p))
        existing = self.get(p)
        if existing and existing.kind == "dir":
            raise FsError("EISDIR", p)
        if existing:
            if not self.can(existing, user, groups, 2):
                raise FsError("EACCES", p)
        elif parent and not self.can(parent, user, groups, 2):
            raise FsError("EACCES", p)
        old = ""
        if append and existing:
            old = existing.content
        node = Node("file", old + content, existing.mode if existing else mode, existing.owner if existing else user,
                    existing.group if existing else user, time.time())
        self._set(p, node.to_json())

    def mkdir(self, path: str, cwd: str = "/", user: str = "root", groups: tuple[str, ...] = ()) -> None:
        p = self.resolve(path, cwd)
        if self.exists(p):
            raise FsError("EEXIST", p)
        self._check_parents(p, user, groups)
        parent = self.get(posixpath.dirname(p))
        if parent and not self.can(parent, user, groups, 2):
            raise FsError("EACCES", p)
        self._set(p, Node("dir", "", 0o755, user, user, time.time()).to_json())

    def delete(self, path: str, cwd: str = "/", user: str = "root", groups: tuple[str, ...] = (),
               recursive: bool = False) -> None:
        p = self.resolve(path, cwd)
        node = self.get(p)
        if node is None:
            raise FsError("ENOENT", p)
        parent = self.get(posixpath.dirname(p))
        if parent and not self.can(parent, user, groups, 2):
            raise FsError("EACCES", p)
        if node.kind == "dir":
            if not recursive:
                raise FsError("EISDIR", p)
            prefix = p.rstrip("/") + "/"
            for full in list(self._all_paths()):
                if full.startswith(prefix):
                    self._set(full, {"deleted": True})
        self._set(p, {"deleted": True})

    def chmod(self, path: str, mode: int, cwd: str = "/", user: str = "root") -> None:
        p = self.resolve(path, cwd)
        node = self.get(p)
        if node is None:
            raise FsError("ENOENT", p)
        if user not in ("root", node.owner):
            raise FsError("EPERM", p)
        node.mode = mode
        self._set(p, node.to_json())

    def _set(self, path: str, entry: dict) -> None:
        self.overlay[path] = entry
        self.dirty[path] = entry


def binary_blob(path: str, size: int) -> str:
    """Deterministic pseudo-binary content for files we only know the size of."""
    rng = random.Random(path)
    n = min(size, 2048)
    if path.endswith(".gz"):
        head = "\x1f\x8b\x08\x00"
    elif path.endswith(".pdf"):
        head = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    else:
        head = "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00"
    return head + "".join(chr(rng.randint(0, 255)) for _ in range(n))


FS_ERR_TEXT = {
    "ENOENT": "No such file or directory",
    "EACCES": "Permission denied",
    "EISDIR": "Is a directory",
    "ENOTDIR": "Not a directory",
    "EEXIST": "File exists",
    "EPERM": "Operation not permitted",
}


def fmt_mode(node: Node) -> str:
    t = {"dir": "d", "link": "l"}.get(node.kind, "-")
    bits = ""
    for shift in (6, 3, 0):
        v = (node.mode >> shift) & 7
        bits += ("r" if v & 4 else "-") + ("w" if v & 2 else "-") + ("x" if v & 1 else "-")
    if node.mode & 0o1000:
        bits = bits[:-1] + ("t" if node.mode & 1 else "T")
    return t + bits


def node_size(node: Node) -> int:
    if node.kind == "dir":
        return 4096
    if node.kind == "link":
        return len(node.target)
    if node.size is not None and not node.content:
        return node.size
    return len(node.content.encode("utf-8", "surrogateescape"))
