"""Procedural, deterministic "world" generation.

Everything the attacker can observe (company, people, credentials, database rows,
files, versions) derives from a single seed. The core data is persisted in
``world.json``; the virtual filesystem is rebuilt from it on load, so it is always
consistent with the data an attacker may have already seen through another vector.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import secrets
import string
import time
from dataclasses import dataclass, field
from pathlib import Path

FIRST_NAMES = [
    "Laura", "Daniel", "Sofia", "Martin", "Lucia", "Pablo", "Elena", "Javier", "Carmen", "Diego",
    "Andrea", "Sergio", "Marta", "Alberto", "Paula", "Raul", "Irene", "Hector", "Claudia", "Ivan",
    "Emma", "Oliver", "Grace", "Henry", "Chloe", "Lucas", "Mia", "Ethan", "Zoe", "Nathan",
    "Hannah", "Samuel", "Ava", "Adrian", "Julia", "Victor", "Nora", "Felix", "Alicia", "Tomas",
    "Rebecca", "Marcus", "Ines", "Oscar", "Natalia", "Kevin", "Sara", "Ruben", "Eva", "Gabriel",
]
LAST_NAMES = [
    "Garcia", "Martinez", "Lopez", "Sanchez", "Romero", "Navarro", "Torres", "Ortega", "Delgado",
    "Castro", "Moreno", "Vidal", "Herrera", "Molina", "Iglesias", "Ramos", "Pascual", "Serrano",
    "Mitchell", "Turner", "Parker", "Collins", "Bennett", "Hughes", "Foster", "Bryant", "Coleman",
    "Reed", "Ward", "Hayes", "Fisher", "Graham", "Wallace", "Porter", "Hunter", "Spencer", "Webb",
    "Lindqvist", "Novak", "Brandt", "Keller", "Moretti", "Duarte", "Silva", "Kowalski", "Weber",
]
COMPANY_PREFIX = [
    "Norvane", "Altheris", "Quenby", "Corvista", "Halvorn", "Brintel", "Veldmark", "Talmora",
    "Kestrin", "Orlenta", "Pravex", "Lumora", "Stellan", "Varnex", "Tessaro", "Ombrel",
]
SECTORS = {
    "Logistics": ["Pallet Tracker Pro", "Fleet GPS Unit", "Cold Chain Sensor", "Route Planner License",
                  "Dock Scheduler", "Barcode Scanner X2", "Warehouse Label Pack", "Customs Filing Service"],
    "Health": ["Patient Portal License", "Vitals Monitor M3", "Lab Sync Module", "Telehealth Seat",
               "e-Prescription Add-on", "Clinic Scheduler", "HL7 Gateway", "Records Archive 1TB"],
    "Retail": ["POS Terminal T5", "Receipt Printer", "Inventory Sync", "Loyalty Module",
               "Self-Checkout Kiosk", "Handheld Scanner", "Shelf Label Pack", "Gift Card Stock"],
    "Energy": ["Smart Meter SM-200", "Grid Analytics Seat", "Field Tablet", "SCADA Connector",
               "Load Forecast Module", "Inverter Monitor", "Substation Sensor", "Outage Map License"],
}
DEPARTMENTS = {
    "IT": ["Systems Administrator", "DevOps Engineer", "IT Support Technician", "Security Analyst",
           "Backend Developer", "IT Manager"],
    "Finance": ["Accountant", "Financial Controller", "Accounts Payable Clerk", "CFO"],
    "Sales": ["Account Executive", "Sales Manager", "Sales Representative", "Customer Success Manager"],
    "Operations": ["Operations Manager", "Logistics Coordinator", "Warehouse Supervisor", "COO"],
    "HR": ["HR Generalist", "Recruiter", "HR Director"],
    "Management": ["CEO", "Office Manager", "Executive Assistant"],
}
WEAK_PASSWORDS = [
    "Summer2023!", "Welcome1", "Password123", "Company2024", "Qwerty123!", "Spring2024",
    "Winter2023!", "Admin@123", "Changeme1", "Football1", "Monday123", "Passw0rd!",
]
SSH_WEAK = [
    ("root", "admin123"), ("root", "P@ssw0rd"), ("root", "toor2023"), ("admin", "admin2024"),
    ("ubuntu", "ubuntu123"), ("deploy", "deploy2023"),
]
CITIES = [("Madrid", "ES"), ("Barcelona", "ES"), ("Valencia", "ES"), ("Austin", "US"),
          ("Denver", "US"), ("Rotterdam", "NL"), ("Lyon", "FR"), ("Porto", "PT")]

UBUNTU = {
    "pretty": "Ubuntu 20.04.6 LTS",
    "codename": "focal",
    "kernel": "5.4.0-169-generic",
    "kernel_build": "#187-Ubuntu SMP Thu Nov 23 14:52:28 UTC 2023",
    "gcc": "gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)",
}

PROFILE_STACKS = {
    "nginx-php-legacy": {"webroot": "/var/www/html", "web_user": "www-data", "server": "nginx",
                         "server_version": "1.18.0", "php": "7.4.3-4ubuntu2.19", "app": "portal"},
    "ubuntu-admin-panel": {"webroot": "/var/www/ops", "web_user": "www-data", "server": "apache2",
                           "server_version": "2.4.41", "php": "7.4.3-4ubuntu2.19", "app": "ops"},
    "node-express-api": {"webroot": "/srv/app", "web_user": "node", "server": "node",
                         "server_version": "v16.20.2", "php": "", "app": "api"},
}


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _rand_str(rng: random.Random, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _fake_bcrypt(rng: random.Random) -> str:
    alphabet = "./" + string.ascii_uppercase + string.ascii_lowercase + string.digits
    return "$2y$10$" + _rand_str(rng, 53, alphabet)


def _fake_sha512crypt(rng: random.Random) -> str:
    alphabet = "./" + string.ascii_letters + string.digits
    return f"$6${_rand_str(rng, 16, alphabet)}${_rand_str(rng, 86, alphabet)}"


@dataclass
class World:
    data: dict
    vfs: dict = field(default_factory=dict)

    # convenient accessors ----------------------------------------------
    def __getitem__(self, key):
        return self.data[key]

    @property
    def profile(self) -> str:
        return self.data["profile"]

    @property
    def stack(self) -> dict:
        return PROFILE_STACKS[self.profile]

    @property
    def hostname(self) -> str:
        return self.data["host"]["hostname"]

    @property
    def company(self) -> dict:
        return self.data["company"]

    def uptime_seconds(self, now: float | None = None) -> float:
        return (now or time.time()) - self.data["host"]["boot_time"]

    def canaries(self) -> list[tuple[str, str, str]]:
        s = self.data["secrets"]
        out = [
            (s["db_password"], "password", "MySQL app user password"),
            (s["db_root_password"], "password", "MySQL root password"),
            (s["aws_access_key_id"], "aws_key", "AWS access key id"),
            (s["aws_secret_access_key"], "aws_secret", "AWS secret key"),
            (s["jwt_secret"], "secret", "JWT signing secret"),
            (s["stripe_key"], "api_key", "Stripe key"),
            (s["smtp_password"], "password", "SMTP password"),
            (s["redis_password"], "password", "Redis password"),
            (s["app_key"], "secret", "APP_KEY"),
            (s["deploy_password"], "password", "deploy user password (bash_history)"),
        ]
        for emp in self.data["employees"]:
            out.append((emp["password"], "password", f"employee {emp['username']} password"))
        return out

    def find_employee(self, username: str) -> dict | None:
        for emp in self.data["employees"]:
            if emp["username"] == username or emp["email"] == username:
                return emp
        return None

    def system_password_ok(self, username: str, password: str) -> bool:
        for user, pw in self.data["ssh_accept"]:
            if user == username and pw == password:
                return True
        emp = self.find_employee(username)
        return bool(emp and emp.get("shell_access") and emp["password"] == password)


def generate_world(profile: str, seed: int = 0, domain: str = "") -> dict:
    if profile not in PROFILE_STACKS:
        raise ValueError(f"unknown profile {profile!r}")
    seed = seed or secrets.randbelow(2**31 - 1) + 1
    rng = random.Random(seed)
    now = time.time()

    prefix = rng.choice(COMPANY_PREFIX)
    sector = rng.choice(list(SECTORS))
    company_name = f"{prefix} {sector}"
    slug = prefix.lower()
    domain = domain or f"{slug}-{sector.lower()}.com"
    city, country = rng.choice(CITIES)

    # host ---------------------------------------------------------------
    net = f"10.{rng.randint(10, 60)}.{rng.randint(1, 30)}"
    host_octet = rng.randint(10, 60)
    role = {"nginx-php-legacy": "web", "ubuntu-admin-panel": "ops", "node-express-api": "api"}[profile]
    host = {
        "hostname": f"{role}-prod-{rng.randint(1, 4):02d}",
        "ip": f"{net}.{host_octet}",
        "netmask": "255.255.255.0",
        "gateway": f"{net}.1",
        "db_host": f"{net}.{host_octet + rng.randint(2, 9)}",
        "db_hostname": "db-prod-01",
        "mac": "02:42:" + ":".join(f"{rng.randint(0, 255):02x}" for _ in range(4)),
        "boot_time": now - rng.randint(9, 140) * 86400 - rng.randint(0, 86400),
        "cpus": rng.choice([2, 4, 4, 8]),
        "mem_mb": rng.choice([3936, 7957, 7957, 15990]),
        "disk_gb": rng.choice([40, 80, 80, 160]),
        "disk_used_pct": rng.randint(31, 78),
        "cpu_model": rng.choice([
            "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
            "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz",
            "AMD EPYC 7R32",
        ]),
        "installed": now - rng.randint(500, 1400) * 86400,
    }

    # people --------------------------------------------------------------
    employees = []
    used = set()
    n_emp = rng.randint(34, 58)
    for i in range(n_emp):
        while True:
            first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
            username = (first[0] + last).lower()
            if username not in used:
                used.add(username)
                break
        dept = rng.choices(list(DEPARTMENTS), weights=[3, 2, 4, 3, 1, 1])[0]
        title = rng.choice(DEPARTMENTS[dept])
        password = rng.choice(WEAK_PASSWORDS) if rng.random() < 0.35 else (
            rng.choice(["Ilove", "Mi", "The", "My"]) + rng.choice(["Dog", "Casa", "Team", "Beach"])
            + str(rng.randint(10, 99)) + rng.choice(["!", "#", "", "."])
        )
        created = host["installed"] + rng.randint(0, 400) * 86400
        employees.append({
            "id": i + 1,
            "first": first,
            "last": last,
            "username": username,
            "email": f"{username}@{domain}",
            "department": dept,
            "title": title,
            "phone": f"+{ {'ES': 34, 'US': 1, 'NL': 31, 'FR': 33, 'PT': 351}[country] } "
                     f"{rng.randint(600, 699)} {rng.randint(100, 999)} {rng.randint(100, 999)}",
            "password": password,
            "md5": _md5(password),
            "bcrypt": _fake_bcrypt(rng),
            "role": "admin" if title in ("Systems Administrator", "IT Manager", "DevOps Engineer", "CEO") else "user",
            "active": 0 if rng.random() < 0.08 else 1,
            "created_at": created,
            "last_login": now - rng.randint(0, 30) * 86400 - rng.randint(0, 86400),
            "shell_access": title in ("Systems Administrator", "DevOps Engineer", "Backend Developer"),
            "uid": 1001 + i,
        })

    # secrets -------------------------------------------------------------
    upper_digits = string.ascii_uppercase + string.digits
    sec = {
        "db_name": f"{slug}_{'portal' if role == 'web' else role}",
        "db_user": f"{slug}_app",
        "db_password": _rand_str(rng, 6) + rng.choice(["!", "#", "$"]) + _rand_str(rng, 8),
        "db_root_password": f"{prefix}{rng.randint(2018, 2023)}!db",
        "app_key": "base64:" + base64.b64encode(rng.randbytes(32)).decode(),
        "jwt_secret": _rand_str(rng, 48, string.ascii_lowercase + string.digits),
        "aws_access_key_id": "AKIA" + _rand_str(rng, 16, upper_digits),
        "aws_secret_access_key": _rand_str(rng, 40, string.ascii_letters + string.digits + "+/"),
        "aws_bucket": f"{slug}-prod-backups",
        "aws_region": rng.choice(["eu-west-1", "eu-central-1", "us-east-1", "us-west-2"]),
        "stripe_key": "sk_live_" + _rand_str(rng, 24),
        "smtp_host": f"smtp.{domain}",
        "smtp_user": f"noreply@{domain}",
        "smtp_password": _rand_str(rng, 14),
        "redis_password": _rand_str(rng, 20, string.ascii_lowercase + string.digits),
        "deploy_password": f"{prefix.lower()}Deploy{rng.randint(10, 99)}",
        "sentry_dsn": f"https://{_rand_str(rng, 32, '0123456789abcdef')}@o{rng.randint(100000, 999999)}"
                      f".ingest.sentry.io/{rng.randint(1000000, 9999999)}",
        "gitlab": f"gitlab.{domain}",
    }

    # business data -------------------------------------------------------
    product_names = SECTORS[sector]
    products = []
    for i, name in enumerate(product_names):
        products.append({
            "id": i + 1,
            "sku": f"{prefix[:3].upper()}-{rng.randint(1000, 9999)}",
            "name": name,
            "price": round(rng.uniform(19, 2400), 2),
            "stock": rng.randint(0, 900),
            "description": f"{name} for {sector.lower()} operations. Supplied and supported by {company_name}.",
        })
    customers = []
    for i in range(rng.randint(90, 160)):
        first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
        cdomain = rng.choice(["gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me"])
        customers.append({
            "id": i + 1,
            "name": f"{first} {last}",
            "email": f"{first.lower()}.{last.lower()}{rng.randint(1, 99)}@{cdomain}",
            "phone": f"+{rng.randint(1, 49)} {rng.randint(600, 799)} {rng.randint(100000, 999999)}",
            "city": rng.choice(CITIES)[0],
            "created_at": host["installed"] + rng.randint(0, 700) * 86400,
            "card_last4": f"{rng.randint(0, 9999):04d}",
        })
    orders = []
    for i in range(rng.randint(220, 380)):
        p = rng.choice(products)
        qty = rng.randint(1, 12)
        orders.append({
            "id": 10000 + i,
            "customer_id": rng.choice(customers)["id"],
            "product_id": p["id"],
            "qty": qty,
            "total": round(p["price"] * qty, 2),
            "status": rng.choices(["paid", "shipped", "pending", "refunded", "cancelled"],
                                  weights=[5, 6, 2, 1, 1])[0],
            "created_at": now - rng.randint(0, 365) * 86400 - rng.randint(0, 86400),
        })

    # ssh: deterministic weak credentials accepted by this instance ---------
    ssh_accept = rng.sample(SSH_WEAK, 2) + [["deploy", sec["deploy_password"]]]

    return {
        "version": 1,
        "seed": seed,
        "profile": profile,
        "created": now,
        "company": {"name": company_name, "slug": slug, "domain": domain, "sector": sector,
                    "city": city, "country": country},
        "host": host,
        "os": UBUNTU,
        "employees": employees,
        "secrets": sec,
        "products": products,
        "customers": customers,
        "orders": orders,
        "ssh_accept": [list(x) for x in ssh_accept],
        "fake_shadow": {u: _fake_sha512crypt(rng) for u in ["root", "ubuntu", "deploy"]},
        "fs_salt": _rand_str(rng, 16),
    }


def save_world(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")


def load_world(path: Path) -> World:
    from mirage_trap.core.vfs import build_base_vfs  # local import: vfs depends on World

    data = json.loads(path.read_text(encoding="utf-8"))
    world = World(data=data)
    world.vfs = build_base_vfs(world)
    return world
