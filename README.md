# mirage-trap

High-interaction deception honeypot for HTTP, SSH and Telnet. Deterministic emulators handle the common paths; an LLM fills the long tail. Every attacker gets persistent state, and a local dashboard shows what they do.

**[Español](#español)** · **[English](#english)**

---

## Español

### Qué es

`mirage-trap` se hace pasar por un servidor de producción vulnerable (un portal PHP sobre nginx, una consola de operaciones sobre Apache o una API Express) de una empresa ficticia pero coherente. Todo lo que el atacante ve sale de un único **mundo** generado a partir de una semilla: empleados, contraseñas, base de datos, sistema de archivos, `.env`, `.git`, `bash_history`, claves AWS…

- **Nada se ejecuta de verdad.** SQL, shell y lecturas de archivos van a emuladores en Python. Un test analiza el código (AST) y falla si aparece `subprocess`, `os.system`, `eval` o `exec` fuera del adaptador `claude_cli`.
- **Primero lo determinista, después el LLM.** SQLi (UNION, boolean, error-based y time-based con `SLEEP()` real), LFI, inyección de comandos, phpMyAdmin, JWT y GraphQL funcionan sin modelo. El LLM solo genera comandos o archivos poco comunes, y lo que produce se guarda para que la siguiente lectura sea idéntica.
- **Estado por atacante.** Lo que alguien crea, borra o modifica (filas SQL, archivos, variables, directorio actual) persiste entre peticiones, entre protocolos y entre reinicios. Cada atacante trabaja en su propia réplica.
- **Huella fiel.** Orden y mayúsculas de cabeceras, frases de estado, páginas de error byte a byte (incluido el relleno de nginx para Chrome/MSIE), respuestas a peticiones malformadas y latencias log-normales. SSH con el banner y los algoritmos de OpenSSH 8.2p1 y MOTD de Ubuntu 20.04.
- **Canary tokens.** Cada secreto servido queda registrado. Si un atacante lo reutiliza (por ejemplo, roba la contraseña de MySQL del `.env` y la usa en phpMyAdmin o por SSH), queda registrado como *canary hit*.
- **Perfilado.** Cada sesión se clasifica como `scanner`, `bot`, `human` o `hybrid`, se identifica la herramienta (sqlmap, nuclei, Hydra, libssh…) y se puntúa la sofisticación de 0 a 5, con las señales que llevaron a esa conclusión.
- **Panel local.** Sesiones en vivo (SSE), transcripción de cada ataque, estadísticas, canaries e IOCs. Escucha solo en `127.0.0.1`, pide token y valida la cabecera `Host`.

### Inicio rápido

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install git+https://github.com/deivycom21-cell/mirage-trap.git
# con GeoIP/ASN offline (bases MaxMind .mmdb):
# pip install "mirage-trap[geoip] @ git+https://github.com/deivycom21-cell/mirage-trap.git"
mirage-trap init --profile nginx-php-legacy --domain portal.example.com
mirage-trap run                                    # HTTP :8080, SSH :2222
mirage-trap dashboard                              # http://127.0.0.1:9090/?token=...
```

`mirage-trap` no se publica en PyPI: se instala directamente desde este repositorio.

Pruébalo:

```bash
curl -i http://127.0.0.1:8080/.env
curl "http://127.0.0.1:8080/product.php?id=-1%20UNION%20SELECT%201,CONCAT(username,0x3a,password),3,4%20FROM%20users--%20-"
mirage-trap world show --secrets                   # credenciales SSH aceptadas y canaries
ssh -p 2222 root@127.0.0.1
```

### Perfiles

| Perfil | Pila imitada | Superficie |
|---|---|---|
| `nginx-php-legacy` | nginx 1.18 + PHP-FPM 7.4, Ubuntu 20.04 | portal de clientes con SQLi, login bypass, LFI en `download.php`, inyección de comandos en `admin/tools.php`, phpMyAdmin, `.env`, `.git`, backups |
| `ubuntu-admin-panel` | Apache 2.4.41 + mod_php 7.4 | consola de operaciones con diagnóstico (ping/dig/traceroute inyectable), visor de logs, phpMyAdmin |
| `node-express-api` | Node 16 / Express 4 + mysql2 | API REST con JWT (HS256 con secreto filtrable), búsqueda inyectable, descarga de backups con traversal, GraphQL con introspección |

SSH y Telnet comparten el mismo emulador de shell y el mismo sistema de archivos virtual que la web. Si un atacante sube algo por la web, lo encuentra después al entrar por SSH.

### Comandos

| Comando | Qué hace |
|---|---|
| `mirage-trap init` | crea `config.toml`, el directorio de datos, el token del panel, las claves de host SSH y el mundo |
| `mirage-trap world init/show/warm` | genera, inspecciona o precalienta (con el LLM) el mundo |
| `mirage-trap run` | arranca HTTP (+TLS opcional con JA3/JA4), SSH y Telnet |
| `mirage-trap dashboard` | panel local de solo lectura |
| `mirage-trap export -f jsonl\|csv\|stix --since 24h` | exporta telemetría (STIX 2.1 con indicadores y avistamientos) |
| `mirage-trap doctor [--target host:puerto]` | autoauditoría: config, proveedores, invariante de no ejecución y sondas de huella |

### Proveedores LLM

Configurados en `[llm].providers` y probados en orden. `static` (sin modelo) es siempre el último eslabón: si todo falla, el atacante recibe el error que imprimiría el programa real, nunca un traceback.

`ollama` (local, recomendado por privacidad) · `anthropic` · `openai` (o cualquier endpoint compatible) · `claude_cli` (usa tu sesión de Claude Code, sin herramientas ni MCP, el prompt va por stdin) · `static`.

La salida del modelo pasa por un filtro que rechaza frases de asistente, nombres de modelos, cercas de código y fragmentos del prompt. Hay límite de llamadas por IP y global por día.

### Despliegue

- **Standalone:** `mirage-trap run` con `--tls-cert/--tls-key` para capturar JA3/JA4. Usa `deploy/iptables.sh` para exponer 80/22/23 sin ser root.
- **Detrás de nginx (recomendado):** `deploy/nginx.conf`. La huella TCP/TLS es la de un nginx real, porque lo es.
- **systemd:** `deploy/mirage-trap.service` y `deploy/mirage-dashboard.service`, con sandboxing.
- **Docker:** `docker compose up -d` (el panel solo se publica en el loopback del host).

### Seguridad y responsabilidad

- Despliega en una máquina o VM aislada, sin acceso a tu red interna, y restringe la salida (ver `deploy/iptables.sh`).
- No lo ejecutes como root. Usa puertos altos con redirección.
- La telemetría guarda IPs, payloads y credenciales. Cumplir la normativa aplicable (RGPD, etc.) es responsabilidad de quien lo opera. Ajusta `retention_days`.
- Un proveedor LLM remoto recibe los payloads de los atacantes. Para máxima privacidad, usa Ollama.
- Uso exclusivamente defensivo: detección, investigación e inteligencia de amenazas en infraestructura propia.

### Limitaciones conocidas

- Python no puede imitar la pila TCP/IP del sistema operativo (p0f, TTL) ni el ServerHello TLS (JA3S). Para eso está el modo *behind-nginx*.
- El emulador de shell cubre los comandos de reconocimiento y post-explotación habituales; la cola larga depende del LLM configurado (sin LLM, esos comandos devuelven un error creíble).
- SFTP/SCP se rechazan (y se registran).

---

## English

### What it is

`mirage-trap` poses as a vulnerable production server (a PHP portal on nginx, an ops console on Apache, or an Express API) belonging to a fictitious but internally consistent company. Everything an attacker sees comes from a single seeded **world**: staff, passwords, database, filesystem, `.env`, `.git`, `bash_history`, AWS keys, and so on.

- **Nothing is ever executed.** SQL, shell and file reads go to Python emulators. An AST test fails if `subprocess`, `os.system`, `eval` or `exec` appear anywhere outside the `claude_cli` adapter.
- **Deterministic first, LLM second.** SQLi (UNION, boolean, error-based, and time-based with a real `SLEEP()`), LFI, command injection, phpMyAdmin, JWT and GraphQL all work without a model. The LLM only covers uncommon commands and files, and its output is persisted so the next read is identical.
- **Per-attacker state.** Whatever an attacker creates, deletes or changes (SQL rows, files, environment variables, working directory) persists across requests, across protocols and across restarts. Each attacker works on their own replica.
- **Byte-level fidelity.** Header order and casing, reason phrases, byte-exact error pages (including nginx's MSIE/Chrome padding), malformed-request handling and log-normal latency. SSH uses OpenSSH 8.2p1's banner and algorithm order, with the Ubuntu 20.04 MOTD.
- **Canary tokens.** Every secret the trap serves is registered. When an attacker reuses one (for example, they steal the MySQL password from `.env` and try it on phpMyAdmin or over SSH), it is recorded as a canary hit.
- **Profiling.** Each session is labelled `scanner`, `bot`, `human` or `hybrid`, with the likely tool (sqlmap, nuclei, Hydra, libssh…) and a 0–5 sophistication score. The signals behind each verdict are kept, so an analyst can check it.
- **Local dashboard.** Live sessions over SSE, per-attack transcripts, stats, canaries and IOCs. It listens on `127.0.0.1` only, requires a token and validates the `Host` header.

### Quick start

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install git+https://github.com/deivycom21-cell/mirage-trap.git
# with offline GeoIP/ASN enrichment (MaxMind .mmdb databases):
# pip install "mirage-trap[geoip] @ git+https://github.com/deivycom21-cell/mirage-trap.git"
mirage-trap init --profile nginx-php-legacy --domain portal.example.com
mirage-trap run                                    # HTTP :8080, SSH :2222
mirage-trap dashboard                              # http://127.0.0.1:9090/?token=...
```

`mirage-trap` is not published on PyPI: install it straight from this repository.

### Commands

| Command | What it does |
|---|---|
| `mirage-trap init` | writes `config.toml`, the data dir, dashboard token, SSH host keys and the world |
| `mirage-trap world init/show/warm` | generate, inspect, or pre-generate (with the LLM) the world |
| `mirage-trap run` | serve HTTP (+ optional TLS with JA3/JA4), SSH and Telnet |
| `mirage-trap dashboard` | local read-only dashboard |
| `mirage-trap export -f jsonl\|csv\|stix --since 24h` | export telemetry (STIX 2.1 indicators + sightings) |
| `mirage-trap doctor [--target host:port]` | self-audit: config, providers, no-execution invariant, fingerprint probes |

### LLM providers

Tried in the order given in `[llm].providers`: `ollama` (local, best for privacy), `anthropic`, `openai` (or any compatible endpoint), `claude_cli` (your Claude Code login, with every tool and MCP server disabled and the prompt sent over stdin) and `static`. `static` uses no model and always comes last, so when everything else fails the attacker gets the error the real program would print, never a traceback. Model output is filtered for assistant phrasing, model names, code fences and prompt fragments, and calls are capped per IP and per day.

### Configuration

`config.example.toml` is documented inline. Every key can be overridden from the environment: `MIRAGE_SERVER__PORT=80`, `MIRAGE_LLM__PROVIDERS='["ollama","static"]'`, `MIRAGE_LLM__OLLAMA__BASE_URL=http://ollama:11434`.

### Architecture

```
            ┌────────── HTTP (uvicorn + custom h11 protocol, profile fingerprint) ──────────┐
attacker ──►│ SSH (asyncssh, OpenSSH 8.2 look-alike) · Telnet (telnetd look-alike)          │
            └──────────────┬─────────────────────────────────────────────────────────────────┘
                           ▼
                 Deceiver (per-session runtime)
        ┌───────────┬───────────┬──────────────┬────────────────────┐
        │ SQL engine│ Shell     │ Virtual FS   │ LLM chain          │
        │ (sandboxed│ emulator  │ (world base +│ (sanitized, cached,│
        │  SQLite)  │           │  overlays)   │  budgeted)         │
        └───────────┴───────────┴──────────────┴────────────────────┘
                           │  queue (never blocks a response)
                           ▼
           Telemetry writer ─► SQLite (WAL) ◄─ Profiler (background)
                                    ▲
                                    └─ Dashboard (separate process, read-only, 127.0.0.1)
```

### Deployment

- **Standalone:** `mirage-trap run` (add `--tls-cert/--tls-key` to capture JA3/JA4). Use `deploy/iptables.sh` to expose 80/22/23 without running as root.
- **Behind nginx (recommended):** `deploy/nginx.conf`. The TCP/TLS fingerprint is a real nginx's, because it is one.
- **systemd:** `deploy/mirage-trap.service` and `deploy/mirage-dashboard.service`, both sandboxed.
- **Docker:** `docker compose up -d` (the dashboard is published on the host's loopback only).

### Safety and responsibility

Run it on an isolated host or VM with restricted egress, never as root. Telemetry stores IPs, payloads and credentials: complying with the applicable law (GDPR, etc.) is the operator's job, and `retention_days` controls how long data is kept. Remote LLM providers receive attacker payloads; use Ollama for full privacy. Defensive use only: detection, research and threat intelligence on infrastructure you own.

### Known limitations

Python cannot imitate the OS TCP/IP stack (p0f, TTL) or the TLS ServerHello (JA3S); use the behind-nginx mode for that. The shell emulator covers the usual recon and post-exploitation commands; the long tail depends on the configured LLM, and without one those commands return a plausible error. SFTP/SCP are refused and logged.

### Development

```bash
git clone https://github.com/deivycom21-cell/mirage-trap.git && cd mirage-trap
pip install -e ".[dev]"       # editable install of your clone, for working on the code
pytest -q                     # 118 tests: fingerprint, no-execution invariant, state, attacks, LLM chain, protocols
```

See `PLAN.md` for the design rationale.

### License

Apache-2.0.
