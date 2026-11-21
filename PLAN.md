# mirage-trap — Plan de desarrollo

Honeypot de alta interacción en Python con respuestas generadas por LLM, estado persistente por atacante y un panel de vigilancia local.

---

## 0. Principios de diseño

| Principio | Qué significa en la práctica |
|---|---|
| **Nada se ejecuta de verdad** | Ninguna entrada del atacante llega a una shell, a un motor SQL ni al sistema de archivos real. Todo es simulado. Esta es la invariante de seguridad n.º 1 y tendrá tests propios. |
| **Determinista primero, LLM después** | Las rutas comunes (`/.env`, `/robots.txt`, `/phpmyadmin/`, 404) se sirven desde plantillas precalculadas. El LLM solo entra con entradas nuevas. Así baja la latencia, el coste y el riesgo de incoherencias. |
| **Un "mundo" por instancia** | En el primer arranque se genera un *world seed*: empresa ficticia, dominio, empleados, esquema de BD, versiones de software y credenciales trampa. Todas las respuestas (plantillas y LLM) se basan en ese mundo. Es la base de la coherencia. |
| **Estado por atacante** | Lo que un atacante crea, borra o lee queda en SQLite y se inyecta como contexto en las respuestas siguientes. |
| **Telemetría fuera de banda** | El registro nunca bloquea ni altera la respuesta: va por una cola asíncrona. Si la telemetría falla, el atacante no nota nada. |
| **Panel aislado** | Proceso/puerto separado, enlazado solo a `127.0.0.1`, sin rutas compartidas con la trampa. |

---

## 1. Estructura del proyecto

```
mirage-trap/
├── PLAN.md
├── README.md                  # ES + EN
├── LICENSE                    # Apache-2.0 (propuesta)
├── pyproject.toml             # hatchling; entry point `mirage-trap`
├── config.example.toml
├── mirage_trap/
│   ├── __init__.py
│   ├── cli.py                 # Typer: init | run | dashboard | world | export | doctor
│   ├── config.py              # Pydantic Settings (TOML + env vars)
│   ├── core/
│   │   ├── camouflage.py      # App ASGI, cabeceras, errores nativos, latencias
│   │   ├── deceiver.py        # Router de engaño: plantilla → caché → LLM
│   │   ├── classifier.py      # Detección de payloads (SQLi, LFI, RCE, SSRF…)
│   │   ├── state.py           # Memoria de estado por sesión (SQLite)
│   │   ├── world.py           # Generación y carga del world seed
│   │   ├── telemetry.py       # Captura + cola async + persistencia
│   │   ├── profiler.py        # Clasificador bot/humano y sofisticación
│   │   ├── tls.py             # Listener TLS con extracción JA3/JA4
│   │   ├── geo.py             # GeoIP/ASN offline (MaxMind / ip2asn)
│   │   ├── db.py              # Esquema SQLite, migraciones, WAL
│   │   └── sanitizer.py       # Filtro de salida del LLM (anti-fugas)
│   ├── adapters/
│   │   ├── base.py            # Protocolo LLMProvider
│   │   ├── claude_cli.py      # `claude -p` vía subprocess async
│   │   ├── anthropic_api.py   # BYOK Anthropic
│   │   ├── openai_compat.py   # BYOK OpenAI y cualquier endpoint compatible
│   │   ├── ollama.py          # Ollama local
│   │   └── static.py          # Proveedor sin LLM (solo plantillas), útil para tests
│   ├── profiles/
│   │   ├── nginx-php-legacy/
│   │   │   ├── profile.toml   # cabeceras, cookies, latencias, rutas
│   │   │   ├── errors/        # 400/403/404/405/500/502 HTML exactos
│   │   │   └── templates/     # login.php, phpinfo, .env, etc. (Jinja2)
│   │   ├── node-express-api/
│   │   └── ubuntu-admin-panel/
│   ├── prompts/               # System prompts por "personalidad" (mysql, bash, api…)
│   └── dashboard/
│       ├── server.py          # Starlette en 127.0.0.1:9090, SSE
│       └── static/            # index.html, app.css, app.js (sin framework)
└── tests/
    ├── test_fingerprint.py    # Compara contra capturas de nginx/express reales
    ├── test_no_execution.py   # Invariante: nada se ejecuta
    ├── test_state.py
    ├── test_sanitizer.py
    └── test_profiler.py
```

---

## 2. Módulos en detalle

### 2.1 `camouflage.py` — Camuflaje de red y huella

**Base:** Starlette pura con una ruta *catch-all*, no el enrutador de FastAPI. Motivo: FastAPI añade comportamientos delatores (`/docs`, `/openapi.json`, errores 422 en JSON, redirecciones de barra final). Si se quiere FastAPI se usa con `docs_url=None, redoc_url=None, openapi_url=None` y un manejador de excepciones global, pero el *catch-all* en Starlette es más limpio. **Decisión: Starlette.**

**Eliminar rastros de Uvicorn/Python:**
- `uvicorn.Config(server_header=False, date_header=False)` y cabeceras `Server`/`Date` puestas por el perfil.
- Orden de cabeceras idéntico al stack imitado (nginx emite `Server, Date, Content-Type, Content-Length, Connection, …` en un orden fijo; los escáneres como `nmap -sV` o `httprint` lo miran).
- `Connection: keep-alive` y `Keep-Alive: timeout=…` como lo haría nginx.
- Reescribir las respuestas de error de h11 (peticiones malformadas, método inválido, URI demasiado larga): por defecto Uvicorn responde `Invalid HTTP request received.` en texto plano, una señal evidente. Se interceptan con un protocolo HTTP propio (subclase de `H11Protocol`) que devuelve el `400 Bad Request` HTML exacto de nginx.
- Normalizar `HEAD`, `OPTIONS`, `TRACE` (nginx responde 405 a TRACE con su página propia).

**Perfiles** (`profile.toml`):
```toml
[identity]
server = "nginx/1.18.0 (Ubuntu)"
powered_by = "PHP/7.4.3"
session_cookie = { name = "PHPSESSID", format = "hex26", flags = "path=/" }

[latency]                      # ms, distribución log-normal
static = { median = 4, sigma = 0.4 }
dynamic = { median = 38, sigma = 0.6 }
db_query = { median = 120, sigma = 0.8, per_row_ms = 0.3 }

[routes]
"/" = { template = "index.php.j2" }
"/robots.txt" = { template = "robots.txt.j2" }
"/.env" = { handler = "env_file", trap = true }
"/phpmyadmin/" = { handler = "pma_login", trap = true }
"/admin" = { handler = "admin_login", trap = true }
"/api/v1/users" = { handler = "llm:api", trap = true }
```

**Latencias realistas:** `asyncio.sleep` con distribución log-normal (no uniforme: una distribución uniforme se detecta estadísticamente). La latencia de "consulta a BD" escala con el número de filas devueltas. Un *jitter* por sesión simula la variación del enlace.

**El problema de la latencia del LLM:** una llamada al LLM tarda 1–8 s y un nginx real responde en ms. Mitigaciones, en orden:
1. Plantillas y caché para todo lo predecible (cubre más del 90 % del tráfico de escáneres).
2. Pregeneración: al iniciar el mundo se generan en lote las respuestas probables (tablas, `.env`, `/etc/passwd`…).
3. Para respuestas LLM inevitables, se *disfrazan* de endpoint lento: el perfil marca esas rutas como "pesadas" (búsquedas, reportes, `phpMyAdmin` ejecutando SQL), donde varios segundos son creíbles.
4. *Streaming*: se envían cabeceras y el inicio del cuerpo enseguida (`Transfer-Encoding: chunked`, como haría PHP con `flush()`).

**Fidelidad a nivel TCP/TLS (limitación declarada):** Python no puede falsificar la huella TCP/IP del sistema operativo (p0f, TTL, window size) ni la del handshake TLS del servidor (JA3S). Hay dos modos de despliegue:
- **Standalone:** Uvicorn sirve directamente. Bueno para escáneres HTTP, delatable con análisis TLS profundo.
- **Behind-nginx (recomendado para producción):** un nginx real termina TLS y hace proxy a mirage-trap. La huella TLS/TCP es la de un nginx auténtico porque *es* un nginx. Se incluye un `deploy/nginx.conf` de ejemplo que pasa la IP real y la huella JA3 (módulo `nginx-ssl-ja3` o cabecera desde el proxy).

### 2.2 `deceiver.py` — Motor de engaño

**Flujo por petición:**
```
request ─► classifier ─► ¿ruta/plantilla conocida? ──sí──► render(world, state) ─► respuesta
                │                     │no
                │                     ▼
                │            ¿en caché (sesión, hash normalizado)? ──sí──► respuesta
                │                     │no
                │                     ▼
                └──payload──► construir prompt(persona, world, state, petición)
                                      ▼
                              LLMProvider.generate(temperature=0)
                                      ▼
                              sanitizer ─► extraer mutaciones de estado ─► guardar ─► respuesta
```

**Clasificador de payloads** (`classifier.py`): reglas regex + tokenización para SQLi (union, boolean, time-based, stacked, error-based), path traversal/LFI, inyección de comandos, SSTI, SSRF, XXE, Log4Shell (`${jndi:`), deserialización. Devuelve `{tipo, técnica, confianza}`. Decide la "persona" que responde:
- `mysql` → errores reales de MySQL 5.7/8.0 (`ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '...' at line 1`), resultados tabulares coherentes con el esquema del mundo.
- `bash` → salida de shell de Ubuntu 20.04 coherente con el sistema de archivos virtual.
- `api` → JSON con la forma exacta de la API del perfil.
- `file` → contenido de archivos (`/etc/passwd`, configs) derivados del mundo.

**Casos sin LLM:** los ataques *time-based* (`SLEEP(5)`, `pg_sleep`, `; sleep 5`) se resuelven de forma determinista: se extrae el valor y se hace `asyncio.sleep` real. Un LLM no puede simular tiempo y estos son la técnica más usada por sqlmap para confirmar una inyección.

**Prompt estricto (cero chat):**
- System prompt por persona en `prompts/`, con: rol ("eres el binario mysqld 8.0.32; tu salida va directamente a un socket"), el mundo serializado, el estado de la sesión y reglas duras (sin markdown, sin explicaciones, sin disculpas, sin "como IA", sin cercas de código).
- *Few-shot* con pares entrada→salida reales.
- Salida estructurada: el modelo devuelve JSON `{ "output": "...", "state_ops": [...] }`. `output` va al atacante y `state_ops` (p. ej. `{"op":"insert","table":"users","row":{…}}`) actualiza el estado. Así el estado no depende de volver a interpretar texto libre.
- `temperature=0` y caché por `(session_id, persona, hash(petición_normalizada))`: la misma petición devuelve el mismo resultado.

**Defensa contra *prompt injection*:** el atacante controla la entrada que va al LLM. Medidas:
- La entrada del atacante va delimitada y marcada como datos, nunca como instrucciones.
- `sanitizer.py` revisa la salida antes de enviarla: rechaza frases de asistente ("I cannot", "As an AI", "Lo siento", "```"), nombres de modelos/proveedores, fragmentos del system prompt y cadenas del world seed marcadas como internas. Si falla, se usa un fallback determinista (error genérico de la persona, p. ej. `bash: syntax error near unexpected token`).
- Límite de longitud de salida por persona.
- Las credenciales trampa salen solo del mundo, nunca inventadas por el LLM sobre la marcha (así se pueden rastrear como *canary tokens*).

**Memoria de estado** (`state.py`):
- Sesión = IP + cookie de sesión (si el atacante la conserva) + huella JA3/UA. Varias IPs que reutilizan la misma cookie se unen a una sola sesión (útil contra atacantes que rotan proxies).
- Tablas: `sessions`, `vfs` (sistema de archivos virtual con diffs por sesión sobre el VFS base del mundo), `vdb` (filas añadidas, modificadas o borradas por sesión sobre la BD base), `shell_env` (cwd, variables, historial), `responses_cache`.
- El contexto que se inyecta al LLM es un **resumen compacto** del estado relevante (no el historial completo), para mantener el prompt acotado.
- Estado base compartido (el mundo) + capa por sesión: lo que un atacante modifica no lo ve otro, igual que si cada uno estuviera en una réplica.

**Proveedores** (`adapters/`), con interfaz común:
```python
class LLMProvider(Protocol):
    name: str
    async def generate(self, system: str, messages: list[Msg], *,
                       max_tokens: int, temperature: float = 0.0,
                       json_schema: dict | None = None) -> str: ...
    async def health(self) -> bool: ...
```
- `claude_cli`: `asyncio.create_subprocess_exec("claude", "-p", "--output-format", "json", …)` con *timeout* y prompt por stdin (nunca en argv, para que no aparezca en `ps`).
- `anthropic_api`, `openai_compat`, `ollama`: `httpx.AsyncClient`. Claves solo desde variables de entorno o desde el archivo de config con permisos 600.
- Cadena de *fallback* configurable: `["ollama", "anthropic_api", "static"]`. Si todos fallan se usa `static` (error genérico creíble), nunca un 500 de Python.
- Límite de gasto por IP/día y global, con contador en SQLite. Al llegar al límite, la sesión pasa a `static`. Evita que un atacante convierta el honeypot en una factura alta.

### 2.3 `world.py` — Generación del mundo

`mirage-trap world init --profile nginx-php-legacy --seed 1234` genera (con LLM una sola vez, y después se queda fijo en `world.json`):
- Empresa ficticia (nombre, sector, dominio `.internal`), 30–80 empleados con nombres, emails, cargos y hashes bcrypt/MD5 de contraseñas.
- Esquema MySQL (`users`, `customers`, `orders`, `invoices`, `sessions`, `audit_log`) con datos semilla.
- VFS base: `/etc/passwd`, `/etc/hosts`, `/var/www/html/…`, `config.php`, `.env`, `.git/config`, `id_rsa` trampa, crontabs.
- **Canary tokens:** las credenciales trampa (AWS keys con formato válido, tokens de API, contraseñas de BD) se registran en `canaries`. Si aparecen más tarde en otra petición o en otro honeypot, se asocian las sesiones. Opcional: integración con canarytokens.org para alertar si se usan fuera.
- Todo es ficticio y validado: nunca dominios ni datos de empresas reales. Se usa `example`-style y TLDs reservados donde sea visible.

### 2.4 `telemetry.py` — Telemetría silenciosa

**Captura por petición:** timestamp (ns), IP, puerto, método, ruta, query, cabeceras completas y en orden, cuerpo (con límite configurable, truncado y hasheado), huella JA3/JA4, HTTP/1.1 vs HTTP/2, persona y payload detectado, respuesta enviada, latencia simulada y real, proveedor usado.

**Invisibilidad:**
- Se encola con `asyncio.Queue` y un *writer* en segundo plano escribe por lotes (SQLite en modo WAL). La respuesta nunca espera al disco.
- Sin llamadas de red salientes durante la petición (nada de APIs de GeoIP en línea: un atacante que controla un DNS podría detectar consultas inversas).

**JA3/JA4** (`tls.py`): Uvicorn/`ssl` no exponen el ClientHello. Solución: un listener `asyncio` propio que lee el ClientHello en bruto, calcula JA3 y JA4, y luego hace el handshake con `ssl.SSLObject` sobre los mismos bytes antes de pasar la conexión al ASGI. En modo *behind-nginx* la huella llega en una cabecera interna desde el proxy (que se elimina antes de cualquier otra lógica).

**Geo/ASN** (`geo.py`): bases offline (MaxMind GeoLite2 City/ASN con licencia gratuita del usuario, o `ip2asn` sin registro). Se enriquece en el *writer*, fuera de la ruta crítica.

### 2.5 `profiler.py` — Bot vs humano y sofisticación

Analizador en segundo plano (cada N segundos sobre sesiones activas). Señales:

| Señal | Bot | Humano |
|---|---|---|
| Intervalo entre peticiones | Regular, < 200 ms, baja varianza | Irregular, con pausas de lectura (2–60 s) |
| Patrón de rutas | Diccionario (wordlists conocidas: dirb, SecLists) | Sigue enlaces, reacciona al contenido |
| User-Agent / JA3 | Coincide con herramientas conocidas (sqlmap, nuclei, zgrab, masscan, python-requests, Go-http-client) | Navegador real, JA3 de navegador |
| Reacción a la respuesta | No usa datos devueltos | Reutiliza credenciales/rutas que se le mostraron |
| Errores tipográficos y correcciones | No | Sí |
| Payloads | Plantillas de herramientas | Adaptados, iterativos |

**Salida:** `kind ∈ {scanner, bot, human, hybrid}` con confianza, herramienta probable (`sqlmap 1.7`, `nuclei`, `Nikto`…), y **sofisticación 0–5** (0 = escaneo masivo, 5 = encadenamiento manual de vulnerabilidades + evasión). Empieza con reglas y puntuación ponderada, explicable y sin dependencias de ML. La interfaz se deja preparada para un modelo entrenado más adelante.

### 2.6 `dashboard/` — Centro de vigilancia

- Proceso propio (`mirage-trap dashboard`), Starlette en `127.0.0.1:9090`. El bind se valida al arrancar: si la config intenta otro host, se niega a iniciar salvo `--i-know-what-im-doing`. Acceso remoto recomendado: túnel SSH (`ssh -L 9090:127.0.0.1:9090`).
- Token de acceso local generado en `init` (protege frente a otros usuarios de la misma máquina y frente a DNS rebinding; además se valida la cabecera `Host`).
- Lee SQLite en modo solo lectura. Tiempo real con **Server-Sent Events** (más simple que WebSockets, suficiente para un flujo unidireccional).
- Vistas:
  1. **Live:** sesiones activas, con IP, país, ASN, tipo (bot/humano), sofisticación y última actividad.
  2. **Sesión:** vista tipo terminal con lo que el atacante envió y lo que recibió, cronológico, con resaltado del payload detectado.
  3. **Estadísticas:** top rutas, top payloads, distribución por país/ASN, herramientas detectadas.
  4. **Canaries:** credenciales trampa que se han filtrado y dónde reaparecieron.
- HTML/CSS/JS sin framework ni build, tema oscuro, todo servido localmente (sin CDNs: nada sale de la máquina).

### 2.7 `cli.py`

```
mirage-trap init                 # crea config.toml, genera token del panel, comprueba proveedor
mirage-trap world init|show      # genera / inspecciona el mundo
mirage-trap run --profile nginx-php-legacy --port 8080 [--tls cert key]
mirage-trap dashboard            # 127.0.0.1:9090
mirage-trap export --format jsonl|csv|stix --since 24h
mirage-trap doctor               # autoauditoría de huella (ver §3)
```

---

## 3. Verificación de realismo (`doctor` + tests)

El objetivo "cero sospechas" necesita medición, no solo intención:
- **Diff de huella:** se capturan respuestas de un nginx 1.18 + PHP 7.4 real, de un Express real, etc. (en Docker) y se comparan byte a byte con las de mirage-trap para: cabeceras y su orden, páginas de error, respuestas a peticiones malformadas, `HEAD`/`OPTIONS`/`TRACE`, rutas con `..`, URIs largas.
- **Escáneres reales en CI (opcional, Docker):** `nmap -sV --script http-*`, `whatweb`, `nikto`, `nuclei -tags tech`. El test pasa si identifican el stack del perfil y no detectan Python/Uvicorn.
- **Detectores de honeypots conocidos:** se comprueba contra las heurísticas públicas que buscan honeypots (respuestas idénticas a cualquier ruta, banners incoherentes, `200` en todo).
- **Coherencia del LLM:** batería de sesiones guionizadas (crear usuario → listarlo → borrarlo → listarlo) que verifica que el estado se mantiene.
- **Invariante de no ejecución:** test que analiza el código (`ast`) y falla si aparecen `subprocess`, `os.system`, `eval` o `exec` fuera de `adapters/claude_cli.py`.

---

## 4. Seguridad y responsabilidad (sección del README)

- Desplegar en una máquina o VM aislada, sin acceso a la red interna y con salida a Internet restringida (solo al proveedor LLM si se usa uno remoto).
- Ejecutar como usuario sin privilegios. Puertos < 1024 mediante `authbind`/`setcap` o redirección con iptables, nunca como root.
- La telemetría almacena IPs y payloads: el operador es responsable del cumplimiento legal en su jurisdicción (RGPD, etc.). Se incluye la opción de retención (`retention_days`).
- Usar proveedores LLM remotos implica enviar los payloads de los atacantes a un tercero. Se documenta y se recomienda Ollama para máxima privacidad.
- Uso exclusivamente defensivo: detección, investigación e inteligencia de amenazas en infraestructura propia.

---

## 5. Fases de desarrollo

| Fase | Contenido | Entregable verificable |
|---|---|---|
| **F0 · Esqueleto** | `pyproject.toml`, estructura, `config.py`, `db.py` con esquema y migraciones, `cli.py` con comandos vacíos, README ES/EN, LICENSE | `pip install -e .` y `mirage-trap --help` funcionan |
| **F1 · Camuflaje** | `camouflage.py` con Starlette catch-all, protocolo h11 propio, 3 perfiles con páginas de error reales, latencias log-normales | Diff de huella frente a nginx real = 0 en cabeceras y errores |
| **F2 · Mundo + plantillas** | `world.py`, VFS/BD base, plantillas Jinja para rutas trampa, canaries | `/.env`, `/robots.txt`, `/phpmyadmin/` responden sin LLM |
| **F3 · Telemetría** | Cola async, writer WAL, geo offline, captura completa | Cada petición queda registrada sin aumentar la latencia (p99 < 1 ms de overhead) |
| **F4 · Adaptadores LLM** | `base`, `claude_cli`, `anthropic_api`, `openai_compat`, `ollama`, `static`, cadena de fallback, límites de gasto | `mirage-trap doctor` valida cada proveedor configurado |
| **F5 · Motor de engaño** | `classifier`, `deceiver`, personas, prompts, salida JSON con `state_ops`, `state.py`, caché, `sanitizer`, time-based determinista | Sesiones guionizadas de SQLi y shell mantienen coherencia; sqlmap detecta "MySQL" y extrae datos del mundo |
| **F6 · Perfilador** | `profiler.py` con reglas y puntuación | Clasifica bien un corpus de prueba (sqlmap, nuclei, sesión manual grabada) |
| **F7 · Dashboard** | Servidor 127.0.0.1, SSE, 4 vistas, token, validación de `Host` | Ver en vivo una sesión de ataque de prueba |
| **F8 · TLS/JA3** | `tls.py` con listener propio + modo behind-nginx con `deploy/` | JA3 de curl/Chrome/Python calculado correctamente |
| **F9 · Endurecimiento** | `doctor`, tests de escáneres en Docker, Dockerfile, docs | CI verde; `whatweb`/`nmap` identifican el stack falso |

Orden razonado: F1–F3 ya dan un honeypot útil sin ningún LLM. El LLM (F4–F5) se suma sobre una base que ya es creíble, en lugar de ser la base.

---

## 6. Dependencias

`starlette`, `uvicorn[standard]`, `h11`, `httpx`, `pydantic-settings`, `typer`, `jinja2`, `aiosqlite`, `maxminddb` (opcional), `anthropic` (opcional), `rich`. Python ≥ 3.11. Sin dependencias de ML.

---

## 7. Decisiones tomadas

1. **Licencia:** Apache-2.0.
2. **SSH y Telnet entran en esta versión** (ver §2.8).
3. **Proveedor por defecto:** `ollama`, con `static` como último eslabón de la cadena.

### Ajustes de diseño durante la implementación

- **El mundo se genera de forma procedural y determinista** (`random.Random(seed)` + listas propias), no con LLM. Así es reproducible, rápido, no requiere proveedor y nunca inventa una empresa real por accidente. El dominio se configura (`--domain`): lo ideal es el dominio real del operador.
- **Emulador SQL en sandbox:** las consultas del atacante se ejecutan sobre una SQLite **en memoria, por sesión, con solo datos ficticios del mundo**, con traducción de dialecto MySQL (`#`, `0x..`, `@@version`, `information_schema`, `SLEEP()`, `CONCAT()`…), un *authorizer* que bloquea `ATTACH`/`PRAGMA`/extensiones y un *progress handler* que corta consultas costosas. Los errores se reescriben al formato exacto de MySQL (`ERROR 1064 (42000)`, `1146`, `1222`…). Resultado: UNION, boolean-based, error-based y time-based se comportan como en un MySQL real (sqlmap incluido), con coherencia total sin LLM.
- **Emulador de shell determinista** (`core/shell.py`) compartido por SSH, Telnet y la inyección de comandos web. Implementa los comandos habituales de reconocimiento sobre el VFS. El LLM solo cubre la cola larga (comandos raros, archivos que no existen en el VFS base), y lo que genera se guarda para que la siguiente lectura sea idéntica.
- **JA3/JA4 en modo standalone** mediante `SSLContext._msg_callback` (recibe el ClientHello en bruto durante el handshake), sin listener TLS propio.

## 2.8 SSH y Telnet (`core/ssh.py`, `core/telnet.py`)

- **SSH** con `asyncssh`: banner exacto (`SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`), algoritmos KEX/cifrado/MAC en el orden de OpenSSH 8.2 (huella HASSH coherente), claves de host persistentes generadas en `init` (si cambian, se nota).
- **Autenticación:** se registran todos los intentos (usuario/contraseña). Se acepta solo: credenciales del mundo (lo que dispara un *canary hit*, porque significa que el atacante las robó antes por la web) y una lista corta de credenciales débiles elegida de forma determinista por instancia. Nunca se acepta "cualquier contraseña" (una señal conocida de Cowrie).
- **Sesión:** MOTD de Ubuntu 20.04, `Last login:` coherente, prompt `user@host:~$`, PTY con edición de línea, `exec` (`ssh host 'cmd'`) con código de salida. SFTP/SCP se rechazan y se registra el intento.
- **Telnet:** negociación IAC (`WILL ECHO`, `WILL SGA`, `DO NAWS`), `Ubuntu 20.04.6 LTS` + `host login:` + `Password:`, `Login incorrect`, y la misma shell.
- **Descargas (`wget`/`curl`)**: nunca se descargan. La URL se guarda como IOC y se simula la salida y el archivo.

---

## 8. Estado (2026-11-20)

Todas las fases F0–F9 están implementadas. `pytest` → 118 tests en verde.

| Fase | Estado | Dónde |
|---|---|---|
| F0 · Esqueleto | hecho | `pyproject.toml`, `config.py`, `core/db.py`, `cli.py`, README ES/EN |
| F1 · Camuflaje | hecho | `core/camouflage.py` (protocolo h11 propio, reordenado de cabeceras que h11 altera, páginas de error exactas), `tests/test_fingerprint.py` (incluye pruebas sobre el cable con uvicorn real) |
| F2 · Mundo + plantillas | hecho | `core/world.py`, `core/vfs.py`, `profiles/` |
| F3 · Telemetría | hecho | `core/telemetry.py`, `core/geo.py` |
| F4 · Adaptadores LLM | hecho | `adapters/`, límites de gasto en `core/deceiver.py` |
| F5 · Motor de engaño | hecho | `core/deceiver.py`, `core/sqlemu.py`, `core/shell.py`, `core/web.py`, `core/sanitizer.py` |
| F6 · Perfilador | hecho | `core/profiler.py` (reglas explicables; corre cada 15 s en `run`) |
| F7 · Dashboard | hecho | `dashboard/server.py` + `dashboard/static/` (Live, Sesión, Stats, Canaries, IOCs; SSE; token; validación de `Host`; CSP estricta) |
| F8 · TLS/JA3 | hecho | `core/tls.py` (standalone) + `deploy/nginx.conf` (behind-nginx) |
| F9 · Endurecimiento | hecho | `core/doctor.py`, `deploy/` (systemd con sandboxing, iptables), `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml` (tests en 3 SO × 3 Python, nmap/whatweb contra el trap, build de Docker) |

Módulos añadidos respecto a §1: `core/runner.py` (orquestación de procesos y retención), `core/export.py` (JSONL/CSV/STIX 2.1), `core/doctor.py`.

Correcciones hechas al cerrar el proyecto (detectadas por los tests nuevos):
- Los cambios SQL del atacante no sobrevivían a un reinicio: `serialize()` no ve una transacción implícita sin commit.
- SSH escribía `\r\r\n` en una PTY (asyncssh ya convierte LF→CRLF).
- h11 movía `Transfer-Encoding` y `Connection: close` al final de las cabeceras.
- La página de error de Apache revelaba el puerto interno (8080) y no escapaba la cabecera `Host`.
- El clasificador marcaba como RCE cualquier petición con User-Agent `python-*`.
- Shell: `$?` se expandía una sola vez por línea; faltaban `id -un`, `sudo -l`/`sudo -i` y el código de salida de `mysql -e` con error.

Pendiente de verificar fuera de este entorno: el job de Docker y el de escáneres (nmap/whatweb) de CI, y una ejecución con un proveedor LLM real (la cadena está cubierta con un proveedor simulado en `tests/test_llm.py`).
