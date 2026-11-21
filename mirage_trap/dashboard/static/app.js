/* mirage-trap dashboard: no framework, no build step, no external requests.
 * All attacker-controlled data is inserted with textContent, never innerHTML. */
"use strict";

const $view = document.getElementById("view");
const $range = document.getElementById("range");
const $dot = document.getElementById("live-dot");
const state = { feed: [], timers: [], es: null, onEvents: null };

// ---------------------------------------------------------------- helpers
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v;   // CSSOM: allowed by the strict CSP
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;
const clean = (s) => (s == null ? "" : String(s).replace(ANSI, ""));
const fmtN = (n) => (n == null ? "–" : Number(n).toLocaleString());
function ago(ts) {
  if (!ts) return "–";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function stamp(ts) {
  const d = new Date(ts * 1000);
  return d.toISOString().replace("T", " ").slice(0, 19);
}
const time = (ts) => new Date(ts * 1000).toTimeString().slice(0, 8);

async function api(path) {
  const r = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (r.status === 401) { location.reload(); throw new Error("unauthorized"); }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
function every(ms, fn) { const id = setInterval(fn, ms); state.timers.push(id); }
function clearTimers() { state.timers.forEach(clearInterval); state.timers = []; state.onEvents = null; }

const kindBadge = (k, conf) => h("span", { class: `b ${k || "unknown"}`, title: conf ? `confidence ${Math.round(conf * 100)}%` : null }, k || "unknown");
function soph(n) {
  n = n || 0;
  const el = h("span", { class: `soph l${n}`, title: `sophistication ${n}/5` });
  for (let i = 1; i <= 5; i++) el.append(h("i", { class: i <= n ? "on" : "" }));
  return el;
}
const atkBadge = (a) => (a ? h("span", { class: `b ${a === "recon" ? "recon" : "atk"}` }, a) : "");
const protoBadges = (p) => (p || "").split(",").filter(Boolean).map((x) => h("span", { class: "b proto" }, x));
const geo = (s) => [s.country, s.as_org ? `AS${s.asn} ${s.as_org}` : null].filter(Boolean).join(" · ") || "–";

function bars(rows, opts = {}) {
  if (!rows || !rows.length) return h("div", { class: "empty" }, "nothing yet");
  const max = Math.max(...rows.map((r) => r.n));
  return h("div", { class: "bars" }, rows.map((r) =>
    h("div", { class: "bar", title: `${r.k ?? "–"}: ${r.n}` },
      h("div", { class: "track" },
        h("div", { class: "fill", style: `width:${(100 * r.n) / max}%` }),
        h("div", { class: "lbl" }, opts.label ? opts.label(r.k) : (r.k ?? "–"))),
      h("div", { class: "n" }, fmtN(r.n)))));
}
function panel(title, ...body) { return h("section", { class: "panel" }, h("h2", {}, title), ...body); }
function setNav(view) {
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.view === view));
}
function failure(e) { $view.replaceChildren(h("div", { class: "panel err" }, String(e.message || e))); }

// ---------------------------------------------------------------- live stream
function connectStream() {
  if (state.es) return;
  const es = new EventSource("/api/stream");
  state.es = es;
  es.onopen = () => $dot.className = "dot on";
  es.onerror = () => { $dot.className = "dot off"; };
  es.addEventListener("events", (m) => {
    const rows = JSON.parse(m.data);
    state.feed = rows.concat(state.feed).slice(0, 200);
    if (state.onEvents) state.onEvents(rows);
  });
}

// ---------------------------------------------------------------- views
function kpis(t) {
  const tile = (v, l, cls) => h("div", { class: `kpi ${cls || ""}` }, h("div", { class: "v" }, fmtN(v)), h("div", { class: "l" }, l));
  return h("div", { class: "kpis" },
    tile(t.active, "active sessions", t.active ? "good" : ""),
    tile(t.sessions, "sessions"),
    tile(t.ips, "source IPs"),
    tile(t.events, "events"),
    tile(t.commands, "shell commands"),
    tile(t.credentials, "login attempts"),
    tile(t.logins, "successful logins", t.logins ? "hot" : ""),
    tile(t.canary_hits, "canary hits", t.canary_hits ? "hot" : ""),
    tile(t.llm_calls_today, "LLM calls today"));
}

function sessionsTable(rows) {
  if (!rows.length) return h("div", { class: "empty" }, "no sessions in this window");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["last seen", "source", "where", "proto", "kind", "tool", "soph.", "events", "last attack", "flags"].map((c) => h("th", { class: c === "events" ? "num" : "" }, c)))),
    h("tbody", {}, rows.map((s) => h("tr", { class: "click", onclick: () => (location.hash = `#/session/${s.id}`) },
      h("td", { title: stamp(s.last_seen) }, ago(s.last_seen)),
      h("td", { class: "mono" }, s.ip, s.ips.length > 1 ? h("span", { class: "b", title: s.ips.join(", ") }, `+${s.ips.length - 1}`) : ""),
      h("td", {}, h("span", { class: "trunc", style: "max-width:200px" }, geo(s))),
      h("td", {}, protoBadges(s.protocol)),
      h("td", {}, kindBadge(s.kind, s.kind_confidence)),
      h("td", {}, h("span", { class: "trunc", style: "max-width:160px", title: s.user_agent || "" }, s.tool || "–")),
      h("td", {}, soph(s.sophistication)),
      h("td", { class: "num" }, fmtN(s.req_count)),
      h("td", {}, atkBadge(s.last_attack)),
      h("td", {},
        s.logins ? h("span", { class: "b atk", title: "successful login" }, "login") : "",
        " ",
        s.canary_hits ? h("span", { class: "b atk", title: "reused leaked credentials" }, `canary ×${s.canary_hits}`) : ""))))));
}

function feedRow(e, isNew) {
  const label = e.kind === "request" ? `${e.method} ${e.path}` : e.kind === "command" ? `$ ${e.path}` : `${e.kind} ${e.method || ""} ${e.path || ""}`;
  return h("div", { class: isNew ? "new" : "" },
    h("span", { class: "t" }, time(e.ts)),
    h("a", { href: `#/session/${e.session_id}`, class: "mono" }, e.ip),
    h("span", { class: "b proto" }, e.protocol),
    e.status != null && e.kind === "request" ? h("span", { class: "t" }, e.status) : "",
    atkBadge(e.attack_type),
    h("span", { class: "p", title: label }, label));
}

async function viewLive() {
  setNav("live");
  const feed = h("div", { class: "feed" });
  const fill = () => {
    if (!state.feed.length) feed.replaceChildren(h("div", { class: "empty" }, "waiting for traffic…"));
    else feed.replaceChildren(...state.feed.slice(0, 120).map((e) => feedRow(e)));
  };
  const kpiBox = h("div");
  const activeBox = h("div");
  const recentBox = h("div");
  const search = h("input", { type: "search", placeholder: "filter by IP, tool, country, UA…", oninput: () => refresh() });
  $view.replaceChildren(kpiBox,
    h("div", { class: "grid cols-2" },
      panel("Active sessions (last 30 min)", activeBox),
      panel("Live events", feed)),
    h("section", { class: "panel" }, h("div", { class: "toolbar" }, h("h2", { style: "margin:0" }, "Sessions in window"), search), recentBox));
  fill();
  async function refresh() {
    try {
      const since = $range.value;
      const [ov, active, recent] = await Promise.all([
        api(`/api/overview?since=${encodeURIComponent(since)}`),
        api("/api/sessions?active=1&limit=50"),
        api(`/api/sessions?limit=200&since=${encodeURIComponent(since)}&q=${encodeURIComponent(search.value)}`),
      ]);
      kpiBox.replaceChildren(kpis(ov.totals));
      activeBox.replaceChildren(sessionsTable(active));
      recentBox.replaceChildren(sessionsTable(recent));
    } catch (e) { kpiBox.replaceChildren(h("div", { class: "panel err" }, String(e.message || e))); }
  }
  state.onEvents = (rows) => {
    if (feed.querySelector(".empty")) feed.replaceChildren();
    rows.slice().reverse().forEach((e) => feed.prepend(feedRow(e, true)));
    while (feed.childElementCount > 150) feed.lastChild.remove();
  };
  await refresh();
  every(5000, refresh);
}

function timelineChart(tl) {
  const n = Math.max(1, Math.round((Date.now() / 1000 - tl.start) / tl.bucket));
  const pts = new Map(tl.points.map((p) => [p.b, p]));
  const max = Math.max(1, ...tl.points.map((p) => p.n));
  const cols = [];
  for (let i = 0; i < n; i++) {
    const p = pts.get(i) || { n: 0, a: 0 };
    const label = `${stamp(tl.start + i * tl.bucket)} — ${p.n} events, ${p.a} attacks`;
    cols.push(h("div", { class: "col", title: label },
      h("span", { class: "atk", style: `height:${(100 * p.a) / max}%` }),
      h("span", { class: "all", style: `height:${(100 * (p.n - p.a)) / max}%` })));
  }
  return h("div", {},
    h("div", { class: "legend" }, h("span", {}, h("i", { style: "background:var(--accent-dim)" }), "events"), h("span", {}, h("i", { style: "background:var(--bad)" }), "exploitation attempts")),
    h("div", { class: "chart" }, cols),
    h("div", { class: "chart-axis" }, h("span", {}, stamp(tl.start)), h("span", {}, "now")));
}

async function viewStats() {
  setNav("stats");
  let ov;
  try { ov = await api(`/api/overview?since=${encodeURIComponent($range.value)}`); } catch (e) { return failure(e); }
  const sophLabel = (k) => ["0 · mass scan", "1 · probing", "2 · automated exploit", "3 · manual exploitation", "4 · chaining", "5 · evasion / persistence"][k] || k;
  $view.replaceChildren(
    kpis(ov.totals),
    panel("Activity", timelineChart(ov.timeline)),
    h("div", { class: "grid cols-3" },
      panel("Attack types", bars(ov.attacks)),
      panel("Session kinds", bars(ov.kinds)),
      panel("Sophistication", bars(ov.sophistication, { label: sophLabel }))),
    h("div", { class: "grid cols-2" },
      panel("Top paths", bars(ov.paths)),
      panel("Top payload signatures", bars(ov.payloads))),
    h("div", { class: "grid cols-2" },
      panel("Top shell commands", bars(ov.commands)),
      panel("Tools detected", bars(ov.tools))),
    h("div", { class: "grid cols-3" },
      panel("Countries", bars(ov.countries)),
      panel("Networks (ASN)", bars(ov.asns)),
      panel("Protocols", bars(ov.protocols))),
    h("div", { class: "grid cols-2" },
      panel("Usernames tried", bars(ov.usernames)),
      panel("Passwords tried", bars(ov.passwords))));
}

async function viewCanaries() {
  setNav("canaries");
  let d;
  try { d = await api("/api/canaries"); } catch (e) { return failure(e); }
  const hit = d.tokens.filter((t) => t.hits);
  $view.replaceChildren(
    panel(`Leaked credentials that came back (${hit.length} of ${d.tokens.length} tokens)`,
      h("p", { style: "color:var(--muted);margin-top:0" }, "Every secret the trap serves (.env, configs, bash_history, database rows) is a canary. A hit means an attacker read it somewhere and reused it."),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["label", "kind", "token", "hits", "sessions", "last hit"].map((c) => h("th", { class: ["hits", "sessions"].includes(c) ? "num" : "" }, c)))),
        h("tbody", {}, d.tokens.map((t) => h("tr", {},
          h("td", {}, t.label), h("td", {}, h("span", { class: "b" }, t.kind)),
          h("td", { class: "mono" }, h("span", { class: "trunc", style: "max-width:260px", title: t.token }, t.token)),
          h("td", { class: "num" }, t.hits ? h("span", { class: "b atk" }, t.hits) : "0"),
          h("td", { class: "num" }, t.sessions || 0),
          h("td", { title: t.last_hit ? stamp(t.last_hit) : "" }, ago(t.last_hit)))))))),
    panel("Recent canary hits", d.hits.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["when", "source", "protocol", "credential", "where it was used"].map((c) => h("th", {}, c)))),
      h("tbody", {}, d.hits.map((x) => h("tr", { class: "click", onclick: () => (location.hash = `#/session/${x.session_id}`) },
        h("td", { title: stamp(x.ts) }, ago(x.ts)), h("td", { class: "mono" }, x.ip || x.session_id, x.country ? ` (${x.country})` : ""),
        h("td", {}, protoBadges(x.protocol)), h("td", {}, x.label || x.kind), h("td", { class: "wrap" }, x.context))))))
      : h("div", { class: "empty" }, "no canary has been reused yet")));
}

async function viewIocs() {
  setNav("iocs");
  let rows;
  try { rows = await api("/api/iocs"); } catch (e) { return failure(e); }
  $view.replaceChildren(panel("Indicators captured (download URLs, reverse shells, webshells, executed files)",
    rows.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["when", "source", "kind", "value", "context"].map((c) => h("th", {}, c)))),
      h("tbody", {}, rows.map((i) => h("tr", { class: "click", onclick: () => (location.hash = `#/session/${i.session_id}`) },
        h("td", { title: stamp(i.ts) }, ago(i.ts)), h("td", { class: "mono" }, i.ip || "–"),
        h("td", {}, h("span", { class: "b atk" }, i.kind)), h("td", { class: "wrap mono" }, i.value),
        h("td", { class: "wrap mono" }, i.context))))))
      : h("div", { class: "empty" }, "no indicators yet")));
}

// -------- session transcript
const ATTACK_HL = /(union[\s/*()]+(all[\s/*()]+)?select|sleep\s*\(|benchmark\s*\(|information_schema|\.\.\/|\/etc\/passwd|\$\{jndi:[^}]*\}|<script|;\s*(id|whoami|uname|cat|wget|curl)\b|\|\s*(sh|bash)\b|`[^`]+`|\$\([^)]*\))/gi;
function highlight(text) {
  const frag = document.createDocumentFragment();
  let last = 0;
  text.replace(ATTACK_HL, (m, ...rest) => {
    const idx = rest[rest.length - 2];
    frag.append(text.slice(last, idx), h("span", { class: "hl" }, m));
    last = idx + m.length;
    return m;
  });
  frag.append(text.slice(last));
  return frag;
}
function decodeQ(s) { try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch { return s; } }

function eventNode(e) {
  const meta = h("div", { class: "meta" }, h("span", { title: stamp(e.ts) }, time(e.ts)), h("span", { class: "b proto" }, e.protocol),
    e.status != null && e.kind === "request" ? h("span", {}, `HTTP ${e.status}`) : "",
    e.kind === "command" && e.status != null ? h("span", {}, `exit ${e.status}`) : "",
    atkBadge(e.attack_type), e.attack_detail && e.attack_type !== "recon" ? h("span", {}, e.attack_detail) : "",
    e.persona ? h("span", { class: "b" }, e.persona) : "", e.provider ? h("span", { class: "b" }, `llm:${e.provider}`) : "",
    e.latency_sim_ms != null ? h("span", { title: "simulated / real latency" }, `${e.latency_sim_ms} / ${e.latency_real_ms} ms`) : "");
  const node = h("div", { class: `ev ${e.attack_type && e.attack_type !== "recon" ? "attack" : ""}` }, meta);
  if (e.kind === "request") {
    const line = `${e.method} ${decodeQ(e.path || "")}${e.query && !(e.path || "").includes("?") ? "?" + decodeQ(e.query) : ""}`;
    node.append(h("div", { class: "in http" }, highlight(line)));
    const hdrs = (e.headers || []).map(([k, v]) => `${k}: ${v}`).join("\n");
    node.append(h("details", {}, h("summary", {}, `request headers${e.body_len ? ` + body (${e.body_len} B)` : ""}`),
      h("pre", {}, hdrs), e.body ? h("pre", {}, highlight(decodeQ(e.body))) : ""));
    if (e.response) node.append(h("details", {}, h("summary", {}, `response (${fmtN(e.response_len)} B)`), h("pre", {}, clean(e.response))));
  } else if (e.kind === "command") {
    node.append(h("div", { class: "in" }, highlight(`$ ${e.path || ""}`)));
    if (e.response) node.append(h("pre", { class: "out" }, clean(e.response)));
  } else if (e.kind === "connect") {
    const ver = (e.headers || []).find(([k]) => k === "client_version");
    node.append(h("div", { class: "in" }, `connect from ${e.ip}:${e.port || ""}${ver ? `  (${ver[1]})` : ""}`));
  } else {
    node.append(h("div", { class: "in" }, `${e.kind} ${e.method || ""} ${e.path || ""}`));
  }
  return node;
}

async function viewSession(sid) {
  setNav("");
  let d;
  try { d = await api(`/api/sessions/${encodeURIComponent(sid)}`); } catch (e) { return failure(e); }
  const s = d.session;
  const fact = (k, v) => h("div", {}, h("div", { class: "k" }, k), h("div", { class: "v" }, v ?? "–"));
  const term = h("div", { class: "term" });
  let lastId = 0;
  const addEvents = (evs) => {
    if (!evs.length) return;
    const atBottom = term.scrollTop + term.clientHeight >= term.scrollHeight - 30;
    evs.forEach((e) => term.append(eventNode(e)));
    lastId = evs[evs.length - 1].id;
    if (atBottom) term.scrollTop = term.scrollHeight;
  };
  if (!d.events.length) term.append(h("div", { class: "empty" }, "no events"));
  addEvents(d.events);

  const tables = {
    transcript: term,
    credentials: d.credentials.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["when", "protocol", "username", "password / key", "result"].map((c) => h("th", {}, c)))),
      h("tbody", {}, d.credentials.map((c) => h("tr", {}, h("td", {}, stamp(c.ts)), h("td", {}, c.protocol),
        h("td", { class: "mono" }, c.username), h("td", { class: "mono wrap" }, c.password),
        h("td", {}, c.success ? h("span", { class: "b ok" }, "accepted") : h("span", { class: "b" }, "rejected")))))))
      : h("div", { class: "empty" }, "no login attempts"),
    iocs: d.iocs.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["when", "kind", "value", "context"].map((c) => h("th", {}, c)))),
      h("tbody", {}, d.iocs.map((i) => h("tr", {}, h("td", {}, stamp(i.ts)), h("td", {}, h("span", { class: "b atk" }, i.kind)),
        h("td", { class: "mono wrap" }, i.value), h("td", { class: "mono wrap" }, i.context))))))
      : h("div", { class: "empty" }, "no indicators"),
    canaries: d.canary_hits.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["when", "credential", "context"].map((c) => h("th", {}, c)))),
      h("tbody", {}, d.canary_hits.map((c) => h("tr", {}, h("td", {}, stamp(c.ts)), h("td", {}, c.label || c.kind),
        h("td", { class: "wrap" }, c.context))))))
      : h("div", { class: "empty" }, "no leaked credential reused"),
  };
  const body = h("div", {}, tables.transcript);
  const tabBtns = Object.keys(tables).map((k) => h("button", {
    class: k === "transcript" ? "on" : "", onclick: (ev) => {
      tabBtns.forEach((b) => b.classList.remove("on")); ev.target.classList.add("on"); body.replaceChildren(tables[k]);
    },
  }, k === "transcript" ? `Transcript (${d.events.length})` : k === "credentials" ? `Credentials (${d.credentials.length})`
    : k === "iocs" ? `IOCs (${d.iocs.length})` : `Canary hits (${d.canary_hits.length})`));

  $view.replaceChildren(
    h("div", { class: "toolbar" }, h("a", { href: "#/live" }, "← back"), h("span", { class: "mono" }, `session ${s.id}`)),
    h("section", { class: "panel" },
      h("div", { class: "toolbar" }, h("span", { class: "mono", style: "font-size:18px" }, s.ip), protoBadges(s.protocol),
        kindBadge(s.kind, s.kind_confidence), soph(s.sophistication), s.tool ? h("span", { class: "b" }, s.tool) : ""),
      h("div", { class: "facts" },
        fact("location / network", geo(s) + (s.city ? ` (${s.city})` : "")),
        fact("all source IPs", s.ips.join(", ")),
        fact("first seen", stamp(s.first_seen)), fact("last seen", `${stamp(s.last_seen)} (${ago(s.last_seen)})`),
        fact("events", fmtN(s.req_count)), fact("authenticated as", s.authenticated),
        fact("user-agent", s.user_agent), fact("JA3", s.ja3), fact("JA4", s.ja4), fact("session cookie", s.cookie))),
    h("div", { class: "tabs" }, tabBtns), body);
  term.scrollTop = term.scrollHeight;

  const poll = async () => {
    try { const n = await api(`/api/sessions/${encodeURIComponent(sid)}?after=${lastId}`); addEvents(n.events); } catch { /* transient */ }
  };
  state.onEvents = (rows) => { if (rows.some((r) => r.session_id === sid)) poll(); };
  every(10000, poll);
}

// ---------------------------------------------------------------- router
async function route() {
  clearTimers();
  const [, view, arg] = (location.hash || "#/live").split("/");
  try {
    if (view === "session" && arg) await viewSession(decodeURIComponent(arg));
    else if (view === "stats") await viewStats();
    else if (view === "canaries") await viewCanaries();
    else if (view === "iocs") await viewIocs();
    else await viewLive();
  } catch (e) { failure(e); }
}
window.addEventListener("hashchange", route);
$range.addEventListener("change", () => { try { localStorage.setItem("mt-range", $range.value); } catch { /* private mode */ } route(); });
try { const r = localStorage.getItem("mt-range"); if (r !== null) $range.value = r; } catch { /* private mode */ }
connectStream();
route();
