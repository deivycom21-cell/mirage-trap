"""Telemetry export: JSON Lines, CSV and STIX 2.1 bundles."""

from __future__ import annotations

import csv
import io
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Iterator, TextIO

from mirage_trap.core.db import Database

EVENT_COLUMNS = ["id", "session_id", "ts", "protocol", "ip", "port", "kind", "method", "path", "query", "status",
                 "attack_type", "attack_detail", "persona", "provider", "body_len", "body_sha256", "response_len",
                 "latency_sim_ms", "latency_real_ms", "user_agent", "country", "asn", "as_org", "session_kind",
                 "tool", "sophistication"]
STIX_NS = uuid.UUID("6f1c2a5e-8b0d-4c39-9a57-6d3b1e1f0a42")


def parse_since(value: str | None, now: float | None = None) -> float:
    """'24h', '7d', '30m', '90s' or an ISO date -> unix timestamp. Empty -> 0 (everything)."""
    if not value:
        return 0.0
    now = now or time.time()
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*", value)
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
        return now - float(m.group(1)) * mult
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as e:
        raise ValueError(f"cannot parse --since {value!r} (use 24h, 7d, or an ISO date)") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def iter_events(db: Database, since: float = 0.0, batch: int = 2000) -> Iterator[dict]:
    last = 0
    while True:
        rows = db.query(
            "SELECT e.id, e.session_id, e.ts, e.protocol, e.ip, e.port, e.kind, e.method, e.path, e.query, e.headers, "
            "e.body, e.body_len, e.body_sha256, e.attack_type, e.attack_detail, e.persona, e.status, e.response, "
            "e.response_len, e.latency_sim_ms, e.latency_real_ms, e.provider, s.user_agent, s.country, s.asn, "
            "s.as_org, s.kind AS session_kind, s.tool, s.sophistication "
            "FROM events e LEFT JOIN sessions s ON s.id = e.session_id "
            "WHERE e.ts >= ? AND e.id > ? ORDER BY e.id LIMIT ?", (since, last, batch))
        if not rows:
            return
        for r in rows:
            if r.get("headers"):
                try:
                    r["headers"] = json.loads(r["headers"])
                except ValueError:
                    pass
            yield r
        last = rows[-1]["id"]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def write_jsonl(db: Database, out: TextIO, since: float = 0.0) -> int:
    n = 0
    for e in iter_events(db, since):
        e["time"] = _iso(e["ts"])
        out.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")
        n += 1
    return n


def write_csv(db: Database, out: TextIO, since: float = 0.0) -> int:
    w = csv.DictWriter(out, fieldnames=["time"] + EVENT_COLUMNS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    n = 0
    for e in iter_events(db, since):
        e["time"] = _iso(e["ts"])
        w.writerow(e)
        n += 1
    return n


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(STIX_NS, kind + ':' + key)}"


def stix_bundle(db: Database, since: float = 0.0) -> dict:
    """Indicators for attacker IPs and IOCs (download URLs, webshells), sightings
    linking them to this sensor, and notes with the behavioural verdict."""
    now = _iso(time.time())
    identity_id = _sid("identity", "mirage-trap-sensor")
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
        "name": "mirage-trap sensor", "identity_class": "system",
    }]
    sessions = db.query("SELECT * FROM sessions WHERE last_seen >= ? ORDER BY first_seen", (since,))
    for s in sessions:
        ips = sorted(set(json.loads(s.get("ips") or "[]")) | {s["ip"]})
        for ip in ips:
            sco_type = "ipv6-addr" if ":" in ip else "ipv4-addr"
            ind_id = _sid("indicator", ip)
            if any(o["id"] == ind_id for o in objects):
                continue
            attacks = [r["attack_type"] for r in db.query(
                "SELECT DISTINCT attack_type FROM events WHERE session_id = ? AND attack_type IS NOT NULL", (s["id"],))]
            labels = sorted({"malicious-activity", *(a for a in attacks if a)})
            desc = (f"Source of {s['req_count']} interactions ({s['protocol']}) against a deception sensor. "
                    f"Behaviour: {s.get('kind') or 'unknown'}, sophistication {s.get('sophistication') or 0}/5"
                    + (f", tool {s['tool']}" if s.get("tool") else "") + ".")
            objects.append({
                "type": "indicator", "spec_version": "2.1", "id": ind_id, "created": _iso(s["first_seen"]),
                "modified": _iso(s["last_seen"]), "name": f"Hostile source {ip}", "description": desc,
                "indicator_types": ["malicious-activity"], "labels": labels,
                "pattern": f"[{sco_type}:value = '{ip}']", "pattern_type": "stix",
                "valid_from": _iso(s["first_seen"]), "created_by_ref": identity_id,
            })
            objects.append({
                "type": "sighting", "spec_version": "2.1", "id": _sid("sighting", f"{s['id']}:{ip}"),
                "created": _iso(s["first_seen"]), "modified": _iso(s["last_seen"]),
                "first_seen": _iso(s["first_seen"]), "last_seen": _iso(s["last_seen"]),
                "count": max(1, s["req_count"] or 1), "sighting_of_ref": ind_id,
                "where_sighted_refs": [identity_id], "created_by_ref": identity_id,
            })
    for i in db.query("SELECT * FROM iocs WHERE ts >= ? ORDER BY id", (since,)):
        value = i["value"]
        if i["kind"] in ("url", "download"):
            esc = value.replace("\\", "\\\\").replace("'", "\\'")
            pattern = f"[url:value = '{esc}']"
        elif i["kind"] == "hash" and re.fullmatch(r"[0-9a-fA-F]{64}", value):
            pattern = f"[file:hashes.'SHA-256' = '{value.lower()}']"
        elif i["kind"] in ("reverse_shell", "connect") and (m := re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", value)):
            pattern = (f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = "
                       f"'{m.group(1)}' AND network-traffic:dst_port = {int(m.group(2))}]")
        else:
            continue
        ind_id = _sid("indicator", f"{i['kind']}:{value}")
        if any(o["id"] == ind_id for o in objects):
            continue
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id, "created": _iso(i["ts"]),
            "modified": _iso(i["ts"]), "name": f"Payload {i['kind']} seen on sensor",
            "description": (i.get("context") or "")[:500], "indicator_types": ["malicious-activity"],
            "pattern": pattern, "pattern_type": "stix", "valid_from": _iso(i["ts"]), "created_by_ref": identity_id,
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def export(db: Database, fmt: str, out: TextIO, since: float = 0.0) -> int:
    fmt = fmt.lower()
    if fmt == "jsonl":
        return write_jsonl(db, out, since)
    if fmt == "csv":
        return write_csv(db, out, since)
    if fmt == "stix":
        bundle = stix_bundle(db, since)
        json.dump(bundle, out, indent=1, ensure_ascii=False)
        out.write("\n")
        return len(bundle["objects"])
    raise ValueError(f"unknown format {fmt!r} (jsonl, csv, stix)")


def export_to_string(db: Database, fmt: str, since: float = 0.0) -> str:
    buf = io.StringIO()
    export(db, fmt, buf, since)
    return buf.getvalue()
