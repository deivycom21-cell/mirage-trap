"""TLS client fingerprinting (JA3 / JA4) in standalone mode.

``SSLContext._msg_callback`` hands us every TLS handshake message, including the
raw ClientHello, while the stdlib performs the handshake. We fingerprint it and key
the result by the SSL object; the HTTP protocol picks it up once the connection is
made. No custom TLS stack, no packet capture.
"""

from __future__ import annotations

import hashlib
import ssl
import struct
import threading

GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
          0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
_TLS_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}

_fingerprints: dict[int, dict] = {}
_lock = threading.Lock()


def parse_client_hello(msg: bytes) -> dict | None:
    """``msg`` is the handshake message: type(1) + length(3) + body."""
    try:
        if not msg or msg[0] != 1:
            return None
        body = msg[4:]
        p = 0
        legacy_version = struct.unpack_from("!H", body, p)[0]
        p += 2 + 32
        sid_len = body[p]
        p += 1 + sid_len
        cs_len = struct.unpack_from("!H", body, p)[0]
        p += 2
        ciphers = [struct.unpack_from("!H", body, p + i)[0] for i in range(0, cs_len, 2)]
        p += cs_len
        comp_len = body[p]
        p += 1 + comp_len
        exts: list[int] = []
        curves: list[int] = []
        point_formats: list[int] = []
        sig_algs: list[int] = []
        alpn: list[str] = []
        versions: list[int] = []
        sni = False
        if p < len(body):
            ext_total = struct.unpack_from("!H", body, p)[0]
            p += 2
            end = p + ext_total
            while p + 4 <= end:
                etype, elen = struct.unpack_from("!HH", body, p)
                p += 4
                data = body[p:p + elen]
                p += elen
                exts.append(etype)
                if etype == 0:
                    sni = True
                elif etype == 10 and len(data) >= 2:
                    n = struct.unpack_from("!H", data, 0)[0]
                    curves = [struct.unpack_from("!H", data, 2 + i)[0] for i in range(0, n, 2)]
                elif etype == 11 and data:
                    point_formats = list(data[1:1 + data[0]])
                elif etype == 13 and len(data) >= 2:
                    n = struct.unpack_from("!H", data, 0)[0]
                    sig_algs = [struct.unpack_from("!H", data, 2 + i)[0] for i in range(0, n, 2)]
                elif etype == 16 and len(data) >= 2:
                    q = 2
                    while q < len(data):
                        ln = data[q]
                        alpn.append(data[q + 1:q + 1 + ln].decode("ascii", "replace"))
                        q += 1 + ln
                elif etype == 43 and data:
                    versions = [struct.unpack_from("!H", data, 1 + i)[0] for i in range(0, data[0], 2)]
        return {"version": legacy_version, "ciphers": ciphers, "extensions": exts, "curves": curves,
                "point_formats": point_formats, "sig_algs": sig_algs, "alpn": alpn, "versions": versions, "sni": sni}
    except (IndexError, struct.error):
        return None


def ja3(h: dict) -> tuple[str, str]:
    def j(vals):
        return "-".join(str(v) for v in vals if v not in GREASE)
    text = ",".join([str(h["version"]), j(h["ciphers"]), j(h["extensions"]), j(h["curves"]), j(h["point_formats"])])
    return text, hashlib.md5(text.encode()).hexdigest()


def ja4(h: dict) -> str:
    ciphers = [c for c in h["ciphers"] if c not in GREASE]
    exts = [e for e in h["extensions"] if e not in GREASE]
    versions = [v for v in h["versions"] if v not in GREASE]
    ver = _TLS_VER.get(max(versions) if versions else h["version"], "00")
    alpn = h["alpn"][0] if h["alpn"] else ""
    alpn_code = (alpn[0] + alpn[-1]) if alpn else "00"
    if alpn_code and not alpn_code.isascii():
        alpn_code = "99"
    a = f"t{ver}{'d' if h['sni'] else 'i'}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn_code}"
    sha12 = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12] if s else "000000000000"
    b = sha12(",".join(f"{c:04x}" for c in sorted(ciphers)))
    ext_sorted = ",".join(f"{e:04x}" for e in sorted(e for e in exts if e not in (0x0000, 0x0010)))
    sigs = ",".join(f"{s:04x}" for s in h["sig_algs"])
    c = sha12(ext_sorted + ("_" + sigs if sigs else ""))
    return f"{a}_{b}_{c}"


def _callback(conn, direction, version, content_type, msg_type, data):
    if direction != "read":
        return
    if getattr(content_type, "name", "") != "HANDSHAKE" or getattr(msg_type, "name", "") != "CLIENT_HELLO":
        return
    parsed = parse_client_hello(bytes(data))
    if parsed is None:
        return
    text, digest = ja3(parsed)
    with _lock:
        _fingerprints[id(conn)] = {"ja3": digest, "ja3_text": text, "ja4": ja4(parsed),
                                   "sni": parsed["sni"], "alpn": parsed["alpn"]}
        if len(_fingerprints) > 10_000:      # connections that never completed
            for k in list(_fingerprints)[:5_000]:
                _fingerprints.pop(k, None)


def install(ctx: ssl.SSLContext) -> None:
    ctx._msg_callback = _callback  # noqa: SLF001 - documented-but-private stdlib debug hook


def pop_fingerprint(ssl_object) -> dict | None:
    if ssl_object is None:
        return None
    with _lock:
        return _fingerprints.pop(id(ssl_object), None)
