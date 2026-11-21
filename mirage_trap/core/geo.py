"""Offline GeoIP/ASN enrichment. Never performs network lookups (an attacker who
controls reverse DNS for their IP would notice a lookup)."""

from __future__ import annotations

import ipaddress
import logging

log = logging.getLogger("mirage.geo")


class GeoIP:
    def __init__(self, city_db: str = "", asn_db: str = ""):
        self.city = self.asn = None
        try:
            import maxminddb  # optional dependency
        except ImportError:
            maxminddb = None
        if maxminddb:
            if city_db:
                try:
                    self.city = maxminddb.open_database(city_db)
                except (OSError, ValueError) as e:
                    log.warning("cannot open GeoIP city db: %s", e)
            if asn_db:
                try:
                    self.asn = maxminddb.open_database(asn_db)
                except (OSError, ValueError) as e:
                    log.warning("cannot open GeoIP ASN db: %s", e)

    def lookup(self, ip: str) -> dict:
        out = {"country": None, "city": None, "asn": None, "as_org": None}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return out
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            out["country"] = "LAN"
            return out
        if self.city:
            rec = self.city.get(ip) or {}
            out["country"] = (rec.get("country") or {}).get("iso_code")
            out["city"] = ((rec.get("city") or {}).get("names") or {}).get("en")
        if self.asn:
            rec = self.asn.get(ip) or {}
            out["asn"] = rec.get("autonomous_system_number")
            out["as_org"] = rec.get("autonomous_system_organization")
        return out
