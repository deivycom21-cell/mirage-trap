#!/bin/sh
# Expose the unprivileged trap ports on the standard ones without running as root.
#
#   80  -> 8080 (HTTP)      only if you are NOT using deploy/nginx.conf
#   22  -> 2222 (SSH)       move your real sshd to another port FIRST (e.g. 22222)
#   23  -> 2323 (Telnet)
#
# Usage: sudo sh deploy/iptables.sh [interface]      (default: eth0)
# Persist with iptables-persistent / netfilter-persistent.
set -eu

IFACE="${1:-eth0}"

redirect() {
    proto_port="$1"; target="$2"
    iptables  -t nat -C PREROUTING -i "$IFACE" -p tcp --dport "$proto_port" -j REDIRECT --to-ports "$target" 2>/dev/null \
      || iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport "$proto_port" -j REDIRECT --to-ports "$target"
    ip6tables -t nat -C PREROUTING -i "$IFACE" -p tcp --dport "$proto_port" -j REDIRECT --to-ports "$target" 2>/dev/null \
      || ip6tables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport "$proto_port" -j REDIRECT --to-ports "$target" || true
}

redirect 80 8080
redirect 22 2222
redirect 23 2323

# Egress: the sensor must not be usable as a pivot. Allow only DNS/NTP/updates and,
# if you use a remote LLM provider, HTTPS to it. Adjust to your environment.
# iptables -A OUTPUT -o "$IFACE" -m owner --uid-owner mirage -p tcp --dport 443 -j ACCEPT
# iptables -A OUTPUT -o "$IFACE" -m owner --uid-owner mirage -m state --state ESTABLISHED,RELATED -j ACCEPT
# iptables -A OUTPUT -o "$IFACE" -m owner --uid-owner mirage -j REJECT

echo "redirects installed on $IFACE: 80->8080 22->2222 23->2323"
