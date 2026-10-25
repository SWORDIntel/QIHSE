#!/usr/bin/env bash
# scripts/cluster_watchdog.sh — one-shot health/alert check for the QIHSE
# cluster. Exits non-zero (and prints a single alert line to stderr) if any
# master fails a QKP PING or any replica's most recent pull was not ok.
#
# Usage:
#   ./scripts/cluster_watchdog.sh            # check all masters + replicas
#   QIHSE_WATCHDOG_HOSTS="..." ./scripts/... # override master list
#
# Designed for cron/systemd-timer. The QKP probes run from this host using
# the pinned admin identity (admin-t420).

set -uo pipefail

ADMIN_CLI=/opt/QIHSE/bin/qihse-admin-cli
ADMIN_NODE_ID="${QIHSE_ADMIN_NODE_ID:-admin-t420}"

# master: ip|port|pub-file
MASTERS="${QIHSE_WATCHDOG_MASTERS:-192.168.1.91|7100|qihse_dsa_pub_t420.pem 192.168.1.90|7115|qihse_dsa_pub_730xd.pem 192.168.1.250|7101|qihse_dsa_pub_t320.pem}"

# replica: host|ssh-target|unit  (ssh-target 'local' = this host)
REPLICAS="${QIHSE_WATCHDOG_REPLICAS:-t420|local|qihse-replica-keystone t420|local|qihse-replica-kp14 730xd|root@192.168.1.90|qihse-replica-audit 730xd|root@192.168.1.90|qihse-replica-chain t320|root@192.168.1.95|qihse-replica-tool t320|root@192.168.1.95|qihse-replica-sabot}"

failures=0

probe_ping() {
    local ip="$1" port="$2" pub="$3"
    [ -x "$ADMIN_CLI" ] || { echo "watchdog: $ADMIN_CLI not found" >&2; return 1; }
    sudo "$ADMIN_CLI" --host "$ip" --port "$port" --node-id "$ADMIN_NODE_ID" \
        --identity-dir /etc/qihse/keys \
        --trusted-pub "/etc/qihse/keys/$pub" --ping 2>/dev/null
}

on_host() {
    local target="$1"; shift
    if [ "$target" = "local" ]; then bash -c "$*"; else ssh -o BatchMode=yes -o ConnectTimeout=8 "$target" "$*" 2>/dev/null; fi
}

# Masters: PING
for m in $MASTERS; do
    ip="${m%%|*}"; rest="${m#*|}"; port="${rest%%|*}"; pub="${rest#*|}"
    out="$(probe_ping "$ip" "$port" "$pub" || true)"
    if ! grep -qi pong <<<"$out"; then
        echo "ALERT: master $ip:$port PING failed (got '${out:-}')" >&2
        failures=$((failures + 1))
    fi
done

# Replicas: last pull ok?
for r in $REPLICAS; do
    host="${r%%|*}"; rest="${r#*|}"; target="${rest%%|*}"; unit="${rest#*|}"
    last="$(on_host "$target" "journalctl -u '$unit' --no-pager -n 200 2>/dev/null | grep 'replica pull' | tail -1" || true)"
    if [ -n "$last" ] && ! grep -q '(ok)' <<<"$last"; then
        echo "ALERT: replica $host/$unit latest pull not ok: $last" >&2
        failures=$((failures + 1))
    fi
done

if [ "$failures" -gt 0 ]; then
    echo "watchdog: $failures failure(s)" >&2
    exit 1
fi
echo "watchdog: all masters PONG, all replicas ok"
exit 0
