#!/usr/bin/env bash
# scripts/cluster_rolling_restart.sh — deploy fresh native binaries and
# rolling-restart the QIHSE cluster daemons one node at a time, then verify
# the cluster has re-converged and replication has synced.
#
# Restart order: non-seed nodes first (node5, node1), the join seed (node0)
# last, so the seed stays available while the others rejoin.
#
# For each node:
#   1. verify the freshly built binaries exist in its build directory
#   2. back up the currently deployed binaries (timestamped .bak)
#   3. install the new libqihse.so + daemon/tool binaries
#   4. systemctl restart the node service
#   5. wait for PING via the pinned QKP admin identity (qihse-admin-cli;
#      redis-cli password AUTH is only a fallback for non-hardened nodes)
#   6. wait for `cluster nodes` to report every peer connected
# After all nodes: verify 3/3 from each side and wait one replication
# interval so the 30s automatic sync has run.
#
# Usage:
#   ./scripts/cluster_rolling_restart.sh           # rolling deploy + restart + verify
#   ./scripts/cluster_rolling_restart.sh --verify-only
#   ./scripts/cluster_rolling_restart.sh --node node5 --node node1 --node node0
#
# The QKP health probes require the masters to pin this host's admin
# identity: --admin-peer-node-id admin-t420 --admin-peer-dsa-pub <pub>.
# Environment:
#   QIHSE_OPERATOR_PASSWORD  redis-cli fallback for non-hardened deployments

set -euo pipefail

# name | ssh target (local = this host) | systemd unit | bin dir | lib dir | build dir | RESP ip | RESP port | master dsa pub (for QKP pin)
NODES=(
    "node5|root@192.168.1.90|qihse-node5-host.service|/opt/QIHSE/bin|/opt/QIHSE/lib|/opt/QIHSE-src|192.168.1.90|7115|qihse_dsa_pub_730xd.pem"
    "node1|root@192.168.1.95|qihse-node1.service|/opt/qihse/bin|/opt/qihse/lib|/opt/qihse-src|192.168.1.250|7101|qihse_dsa_pub_t320.pem"
    "node0|local|qihse-node0.service|/opt/QIHSE/bin|/opt/QIHSE/lib|/opt/QIHSE|192.168.1.91|7100|qihse_dsa_pub_t420.pem"
)

# Pinned admin identity this host presents to the masters (matches the
# --admin-peer-node-id/--admin-peer-dsa-pub pins on each master unit).
ADMIN_CLI=/opt/QIHSE/bin/qihse-admin-cli
ADMIN_NODE_ID=admin-t420

BINARIES=(qihse-cluster-daemon qihse_keygen qihse-federation-ca
          qihse-machine-token qihse-backup qihse-admin-cli)
EXPECTED_NODES=3
PING_TIMEOUT=120
JOIN_TIMEOUT=180
SYNC_WAIT=40

VERIFY_ONLY=0
SELECTED=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --verify-only) VERIFY_ONLY=1; shift ;;
        --node) SELECTED+=("$2"); shift 2 ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s ==\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

node_field() { # node_spec field_index
    local spec="$1" idx="$2"
    awk -F'|' -v i="$idx" '{print $i}' <<<"$spec"
}

# Run a command on a node ("local" runs here, otherwise ssh).
on_node() {
    local target="$1"; shift
    if [ "$target" = "local" ]; then
        bash -c "$*"
    else
        ssh -o BatchMode=yes "$target" "$*"
    fi
}

node_selected() {
    local name="$1"
    [ "${#SELECTED[@]}" -eq 0 ] && return 0
    local s
    for s in "${SELECTED[@]}"; do [ "$s" = "$name" ] && return 0; done
    return 1
}

node_password() {
    local target="$1" name="$2" pw=""
    local envfile="/etc/qihse/cluster-node${name#node}.env"
    if [ "$target" = "local" ]; then
        pw="$(sudo grep -E '^QIHSE_OPERATOR_PASSWORD=' "$envfile" 2>/dev/null | head -1 | cut -d= -f2- || true)"
    else
        pw="$(ssh -o BatchMode=yes "$target" "grep -E '^QIHSE_OPERATOR_PASSWORD=' '$envfile' 2>/dev/null | head -1 | cut -d= -f2-" 2>/dev/null || true)"
    fi
    # strip surrounding quotes locally (avoids remote shell quoting pitfalls)
    pw="${pw#\"}"; pw="${pw%\"}"; pw="${pw#\'}"; pw="${pw%\'}"
    [ -n "$pw" ] || pw="${QIHSE_OPERATOR_PASSWORD:-}"
    printf '%s' "$pw"
}

# RESP probe against a node from here. Prefer the pinned QKP admin identity
# (qihse-admin-cli) — the only path on pqc_require masters; fall back to
# redis-cli password AUTH for non-hardened deployments.
node_probe_ping() {
    local ip="$1" port="$2" pub="$3" pw="$4" out
    if [ -x "$ADMIN_CLI" ] && [ -f "/etc/qihse/keys/$pub" ]; then
        out="$(sudo "$ADMIN_CLI" --host "$ip" --port "$port" --node-id "$ADMIN_NODE_ID" \
            --identity-dir /etc/qihse/keys \
            --trusted-pub "/etc/qihse/keys/$pub" --ping 2>/dev/null || true)"
        [ "$out" = "PONG" ] && { printf 'PONG\n'; return; }
    fi
    if [ -n "$pw" ]; then
        REDISCLI_AUTH="$pw" redis-cli --no-auth-warning -h "$ip" -p "$port" ping 2>/dev/null || true
    else
        redis-cli -h "$ip" -p "$port" ping 2>/dev/null || true
    fi
}

node_probe_cluster() {
    local ip="$1" port="$2" pub="$3" pw="$4" out
    if [ -x "$ADMIN_CLI" ] && [ -f "/etc/qihse/keys/$pub" ]; then
        out="$(sudo "$ADMIN_CLI" --host "$ip" --port "$port" --node-id "$ADMIN_NODE_ID" \
            --identity-dir /etc/qihse/keys \
            --trusted-pub "/etc/qihse/keys/$pub" --cluster-nodes 2>/dev/null || true)"
        [ -n "$out" ] && { printf '%s\n' "$out"; return; }
    fi
    if [ -n "$pw" ]; then
        REDISCLI_AUTH="$pw" redis-cli --no-auth-warning -h "$ip" -p "$port" cluster nodes 2>/dev/null || true
    else
        redis-cli -h "$ip" -p "$port" cluster nodes 2>/dev/null || true
    fi
}

verify_node() {
    local name="$1" spec="$2"
    local target ip port pw pub out
    target="$(node_field "$spec" 2)"
    ip="$(node_field "$spec" 7)"
    port="$(node_field "$spec" 8)"
    pub="$(node_field "$spec" 9)"
    pw="$(node_password "$target" "$name")"

    out="$(node_probe_ping "$ip" "$port" "$pub" "$pw")"
    if ! grep -qi pong <<<"$out"; then
        fail "$name: no PONG from $ip:$port (got '${out:-}')"
    fi

    local nodes_out
    nodes_out="$(node_probe_cluster "$ip" "$port" "$pub" "$pw")"
    local connected
    connected="$(grep -c ' connected' <<<"$nodes_out" || true)"
    say "  $name: PONG ok; cluster reports ${connected}/${EXPECTED_NODES} nodes connected"
    [ "${connected:-0}" -ge "$EXPECTED_NODES" ] || fail "$name: only ${connected}/${EXPECTED_NODES} connected"
}

restart_node() {
    local name="$1" spec="$2"
    local target unit bindir libdir builddir ip port pub
    target="$(node_field "$spec" 2)"
    unit="$(node_field "$spec" 3)"
    bindir="$(node_field "$spec" 4)"
    libdir="$(node_field "$spec" 5)"
    builddir="$(node_field "$spec" 6)"
    ip="$(node_field "$spec" 7)"
    port="$(node_field "$spec" 8)"
    pub="$(node_field "$spec" 9)"

    step "$name — deploy and restart ($unit)"

    # 1. pre-flight: fresh binaries must exist in the build dir
    on_node "$target" "test -f '$builddir/libqihse.so' && test -f '$builddir/qihse-cluster-daemon'" \
        || fail "$name: fresh build missing in $builddir"

    local ts; ts="$(date +%Y%m%d-%H%M%S)"

    # 2. back up + install libqihse.so
    on_node "$target" "
        [ -f '$libdir/libqihse.so' ] && mv '$libdir/libqihse.so' '$libdir/libqihse.so.bak-$ts' || true
        install -m 755 '$builddir/libqihse.so' '$libdir/libqihse.so'"

    # 3. back up + install binaries
    local b
    for b in "${BINARIES[@]}"; do
        on_node "$target" "
            [ -f '$bindir/$b' ] && mv '$bindir/$b' '$bindir/$b.bak-$ts' || true
            install -m 755 '$builddir/$b' '$bindir/$b'"
    done
    say "  installed fresh libqihse.so + ${#BINARIES[@]} binaries (backups: .bak-$ts)"

    # 4. rolling restart: stop/start just this node
    local restart_cmd="systemctl restart '$unit'"
    [ "$target" = "local" ] && restart_cmd="sudo systemctl restart '$unit'"
    on_node "$target" "$restart_cmd"

    # 5. wait for PING
    local pw; pw="$(node_password "$target" "$name")"
    local i out
    for i in $(seq 1 "$PING_TIMEOUT"); do
        out="$(node_probe_ping "$ip" "$port" "$pub" "$pw")"
        if grep -qi pong <<<"$out"; then break; fi
        sleep 1
    done
    grep -qi pong <<<"$out" || fail "$name: no PONG within ${PING_TIMEOUT}s of restart"

    # 6. wait for full membership
    local nodes_out connected
    for i in $(seq 1 "$JOIN_TIMEOUT"); do
        nodes_out="$(node_probe_cluster "$ip" "$port" "$pub" "$pw")"
        connected="$(grep -c ' connected' <<<"$nodes_out" || true)"
        if [ "${connected:-0}" -ge "$EXPECTED_NODES" ]; then break; fi
        sleep 1
    done
    say "  $name: restarted, PONG ok, ${connected:-0}/${EXPECTED_NODES} nodes connected"
    [ "${connected:-0}" -ge "$EXPECTED_NODES" ] || fail "$name: cluster did not re-converge (${connected:-0}/${EXPECTED_NODES})"
}

main() {
    { [ -x "$ADMIN_CLI" ] || command -v redis-cli >/dev/null; } \
        || fail "qihse-admin-cli (or redis-cli) is required for health checks"
    local spec name target unit
    for spec in "${NODES[@]}"; do
        name="$(node_field "$spec" 1)"
        node_selected "$name" || continue
        target="$(node_field "$spec" 2)"
        unit="$(node_field "$spec" 3)"
        if [ "$VERIFY_ONLY" -eq 0 ]; then
            restart_node "$name" "$spec"
        fi
        verify_node "$name" "$spec"
    done

    step "cluster sync"
    say "  replication globs run every 30s per node; waiting ${SYNC_WAIT}s for a sync pass..."
    sleep "$SYNC_WAIT"
    for spec in "${NODES[@]}"; do
        name="$(node_field "$spec" 1)"
        node_selected "$name" || continue
        target="$(node_field "$spec" 2)"
        unit="$(node_field "$spec" 3)"
        local joined
        joined="$(on_node "$target" "journalctl -u '$unit' --no-pager --since '-60s' 2>/dev/null | grep -cE 'joined cluster|replica pull' || true")"
        say "  $name: daemon journal (last 60s) shows $joined cluster/sync lines"
    done

    step "final verification"
    for spec in "${NODES[@]}"; do
        name="$(node_field "$spec" 1)"
        node_selected "$name" || continue
        verify_node "$name" "$spec"
    done
    say ""
    say "OK: rolling restart complete, all ${EXPECTED_NODES} nodes connected and syncing."
}

main "$@"
