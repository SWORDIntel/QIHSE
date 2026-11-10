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
#   5. wait for PING via the pinned QKP admin identity (qihse-admin-cli)
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
#   QIHSE_ADMIN_CLI          path to the pinned QKP admin client

set -euo pipefail

# name | ssh target (local = this host) | systemd unit | build dir | RESP ip | RESP port | master DSA pub (QKP pin)
NODES=(
    "node5|root@192.168.1.90|qihse-node5-host.service|/opt/QIHSE-src|192.168.1.90|7115|qihse_dsa_pub_730xd.pem"
    "node1|root@192.168.1.95|qihse-node1.service|/opt/qihse-src|192.168.1.250|7101|qihse_dsa_pub_t320.pem"
    "node0|local|qihse-node0.service|/opt/QIHSE|192.168.1.91|7100|qihse_dsa_pub_t420.pem"
)

# Pinned admin identity this host presents to the masters (matches the
# --admin-peer-node-id/--admin-peer-dsa-pub pins on each master unit).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ADMIN_CLI="${QIHSE_ADMIN_CLI:-$SCRIPT_DIR/../bin/qihse-admin-cli}"
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
        --node)
            [ "$#" -ge 2 ] && [ -n "$2" ] || { echo "--node requires a node name" >&2; exit 2; }
            SELECTED+=("$2"); shift 2 ;;
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

# Reject a typo before any connection, file copy or restart.
for selected_name in "${SELECTED[@]}"; do
    found=0
    for spec in "${NODES[@]}"; do
        [ "$(node_field "$spec" 1)" = "$selected_name" ] && found=1
    done
    [ "$found" -eq 1 ] || { echo "unknown node: $selected_name" >&2; exit 2; }
done

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

# RESP probes use only the pinned QKP admin identity. A failed/missing QKP
# configuration is an error; never downgrade a cluster rollout to cleartext.
node_probe_ping() {
    local ip="$1" port="$2" pub="$3"
    sudo "$ADMIN_CLI" --host "$ip" --port "$port" --node-id "$ADMIN_NODE_ID" \
        --identity-dir /etc/qihse/keys --trusted-pub "/etc/qihse/keys/$pub" --ping 2>/dev/null || true
}

node_probe_cluster() {
    local ip="$1" port="$2" pub="$3"
    sudo "$ADMIN_CLI" --host "$ip" --port "$port" --node-id "$ADMIN_NODE_ID" \
        --identity-dir /etc/qihse/keys --trusted-pub "/etc/qihse/keys/$pub" --cluster-nodes 2>/dev/null || true
}

# Resolve the exact files mapped by the running unit. This intentionally fails
# closed for stopped/unknown units instead of installing into a guessed legacy
# prefix which systemd may not execute.
node_live_artifacts() {
    local target="$1" unit="$2" unit_arg pid exe lib_map lib
    printf -v unit_arg '%q' "$unit"
    pid="$(on_node "$target" "systemctl show --property=MainPID --value $unit_arg")" \
        || return 1
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    exe="$(on_node "$target" "readlink -f /proc/$pid/exe")" || return 1
    [ "${exe##*/}" = "qihse-cluster-daemon" ] || return 1
    lib_map="$(on_node "$target" "awk '\$NF ~ /\\/libqihse\\.so$/ {print \$NF; exit}' /proc/$pid/maps")" \
        || return 1
    [ -n "$lib_map" ] || return 1
    lib="$(on_node "$target" "readlink -f $(printf '%q' "$lib_map")")" || return 1
    [ -f "$exe" ] && [ -f "$lib" ] || return 1
    printf '%s\n%s\n' "$exe" "$lib"
}

shell_quote() {
    local quoted
    printf -v quoted '%q' "$1"
    printf '%s' "$quoted"
}

verify_node() {
    local name="$1" spec="$2"
    local target ip port pub out
    target="$(node_field "$spec" 2)"
    ip="$(node_field "$spec" 5)"
    port="$(node_field "$spec" 6)"
    pub="$(node_field "$spec" 7)"
    out="$(node_probe_ping "$ip" "$port" "$pub")"
    if ! grep -qi pong <<<"$out"; then
        fail "$name: no PONG from $ip:$port (got '${out:-}')"
    fi

    local nodes_out
    nodes_out="$(node_probe_cluster "$ip" "$port" "$pub")"
    local connected
    connected="$(grep -c ' connected' <<<"$nodes_out" || true)"
    say "  $name: PONG ok; cluster reports ${connected}/${EXPECTED_NODES} nodes connected"
    [ "${connected:-0}" -ge "$EXPECTED_NODES" ] || fail "$name: only ${connected}/${EXPECTED_NODES} connected"
}

restart_node() {
    local name="$1" spec="$2"
    local target unit builddir ip port pub
    target="$(node_field "$spec" 2)"
    unit="$(node_field "$spec" 3)"
    builddir="$(node_field "$spec" 4)"
    ip="$(node_field "$spec" 5)"
    port="$(node_field "$spec" 6)"
    pub="$(node_field "$spec" 7)"

    step "$name — deploy and restart ($unit)"

    # 1. pre-flight: fresh binaries must exist in the build dir
    on_node "$target" "test -f '$builddir/libqihse.so' && test -f '$builddir/qihse-cluster-daemon'" \
        || fail "$name: fresh build missing in $builddir"

    local artifacts daemon_dest lib_dest daemon_q lib_q lib_backup_q lib_tmp_q source_q
    artifacts="$(node_live_artifacts "$target" "$unit")" \
        || fail "$name: cannot resolve the live executable/library paths for $unit"
    daemon_dest="$(sed -n '1p' <<<"$artifacts")"
    lib_dest="$(sed -n '2p' <<<"$artifacts")"
    [ -n "$daemon_dest" ] && [ -n "$lib_dest" ] \
        || fail "$name: live unit path discovery returned incomplete paths"

    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    daemon_q="$(shell_quote "$daemon_dest")"
    lib_q="$(shell_quote "$lib_dest")"
    lib_backup_q="$(shell_quote "$lib_dest.bak-$ts")"
    lib_tmp_q="$(shell_quote "$lib_dest.tmp-$ts")"
    source_q="$(shell_quote "$builddir/libqihse.so")"

    # 2. Copy a backup, stage the replacement beside the live file, then
    # atomically rename it into place. An install failure leaves the old file.
    on_node "$target" "
        set -eu
        if [ -f $lib_q ]; then cp -p $lib_q $lib_backup_q; fi
        install -m 755 $source_q $lib_tmp_q || { rm -f $lib_tmp_q; exit 1; }
        mv -f $lib_tmp_q $lib_q || { rm -f $lib_tmp_q; exit 1; }"

    # 3. back up + install binaries
    local b
    for b in "${BINARIES[@]}"; do
        local dest dest_q backup_q tmp_q build_q
        if [ "$b" = "qihse-cluster-daemon" ]; then
            dest="$daemon_dest"
        else
            dest="$(dirname "$daemon_dest")/$b"
        fi
        dest_q="$(shell_quote "$dest")"
        backup_q="$(shell_quote "$dest.bak-$ts")"
        tmp_q="$(shell_quote "$dest.tmp-$ts")"
        build_q="$(shell_quote "$builddir/$b")"
        on_node "$target" "
            set -eu
            if [ -f $dest_q ]; then cp -p $dest_q $backup_q; fi
            install -m 755 $build_q $tmp_q || { rm -f $tmp_q; exit 1; }
            mv -f $tmp_q $dest_q || { rm -f $tmp_q; exit 1; }"
    done
    say "  installed fresh libqihse.so + ${#BINARIES[@]} binaries (backups: .bak-$ts)"

    # 4. rolling restart: stop/start just this node
    local restart_cmd="systemctl restart '$unit'"
    [ "$target" = "local" ] && restart_cmd="sudo systemctl restart '$unit'"
    on_node "$target" "$restart_cmd"

    # 5. wait for PING
    local i out
    for i in $(seq 1 "$PING_TIMEOUT"); do
        out="$(node_probe_ping "$ip" "$port" "$pub")"
        if grep -qi pong <<<"$out"; then break; fi
        sleep 1
    done
    grep -qi pong <<<"$out" || fail "$name: no PONG within ${PING_TIMEOUT}s of restart"

    local active_after
    active_after="$(node_live_artifacts "$target" "$unit")" \
        || fail "$name: restarted unit does not map a resolvable daemon/library pair"
    [ "$(sed -n '1p' <<<"$active_after")" = "$daemon_dest" ] &&
    [ "$(sed -n '2p' <<<"$active_after")" = "$lib_dest" ] \
        || fail "$name: restarted unit did not load the deployed release paths"

    # 6. wait for full membership
    local nodes_out connected
    for i in $(seq 1 "$JOIN_TIMEOUT"); do
        nodes_out="$(node_probe_cluster "$ip" "$port" "$pub")"
        connected="$(grep -c ' connected' <<<"$nodes_out" || true)"
        if [ "${connected:-0}" -ge "$EXPECTED_NODES" ]; then break; fi
        sleep 1
    done
    say "  $name: restarted, PONG ok, ${connected:-0}/${EXPECTED_NODES} nodes connected"
    [ "${connected:-0}" -ge "$EXPECTED_NODES" ] || fail "$name: cluster did not re-converge (${connected:-0}/${EXPECTED_NODES})"
}

main() {
    [ -x "$ADMIN_CLI" ] || fail "pinned QKP admin client not executable: $ADMIN_CLI (set QIHSE_ADMIN_CLI if it is elsewhere)"
    local spec name target unit pub
    for spec in "${NODES[@]}"; do
        name="$(node_field "$spec" 1)"
        node_selected "$name" || continue
        pub="$(node_field "$spec" 7)"
        [ -f "/etc/qihse/keys/$pub" ] || fail "$name: pinned QKP trust key missing: /etc/qihse/keys/$pub"
    done
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
    say "OK: rolling restart complete; selected nodes checked and each reported ${EXPECTED_NODES}/${EXPECTED_NODES} members connected."
}

main "$@"
