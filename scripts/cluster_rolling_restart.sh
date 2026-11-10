#!/usr/bin/env bash
# scripts/cluster_rolling_restart.sh — deploy fresh native binaries and
# rolling-restart the QIHSE cluster daemons one node at a time, then verify
# the cluster has re-converged and replication has synced.
#
# Restart order is the order in the operator-provided node file.
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
#   QIHSE_CLUSTER_NODES_FILE=./cluster-nodes.conf ./scripts/cluster_rolling_restart.sh
#   ./scripts/cluster_rolling_restart.sh --verify-only
#   ... --node node-a --node node-b
#
# The QKP health probes require each master to pin this host's admin identity.
# Environment:
#   QIHSE_CLUSTER_NODES_FILE pipe-delimited node configuration (required)
#   QIHSE_ADMIN_CLI          path to the pinned QKP admin client (required)
#   QIHSE_ADMIN_IDENTITY_DIR local QKP identity directory (required)
#   QIHSE_ADMIN_NODE_ID      pinned local admin identity name (required)

set -euo pipefail

NODES=()
ADMIN_CLI="${QIHSE_ADMIN_CLI:-}"
ADMIN_IDENTITY_DIR="${QIHSE_ADMIN_IDENTITY_DIR:-}"
ADMIN_NODE_ID="${QIHSE_ADMIN_NODE_ID:-}"

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

load_nodes() {
    [ -n "${QIHSE_CLUSTER_NODES_FILE:-}" ] && [ -r "$QIHSE_CLUSTER_NODES_FILE" ] \
        || fail "set QIHSE_CLUSTER_NODES_FILE to a readable node specification file"
    local line name target unit builddir ip port pub extra old
    while IFS= read -r line || [ -n "$line" ]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        IFS='|' read -r name target unit builddir ip port pub extra <<<"$line"
        [ -n "$name" ] && [ -n "$target" ] && [ -n "$unit" ] && \
            [ -n "$builddir" ] && [ -n "$ip" ] && [ -n "$port" ] && [ -n "$pub" ] && \
            [ -z "${extra:-}" ] || fail "invalid node entry (expected name|target|unit|build-dir|ip|port|trust-pub): $line"
        [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "invalid node name: $name"
        [[ "$target" == local || "$target" =~ ^[A-Za-z0-9_.@:-]+$ ]] || fail "$name: invalid SSH target: $target"
        [[ "$unit" =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || fail "$name: invalid systemd unit: $unit"
        [[ "$pub" != */* && "$pub" != . && "$pub" != .. ]] || fail "$name: trusted public key must be a basename"
        [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 0 ] && [ "$port" -le 65535 ] \
            || fail "$name: invalid RESP port: $port"
        for old in "${NODES[@]}"; do
            [ "$(node_field "$old" 1)" != "$name" ] || fail "duplicate node name: $name"
        done
        NODES+=("$line")
    done < "$QIHSE_CLUSTER_NODES_FILE"
    [ "${#NODES[@]}" -gt 0 ] || fail "node specification contains no nodes"
    EXPECTED_NODES="${#NODES[@]}"
}

validate_selection() {
    local selected_name found spec
    for selected_name in "${SELECTED[@]}"; do
        found=0
        for spec in "${NODES[@]}"; do
            [ "$(node_field "$spec" 1)" = "$selected_name" ] && found=1
        done
        [ "$found" -eq 1 ] || fail "unknown node: $selected_name"
    done
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

# RESP probes use only the pinned QKP admin identity. A failed/missing QKP
# configuration is an error; never downgrade a cluster rollout to cleartext.
node_probe_ping() {
    local ip="$1" port="$2" pub="$3"
    sudo "$ADMIN_CLI" --host "$ip" --port "$port" --node-id "$ADMIN_NODE_ID" \
        --identity-dir "$ADMIN_IDENTITY_DIR" --trusted-pub "$ADMIN_IDENTITY_DIR/$pub" --ping 2>/dev/null || true
}

node_probe_cluster() {
    local ip="$1" port="$2" pub="$3"
    sudo "$ADMIN_CLI" --host "$ip" --port "$port" --node-id "$ADMIN_NODE_ID" \
        --identity-dir "$ADMIN_IDENTITY_DIR" --trusted-pub "$ADMIN_IDENTITY_DIR/$pub" --cluster-nodes 2>/dev/null || true
}

# Resolve mapped executable/library files. /proc/PID/exe can be ld-linux
# when systemd starts the daemon through an explicit dynamic loader.
shell_quote() {
    local quoted
    printf -v quoted '%q' "$1"
    printf '%s' "$quoted"
}

node_live_artifacts() {
    local target="$1" unit="$2" unit_arg pid daemon_map exe lib_map lib
    printf -v unit_arg '%q' "$unit"
    pid="$(on_node "$target" "systemctl show --property=MainPID --value $unit_arg")" || return 1
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    daemon_map="$(on_node "$target" "awk '\$2 ~ /x/ {p=substr(\$0,index(\$0,\$6)); if (p ~ /\\/qihse-cluster-daemon( \\(deleted\\))?$/) {sub(/ \\(deleted\\)$/, \"\", p); print p; exit}}' /proc/$pid/maps")" || return 1
    [ -n "$daemon_map" ] || return 1
    exe="$(on_node "$target" "readlink -f $(shell_quote "$daemon_map")")" || return 1
    lib_map="$(on_node "$target" "awk '{p=substr(\$0,index(\$0,\$6)); if (p ~ /\\/libqihse\\.so( \\(deleted\\))?$/) {sub(/ \\(deleted\\)$/, \"\", p); print p; exit}}' /proc/$pid/maps")" || return 1
    [ -n "$lib_map" ] || return 1
    lib="$(on_node "$target" "readlink -f $(shell_quote "$lib_map")")" || return 1
    on_node "$target" "test -f $(shell_quote "$exe") && test -f $(shell_quote "$lib")" || return 1
    printf '%s\n%s\n' "$exe" "$lib"
}

reject_immutable_release() {
    case "$1" in
        */releases/*|*/release-*/*|*/native-*/*|*/versions/*)
            fail "refusing in-place replacement inside immutable/versioned package path: $1; configure systemd to activate a fresh release directory first" ;;
    esac
    local part
    local -a parts
    IFS='/' read -r -a parts <<<"$1"
    for part in "${parts[@]}"; do
        [[ "$part" =~ ^[[:xdigit:]]{12,40}$ || "$part" =~ ^(release|build|native)-[[:xdigit:]]{8,40}$ ]] &&
            fail "refusing in-place replacement inside commit-labelled package path: $1; configure systemd to activate a fresh release directory first"
    done
    return 0
}

remote_sha256() {
    on_node "$1" "sha256sum $(shell_quote "$2") | cut -d' ' -f1"
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
    local b build_q
    for b in libqihse.so "${BINARIES[@]}"; do
        build_q="$(shell_quote "$builddir/$b")"
        on_node "$target" "test -f $build_q" || fail "$name: fresh build missing $builddir/$b"
    done

    local artifacts daemon_dest lib_dest daemon_q lib_q lib_backup_q lib_tmp_q source_q
    artifacts="$(node_live_artifacts "$target" "$unit")" \
        || fail "$name: cannot resolve the live executable/library paths for $unit"
    daemon_dest="$(sed -n '1p' <<<"$artifacts")"
    lib_dest="$(sed -n '2p' <<<"$artifacts")"
    [ -n "$daemon_dest" ] && [ -n "$lib_dest" ] \
        || fail "$name: live unit path discovery returned incomplete paths"
    reject_immutable_release "$daemon_dest"
    reject_immutable_release "$lib_dest"

    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    daemon_q="$(shell_quote "$daemon_dest")"
    lib_q="$(shell_quote "$lib_dest")"
    lib_backup_q="$(shell_quote "$lib_dest.bak-$ts")"
    lib_tmp_q="$(shell_quote "$lib_dest.tmp-$ts")"
    source_q="$(shell_quote "$builddir/libqihse.so")"
    local expected_lib_sha expected_daemon_sha
    expected_lib_sha="$(remote_sha256 "$target" "$builddir/libqihse.so")"
    expected_daemon_sha="$(remote_sha256 "$target" "$builddir/qihse-cluster-daemon")"

    # 2. Copy a backup, stage the replacement beside the live file, then
    # atomically rename it into place. An install failure leaves the old file.
    on_node "$target" "
        set -eu
        if [ -f $lib_q ]; then cp -p $lib_q $lib_backup_q; fi
        install -m 755 $source_q $lib_tmp_q || { rm -f $lib_tmp_q; exit 1; }
        mv -f $lib_tmp_q $lib_q || { rm -f $lib_tmp_q; exit 1; }"

    # 3. back up + install binaries
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
    local unit_q restart_cmd
    unit_q="$(shell_quote "$unit")"
    restart_cmd="systemctl restart $unit_q"
    [ "$target" = "local" ] && restart_cmd="sudo systemctl restart $unit_q"
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
        || fail "$name: restarted unit did not load the deployed paths"
    [ "$(remote_sha256 "$target" "$daemon_dest")" = "$expected_daemon_sha" ] \
        || fail "$name: running daemon path content does not match this build"
    [ "$(remote_sha256 "$target" "$lib_dest")" = "$expected_lib_sha" ] \
        || fail "$name: mapped library content does not match this build"

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
    [ -x "$ADMIN_CLI" ] || fail "pinned QKP admin client not executable: set QIHSE_ADMIN_CLI"
    [ -n "$ADMIN_IDENTITY_DIR" ] && [ -d "$ADMIN_IDENTITY_DIR" ] \
        || fail "set QIHSE_ADMIN_IDENTITY_DIR to the local pinned QKP identity directory"
    [ -n "$ADMIN_NODE_ID" ] || fail "set QIHSE_ADMIN_NODE_ID to the pinned QKP admin identity"
    load_nodes
    validate_selection
    local spec name target unit pub
    for spec in "${NODES[@]}"; do
        name="$(node_field "$spec" 1)"
        node_selected "$name" || continue
        pub="$(node_field "$spec" 7)"
        [ -f "$ADMIN_IDENTITY_DIR/$pub" ] || fail "$name: pinned QKP trust key missing: $ADMIN_IDENTITY_DIR/$pub"
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

if [ "${QIHSE_CLUSTER_ROLLING_LIBRARY_ONLY:-0}" != "1" ]; then
    main "$@"
fi
