#!/usr/bin/env bash
# scripts/cluster_replica_deploy.sh — deploy read-only QKP-protected replica
# daemons that pull the sovereign namespaces (tool:*, sabot/*, chain:*,
# audit/*, keystone/*, kp14/*) from the pinned master nodes, one namespace
# per replica instance.
#
# The replication puller requires --replica-read-only (the replica store is
# read-only) plus exactly one --replicate namespace, a pinned upstream
# identity (--replication-peer-node-id + --replication-peer-dsa-pub), a
# stable --pqc-node-id and operator password. Each master already trusts all
# three nodes' DSA pubs, so the replicas reuse the node identity under
# /etc/qihse/keys and need no master-side changes.
#
# Topology (each namespace exists on its owner + one replica):
#   t420  replica: tool:*      <- node5 (192.168.1.90:7115)
#   t420  replica: keystone/*  <- node1 (192.168.1.250:7101)
#   730xd replica: chain:*     <- node0 (192.168.1.91:7100)
#   730xd replica: kp14/*      <- node1 (192.168.1.250:7101)
#   t320  replica: audit/*     <- node0 (192.168.1.91:7100)
#   t320  replica: sabot/*     <- node5 (192.168.1.90:7115)
#
# Usage:
#   ./scripts/cluster_replica_deploy.sh              # install + start + verify
#   ./scripts/cluster_replica_deploy.sh --status     # report state only
#   ./scripts/cluster_replica_deploy.sh --remove     # stop + remove units

set -euo pipefail

# Ring topology (each master pins ONE peer node identity; that peer runs
# one replica instance per namespace pulled from that master):
#   node0 (t420)   -> serves 730xd replicas: audit/*, chain:*
#   node5 (730xd)  -> serves t320 replicas:  tool:*, sabot/*
#   node1 (t320)   -> serves t420 replicas:  keystone/*, kp14/*
#
# NOTE: enabling the source-side pin makes the master QKP-only for RESP
# (pqc_require): cleartext redis-cli access is rejected; verification uses
# the replica pull logs + systemd state instead.
#
# host | name | glob | source host | source port | peer node id | peer dsa pub | local RESP port | env file | local bus port
REPLICAS=(
    "t420|keystone|keystone/*|192.168.1.250|7101|192.168.1.250|qihse_dsa_pub_t320.pem|7201|cluster-node0.env|17201"
    "t420|kp14|kp14/*|192.168.1.250|7101|192.168.1.250|qihse_dsa_pub_t320.pem|7202|cluster-node0.env|17202"
    "730xd|audit|audit/*|192.168.1.91|7100|192.168.1.91|qihse_dsa_pub_t420.pem|7201|cluster-node5.env|17201"
    "730xd|chain|chain:*|192.168.1.91|7100|192.168.1.91|qihse_dsa_pub_t420.pem|7202|cluster-node5.env|17202"
    "t320|tool|tool:*|192.168.1.90|7115|192.168.1.90|qihse_dsa_pub_730xd.pem|7201|cluster-node1.env|17201"
    "t320|sabot|sabot/*|192.168.1.90|7115|192.168.1.90|qihse_dsa_pub_730xd.pem|7202|cluster-node1.env|17202"
)

declare -A HOST_IP=(
    [t420]=192.168.1.91
    [730xd]=192.168.1.90
    [t320]=192.168.1.250
)
declare -A LIB_DIR=(
    [t420]=/opt/QIHSE/lib
    [730xd]=/opt/QIHSE/lib
    [t320]=/opt/qihse/lib
)

declare -A SSH_TARGET=(
    [t420]=local
    [730xd]=root@192.168.1.90
    [t320]=root@192.168.1.95
)
declare -A BIN_DIR=(
    [t420]=/opt/QIHSE/bin
    [730xd]=/opt/QIHSE/bin
    [t320]=/opt/qihse/bin
)

MODE=deploy
[ "${1:-}" = "--status" ] && MODE=status
[ "${1:-}" = "--remove" ] && MODE=remove

on_host() {
    local host="$1"; shift
    if [ "${SSH_TARGET[$host]}" = "local" ]; then
        sudo bash -c "$*"
    else
        ssh -o BatchMode=yes "${SSH_TARGET[$host]}" "$*" 2>/dev/null
    fi
}

replica_unit() { # spec -> unit file contents
    local spec="$1"
    local host name glob src_host src_port peer_id peer_pub port envfile bus_port
    IFS='|' read -r host name glob src_host src_port peer_id peer_pub port envfile bus_port <<<"$spec"
    cat <<EOF
[Unit]
Description=QIHSE read-only replica ($name: $glob <- $peer_id)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/qihse/$envfile
Environment=LD_LIBRARY_PATH=${LIB_DIR[$host]}
ExecStart=${BIN_DIR[$host]}/qihse-cluster-daemon \\
  --bind ${HOST_IP[$host]} \\
  --port $port \\
  --bus-port $bus_port \\
  --dir /opt/qihse-replica/$name \\
  --replica-read-only \\
  --replicate '$glob' \\
  --replicate-interval 30 \\
  --replication-source-host $src_host \\
  --replication-source-port $src_port \\
  --replication-transport direct \\
  --replication-peer-node-id $peer_id \\
  --replication-peer-dsa-pub /etc/qihse/keys/$peer_pub \\
  --pqc-node-id replica-$host \\
  --pqc-identity-dir /etc/qihse/keys \\
  --pqc-trusted-pub /etc/qihse/keys/$peer_pub \\
  --pqc-trusted-pub /etc/qihse/keys/qihse_dsa_pub_t420.pem \\
  --admin-peer-node-id admin-t420 \\
  --admin-peer-dsa-pub /etc/qihse/keys/qihse_dsa_pub_t420.pem
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
}

for spec in "${REPLICAS[@]}"; do
    IFS='|' read -r host name glob src_host src_port peer_id peer_pub port envfile <<<"$spec"
    unit="qihse-replica-$name.service"

    case "$MODE" in
        status)
            echo "--- $host/$name ($glob <- $peer_id, port $port) ---"
            on_host "$host" "systemctl is-active '$unit' 2>&1; journalctl -u '$unit' --no-pager -n 2 2>/dev/null | grep -E 'replica pull|error|Error' | tail -2"
            ;;
        remove)
            echo "--- removing $host/$name ---"
            on_host "$host" "systemctl disable --now '$unit' 2>/dev/null || true; rm -f '/etc/systemd/system/$unit'; systemctl daemon-reload"
            ;;
        deploy)
            echo "--- deploying $host/$name ($glob <- $peer_id, port $port) ---"
            on_host "$host" "mkdir -p '/opt/qihse-replica/$name'"
            unit_text="$(replica_unit "$spec")"
            if [ "${SSH_TARGET[$host]}" = "local" ]; then
                printf '%s\n' "$unit_text" | sudo tee "/etc/systemd/system/$unit" >/dev/null
            else
                printf '%s\n' "$unit_text" | ssh -o BatchMode=yes "${SSH_TARGET[$host]}" "cat > '/etc/systemd/system/$unit'" 2>/dev/null
            fi
            on_host "$host" "systemctl daemon-reload && systemctl enable '$unit' && systemctl restart '$unit'"
            sleep 2
            on_host "$host" "systemctl is-active '$unit'" || true
            ;;
    esac
done

if [ "$MODE" = "deploy" ]; then
    echo ""
    echo "Waiting 40s (one pull interval + snapshot) then verifying pulls..."
    sleep 40
    for spec in "${REPLICAS[@]}"; do
        IFS='|' read -r host name glob src_host src_port peer_id peer_pub port envfile <<<"$spec"
        echo "--- $host/$name ---"
        on_host "$host" "journalctl -u 'qihse-replica-$name.service' --no-pager --since '-45s' 2>/dev/null | grep -E 'replica pull|serving|error|Error' | tail -3"
    done
fi
