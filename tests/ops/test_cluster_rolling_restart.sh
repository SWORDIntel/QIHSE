#!/usr/bin/env bash
# Mock-only checks for mapped release discovery and rolling installation.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
QIHSE_CLUSTER_ROLLING_LIBRARY_ONLY=1
# shellcheck disable=SC1091
source "$ROOT/scripts/cluster_rolling_restart.sh"

commands=()
MOCK_LOG="$(mktemp)"
trap 'rm -f "$MOCK_LOG"' EXIT
on_node() {
    local target="$1"; shift
    local command="$*"
    commands+=("$target:$command")
    printf '%s\n' "$target:$command" >> "$MOCK_LOG"
    case "$command" in
        *'systemctl show'*) printf '4242\n' ;;
        *'/proc/4242/maps'*)
            if [[ "$command" == *qihse-cluster-daemon* ]]; then
                printf '/opt/qihse/native-abc123/bin/qihse-cluster-daemon\n'
            else
                printf '/opt/qihse/native-abc123/lib/libqihse.so\n'
            fi ;;
        *'readlink -f'*)
            if [[ "$command" == *qihse-cluster-daemon* ]]; then
                printf '/srv/qihse/bin/qihse-cluster-daemon\n'
            else
                printf '/srv/qihse/lib/libqihse.so\n'
            fi ;;
        *'test -f'*) return 0 ;;
        *'sha256sum'*)
            if [[ "$command" == *qihse-cluster-daemon* ]]; then printf 'daemon-hash\n'; else printf 'library-hash\n'; fi ;;
        *'install -m 755'*) return 0 ;;
        *'systemctl restart'*) return 0 ;;
        *'journalctl'*) printf '1\n' ;;
        *) return 0 ;;
    esac
}
node_probe_ping() { printf 'PONG\n'; }
node_probe_cluster() { printf 'node connected\n'; }
sleep() { :; }

actual="$(node_live_artifacts host qihse.service)"
[[ "$actual" == $'/srv/qihse/bin/qihse-cluster-daemon\n/srv/qihse/lib/libqihse.so' ]]
rg -q '/proc/4242/maps' "$MOCK_LOG"
if rg -q 'readlink -f /proc/4242/exe' "$MOCK_LOG"; then
    echo 'discovery relied on the loader-valued /proc/PID/exe symlink' >&2
    exit 1
fi
rg -q 'test -f /srv/qihse/bin/qihse-cluster-daemon' "$MOCK_LOG"
# The daemon path from the executable mapping is selected even though the
# loader is the process executable in this fixture.
if (reject_immutable_release /srv/qihse/releases/0123456789abcdef/bin/qihse-cluster-daemon) >/dev/null 2>&1; then
    echo 'immutable release path was accepted' >&2
    exit 1
fi
if (reject_immutable_release /srv/qihse/native-0123456789abcdef/bin/qihse-cluster-daemon) >/dev/null 2>&1; then
    echo 'commit-labelled native path was accepted' >&2
    exit 1
fi

# Exercise the remote preflight/install/restart/hash verification path without
# SSH, systemd, a QKP service or local files from the configured build dir.
commands=()
EXPECTED_NODES=1 PING_TIMEOUT=1 JOIN_TIMEOUT=1 SYNC_WAIT=0
restart_node node-a 'node-a|host|qihse.service|/build/output|127.0.0.1|7000|trust.pub'
rg -q 'install -m 755 /build/output/libqihse.so' "$MOCK_LOG"
rg -q 'install -m 755 /build/output/qihse-cluster-daemon' "$MOCK_LOG"
rg -q 'sha256sum /srv/qihse/bin/qihse-cluster-daemon' "$MOCK_LOG"
rg -q 'sha256sum /srv/qihse/lib/libqihse.so' "$MOCK_LOG"

# Empty/mistyped node selection is rejected before any remote operation.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; rm -f "$MOCK_LOG"' EXIT
printf 'node-a|host|qihse.service|/build/output|127.0.0.1|7000|trust.pub\n' > "$TMP/nodes"
if QIHSE_CLUSTER_NODES_FILE="$TMP/nodes" bash "$ROOT/scripts/cluster_rolling_restart.sh" --node '' >/dev/null 2>&1; then
    echo 'empty --node was accepted' >&2
    exit 1
fi
mkdir -p "$TMP/identity"
printf '#!/bin/sh\nexit 0\n' > "$TMP/admin"
chmod +x "$TMP/admin"
touch "$TMP/identity/trust.pub"
if QIHSE_CLUSTER_NODES_FILE="$TMP/nodes" QIHSE_ADMIN_CLI="$TMP/admin" \
   QIHSE_ADMIN_IDENTITY_DIR="$TMP/identity" QIHSE_ADMIN_NODE_ID=operator \
   bash "$ROOT/scripts/cluster_rolling_restart.sh" --node unknown >/dev/null 2>&1; then
    echo 'unknown --node was accepted' >&2
    exit 1
fi
printf 'rolling restart mock checks passed\n'
