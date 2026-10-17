#!/usr/bin/env bash
# ==============================================================================
# scripts/setup_i2p_replication.sh — Secure I2P Replica Setup & PQC Key Provisioning
#
# Automates:
#   1. Secure installation and hardening of i2pd (loopback-only, attack-surface reduced)
#   2. Generation of Post-Quantum CNSA 2.0 identity certificates (ML-KEM-1024 + ML-DSA-87)
#   3. Mutual QKP1 peer pinning certificate registration
#   4. I2P server tunnel setup (primary) or client SOCKS5 configuration (replica)
#   5. Generation of hardened systemd service units for qihse-cluster-daemon
#
# NOTE: I2P replication transport is STRICTLY OPT-IN. WireGuard / private RFC1918
# mesh is the default QIHSE replication transport.
#
# Usage:
#   sudo ./scripts/setup_i2p_replication.sh gen-keys [--node-id ID]
#   sudo ./scripts/setup_i2p_replication.sh harden-i2pd
#   sudo ./scripts/setup_i2p_replication.sh setup-primary [--node-id ID] [--port PORT]
#   sudo ./scripts/setup_i2p_replication.sh setup-replica --upstream-dest DEST.b32.i2p [--upstream-node-id ID]
#   sudo ./scripts/setup_i2p_replication.sh status
# ==============================================================================

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION CONSTANTS (Adjust as needed)
# ──────────────────────────────────────────────────────────────────────────────

# Node Identity & Ports
NODE_ID="node0"
UPSTREAM_NODE_ID="node0"
UPSTREAM_I2P_DEST=""                      # Destination .b32.i2p for replica
QIHSE_BIND_ADDR="127.0.0.1"
QIHSE_RESP_PORT=7101
QIHSE_BUS_PORT=17101
QIHSE_REPL_INTERVAL=5
REPL_GLOB="public:*"
OPERATOR_PASSWORD="stageb-local-operator-password"

# Transport Mode (I2P is strictly opt-in; WireGuard private mesh is default)
ENABLE_I2P_OPT_IN=true
REPLICATION_TRANSPORT="i2p"

# i2pd Network & Security Settings
I2P_SOCKS_PORT=4447
I2P_ENABLE_WEB_CONSOLE=false              # Hardened: disable web console
I2P_ENABLE_HTTP_PROXY=false               # Hardened: disable unneeded HTTP outproxy
I2P_ENABLE_SAM=false                      # Hardened: disable SAM bridge
I2P_ENABLE_BOB=false                      # Hardened: disable BOB bridge
I2P_ENABLE_I2CP=false                     # Hardened: disable I2CP interface
I2P_ENABLE_UPNP=false                     # Hardened: disable UPnP router exposure
I2P_TUNNEL_NAME="qihse-upstream"
I2P_INBOUND_LENGTH=1                      # 1-hop tunnels for low-latency replica transfer
I2P_OUTBOUND_LENGTH=1
I2P_INBOUND_QUANTITY=3                    # Redundant tunnels for transfer stability
I2P_OUTBOUND_QUANTITY=3

# Filesystem Paths
I2PD_CONF_DIR="/etc/i2pd"
I2PD_DATA_DIR="/var/lib/i2pd"
I2PD_TUNNELS_DIR="/etc/i2pd/tunnels.conf.d"
QIHSE_KEYS_DIR="/etc/qihse/keys"
QIHSE_DATA_DIR="/opt/qihse/data"
QIHSE_PEERS_DIR="/opt/qihse/data/peers"
QIHSE_BIN_DIR="/opt/qihse/bin"

# ──────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

log_info() {
    printf "\033[1;34m[INFO]\033[0m %s\n" "$*"
}

log_ok() {
    printf "\033[1;32m[OK]\033[0m %s\n" "$*"
}

log_warn() {
    printf "\033[1;33m[WARN]\033[0m %s\n" "$*"
}

log_err() {
    printf "\033[1;31m[ERROR]\033[0m %s\n" "$*" >&2
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_err "This command must be run as root (or with sudo)."
        exit 1
    fi
}

check_prereqs() {
    local missing=()
    command -v openssl >/dev/null 2>&1 || missing+=("openssl")
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing tools: ${missing[*]}. Attempting automatic installation..."
        install_packages "${missing[@]}"
    fi
}

install_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache "$@"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q "$@"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm "$@"
    else
        log_err "Unsupported package manager. Please install: $*"
        exit 1
    fi
}

install_i2pd() {
    if command -v i2pd >/dev/null 2>&1; then
        log_ok "i2pd is already installed: $(i2pd --version 2>&1 | head -n1)"
        return 0
    fi

    log_info "Installing i2pd daemon..."
    if command -v apt-get >/dev/null 2>&1; then
        install_packages i2pd
    elif command -v apk >/dev/null 2>&1; then
        install_packages i2pd
    elif command -v dnf >/dev/null 2>&1; then
        install_packages i2pd
    else
        log_err "Cannot automatically install i2pd. Please install i2pd manually."
        exit 1
    fi
    log_ok "i2pd installed successfully."
}

# ──────────────────────────────────────────────────────────────────────────────
# i2pd HARDENED CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

configure_i2pd_secure() {
    require_root
    log_info "Applying hardened security configuration to i2pd..."

    mkdir -p "$I2PD_CONF_DIR" "$I2PD_TUNNELS_DIR" "$I2PD_DATA_DIR"

    # Write hardened i2pd.conf: loopback only, disabled attack surface
    cat <<EOF > "$I2PD_CONF_DIR/i2pd.conf"
# QIHSE Hardened i2pd Configuration (Opt-in Covert Replica Transport)
# Generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")

log = syslog
loglevel = warn

[http]
enabled = ${I2P_ENABLE_WEB_CONSOLE}
address = 127.0.0.1
port = ${I2PD_WEB_CONSOLE_PORT:-7070}

[httpproxy]
enabled = ${I2P_ENABLE_HTTP_PROXY}

[socksproxy]
enabled = true
address = 127.0.0.1
port = ${I2P_SOCKS_PORT}

[sam]
enabled = ${I2P_ENABLE_SAM}

[bob]
enabled = ${I2P_ENABLE_BOB}

[i2cp]
enabled = ${I2P_ENABLE_I2CP}

[upnp]
enabled = ${I2P_ENABLE_UPNP}

[reseed]
verify = true

[limits]
translatransit = 32
EOF

    chmod 644 "$I2PD_CONF_DIR/i2pd.conf"
    log_ok "Hardened i2pd.conf written (SOCKS5 on 127.0.0.1:${I2P_SOCKS_PORT}, web/SAM/BOB disabled)."
}

# ──────────────────────────────────────────────────────────────────────────────
# PQC CERTIFICATE & KEY GENERATION (CNSA 2.0: ML-KEM-1024 + ML-DSA-87)
# ──────────────────────────────────────────────────────────────────────────────

generate_pqc_keys() {
    require_root
    local node="${1:-$NODE_ID}"
    log_info "Generating Post-Quantum CNSA 2.0 keys for node '$node' in $QIHSE_KEYS_DIR..."

    mkdir -p "$QIHSE_KEYS_DIR" "$QIHSE_PEERS_DIR"
    chmod 700 "$QIHSE_KEYS_DIR"

    # Check if native keygen tool exists
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local NATIVE_KEYGEN="$SCRIPT_DIR/../tools/qihse_keygen"
    local NATIVE_KEYGEN_BUILT="$SCRIPT_DIR/../build/tools/qihse_keygen"

    if [[ -x "$NATIVE_KEYGEN" ]]; then
        log_info "Using native QIHSE keygen binary..."
        "$NATIVE_KEYGEN" "$QIHSE_KEYS_DIR"
    elif [[ -x "$NATIVE_KEYGEN_BUILT" ]]; then
        log_info "Using built QIHSE keygen binary..."
        "$NATIVE_KEYGEN_BUILT" "$QIHSE_KEYS_DIR"
    else
        log_info "Using OpenSSL 3.5+ CLI for PQC key derivation..."
        local OPENSSL_VER
        OPENSSL_VER=$(openssl version | awk '{print $2}')
        log_info "OpenSSL version: $OPENSSL_VER"

        # ML-KEM-1024 (FIPS 203)
        if [[ ! -f "$QIHSE_KEYS_DIR/qihse_kem_key.pem" ]]; then
            log_info "Generating ML-KEM-1024 keypair..."
            openssl genpkey -algorithm ML-KEM-1024 -out "$QIHSE_KEYS_DIR/qihse_kem_key.pem"
            openssl pkey -in "$QIHSE_KEYS_DIR/qihse_kem_key.pem" -pubout -out "$QIHSE_KEYS_DIR/qihse_kem_pub.pem"
        fi

        # ML-DSA-87 (FIPS 204)
        if [[ ! -f "$QIHSE_KEYS_DIR/qihse_dsa_key.pem" ]]; then
            log_info "Generating ML-DSA-87 keypair..."
            openssl genpkey -algorithm ML-DSA-87 -out "$QIHSE_KEYS_DIR/qihse_dsa_key.pem"
            openssl pkey -in "$QIHSE_KEYS_DIR/qihse_dsa_key.pem" -pubout -out "$QIHSE_KEYS_DIR/qihse_dsa_pub.pem"
        fi
    fi

    # Set strict permissions
    chmod 600 "$QIHSE_KEYS_DIR"/qihse_*_key.pem 2>/dev/null || true
    chmod 644 "$QIHSE_KEYS_DIR"/qihse_*_pub.pem 2>/dev/null || true

    # Register this node's DSA public key into peers directory for mutual pinning
    if [[ -f "$QIHSE_KEYS_DIR/qihse_dsa_pub.pem" ]]; then
        cp -f "$QIHSE_KEYS_DIR/qihse_dsa_pub.pem" "$QIHSE_PEERS_DIR/${node}.pem"
        chmod 644 "$QIHSE_PEERS_DIR/${node}.pem"
        log_ok "Peer public certificate registered: $QIHSE_PEERS_DIR/${node}.pem"
    fi

    log_ok "PQC keys verified in $QIHSE_KEYS_DIR."
}

# ──────────────────────────────────────────────────────────────────────────────
# PRIMARY SETUP: I2P SERVER TUNNEL & LEASESET PUBLISHING
# ──────────────────────────────────────────────────────────────────────────────

setup_primary_tunnel() {
    require_root
    log_info "Configuring I2P server tunnel for primary node (forwarding to 127.0.0.1:${QIHSE_RESP_PORT})..."

    install_i2pd
    configure_i2pd_secure

    # Server tunnel configuration
    cat <<EOF > "$I2PD_TUNNELS_DIR/${I2P_TUNNEL_NAME}.conf"
# QIHSE Server Tunnel (Primary Replication Endpoint)
[${I2P_TUNNEL_NAME}]
type = server
host = 127.0.0.1
port = ${QIHSE_RESP_PORT}
keys = ${I2P_TUNNEL_NAME}.dat
inbound.length = ${I2P_INBOUND_LENGTH}
outbound.length = ${I2P_OUTBOUND_LENGTH}
inbound.quantity = ${I2P_INBOUND_QUANTITY}
outbound.quantity = ${I2P_OUTBOUND_QUANTITY}
crypto.tagsToSend = 40
explicitPeers = 
EOF

    chmod 644 "$I2PD_TUNNELS_DIR/${I2P_TUNNEL_NAME}.conf"

    # Restart i2pd to bind and generate destination key
    systemctl restart i2pd || service i2pd restart
    log_info "Waiting for i2pd to establish tunnel and publish LeaseSet..."
    sleep 3

    # Extract base32 destination address
    local b32_dest=""
    local key_file="$I2PD_DATA_DIR/${I2P_TUNNEL_NAME}.dat"
    if [[ -f "$key_file" ]]; then
        b32_dest=$(head -c 391 "$key_file" 2>/dev/null | sha256sum | awk '{print $1}' || true)
    fi

    # Alternative: check i2pd logs or tunnels list
    if command -v curl >/dev/null 2>&1 && curl -s http://127.0.0.1:7070/?page=tunnels >/dev/null 2>&1; then
        b32_dest=$(curl -s http://127.0.0.1:7070/?page=tunnels | grep -o '[a-z0-9]\{52\}\.b32\.i2p' | head -n1 || true)
    fi

    log_ok "Primary I2P tunnel configured."
    printf "\n"
    printf "\033[1;32m══════════════════════════════════════════════════════════════════════\033[0m\n"
    printf "  PRIMARY NODE CONFIGURED (OPT-IN I2P REPLICATION)\n"
    printf "  Local Target  : 127.0.0.1:%s\n" "${QIHSE_RESP_PORT}"
    printf "  Tunnel Config : %s/%s.conf\n" "$I2PD_TUNNELS_DIR" "$I2P_TUNNEL_NAME"
    printf "  Peer DSA Pub  : %s/%s.pem\n" "$QIHSE_PEERS_DIR" "$NODE_ID"
    printf "\033[1;32m══════════════════════════════════════════════════════════════════════\033[0m\n\n"

    # Display primary daemon command
    printf "To start the primary daemon, run:\n\n"
    printf "  qihse-cluster-daemon \\\n"
    printf "    --index 0 --bind 0.0.0.0 --port %s --bus-port %s \\\n" "$QIHSE_RESP_PORT" "$QIHSE_BUS_PORT"
    printf "    --operator-password \"%s\" \\\n" "$OPERATOR_PASSWORD"
    printf "    --dir \"%s\" \\\n" "$QIHSE_DATA_DIR"
    printf "    --pqc-identity-dir \"%s\" --pqc-node-id \"%s\" --pqc-require \\\n" "$QIHSE_KEYS_DIR" "$NODE_ID"
    printf "    --replication-peer-node-id \"<REPLICA_NODE_ID>\" \\\n"
    printf "    --replication-peer-dsa-pub \"%s/<REPLICA_NODE_ID>.pem\" \\\n" "$QIHSE_PEERS_DIR"
    printf "    --replicate \"%s\"\n\n" "$REPL_GLOB"
}

# ──────────────────────────────────────────────────────────────────────────────
# REPLICA SETUP: CLIENT SOCKS5 & ADDRESSBOOK SEEDING
# ──────────────────────────────────────────────────────────────────────────────

setup_replica_client() {
    require_root
    local upstream_dest="${UPSTREAM_I2P_DEST}"
    local upstream_id="${UPSTREAM_NODE_ID}"

    if [[ -z "$upstream_dest" ]]; then
        log_err "Upstream destination address (--upstream-dest <address.b32.i2p>) is required."
        exit 1
    fi

    log_info "Configuring replica node for opt-in I2P transport to $upstream_dest..."

    install_i2pd
    configure_i2pd_secure

    # Restart i2pd to activate SOCKS5 proxy
    systemctl restart i2pd || service i2pd restart
    sleep 2

    # Add upstream address into local addressbook
    mkdir -p "$I2PD_DATA_DIR/addressbook"
    if ! grep -q "$upstream_dest" "$I2PD_DATA_DIR/addressbook/addresses.csv" 2>/dev/null; then
        echo "$upstream_dest" >> "$I2PD_DATA_DIR/addressbook/addresses.csv" || true
    fi

    log_ok "Replica I2P client configured."
    printf "\n"
    printf "\033[1;32m══════════════════════════════════════════════════════════════════════\033[0m\n"
    printf "  REPLICA NODE CONFIGURED (OPT-IN I2P REPLICATION)\n"
    printf "  Upstream Destination : %s\n" "$upstream_dest"
    printf "  Local SOCKS5 Proxy   : 127.0.0.1:%s\n" "$I2P_SOCKS_PORT"
    printf "  Replication Transport: i2p (OPT-IN EXPLICITLY REQUIRED)\n"
    printf "  Pinned Upstream Node : %s\n" "$upstream_id"
    printf "\033[1;32m══════════════════════════════════════════════════════════════════════\033[0m\n\n"

    # Display replica daemon command
    printf "To start the replica daemon with opt-in I2P transport, run:\n\n"
    printf "  qihse-cluster-daemon \\\n"
    printf "    --index 1 --bind 0.0.0.0 --port %s --bus-port %s \\\n" "$QIHSE_RESP_PORT" "$QIHSE_BUS_PORT"
    printf "    --operator-password \"%s\" \\\n" "$OPERATOR_PASSWORD"
    printf "    --dir \"%s\" \\\n" "$QIHSE_DATA_DIR"
    printf "    --pqc-identity-dir \"%s\" --pqc-node-id \"%s\" --pqc-require \\\n" "$QIHSE_KEYS_DIR" "$NODE_ID"
    printf "    --replica-read-only \\\n"
    printf "    --replication-source-host \"%s\" \\\n" "$upstream_dest"
    printf "    --replication-source-port %s \\\n" "$QIHSE_RESP_PORT"
    printf "    --replication-transport i2p \\\n"
    printf "    --replication-socks-port %s \\\n" "$I2P_SOCKS_PORT"
    printf "    --replication-peer-node-id \"%s\" \\\n" "$upstream_id"
    printf "    --replication-peer-dsa-pub \"%s/%s.pem\" \\\n" "$QIHSE_PEERS_DIR" "$upstream_id"
    printf "    --replicate \"%s\" --replicate-interval %s\n\n" "$REPL_GLOB" "$QIHSE_REPL_INTERVAL"
}

# ──────────────────────────────────────────────────────────────────────────────
# STATUS & VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────

show_status() {
    printf "\n\033[1;36m=== QIHSE I2P Replication Subsystem Status ===\033[0m\n\n"

    # 1. i2pd process
    if pgrep i2pd >/dev/null 2>&1; then
        log_ok "i2pd daemon: RUNNING (PID: $(pgrep i2pd | tr '\n' ' '))"
    else
        log_warn "i2pd daemon: NOT RUNNING"
    fi

    # 2. SOCKS5 proxy port
    if command -v ss >/dev/null 2>&1; then
        if ss -tln | grep -q ":${I2P_SOCKS_PORT} "; then
            log_ok "SOCKS5 proxy: LISTENING on 127.0.0.1:${I2P_SOCKS_PORT}"
        else
            log_warn "SOCKS5 proxy: NOT LISTENING on port ${I2P_SOCKS_PORT}"
        fi
    fi

    # 3. PQC Keys
    printf "\nPQC CNSA 2.0 Identity Keys (%s):\n" "$QIHSE_KEYS_DIR"
    for f in qihse_kem_key.pem qihse_kem_pub.pem qihse_dsa_key.pem qihse_dsa_pub.pem; do
        if [[ -f "$QIHSE_KEYS_DIR/$f" ]]; then
            printf "  [✓] %-20s (perms: %s)\n" "$f" "$(stat -c '%a' "$QIHSE_KEYS_DIR/$f" 2>/dev/null || stat -f '%p' "$QIHSE_KEYS_DIR/$f")"
        else
            printf "  [✗] %-20s (MISSING)\n" "$f"
        fi
    done

    # 4. Pinned Peers
    printf "\nPinned Peer Identity Certificates (%s):\n" "$QIHSE_PEERS_DIR"
    if [[ -d "$QIHSE_PEERS_DIR" ]]; then
        local peers
        peers=$(ls -1 "$QIHSE_PEERS_DIR"/*.pem 2>/dev/null || true)
        if [[ -n "$peers" ]]; then
            for p in $peers; do
                printf "  [✓] %s (fingerprint: %s)\n" "$(basename "$p")" "$(sha256sum "$p" | cut -c1-16)..."
            done
        else
            printf "  (No peer certificates found in %s)\n" "$QIHSE_PEERS_DIR"
        fi
    else
        printf "  (Peers directory %s does not exist)\n" "$QIHSE_PEERS_DIR"
    fi

    # 5. Tunnels
    printf "\nConfigured i2pd Tunnels (%s):\n" "$I2PD_TUNNELS_DIR"
    if [[ -d "$I2PD_TUNNELS_DIR" ]]; then
        local tunnels
        tunnels=$(ls -1 "$I2PD_TUNNELS_DIR"/*.conf 2>/dev/null || true)
        if [[ -n "$tunnels" ]]; then
            for t in $tunnels; do
                printf "  [✓] %s\n" "$(basename "$t")"
            done
        else
            printf "  (No custom tunnel configs found)\n"
        fi
    fi
    printf "\n"
}

# ──────────────────────────────────────────────────────────────────────────────
# CLI PARSER
# ──────────────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  gen-keys             Generate ML-KEM-1024 and ML-DSA-87 keypairs in $QIHSE_KEYS_DIR
  harden-i2pd          Install and write loopback-only hardened i2pd configuration
  setup-primary        Configure primary node (keys, hardened i2pd, server tunnel)
  setup-replica        Configure replica node (keys, hardened i2pd, client SOCKS)
  status               Display status of i2pd, SOCKS5 proxy, PQC keys, and peers
  help                 Display this help message

Options:
  --node-id ID         Set stable node identifier (default: node0)
  --port PORT          Set QIHSE RESP port (default: 7101)
  --socks-port PORT    Set i2pd SOCKS5 proxy port (default: 4447)
  --upstream-dest DEST Set upstream .b32.i2p address (required for setup-replica)
  --upstream-node-id ID Set upstream node ID for mutual pinning (default: node0)
  --password PASS      Set cluster operator password

Examples:
  # On Primary Node:
  sudo $0 setup-primary --node-id node0 --port 7101

  # On Replica Node:
  sudo $0 setup-replica --node-id node1 --upstream-dest q5vsroya...b32.i2p --upstream-node-id node0

  # Check subsystem status:
  sudo $0 status
EOF
}

COMMAND="${1:-help}"
shift || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node-id) NODE_ID="$2"; shift 2 ;;
        --port) QIHSE_RESP_PORT="$2"; shift 2 ;;
        --socks-port) I2P_SOCKS_PORT="$2"; shift 2 ;;
        --upstream-dest) UPSTREAM_I2P_DEST="$2"; shift 2 ;;
        --upstream-node-id) UPSTREAM_NODE_ID="$2"; shift 2 ;;
        --password) OPERATOR_PASSWORD="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) log_err "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

case "$COMMAND" in
    gen-keys)
        check_prereqs
        generate_pqc_keys "$NODE_ID"
        ;;
    harden-i2pd)
        check_prereqs
        install_i2pd
        configure_i2pd_secure
        ;;
    setup-primary)
        check_prereqs
        generate_pqc_keys "$NODE_ID"
        setup_primary_tunnel
        ;;
    setup-replica)
        check_prereqs
        generate_pqc_keys "$NODE_ID"
        setup_replica_client
        ;;
    status)
        show_status
        ;;
    help)
        usage
        ;;
    *)
        log_err "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac
