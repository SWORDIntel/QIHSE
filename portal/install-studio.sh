#!/usr/bin/env bash
# portal/install-studio.sh — Automated Installer & Systemd Provisioner for QIHSE Studio
#
# Builds React SPA, publishes ASP.NET Core 8 WebAPI server to /opt/QIHSE/studio,
# configures default LAN-only binding (http://0.0.0.0:5100), auto-links to cluster
# network daemons, installs and activates the systemd service (qihse-studio.service).
#
# SPDX-License-Identifier: LicenseRef-SRSL-1.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${1:-/opt/QIHSE/studio}"

echo "======================================================================"
echo "          QIHSE STUDIO DISPLAY — INSTALLER & PROVISIONER              "
echo "======================================================================"

# 1. Resolve Dotnet & Node
DOTNET_BIN="$(command -v dotnet || echo "${DOTNET_ROOT:-$HOME/.dotnet}/dotnet")"
if [ ! -x "$DOTNET_BIN" ]; then
    echo "[-] Error: dotnet not found at $DOTNET_BIN"
    exit 1
fi
DOTNET_DIR="$(dirname "$DOTNET_BIN")"

NODE_BIN="$(command -v node || echo "/usr/local/bin/node")"
NPM_BIN="$(command -v npm || echo "/usr/local/bin/npm")"
if [ ! -x "$NODE_BIN" ] || [ ! -x "$NPM_BIN" ]; then
    echo "[-] Warning: node or npm not found. Will use pre-built SPA bundle in wwwroot."
else
    echo "[+] Building React 18 TypeScript SPA bundle..."
    (cd "${SCRIPT_DIR}/src/Qihse.Studio.Client" && "$NPM_BIN" run build)
fi

# 2. Publish ASP.NET Core 8 Server
echo "[+] Publishing QIHSE Studio Server (Release) to ${TARGET_DIR}..."
mkdir -p "${TARGET_DIR}"
"$DOTNET_BIN" publish "${SCRIPT_DIR}/src/Qihse.Studio.Server" -c Release -o "${TARGET_DIR}"

# Ensure wwwroot is present in target
if [ -d "${SCRIPT_DIR}/src/Qihse.Studio.Server/wwwroot" ]; then
    cp -r "${SCRIPT_DIR}/src/Qihse.Studio.Server/wwwroot" "${TARGET_DIR}/"
fi

# Ensure correct file permissions
CURRENT_USER="$(id -un)"
CURRENT_GROUP="$(id -gn)"
chown -R "${CURRENT_USER}:${CURRENT_GROUP}" "${TARGET_DIR}"

# 3. Detect LAN IP for auto-linking display
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "127.0.0.1")"

# 4. Generate systemd unit file
SERVICE_PATH="/etc/systemd/system/qihse-studio.service"
echo "[+] Provisioning systemd service at ${SERVICE_PATH}..."

SERVICE_CONTENT="[Unit]
Description=QIHSE Studio Operations & Telemetry Display (ASP.NET Core 8 + React SPA)
After=network-online.target qihse-node0.service
Wants=network-online.target

[Service]
Type=simple
User=${CURRENT_USER}
Group=${CURRENT_GROUP}
WorkingDirectory=${TARGET_DIR}
Environment=DOTNET_ROOT=${DOTNET_DIR}
Environment=PATH=${DOTNET_DIR}:/usr/local/bin:/usr/bin:/bin
Environment=ASPNETCORE_URLS=http://0.0.0.0:5100
Environment=Studio__LanOnly=true
Environment=QIHSE_CLUSTER_PASSWORD=QihseCluster2026x!
ExecStart=${DOTNET_BIN} ${TARGET_DIR}/Qihse.Studio.Server.dll
Restart=always
RestartSec=3
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target"

if [ "$(id -u)" -eq 0 ]; then
    echo "$SERVICE_CONTENT" > "$SERVICE_PATH"
    systemctl daemon-reload
    systemctl enable qihse-studio.service
    systemctl restart qihse-studio.service
else
    echo "$SERVICE_CONTENT" | sudo tee "$SERVICE_PATH" > /dev/null
    sudo systemctl daemon-reload
    sudo systemctl enable qihse-studio.service
    sudo systemctl restart qihse-studio.service
fi

echo "[+] Waiting for QIHSE Studio service to initialize..."
HEALTHY=0
for i in $(seq 1 15); do
    if curl -s -f "http://127.0.0.1:5100/api/telemetry/snapshot" >/dev/null 2>&1; then
        HEALTHY=1
        break
    fi
    sleep 1
done

if [ "$HEALTHY" -eq 1 ]; then
    echo "======================================================================"
    echo "  [SUCCESS] QIHSE Studio is provisioned, active, and auto-linked!     "
    echo "  Local Access:      http://localhost:5100/                           "
    echo "  LAN Access:        http://${LAN_IP}:5100/                           "
    echo "  Security Mode:     Default LAN-Only (RFC1918 + Loopback allowed)    "
    echo "  Systemd Service:   qihse-studio.service (Active & Enabled)          "
    echo "======================================================================"
else
    echo "[-] Warning: Service started but healthcheck took longer than expected."
    echo "    Check status: systemctl status qihse-studio.service"
fi
