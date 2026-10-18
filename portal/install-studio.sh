#!/usr/bin/env bash
# Install Studio loopback-only with operator-owned credentials (never embedded in units).
set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then
    echo "Run as a dedicated unprivileged service user with sudo access; root execution refused." >&2
    exit 1
fi
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-/opt/QIHSE/studio}"
DOTNET="$(command -v dotnet || printf '%s' "${DOTNET_ROOT:-$HOME/.dotnet}/dotnet")"
test -x "$DOTNET" || { echo "dotnet missing" >&2; exit 1; }
test -x "$(command -v openssl)" || { echo "openssl missing" >&2; exit 1; }
if command -v npm >/dev/null; then (cd "$DIR/src/Qihse.Studio.Client" && npm ci && npm run build); fi
CURRENT_USER="$(id -un)"
CURRENT_GROUP="$(id -gn)"
RUN_AS=(sudo)
# Provision the target before publishing, even if it lives under /opt.
"${RUN_AS[@]}" install -d -m 0755 -o "$CURRENT_USER" -g "$CURRENT_GROUP" "$TARGET"
"$DOTNET" publish "$DIR/src/Qihse.Studio.Server" -c Release -o "$TARGET"
if [ -d "$DIR/src/Qihse.Studio.Server/wwwroot" ]; then
    cp -a "$DIR/src/Qihse.Studio.Server/wwwroot/." "$TARGET/wwwroot/"
fi
"${RUN_AS[@]}" install -d -m 0700 /etc/qihse
if ! "${RUN_AS[@]}" test -f /etc/qihse/studio.env; then
    KEY="$(openssl rand -hex 32)"
    printf 'QIHSE_STUDIO_API_TOKEN=%s\n' "$KEY" | "${RUN_AS[@]}" tee /etc/qihse/studio.env >/dev/null
    unset KEY
fi
"${RUN_AS[@]}" chmod 0600 /etc/qihse/studio.env
SERVICE="[Unit]
Description=QIHSE Studio (loopback, authenticated)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_GROUP
WorkingDirectory=$TARGET
EnvironmentFile=/etc/qihse/studio.env
Environment=ASPNETCORE_URLS=http://127.0.0.1:5100
ExecStart=$DOTNET $TARGET/Qihse.Studio.Server.dll
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target"
printf '%s\n' "$SERVICE" | "${RUN_AS[@]}" tee /etc/systemd/system/qihse-studio.service >/dev/null
"${RUN_AS[@]}" systemctl daemon-reload
"${RUN_AS[@]}" systemctl enable --now qihse-studio.service
"${RUN_AS[@]}" systemctl restart qihse-studio.service
echo "Studio bound to loopback only. Read /etc/qihse/studio.env as root to obtain the API token."
echo "For remote access, use a TLS-authenticated reverse proxy or secure tunnel."
