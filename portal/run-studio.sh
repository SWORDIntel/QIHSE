#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=========================================================="
echo "  Starting QIHSE Studio (ASP.NET Core 8 + React SPA)"
echo "  Web UI (Local & LAN): http://127.0.0.1:5100"
echo "  SignalR Hub: http://127.0.0.1:5100/hub/telemetry"
echo "=========================================================="

DOTNET_BIN="$(command -v dotnet || echo "${DOTNET_ROOT:-$HOME/.dotnet}/dotnet")"
if [ -z "${QIHSE_STUDIO_API_TOKEN:-}" ]; then
    echo "Set QIHSE_STUDIO_API_TOKEN to a 32+ character random token before starting Studio" >&2
    exit 1
fi
exec "$DOTNET_BIN" run --project "$DIR/src/Qihse.Studio.Server" --urls "http://127.0.0.1:5100"
