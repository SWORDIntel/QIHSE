#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=========================================================="
echo "  Starting QIHSE Studio (ASP.NET Core 8 + React SPA)"
echo "  Web UI (Local & LAN): http://0.0.0.0:5100"
echo "  SignalR Hub: http://0.0.0.0:5100/hub/telemetry"
echo "=========================================================="

DOTNET_BIN="$(command -v dotnet || echo "${DOTNET_ROOT:-$HOME/.dotnet}/dotnet")"
exec "$DOTNET_BIN" run --project "$DIR/src/Qihse.Studio.Server" --urls "http://0.0.0.0:5100"
