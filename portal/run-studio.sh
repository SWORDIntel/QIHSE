#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=========================================================="
echo "  Starting QIHSE Studio (ASP.NET Core 8 + React SPA)"
echo "  Web UI (Loopback): http://127.0.0.1:5100"
echo "  SignalR Hub: http://127.0.0.1:5100/hub/telemetry"
echo "=========================================================="

DOTNET_BIN="$(command -v dotnet || echo "${DOTNET_ROOT:-$HOME/.dotnet}/dotnet")"
if [ -z "${QIHSE_STUDIO_API_TOKEN:-}" ]; then
    echo "Set QIHSE_STUDIO_API_TOKEN to a 32+ character random token before starting Studio" >&2
    exit 1
fi
if command -v npm >/dev/null; then
    if [ ! -d "$DIR/src/Qihse.Studio.Client/node_modules" ]; then
        npm --prefix "$DIR/src/Qihse.Studio.Client" ci
    fi
    npm --prefix "$DIR/src/Qihse.Studio.Client" run build
else
    echo "npm missing; Studio refuses to serve an outdated prebuilt client" >&2
    exit 1
fi
exec "$DOTNET_BIN" run --project "$DIR/src/Qihse.Studio.Server" --urls "http://127.0.0.1:5100"
