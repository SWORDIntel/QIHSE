#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=========================================================="
echo "  Starting QIHSE Studio (ASP.NET Core 8 + React SPA)"
echo "  Web UI: http://localhost:5100"
echo "  SignalR Hub: http://localhost:5100/hub/telemetry"
echo "=========================================================="

exec /home/john/.dotnet/dotnet run --project "$DIR/src/Qihse.Studio.Server" --urls "http://127.0.0.1:5100"
