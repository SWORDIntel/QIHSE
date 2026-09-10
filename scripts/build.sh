#!/bin/sh
# QIHSE Builder launcher — ash/sh compatible
# Detects python3 and runs the builder TUI
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Find python3
PYTHON=""
for p in python3 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$p" >/dev/null 2>&1; then
        PYTHON="$p"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "Error: python3 not found" >&2
    exit 1
fi

exec "$PYTHON" "$SCRIPT_DIR/builder.py" "$@"
