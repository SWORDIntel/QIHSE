#!/bin/sh
# QIHSE Builder launcher — ash/sh compatible
# Bootstraps python3, checks deps with a crude progress bar, then runs builder
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Crude progress bar
progress() {
    # $1 = step number, $2 = total steps, $3 = label
    pct=$(( $1 * 100 / $2 ))
    filled=$(( pct / 5 ))
    empty=$(( 20 - filled ))
    bar=""
    i=0
    while [ $i -lt $filled ]; do bar="${bar}█"; i=$((i+1)); done
    i=0
    while [ $i -lt $empty ]; do bar="${bar}░"; i=$((i+1)); done
    printf "\r  \033[38;5;196m●\033[0m %-30s [\033[38;5;196m%s\033[0m] %3d%%" "$3" "$bar" "$pct"
    if [ $1 -eq $2 ]; then
        printf "\r  \033[32m✓\033[0m %-30s [\033[32m%s\033[0m] 100%%\n" "$3" "$bar"
    fi
}

TOTAL=4
printf "\n  \033[38;5;196m\033[1mQ I H S E\033[0m \033[2mbootstrap\033[0m\n\n"

# Step 1: Find python3
progress 1 $TOTAL "Finding python3"
PYTHON=""
for p in python3 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$p" >/dev/null 2>&1; then
        PYTHON="$p"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    printf "\n  \033[38;5;196m✗ python3 not found\033[0m\n" >&2
    exit 1
fi

# Step 2: Check make
progress 2 $TOTAL "Checking build tools"
if ! command -v make >/dev/null 2>&1; then
    printf "\n  \033[38;5;196m✗ make not found — install build-essential\033[0m\n" >&2
    exit 1
fi

# Step 3: Check gcc
progress 3 $TOTAL "Checking compiler"
if ! command -v gcc >/dev/null 2>&1; then
    printf "\n  \033[38;5;196m✗ gcc not found — install build-essential\033[0m\n" >&2
    exit 1
fi

# Step 4: Launch builder
progress 4 $TOTAL "Launching builder"
printf "\n"
exec "$PYTHON" "$SCRIPT_DIR/builder.py" "$@"
