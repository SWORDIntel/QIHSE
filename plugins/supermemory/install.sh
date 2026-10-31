#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Do not install a stale native hook if a pinned-QKP build fails.
command -v gcc >/dev/null 2>&1 || { echo "gcc required for native QKP hook" >&2; exit 1; }
make -C "${SCRIPT_DIR}"

exec python3 "${SCRIPT_DIR}/install.py" "$@"
