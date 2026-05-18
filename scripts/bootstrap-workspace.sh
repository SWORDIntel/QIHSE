#!/usr/bin/env sh

set -eu

USAGE="Usage: $(basename "$0") [--clean]"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE_DIRS="data results"
VENDOR_DIR="$BASE_DIR/VXUG-Papers"
FORCE_CLEAN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --clean)
      FORCE_CLEAN=1
      ;;
    -h|--help)
      echo "$USAGE"
      exit 0
      ;;
    *)
      echo "$USAGE"
      exit 1
      ;;
  esac
  shift
done

if [ "$FORCE_CLEAN" -eq 1 ]; then
  rm -rf "$BASE_DIR/data" "$BASE_DIR/results" "$VENDOR_DIR"
  exit 0
fi

mkdir -p "$BASE_DIR/data" "$BASE_DIR/results"
if [ ! -d "$VENDOR_DIR" ]; then
  mkdir -p "$VENDOR_DIR"
  echo "VXUG-Papers directory created (empty). Populate as needed."
fi
