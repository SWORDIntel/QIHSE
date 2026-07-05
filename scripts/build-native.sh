#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="${QIHSE_BUILD_FLAGS_FILE:-$ROOT_DIR/.qihse-build-flags}"
TARGET="auto"
CFLAGS_EXTRA="${QIHSE_CFLAGS_EXTRA:--march=native -DNDEBUG}"
ALLOW_UNSUPPORTED=0
CLEAN=0
VERBOSE=0

if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

if [ "${QIHSE_CFLAGS_EXTRA:-}" ]; then
    CFLAGS_EXTRA="$QIHSE_CFLAGS_EXTRA"
fi
if [ "${QIHSE_TARGET_OVERRIDE:-}" ]; then
    TARGET="$QIHSE_TARGET_OVERRIDE"
fi
if [ "${QIHSE_BUILD_ALLOW_UNSUPPORTED:-}" = "1" ]; then
    ALLOW_UNSUPPORTED=1
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --auto)
            TARGET="auto"
            ;;
        --avx2)
            TARGET="avx2"
            ;;
        --avx512)
            TARGET="avx512"
            ;;
        --none|--scalar)
            TARGET="none"
            ;;
        --allow-unsupported)
            ALLOW_UNSUPPORTED=1
            ;;
        --cflags)
            shift
            CFLAGS_EXTRA="$1"
            ;;
        --clean)
            CLEAN=1
            ;;
        --verbose|-v)
            VERBOSE=1
            ;;
        --help|-h)
            cat <<'EOF'
Usage: ./build-native.sh [options]

Auto-detects host SIMD features and builds with safe optimized defaults.

Options:
  --auto               Auto-detect CPU and pick AVX2/AVX512 if available (default).
  --avx2               Force AVX2 build.
  --avx512             Force AVX512 build.
  --none|--scalar      Force scalar-only build.
  --allow-unsupported  Allow forcing a feature set not present on current CPU.
  --cflags "FLAGS"     Extra CFLAGS to append (overrides defaults).
  --clean               Run `make clean` before building.
  --verbose             Show detected feature summary.
  --help                Show this message.

Easy file-based override:
  Set QIHSE_BUILD_FLAGS_FILE=/path/to/file
  or create $ROOT/.qihse-build-flags with:
    QIHSE_TARGET_OVERRIDE=avx512
    QIHSE_CFLAGS_EXTRA="-march=native -DNDEBUG -flto"
    QIHSE_BUILD_ALLOW_UNSUPPORTED=1

Environment override:
  QIHSE_BUILD_FLAGS_FILE
  QIHSE_TARGET_OVERRIDE
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Use --help for usage." >&2
            exit 1
            ;;
    esac
    shift
done

cpu_flags() {
    if [ -r /proc/cpuinfo ]; then
        awk -F: '/^flags/{sub(/^ /, "", $2); print $2; exit}' /proc/cpuinfo
        return
    fi
    if command -v lscpu >/dev/null 2>&1; then
        lscpu | awk -F: '/^Flags:/{sub(/^ /, "", $2); print $2; exit}'
    fi
}

HAS_FLAG() {
    case " $1 " in
        *" $2 "*) return 0 ;;
        *) return 1 ;;
    esac
}

FLAGS="$(cpu_flags || true)"
HAS_AVX2=0
HAS_AVX512F=0
HAS_AVX512DQ=0
HAS_AVX512BW=0
HAS_AVX512VL=0
if [ -n "$FLAGS" ]; then
    HAS_FLAG "$FLAGS" "avx2" && HAS_AVX2=1 || true
    HAS_FLAG "$FLAGS" "avx512f" && HAS_AVX512F=1 || true
    HAS_FLAG "$FLAGS" "avx512dq" && HAS_AVX512DQ=1 || true
    HAS_FLAG "$FLAGS" "avx512bw" && HAS_AVX512BW=1 || true
    HAS_FLAG "$FLAGS" "avx512vl" && HAS_AVX512VL=1 || true
fi

HAS_AVX512=0
if [ "$HAS_AVX512F" -eq 1 ] && [ "$HAS_AVX512DQ" -eq 1 ] && [ "$HAS_AVX512BW" -eq 1 ] && [ "$HAS_AVX512VL" -eq 1 ]; then
    HAS_AVX512=1
fi

QIHSE_ENABLE_AVX2=0
QIHSE_ENABLE_AVX512=0
case "$TARGET" in
    auto)
        if [ "$HAS_AVX512" -eq 1 ]; then
            QIHSE_ENABLE_AVX2=1
            QIHSE_ENABLE_AVX512=1
        elif [ "$HAS_AVX2" -eq 1 ]; then
            QIHSE_ENABLE_AVX2=1
        fi
        ;;
    avx2)
        QIHSE_ENABLE_AVX2=1
        ;;
    avx512)
        QIHSE_ENABLE_AVX2=1
        QIHSE_ENABLE_AVX512=1
        ;;
    none)
        ;;
    *)
        echo "Invalid target: $TARGET" >&2
        exit 1
        ;;
esac

if [ "$VERBOSE" -eq 1 ]; then
    echo "CPU flags:    $FLAGS"
    echo "Detected: avx2=$HAS_AVX2 avx512=$HAS_AVX512"
    echo "Chosen build: QIHSE_ENABLE_AVX2=$QIHSE_ENABLE_AVX2 QIHSE_ENABLE_AVX512=$QIHSE_ENABLE_AVX512"
    echo "Extra flags:  $CFLAGS_EXTRA"
fi

if [ "$TARGET" = "avx512" ] && [ "$HAS_AVX512" -eq 0 ] && [ "$ALLOW_UNSUPPORTED" -eq 0 ]; then
    echo "Requested AVX512 but host flags are not present. Aborting."
    echo "Use --allow-unsupported to force, or run with --auto for safe defaults."
    exit 1
fi
if [ "$TARGET" = "avx2" ] && [ "$HAS_AVX2" -eq 0 ] && [ "$ALLOW_UNSUPPORTED" -eq 0 ]; then
    echo "Requested AVX2 but host flags are not present. Aborting."
    echo "Use --allow-unsupported to force, or run with --auto for safe defaults."
    exit 1
fi

if [ "$CLEAN" -eq 1 ]; then
    make clean
fi

echo "Building with: make QIHSE_ENABLE_AVX2=$QIHSE_ENABLE_AVX2 QIHSE_ENABLE_AVX512=$QIHSE_ENABLE_AVX512 QIHSE_CFLAGS_EXTRA='$CFLAGS_EXTRA'"
(cd "$ROOT_DIR" && \
make QIHSE_ENABLE_AVX2="$QIHSE_ENABLE_AVX2" QIHSE_ENABLE_AVX512="$QIHSE_ENABLE_AVX512" QIHSE_CFLAGS_EXTRA="$CFLAGS_EXTRA")

