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
        --amx)
            TARGET="amx"
            ;;
        --avx-vnni)
            TARGET="avx-vnni"
            ;;
        --f16c)
            TARGET="f16c"
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
  --auto               Auto-detect CPU and enable every SIMD ISA present (default).
  --avx2               Force AVX2 build.
  --avx512             Force AVX-512 build (F/DQ/BW/VL + FMA).
  --amx                Force AMX build (tile/int8/bf16, Sapphire Rapids+).
  --avx-vnni           Force AVX-VNNI build (VEX vpdpbusd; implies AVX2).
  --f16c               Force F16C (half-precision conversion) build.
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

# Per-flag presence (mirrors the Makefile REQ_* groups; see Makefile).
HAS_AVX=0
HAS_F16C=0
HAS_AVX2=0
HAS_AVX512F=0
HAS_AVX512DQ=0
HAS_AVX512BW=0
HAS_AVX512VL=0
HAS_AVX_VNNI=0
HAS_AMX_TILE=0
HAS_AMX_INT8=0
HAS_AMX_BF16=0
HAS_FMA=0
if [ -n "$FLAGS" ]; then
    HAS_FLAG "$FLAGS" "avx" && HAS_AVX=1 || true
    HAS_FLAG "$FLAGS" "f16c" && HAS_F16C=1 || true
    HAS_FLAG "$FLAGS" "avx2" && HAS_AVX2=1 || true
    HAS_FLAG "$FLAGS" "avx512f" && HAS_AVX512F=1 || true
    HAS_FLAG "$FLAGS" "avx512dq" && HAS_AVX512DQ=1 || true
    HAS_FLAG "$FLAGS" "avx512bw" && HAS_AVX512BW=1 || true
    HAS_FLAG "$FLAGS" "avx512vl" && HAS_AVX512VL=1 || true
    HAS_FLAG "$FLAGS" "avx_vnni" && HAS_AVX_VNNI=1 || true
    HAS_FLAG "$FLAGS" "amx_tile" && HAS_AMX_TILE=1 || true
    HAS_FLAG "$FLAGS" "amx_int8" && HAS_AMX_INT8=1 || true
    HAS_FLAG "$FLAGS" "amx_bf16" && HAS_AMX_BF16=1 || true
    HAS_FLAG "$FLAGS" "fma" && HAS_FMA=1 || true
fi

# Group gates: an ISA is available only when every required flag is present.
HAS_AVX_GROUP=0
[ "$HAS_AVX" -eq 1 ] && HAS_AVX_GROUP=1 || true
HAS_F16C_GROUP=0
[ "$HAS_AVX" -eq 1 ] && [ "$HAS_F16C" -eq 1 ] && HAS_F16C_GROUP=1 || true
HAS_AVX2_GROUP=0
[ "$HAS_AVX2" -eq 1 ] && [ "$HAS_FMA" -eq 1 ] && HAS_AVX2_GROUP=1 || true
HAS_AVX512_GROUP=0
[ "$HAS_AVX512F" -eq 1 ] && [ "$HAS_AVX512DQ" -eq 1 ] && [ "$HAS_AVX512BW" -eq 1 ] && [ "$HAS_AVX512VL" -eq 1 ] && [ "$HAS_FMA" -eq 1 ] && HAS_AVX512_GROUP=1 || true
HAS_AVX_VNNI_GROUP=0
[ "$HAS_AVX2" -eq 1 ] && [ "$HAS_AVX_VNNI" -eq 1 ] && HAS_AVX_VNNI_GROUP=1 || true
HAS_AMX_GROUP=0
[ "$HAS_AMX_TILE" -eq 1 ] && [ "$HAS_AMX_INT8" -eq 1 ] && [ "$HAS_AMX_BF16" -eq 1 ] && HAS_AMX_GROUP=1 || true

# Resolve the chosen target into explicit QIHSE_ENABLE_* values.
EN_AVX=0
EN_F16C=0
EN_AVX2=0
EN_AVX512=0
EN_AVX_VNNI=0
EN_AMX=0
case "$TARGET" in
    auto)
        EN_AVX="$HAS_AVX_GROUP"
        EN_F16C="$HAS_F16C_GROUP"
        EN_AVX2="$HAS_AVX2_GROUP"
        EN_AVX512="$HAS_AVX512_GROUP"
        EN_AVX_VNNI="$HAS_AVX_VNNI_GROUP"
        EN_AMX="$HAS_AMX_GROUP"
        ;;
    avx2)
        EN_AVX=1; EN_AVX2=1
        ;;
    avx512)
        EN_AVX=1; EN_AVX2=1; EN_AVX512=1
        ;;
    amx)
        EN_AVX=1; EN_AMX=1
        ;;
    avx-vnni)
        EN_AVX=1; EN_AVX2=1; EN_AVX_VNNI=1
        ;;
    f16c)
        EN_AVX=1; EN_F16C=1
        ;;
    none)
        ;;
    *)
        echo "Invalid target: $TARGET" >&2
        exit 1
        ;;
esac

# Refuse to force an ISA the host cannot run, unless explicitly allowed.
if [ "$ALLOW_UNSUPPORTED" -eq 0 ]; then
    if [ "$EN_AVX2" -eq 1 ] && [ "$HAS_AVX2_GROUP" -eq 0 ]; then
        echo "Requested AVX2 but host flags are not present. Aborting."
        echo "Use --allow-unsupported to force, or run with --auto for safe defaults."
        exit 1
    fi
    if [ "$EN_AVX512" -eq 1 ] && [ "$HAS_AVX512_GROUP" -eq 0 ]; then
        echo "Requested AVX-512 but host flags are not present. Aborting."
        echo "Use --allow-unsupported to force, or run with --auto for safe defaults."
        exit 1
    fi
    if [ "$EN_AMX" -eq 1 ] && [ "$HAS_AMX_GROUP" -eq 0 ]; then
        echo "Requested AMX but host flags are not present. Aborting."
        echo "Use --allow-unsupported to force, or run with --auto for safe defaults."
        exit 1
    fi
    if [ "$EN_AVX_VNNI" -eq 1 ] && [ "$HAS_AVX_VNNI_GROUP" -eq 0 ]; then
        echo "Requested AVX-VNNI but host flags are not present. Aborting."
        echo "Use --allow-unsupported to force, or run with --auto for safe defaults."
        exit 1
    fi
    if [ "$EN_F16C" -eq 1 ] && [ "$HAS_F16C_GROUP" -eq 0 ]; then
        echo "Requested F16C but host flags are not present. Aborting."
        echo "Use --allow-unsupported to force, or run with --auto for safe defaults."
        exit 1
    fi
fi

if [ "$VERBOSE" -eq 1 ]; then
    echo "CPU flags:    $FLAGS"
    echo "Detected: avx=$HAS_AVX_GROUP f16c=$HAS_F16C_GROUP avx2=$HAS_AVX2_GROUP avx512=$HAS_AVX512_GROUP avx_vnni=$HAS_AVX_VNNI_GROUP amx=$HAS_AMX_GROUP"
    echo "Chosen build: AVX=$EN_AVX F16C=$EN_F16C AVX2=$EN_AVX2 AVX512=$EN_AVX512 AVX_VNNI=$EN_AVX_VNNI AMX=$EN_AMX"
    echo "Extra flags:  $CFLAGS_EXTRA"
fi

if [ "$CLEAN" -eq 1 ]; then
    make clean
fi

echo "Building with: make QIHSE_ENABLE_AVX=$EN_AVX QIHSE_ENABLE_F16C=$EN_F16C QIHSE_ENABLE_AVX2=$EN_AVX2 QIHSE_ENABLE_AVX512=$EN_AVX512 QIHSE_ENABLE_AVX_VNNI=$EN_AVX_VNNI QIHSE_ENABLE_AMX=$EN_AMX QIHSE_CFLAGS_EXTRA='$CFLAGS_EXTRA'"
(cd "$ROOT_DIR" && \
make all QIHSE_ENABLE_AVX="$EN_AVX" QIHSE_ENABLE_F16C="$EN_F16C" QIHSE_ENABLE_AVX2="$EN_AVX2" QIHSE_ENABLE_AVX512="$EN_AVX512" QIHSE_ENABLE_AVX_VNNI="$EN_AVX_VNNI" QIHSE_ENABLE_AMX="$EN_AMX" QIHSE_CFLAGS_EXTRA="$CFLAGS_EXTRA")
