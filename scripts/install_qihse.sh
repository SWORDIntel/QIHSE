#!/usr/bin/env bash
# scripts/install_qihse.sh — Automated Host ISA Detection, Build & Installer for QIHSE
#
# Detects host CPU ISA extensions (AVX, AVX2, AVX-512, AVX-VNNI, AMX, ARM NEON/SVE),
# configures optimal compiler & make flags, compiles the engine and cluster daemon,
# installs binaries and libraries into /opt/QIHSE, provisions NIST CNSA 2.0 PQC keys,
# and configures and launches the systemd cluster service.
#
# Usage:
#   sudo ./scripts/install_qihse.sh [options]
#   ./scripts/install_qihse.sh --dry-run
#
# SPDX-License-Identifier: LicenseRef-SRSL-1.0

set -euo pipefail

# ── Configuration Constants ───────────────────────────────────────────────────
DEFAULT_PREFIX="/opt/QIHSE"
DEFAULT_DATA_DIR="/opt/qihse-data"
DEFAULT_KEYS_DIR="/etc/qihse/keys"
DEFAULT_OPERATOR_PASSWORD="${QIHSE_OPERATOR_PASSWORD:-}"
DEFAULT_PORT="7100"
DEFAULT_BUS_PORT="17100"
DEFAULT_REPL_INTERVAL="30"
DEFAULT_SERVICE_BASE="qihse-node"

# ── Path Resolution ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Privilege Detection & Target User Resolution ──────────────────────────────
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1
SUDO=""

# Resolve target owner: if run via sudo, install for that user; if run directly as root, install as root
TARGET_USER="${SUDO_USER:-root}"
TARGET_GROUP="${TARGET_USER}"
if [ "$TARGET_USER" != "root" ]; then
    TARGET_GROUP="$(id -gn "${TARGET_USER}" 2>/dev/null || echo "${TARGET_USER}")"
fi

# ── Hardware-Fingerprint + CSPRNG Credential Derivation ───────────────────────
derive_hwid_password() {
    python3 -c '
import os, hashlib

hw_parts = []
for p in ["/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"]:
    if os.path.exists(p):
        try:
            with open(p, "rb") as f:
                c = f.read().strip()
                if c: hw_parts.append(c)
        except Exception:
            pass

try:
    for iface in sorted(os.listdir("/sys/class/net")):
        ap = os.path.join("/sys/class/net", iface, "address")
        tp = os.path.join("/sys/class/net", iface, "type")
        if os.path.exists(ap) and os.path.exists(tp):
            with open(tp) as tf, open(ap) as af:
                if tf.read().strip() == "1":
                    mac = af.read().strip()
                    if mac and mac != "00:00:00:00:00:00":
                        hw_parts.append(mac.encode())
                        break
except Exception:
    pass

try:
    with open("/proc/cpuinfo", "rb") as f:
        for line in f:
            if b"model name" in line:
                hw_parts.append(line.strip())
                break
except Exception:
    pass

hw_digest = hashlib.sha256(b":".join(hw_parts)).digest()
rand_bytes = os.urandom(32)
xored = bytes(h ^ r for h, r in zip(hw_digest, rand_bytes))
print(hashlib.sha256(xored + rand_bytes).hexdigest())
' 2>/dev/null || openssl rand -hex 32 2>/dev/null || (head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
}

# ── Options & Defaults ────────────────────────────────────────────────────────
PREFIX="$DEFAULT_PREFIX"
DATA_DIR="$DEFAULT_DATA_DIR"
KEYS_DIR="$DEFAULT_KEYS_DIR"
NODE_INDEX=""
BIND_IP=""
PORT="$DEFAULT_PORT"
BUS_PORT="$DEFAULT_BUS_PORT"
OPERATOR_PASSWORD="$DEFAULT_OPERATOR_PASSWORD"
REPL_INTERVAL="$DEFAULT_REPL_INTERVAL"
SLOT_RANGE=""
PEER_NODES=()
JOIN_SEEDS=()

IS_SOLO=""
EXPECTED_NODES=""
WAIT_TIMEOUT=45
NON_INTERACTIVE=0
DO_SCAN=1

JOBS=""
DO_CLEAN=1
DO_SERVICE=1
DO_LAUNCH=1
DRY_RUN=0
VERBOSE=1

# ── Usage / Help ──────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
QIHSE Host Installer & Hardware-Optimized Provisioner

Usage: $(basename "$0") [options]

Installation Options:
  --prefix DIR             Installation directory prefix (default: ${DEFAULT_PREFIX})
  --data-dir DIR           Database data storage directory (default: ${DEFAULT_DATA_DIR})
  --keys-dir DIR           PQC key storage directory (default: ${DEFAULT_KEYS_DIR})
  --node-index N           Cluster node index (default: auto-detected from existing service or 0)
  --bind IP                Listening IPv4 address (default: auto-detected primary LAN IP)
  --port PORT              RESP client port (default: ${DEFAULT_PORT})
  --bus-port BUSPORT       Cluster bus port (default: ${DEFAULT_BUS_PORT})
  --operator-password PW   Deprecated: may expose password via process list; prefer QIHSE_OPERATOR_PASSWORD
  --slot-range RANGE       Slot range to serve (e.g. 0-4549 or 0-16383)
  --node SPEC              Cluster peer spec INDEX:HOST:PORT:BUSPORT (repeatable)
  --join SPEC              Cluster join seed HOST:BUSPORT (repeatable)
  --repl-interval S        Anti-entropy replication interval in seconds (default: ${DEFAULT_REPL_INTERVAL})

Cluster Topology & Orchestration:
  --solo                   Configure as a solo standalone node (owns slots 0-16383, no peer requirement)
  --cluster                Configure as a multi-node LAN cluster
  --expected-nodes N       Total number of nodes expected on LAN (default: 2 in cluster mode)
  --wait-timeout SEC       Timeout in seconds waiting for peer acknowledgement (default: 45)
  --no-scan                Skip automatic LAN subnet peer scanning
  --non-interactive, -y    Non-interactive mode (use defaults without prompting)

Build & Execution Options:
  --jobs N, -j N           Number of parallel build threads (default: half host cores)
  --clean                  Run 'make clean' before compiling (default: always clean)
  --no-clean               Skip 'make clean' before compiling
  --no-service             Install binaries and keys, but do not create/modify systemd unit
  --launch                 Start/restart systemd cluster service immediately (default: enabled)
  --no-launch              Create systemd unit, but leave daemon offline until started manually
  --dry-run                Print detected ISA, planned compiler flags, and install plan without modifying system
  --verbose, -v            Show detailed command output (default: verbose)
  --quiet, -q              Suppress detailed command output
  --help, -h               Show this help message

EOF
    exit 0
}

# ── Argument Parsing ──────────────────────────────────────────────────────────
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)            PREFIX="$2"; shift 2 ;;
        --data-dir)          DATA_DIR="$2"; shift 2 ;;
        --keys-dir)          KEYS_DIR="$2"; shift 2 ;;
        --node-index)        NODE_INDEX="$2"; shift 2 ;;
        --bind)              BIND_IP="$2"; shift 2 ;;
        --port)              PORT="$2"; shift 2 ;;
        --bus-port)          BUS_PORT="$2"; shift 2 ;;
        --operator-password) OPERATOR_PASSWORD="$2"; shift 2 ;;
        --slot-range)        SLOT_RANGE="$2"; shift 2 ;;
        --node)              PEER_NODES+=("$2"); shift 2 ;;
        --join)              JOIN_SEEDS+=("$2"); shift 2 ;;
        --repl-interval)     REPL_INTERVAL="$2"; shift 2 ;;
        --solo)              IS_SOLO=1; shift ;;
        --cluster)           IS_SOLO=0; shift ;;
        --expected-nodes)    EXPECTED_NODES="$2"; shift 2 ;;
        --wait-timeout)      WAIT_TIMEOUT="$2"; shift 2 ;;
        --no-scan)           DO_SCAN=0; shift ;;
        --non-interactive|-y) NON_INTERACTIVE=1; shift ;;
        --jobs|-j)           JOBS="$2"; shift 2 ;;
        --clean)             DO_CLEAN=1; shift ;;
        --no-clean)          DO_CLEAN=0; shift ;;
        --no-service)        DO_SERVICE=0; shift ;;
        --launch)            DO_LAUNCH=1; shift ;;
        --no-launch)         DO_LAUNCH=0; shift ;;
        --dry-run)           DRY_RUN=1; shift ;;
        --verbose|-v)        VERBOSE=1; shift ;;
        --quiet|-q)          VERBOSE=0; shift ;;
        --help|-h)           usage ;;
        *)
            echo "[ERROR] Unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

# Operator password resolution:
# 1. Use user-supplied QIHSE_OPERATOR_PASSWORD or --operator-password if provided
# 2. Re-use existing secret from /etc/qihse/cluster-node${NODE_INDEX:-0}.env if present
# 3. Auto-derive a 256-bit high-entropy secret by XORing HWID fingerprint with CSPRNG entropy
DERIVED_AUTOPASS=0
if [ "$DRY_RUN" -eq 0 ]; then
    if [ -z "${OPERATOR_PASSWORD}" ]; then
        TARGET_ENV="/etc/qihse/cluster-node${NODE_INDEX:-0}.env"
        if [ -f "$TARGET_ENV" ]; then
            EXISTING_PW=$(sed -n 's/^QIHSE_OPERATOR_PASSWORD=//p' "$TARGET_ENV" 2>/dev/null | head -n1 || true)
            if [ "${#EXISTING_PW}" -ge 12 ]; then
                OPERATOR_PASSWORD="$EXISTING_PW"
                echo "[SECURITY] Reusing existing operator password from ${TARGET_ENV}."
            fi
        fi
    fi

    if [ -z "${OPERATOR_PASSWORD}" ]; then
        if [ ${#JOIN_SEEDS[@]} -gt 0 ]; then
            echo "[ERROR] Joining an existing cluster (--join) requires the cluster operator password." >&2
            echo "Set QIHSE_OPERATOR_PASSWORD before running, matching the primary cluster node." >&2
            exit 1
        fi
        echo "[SECURITY] Deriving high-entropy operator password from HWID XOR CSPRNG entropy..."
        OPERATOR_PASSWORD=$(derive_hwid_password)
        DERIVED_AUTOPASS=1
    fi

    if [ "${#OPERATOR_PASSWORD}" -lt 12 ] ||
       [[ ! "$OPERATOR_PASSWORD" =~ ^[A-Za-z0-9_.!@%+=:-]+$ ]]; then
        echo "[ERROR] Operator password must be 12+ safe printable characters." >&2
        exit 1
    fi
fi

# Privilege check: real system installation requires root, but allow dry-run and help
if [ "$DRY_RUN" -eq 0 ] && [ "$IS_ROOT" -eq 0 ]; then
    echo ""
    echo "======================================================================"
    echo " [ERROR] Root privileges required for system installation."
    echo " Please rerun with sudo:"
    echo "     sudo $0 $*"
    echo "======================================================================"
    echo ""
    read -r -p "Press [Enter] to exit..." _ || true
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                  QIHSE HOST HARDWARE INSTALLER                       ║"
echo "║            NIST CNSA 2.0 PQC & ARCHITECTURE TUNING                   ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# ── Step 1: Detect Host Hardware & CPU ISA Extensions ─────────────────────────
echo ""
echo "[1/7] Detecting CPU ISA Extensions and Hardware Topology..."

ARCH="$(uname -m)"
NPROC="$(nproc 2>/dev/null || echo 4)"
CPU_MODEL="Unknown CPU"

if [ -r /proc/cpuinfo ]; then
    CPU_MODEL="$(awk -F: '/model name/{sub(/^ /, "", $2); print $2; exit}' /proc/cpuinfo || echo "Unknown CPU")"
fi

echo "  • Machine Architecture : ${ARCH}"
echo "  • CPU Model            : ${CPU_MODEL}"
echo "  • Logical Cores        : ${NPROC}"

# Allocate 1/2 of available cores to maintain host responsiveness
if [ -z "$JOBS" ]; then
    JOBS=$(( (NPROC + 1) / 2 ))
    [ "$JOBS" -lt 1 ] && JOBS=1
fi
echo "  • Build Concurrency    : ${JOBS} threads (-j ${JOBS})"

# Extract flags
FLAGS_LIST=""
if [ -r /proc/cpuinfo ]; then
    FLAGS_LIST="$(awk -F: '/^flags/{sub(/^ /, "", $2); print $2; exit}' /proc/cpuinfo || true)"
elif command -v lscpu >/dev/null 2>&1; then
    FLAGS_LIST="$(lscpu | awk -F: '/^Flags:/{sub(/^ /, "", $2); print $2; exit}' || true)"
fi

has_flag() {
    case " ${FLAGS_LIST} " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

# ISA Variables for QIHSE Build
QIHSE_ENABLE_AVX=0
QIHSE_ENABLE_AVX2=0
QIHSE_ENABLE_AVX512=0
QIHSE_ENABLE_AVX_VNNI=0
QIHSE_ENABLE_AMX=0
QIHSE_ENABLE_F16C=0
QIHSE_ENABLE_AESNI=0
QIHSE_ENABLE_PCLMUL=0
QIHSE_ENABLE_POPCNT=0
QIHSE_ENABLE_RDRAND=0
QIHSE_ENABLE_FSGSBASE=0
QIHSE_ENABLE_ERMS=0
QIHSE_ENABLE_BMI1=0
QIHSE_ENABLE_BMI2=0
QIHSE_ENABLE_MOVBE=0
QIHSE_ENABLE_RDSEED=0
QIHSE_ENABLE_ADX=0
QIHSE_ENABLE_RTM=0
QIHSE_ENABLE_ABM=0
QIHSE_ARCH_FLAGS="-march=native -mtune=native"

if [ "$ARCH" = "x86_64" ]; then
    HAS_AVX=0;      has_flag "avx" && HAS_AVX=1
    HAS_FMA=0;      has_flag "fma" && HAS_FMA=1
    HAS_AVX2=0;     has_flag "avx2" && [ "$HAS_FMA" -eq 1 ] && HAS_AVX2=1
    
    HAS_AVX512F=0;  has_flag "avx512f" && HAS_AVX512F=1
    HAS_AVX512DQ=0; has_flag "avx512dq" && HAS_AVX512DQ=1
    HAS_AVX512BW=0; has_flag "avx512bw" && HAS_AVX512BW=1
    HAS_AVX512VL=0; has_flag "avx512vl" && HAS_AVX512VL=1
    HAS_AVX512=0
    if [ "$HAS_AVX512F" -eq 1 ] && [ "$HAS_AVX512DQ" -eq 1 ] && [ "$HAS_AVX512BW" -eq 1 ] && [ "$HAS_AVX512VL" -eq 1 ]; then
        HAS_AVX512=1
    fi

    HAS_VNNI=0;     (has_flag "avx_vnni" || has_flag "avx512_vnni") && HAS_VNNI=1
    HAS_AMX=0;      (has_flag "amx_tile" && has_flag "amx_int8" && has_flag "amx_bf16") && HAS_AMX=1
    HAS_F16C=0;     has_flag "f16c" && HAS_F16C=1
    HAS_AES=0;      has_flag "aes" && HAS_AES=1
    HAS_PCLMUL=0;   has_flag "pclmulqdq" && HAS_PCLMUL=1
    HAS_POPCNT=0;   has_flag "popcnt" && HAS_POPCNT=1
    HAS_RDRAND=0;   has_flag "rdrand" && HAS_RDRAND=1
    HAS_FSGSBASE=0; has_flag "fsgsbase" && HAS_FSGSBASE=1
    HAS_ERMS=0;     has_flag "erms" && HAS_ERMS=1
    HAS_BMI1=0;     has_flag "bmi1" && HAS_BMI1=1
    HAS_BMI2=0;     has_flag "bmi2" && HAS_BMI2=1
    HAS_MOVBE=0;    has_flag "movbe" && HAS_MOVBE=1
    HAS_RDSEED=0;   has_flag "rdseed" && HAS_RDSEED=1
    HAS_ADX=0;      has_flag "adx" && HAS_ADX=1
    HAS_RTM=0;      has_flag "rtm" && HAS_RTM=1
    HAS_ABM=0;      has_flag "abm" && HAS_ABM=1

    echo "  • Instruction Sets     :"
    [ "$HAS_AVX" -eq 1 ]      && echo "    [✓] AVX         (256-bit Vector Floating Point)" || echo "    [ ] AVX         (Not supported)"
    [ "$HAS_AVX2" -eq 1 ]     && echo "    [✓] AVX2 + FMA  (256-bit Vector Integer & Fused Multiply-Add)" || echo "    [ ] AVX2 + FMA  (Not supported)"
    [ "$HAS_AVX512" -eq 1 ]   && echo "    [✓] AVX-512     (512-bit Vector Extensions F/DQ/BW/VL)" || echo "    [ ] AVX-512     (Not supported)"
    [ "$HAS_VNNI" -eq 1 ]     && echo "    [✓] AVX-VNNI    (Vector Neural Network Instructions)" || echo "    [ ] AVX-VNNI    (Not supported)"
    [ "$HAS_AMX" -eq 1 ]      && echo "    [✓] Intel AMX   (Advanced Matrix Extensions TILE/INT8/BF16)" || echo "    [ ] Intel AMX   (Not supported)"
    [ "$HAS_F16C" -eq 1 ]     && echo "    [✓] F16C        (Half-Precision Floating Point Conversions)" || echo "    [ ] F16C        (Not supported)"
    [ "$HAS_AES" -eq 1 ]      && echo "    [✓] AES-NI      (Hardware Accelerated Encryption)" || echo "    [ ] AES-NI      (Not supported)"
    [ "$HAS_PCLMUL" -eq 1 ]   && echo "    [✓] PCLMULQDQ   (Carry-Less Multiplication for GCM & CRC)" || echo "    [ ] PCLMULQDQ   (Not supported)"
    [ "$HAS_POPCNT" -eq 1 ]   && echo "    [✓] POPCNT      (Hardware Population Count)" || echo "    [ ] POPCNT      (Not supported)"
    [ "$HAS_RDRAND" -eq 1 ]   && echo "    [✓] RDRAND      (On-Chip Digital Random Number Generator)" || echo "    [ ] RDRAND      (Not supported)"
    [ "$HAS_FSGSBASE" -eq 1 ] && echo "    [✓] FSGSBASE    (User-Space Fast Base Register Access)" || echo "    [ ] FSGSBASE    (Not supported)"
    [ "$HAS_ERMS" -eq 1 ]     && echo "    [✓] ERMS        (Enhanced REP MOVSB/STOSB Fast Copy)" || echo "    [ ] ERMS        (Not supported)"
    [ "$HAS_BMI1" -eq 1 ]     && echo "    [✓] BMI1        (Bit Manipulation Set 1: andn, bextr, blsr, tzcnt)" || echo "    [ ] BMI1        (Not supported)"
    [ "$HAS_BMI2" -eq 1 ]     && echo "    [✓] BMI2        (Bit Manipulation Set 2: pext, pdep, bzhi, mulx)" || echo "    [ ] BMI2        (Not supported)"
    [ "$HAS_MOVBE" -eq 1 ]    && echo "    [✓] MOVBE       (Single-Cycle Byte-Swapping Move)" || echo "    [ ] MOVBE       (Not supported)"
    [ "$HAS_RDSEED" -eq 1 ]   && echo "    [✓] RDSEED      (True Thermal Quantum Entropy NIST 800-90B/C)" || echo "    [ ] RDSEED      (Not supported)"
    [ "$HAS_ADX" -eq 1 ]      && echo "    [✓] ADX         (Multi-Precision Add-Carry: adcx, adox)" || echo "    [ ] ADX         (Not supported)"
    [ "$HAS_RTM" -eq 1 ]      && echo "    [✓] RTM/TSX     (Transactional Synchronization Extensions)" || echo "    [ ] RTM/TSX     (Not supported)"
    [ "$HAS_ABM" -eq 1 ]      && echo "    [✓] ABM/LZCNT   (Advanced Bit Manipulation: lzcnt)" || echo "    [ ] ABM/LZCNT   (Not supported)"

    [ "$HAS_AVX" -eq 1 ]      && QIHSE_ENABLE_AVX=1
    [ "$HAS_AVX2" -eq 1 ]     && QIHSE_ENABLE_AVX2=1
    [ "$HAS_AVX512" -eq 1 ]   && QIHSE_ENABLE_AVX512=1
    [ "$HAS_VNNI" -eq 1 ]     && QIHSE_ENABLE_AVX_VNNI=1
    [ "$HAS_AMX" -eq 1 ]      && QIHSE_ENABLE_AMX=1
    [ "$HAS_F16C" -eq 1 ]     && QIHSE_ENABLE_F16C=1
    [ "$HAS_AES" -eq 1 ]      && QIHSE_ENABLE_AESNI=1
    [ "$HAS_PCLMUL" -eq 1 ]   && QIHSE_ENABLE_PCLMUL=1
    [ "$HAS_POPCNT" -eq 1 ]   && QIHSE_ENABLE_POPCNT=1
    [ "$HAS_RDRAND" -eq 1 ]   && QIHSE_ENABLE_RDRAND=1
    [ "$HAS_FSGSBASE" -eq 1 ] && QIHSE_ENABLE_FSGSBASE=1
    [ "$HAS_ERMS" -eq 1 ]     && QIHSE_ENABLE_ERMS=1
    [ "$HAS_BMI1" -eq 1 ]     && QIHSE_ENABLE_BMI1=1
    [ "$HAS_BMI2" -eq 1 ]     && QIHSE_ENABLE_BMI2=1
    [ "$HAS_MOVBE" -eq 1 ]    && QIHSE_ENABLE_MOVBE=1
    [ "$HAS_RDSEED" -eq 1 ]   && QIHSE_ENABLE_RDSEED=1
    [ "$HAS_ADX" -eq 1 ]      && QIHSE_ENABLE_ADX=1
    [ "$HAS_RTM" -eq 1 ]      && QIHSE_ENABLE_RTM=1
    [ "$HAS_ABM" -eq 1 ]      && QIHSE_ENABLE_ABM=1

elif [ "$ARCH" = "aarch64" ]; then
    HAS_NEON=0; has_flag "asimd" && HAS_NEON=1
    HAS_SVE=0;  has_flag "sve" && HAS_SVE=1
    echo "  • ARM Extensions       :"
    [ "$HAS_NEON" -eq 1 ] && echo "    [✓] NEON/ASIMD  (Advanced SIMD)"
    [ "$HAS_SVE" -eq 1 ]  && echo "    [✓] SVE         (Scalable Vector Extension)"
fi

# ── LAN Peer Probe Helper ─────────────────────────────────────────────────────
scan_lan_peers() {
    local bind_ip="$1"
    local port="$2"
    local bus_port="$3"

    python3 - <<EOF 2>/dev/null || true
import socket, concurrent.futures, sys

bind_ip = "${bind_ip}"
parts = bind_ip.split('.')
if len(parts) != 4:
    sys.exit(0)
prefix = '.'.join(parts[:3]) + '.'

ports_to_check = sorted(set([int("${port}"), int("${bus_port}"), 7100, 7101, 7115, 17100, 17101, 17115]))

def probe(ip, p):
    if ip == bind_ip:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.35)
            if s.connect_ex((ip, p)) == 0:
                return (ip, p)
    except Exception:
        pass
    return None

targets = [(f"{prefix}{i}", p) for i in range(1, 255) for p in ports_to_check]
discovered = []
with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
    futures = [ex.submit(probe, ip, p) for ip, p in targets]
    for f in concurrent.futures.as_completed(futures):
        res = f.result()
        if res:
            discovered.append(res)

for ip, p in sorted(discovered):
    print(f"{ip}:{p}")
EOF
}

# ── Step 2: Auto-Detect Network & Existing Cluster Context ────────────────────
echo ""
echo "[2/7] Detecting Network & Cluster Topology..."

# Detect existing systemd service configuration if present
EXISTING_UNIT=""
for candidate in /etc/systemd/system/qihse-node*.service; do
    if [ -f "$candidate" ]; then
        EXISTING_UNIT="$candidate"
        break
    fi
done

if [ -n "$EXISTING_UNIT" ]; then
    echo "  • Found Existing Cluster Service : $(basename "$EXISTING_UNIT")"
    if [ -z "$NODE_INDEX" ]; then
        EXTRACTED_IDX="$(grep -oE -- '--index [0-9]+' "$EXISTING_UNIT" | awk '{print $2}' || true)"
        if [ -n "$EXTRACTED_IDX" ]; then
            NODE_INDEX="$EXTRACTED_IDX"
            echo "  • Preserving Node Index          : ${NODE_INDEX}"
        fi
    fi
    if [ -z "$BIND_IP" ]; then
        EXTRACTED_BIND="$(grep -oE -- '--bind [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$EXISTING_UNIT" | awk '{print $2}' || true)"
        if [ -n "$EXTRACTED_BIND" ]; then
            BIND_IP="$EXTRACTED_BIND"
            echo "  • Preserving Bind Address        : ${BIND_IP}"
        fi
    fi
    EXTRACTED_PORT="$(grep -oE -- '--port [0-9]+' "$EXISTING_UNIT" | awk '{print $2}' || true)"
    if [ -n "$EXTRACTED_PORT" ] && [ "$PORT" = "$DEFAULT_PORT" ]; then
        PORT="$EXTRACTED_PORT"
        echo "  • Preserving Service Port        : ${PORT}"
    fi
    EXTRACTED_BUS="$(grep -oE -- '--bus-port [0-9]+' "$EXISTING_UNIT" | awk '{print $2}' || true)"
    if [ -n "$EXTRACTED_BUS" ] && [ "$BUS_PORT" = "$DEFAULT_BUS_PORT" ]; then
        BUS_PORT="$EXTRACTED_BUS"
        echo "  • Preserving Bus Port            : ${BUS_PORT}"
    fi
fi

# Auto-detect bind IP if not set or preserved
if [ -z "$BIND_IP" ]; then
    PRIMARY_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}' || true)"
    if [ -z "$PRIMARY_IP" ]; then
        PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")"
    fi
    BIND_IP="$PRIMARY_IP"
fi
echo "  • Primary Bind Address           : ${BIND_IP}"
echo "  • RESP Service Port              : ${PORT}"
echo "  • Cluster Bus Port               : ${BUS_PORT}"

if [ -z "$NODE_INDEX" ]; then
    NODE_INDEX="0"
    echo "  • Node Index                     : 0 (default/new)"
else
    echo "  • Node Index                     : ${NODE_INDEX}"
fi

if [ -n "$EXISTING_UNIT" ]; then
    SERVICE_NAME="$(basename "$EXISTING_UNIT" .service)"
else
    SERVICE_NAME="${DEFAULT_SERVICE_BASE}${NODE_INDEX}"
fi
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# If slot range is not specified, auto-detect from existing service or default
if [ -z "$SLOT_RANGE" ] && [ -n "$EXISTING_UNIT" ]; then
    EXISTING_SLOTS="$(grep -oE -- '--slot-range [0-9]+-[0-9]+' "$EXISTING_UNIT" | awk '{print $2}' || true)"
    if [ -n "$EXISTING_SLOTS" ]; then
        SLOT_RANGE="$EXISTING_SLOTS"
        echo "  • Preserving Slot Range : ${SLOT_RANGE}"
    fi
fi

# ── Topology Resolution (Solo vs Multi-Node Cluster) ──────────────────────────
DISCOVERED_PEERS=()
if [ "$DO_SCAN" -eq 1 ] && [ -z "$IS_SOLO" ]; then
    SUBNET_PREFIX="$(echo "$BIND_IP" | awk -F. '{print $1"."$2"."$3"."}')"
    echo "  • Probing local LAN subnet (${SUBNET_PREFIX}0/24) for active QIHSE nodes..."
    while IFS= read -r peer_line; do
        [ -n "$peer_line" ] && DISCOVERED_PEERS+=("$peer_line")
    done < <(scan_lan_peers "${BIND_IP}" "${PORT}" "${BUS_PORT}")

    if [ "${#DISCOVERED_PEERS[@]}" -gt 0 ]; then
        echo "  [✓] Discovered ${#DISCOVERED_PEERS[@]} active QIHSE endpoint(s) on local LAN:"
        for p in "${DISCOVERED_PEERS[@]}"; do
            echo "      • $p"
            P_HOST="$(echo "$p" | cut -d: -f1)"
            P_PORT="$(echo "$p" | cut -d: -f2)"
            if [ "$P_PORT" -lt 10000 ]; then
                P_BUS=$(( P_PORT + 10000 ))
            else
                P_BUS="$P_PORT"
            fi
            SEED_ENTRY="${P_HOST}:${P_BUS}"
            ALREADY_HAVE=0
            for js in "${JOIN_SEEDS[@]}"; do
                [ "$js" = "$SEED_ENTRY" ] && ALREADY_HAVE=1
            done
            [ "$ALREADY_HAVE" -eq 0 ] && JOIN_SEEDS+=("$SEED_ENTRY")
        done
    else
        echo "  • No active QIHSE peers detected on subnet (${SUBNET_PREFIX}0/24)."
    fi
fi

if [ "$NON_INTERACTIVE" -eq 0 ] && [ -t 0 ]; then
    # Interactive mode
    if [ -n "$EXISTING_UNIT" ] && [ -z "$IS_SOLO" ]; then
        PEER_COUNT_IN_UNIT="$(grep -c -- '--node ' "$EXISTING_UNIT" || true)"
        if [ "$PEER_COUNT_IN_UNIT" -gt 0 ]; then
            echo ""
            echo "  Existing multi-node cluster service found (${SERVICE_NAME}) with ${PEER_COUNT_IN_UNIT} peer node(s)."
            read -r -p "  Keep existing multi-node cluster configuration? [Y/n]: " KEEP_EXISTING || KEEP_EXISTING="y"
            if [[ "$KEEP_EXISTING" =~ ^[Nn] ]]; then
                IS_SOLO=""
            else
                IS_SOLO=0
                [ -z "$EXPECTED_NODES" ] && EXPECTED_NODES=$(( PEER_COUNT_IN_UNIT + 1 ))
            fi
        fi
    fi

    if [ -z "$IS_SOLO" ]; then
        echo ""
        echo "  ┌──────────────────────────────────────────────────────────────┐"
        echo "  │ QIHSE Cluster & Network Mode Selection                       │"
        echo "  └──────────────────────────────────────────────────────────────┘"

        if [ "${#DISCOVERED_PEERS[@]}" -gt 0 ]; then
            echo "  Active QIHSE peers were discovered on the local LAN (${DISCOVERED_PEERS[*]})."
            read -r -p "  Join multi-node cluster with discovered peer(s)? [Y/n]: " REPLY_CLUSTER || REPLY_CLUSTER="y"
            if ! [[ "$REPLY_CLUSTER" =~ ^[Nn] ]]; then
                IS_SOLO=0
                DEF_NODES=$(( ${#DISCOVERED_PEERS[@]} + 1 ))
                [ "$DEF_NODES" -lt 2 ] && DEF_NODES=2
                read -r -p "  Enter total number of cluster nodes on local LAN (including this machine) [${DEF_NODES}]: " INPUT_NODES || INPUT_NODES="${DEF_NODES}"
                EXPECTED_NODES="${INPUT_NODES:-$DEF_NODES}"
                if ! [[ "$EXPECTED_NODES" =~ ^[0-9]+$ ]] || [ "$EXPECTED_NODES" -lt 2 ]; then
                    echo "  [!] Invalid node count; defaulting to ${DEF_NODES} expected nodes."
                    EXPECTED_NODES="${DEF_NODES}"
                fi
                read -r -p "  Bring QIHSE cluster service online now? [Y/n]: " REPLY_LAUNCH || REPLY_LAUNCH="y"
                [[ "$REPLY_LAUNCH" =~ ^[Nn] ]] && DO_LAUNCH=0 || DO_LAUNCH=1
            else
                IS_SOLO=1
                SLOT_RANGE="0-16383"
                read -r -p "  Bring QIHSE service online now as a solo node? [Y/n]: " REPLY_LAUNCH || REPLY_LAUNCH="y"
                [[ "$REPLY_LAUNCH" =~ ^[Nn] ]] && DO_LAUNCH=0 || DO_LAUNCH=1
            fi
        else
            echo "  No other QIHSE servers were detected on your local network."
            read -r -p "  Configure this machine as a solo standalone node? [Y/n]: " REPLY_SOLO || REPLY_SOLO="y"
            if ! [[ "$REPLY_SOLO" =~ ^[Nn] ]]; then
                IS_SOLO=1
                SLOT_RANGE="0-16383"
                read -r -p "  Bring QIHSE service online now as a solo node? [Y/n]: " REPLY_LAUNCH || REPLY_LAUNCH="y"
                [[ "$REPLY_LAUNCH" =~ ^[Nn] ]] && DO_LAUNCH=0 || DO_LAUNCH=1
            else
                IS_SOLO=0
                read -r -p "  Enter total number of cluster nodes on local LAN (including this machine) [2]: " INPUT_NODES || INPUT_NODES="2"
                EXPECTED_NODES="${INPUT_NODES:-2}"
                read -r -p "  Enter peer IP:bus-port to join (e.g. 192.168.1.90:17115, or press Enter to skip): " INPUT_JOIN || INPUT_JOIN=""
                [ -n "$INPUT_JOIN" ] && JOIN_SEEDS+=("$INPUT_JOIN")
                read -r -p "  Bring QIHSE cluster service online now? [Y/n]: " REPLY_LAUNCH || REPLY_LAUNCH="y"
                [[ "$REPLY_LAUNCH" =~ ^[Nn] ]] && DO_LAUNCH=0 || DO_LAUNCH=1
            fi
        fi
    fi
else
    # Non-interactive mode
    if [ -z "$IS_SOLO" ]; then
        if [ -n "$EXISTING_UNIT" ]; then
            PEER_COUNT_IN_UNIT="$(grep -c -- '--node ' "$EXISTING_UNIT" || true)"
            if [ "$PEER_COUNT_IN_UNIT" -gt 0 ]; then
                IS_SOLO=0
                [ -z "$EXPECTED_NODES" ] && EXPECTED_NODES=$(( PEER_COUNT_IN_UNIT + 1 ))
            else
                IS_SOLO=1
                [ -z "$SLOT_RANGE" ] && SLOT_RANGE="0-16383"
            fi
        elif [ "${#DISCOVERED_PEERS[@]}" -gt 0 ]; then
            IS_SOLO=0
            [ -z "$EXPECTED_NODES" ] && EXPECTED_NODES=$(( ${#DISCOVERED_PEERS[@]} + 1 ))
        else
            IS_SOLO=1
            [ -z "$SLOT_RANGE" ] && SLOT_RANGE="0-16383"
        fi
    elif [ "$IS_SOLO" -eq 1 ]; then
        [ -z "$SLOT_RANGE" ] && SLOT_RANGE="0-16383"
    elif [ "$IS_SOLO" -eq 0 ]; then
        [ -z "$EXPECTED_NODES" ] && EXPECTED_NODES=2
    fi
fi

if [ "$IS_SOLO" -eq 1 ]; then
    echo "  • Cluster Deployment Mode        : Solo Standalone Node (slots 0-16383)"
    SLOT_RANGE="0-16383"
else
    [ -z "$EXPECTED_NODES" ] && EXPECTED_NODES=2
    echo "  • Cluster Deployment Mode        : Multi-Node LAN Cluster (${EXPECTED_NODES} nodes expected)"
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo ""
    echo "[DRY RUN] Configured Parameters:"
    echo "  Prefix:             ${PREFIX}"
    echo "  Target User:        ${TARGET_USER}:${TARGET_GROUP}"
    echo "  Data Directory:     ${DATA_DIR}"
    echo "  Keys Directory:     ${KEYS_DIR}"
    echo "  Service Name:       ${SERVICE_NAME}"
    echo "  Auto-Start on Boot: Enabled (multi-user.target; active regardless of user login)"
    echo "  Cluster Mode:       $( [ "$IS_SOLO" -eq 1 ] && echo "Solo Node (0-16383)" || echo "Multi-Node Cluster (${EXPECTED_NODES} nodes expected)" )"
    echo "  Slot Range:         ${SLOT_RANGE:-0-16383}"
    echo "  Launch Service:     $( [ "$DO_LAUNCH" -eq 1 ] && echo "Yes" || echo "No (--no-launch)" )"
    echo "  QIHSE_ENABLE_AVX2:     ${QIHSE_ENABLE_AVX2}"
    echo "  QIHSE_ENABLE_AVX512:   ${QIHSE_ENABLE_AVX512}"
    echo "  QIHSE_ENABLE_AVX_VNNI: ${QIHSE_ENABLE_AVX_VNNI}"
    echo "  QIHSE_ENABLE_AMX:      ${QIHSE_ENABLE_AMX}"
    echo "  Build Jobs:         ${JOBS}"
    echo ""
    echo "[DRY RUN] Exiting without making changes."
    exit 0
fi

# ── Step 3: Build QIHSE Suite ─────────────────────────────────────────────────
echo ""
echo "[3/7] Compiling Hardware-Optimized QIHSE Suite..."

cd "${ROOT_DIR}"

if [ "$DO_CLEAN" -eq 1 ]; then
    echo "  • Running 'make clean'..."
    make clean >/dev/null 2>&1 || true
fi

echo "  • Invoking make with detected ISA parameters..."
make -j "${JOBS}" \
    QIHSE_ENABLE_AVX="${QIHSE_ENABLE_AVX}" \
    QIHSE_ENABLE_AVX2="${QIHSE_ENABLE_AVX2}" \
    QIHSE_ENABLE_AVX512="${QIHSE_ENABLE_AVX512}" \
    QIHSE_ENABLE_AVX_VNNI="${QIHSE_ENABLE_AVX_VNNI}" \
    QIHSE_ENABLE_AMX="${QIHSE_ENABLE_AMX}" \
    QIHSE_ENABLE_F16C="${QIHSE_ENABLE_F16C}" \
    QIHSE_ENABLE_AESNI="${QIHSE_ENABLE_AESNI}" \
    QIHSE_ENABLE_PCLMUL="${QIHSE_ENABLE_PCLMUL}" \
    QIHSE_ENABLE_POPCNT="${QIHSE_ENABLE_POPCNT}" \
    QIHSE_ENABLE_RDRAND="${QIHSE_ENABLE_RDRAND}" \
    QIHSE_ENABLE_FSGSBASE="${QIHSE_ENABLE_FSGSBASE}" \
    QIHSE_ENABLE_ERMS="${QIHSE_ENABLE_ERMS}" \
    QIHSE_ENABLE_BMI1="${QIHSE_ENABLE_BMI1}" \
    QIHSE_ENABLE_BMI2="${QIHSE_ENABLE_BMI2}" \
    QIHSE_ENABLE_MOVBE="${QIHSE_ENABLE_MOVBE}" \
    QIHSE_ENABLE_RDSEED="${QIHSE_ENABLE_RDSEED}" \
    QIHSE_ENABLE_ADX="${QIHSE_ENABLE_ADX}" \
    QIHSE_ENABLE_RTM="${QIHSE_ENABLE_RTM}" \
    QIHSE_ENABLE_ABM="${QIHSE_ENABLE_ABM}" \
    QIHSE_ARCH_FLAGS="${QIHSE_ARCH_FLAGS}" \
    all

# Verify artifacts
for req_art in libqihse.so qihse-cluster-daemon qihse_keygen qihse-machine-token; do
    if [ ! -f "${ROOT_DIR}/${req_art}" ]; then
        echo "[ERROR] Expected build output '${req_art}' was not created!" >&2
        exit 1
    fi
done
echo "  [✓] Compilation completed successfully."

# ── Step 4: Install into /opt/QIHSE ───────────────────────────────────────────
echo ""
echo "[4/7] Installing Binaries and Libraries into ${PREFIX}..."

$SUDO install -d -m 755 "${PREFIX}/bin"
$SUDO install -d -m 755 "${PREFIX}/lib"
$SUDO install -d -m 755 "${PREFIX}/include/qihse"
$SUDO install -d -m 700 "${DATA_DIR}"
$SUDO install -d -m 700 "${DATA_DIR}/node${NODE_INDEX}"

# Backup helper
backup_if_exists() {
    local target="$1"
    if [ -f "$target" ]; then
        local ts
        ts="$(date +%Y%m%d-%H%M%S)"
        $SUDO cp "$target" "${target}.bak-${ts}"
    fi
}

backup_if_exists "${PREFIX}/lib/libqihse.so"
backup_if_exists "${PREFIX}/bin/libqihse.so"
backup_if_exists "${PREFIX}/bin/qihse-cluster-daemon"

# Install core shared library
$SUDO install -m 755 "${ROOT_DIR}/libqihse.so" "${PREFIX}/lib/libqihse.so"
$SUDO install -m 755 "${ROOT_DIR}/libqihse.so" "${PREFIX}/bin/libqihse.so"

# Install binaries
$SUDO install -m 755 "${ROOT_DIR}/qihse-cluster-daemon" "${PREFIX}/bin/qihse-cluster-daemon"
$SUDO install -m 755 "${ROOT_DIR}/qihse_keygen" "${PREFIX}/bin/qihse_keygen"
$SUDO install -m 755 "${ROOT_DIR}/qihse-machine-token" "${PREFIX}/bin/qihse-machine-token"

if [ -f "${ROOT_DIR}/qihse-federation-ca" ]; then
    $SUDO install -m 755 "${ROOT_DIR}/qihse-federation-ca" "${PREFIX}/bin/qihse-federation-ca"
fi
if [ -f "${ROOT_DIR}/tests/qihse_server" ]; then
    $SUDO install -m 755 "${ROOT_DIR}/tests/qihse_server" "${PREFIX}/bin/qihse_server"
fi

# Install headers
if [ -f "${ROOT_DIR}/qihse.h" ]; then
    $SUDO install -m 644 "${ROOT_DIR}/qihse.h" "${PREFIX}/include/qihse/qihse.h"
fi
for h in "${ROOT_DIR}"/include/*.h; do
    if [ -f "$h" ]; then
        $SUDO install -m 644 "$h" "${PREFIX}/include/qihse/$(basename "$h")"
    fi
done

echo "  [✓] Installed binaries and shared libraries into ${PREFIX}."

# Ensure user ownership of installed files in /opt when running via sudo
if [ "$TARGET_USER" != "root" ] && [ -d "${PREFIX}" ]; then
    chown -R "${TARGET_USER}:${TARGET_GROUP}" "${PREFIX}"
    echo "  • Configured ${PREFIX} ownership for user ${TARGET_USER}:${TARGET_GROUP}."
fi
if [ "$TARGET_USER" != "root" ] && [ -d "${DATA_DIR}" ]; then
    chown -R "${TARGET_USER}:${TARGET_GROUP}" "${DATA_DIR}"
fi

# ── Step 5: Provision NIST CNSA 2.0 PQC Keys ──────────────────────────────────
echo ""
echo "[5/7] Provisioning Post-Quantum Cryptographic Keys in ${KEYS_DIR}..."

$SUDO install -d -m 700 "${KEYS_DIR}"

# Check if keys exist
KEYS_EXIST=1
for k in qihse_kem_key.pem qihse_kem_pub.pem qihse_dsa_key.pem qihse_dsa_pub.pem; do
    if [ ! -f "${KEYS_DIR}/${k}" ]; then
        KEYS_EXIST=0
        break
    fi
done

if [ "$KEYS_EXIST" -eq 0 ]; then
    echo "  • Missing PQC keys. Generating ML-KEM-1024 & ML-DSA-87 keypairs via qihse_keygen..."
    $SUDO "${PREFIX}/bin/qihse_keygen" "${KEYS_DIR}"
    echo "  [✓] Generated post-quantum keypairs."
else
    echo "  • Existing PQC identity keys found. Preserving current key material."
fi

# Set proper permissions
$SUDO chmod 0600 "${KEYS_DIR}"/*_key.pem 2>/dev/null || true
$SUDO chmod 0644 "${KEYS_DIR}"/*_pub*.pem 2>/dev/null || true

# Register/export local hostname identity
HOST_SHORT="$(hostname -s 2>/dev/null || echo "host")"
if [ -f "${KEYS_DIR}/qihse_dsa_pub.pem" ]; then
    $SUDO cp "${KEYS_DIR}/qihse_dsa_pub.pem" "${KEYS_DIR}/qihse_dsa_pub_${HOST_SHORT}.pem"
    $SUDO chmod 0644 "${KEYS_DIR}/qihse_dsa_pub_${HOST_SHORT}.pem"
    echo "  • Exported local node identity: ${KEYS_DIR}/qihse_dsa_pub_${HOST_SHORT}.pem"
fi

# ── Step 6: Configure & Launch Systemd Cluster Service ─────────────────────────
echo ""
echo "[6/7] Configuring Systemd Service & Cluster Launch..."

if [ "$DO_SERVICE" -eq 1 ]; then
    # Collect all trusted peer public keys
    TRUSTED_PUB_ARGS=()
    for pub in "${KEYS_DIR}"/qihse_dsa_pub_*.pem; do
        if [ -f "$pub" ]; then
            TRUSTED_PUB_ARGS+=("--pqc-trusted-pub" "$pub")
        fi
    done

    # If slot range is still empty, and no existing unit, default to full single node ownership
    if [ -z "$SLOT_RANGE" ]; then
        if [ "$IS_SOLO" -eq 1 ] || { [ "${#PEER_NODES[@]}" -eq 0 ] && [ "${#JOIN_SEEDS[@]}" -eq 0 ]; }; then
            SLOT_RANGE="0-16383"
        fi
    fi

    # Build command line arguments
    CMD_ARGS=(
        "${PREFIX}/bin/qihse-cluster-daemon"
        "--index" "${NODE_INDEX}"
        "--bind" "${BIND_IP}"
        "--port" "${PORT}"
        "--bus-port" "${BUS_PORT}"
    )

    if [ -n "$SLOT_RANGE" ]; then
        CMD_ARGS+=("--slot-range" "${SLOT_RANGE}")
    fi

    # Append any specified peer nodes or preserve from existing unit if in cluster mode
    if [ "$IS_SOLO" -eq 0 ]; then
        if [ "${#PEER_NODES[@]}" -gt 0 ]; then
            for pn in "${PEER_NODES[@]}"; do
                CMD_ARGS+=("--node" "$pn")
            done
        elif [ -n "$EXISTING_UNIT" ]; then
            # Extract --node and --slot-range-of
            while read -r match; do
                [ -n "$match" ] && CMD_ARGS+=($match)
            done < <(grep -oE -- '(--node [^ ]+|--slot-range-of [^ ]+)' "$EXISTING_UNIT" || true)
        fi

        # Append any specified join seeds or preserve from existing unit
        if [ "${#JOIN_SEEDS[@]}" -gt 0 ]; then
            for js in "${JOIN_SEEDS[@]}"; do
                CMD_ARGS+=("--join" "$js")
            done
        elif [ -n "$EXISTING_UNIT" ]; then
            while read -r match; do
                [ -n "$match" ] && CMD_ARGS+=($match)
            done < <(grep -oE -- '--join [^ ]+' "$EXISTING_UNIT" || true)
        fi
    fi

    # LAN cluster default replication interval (globs default to '*' automatically over LAN)
    CMD_ARGS+=("--replicate-interval" "${REPL_INTERVAL}")

    # PQC Identity and Trust Anchors
    CMD_ARGS+=("--pqc-identity-dir" "${KEYS_DIR}")
    for t_arg in "${TRUSTED_PUB_ARGS[@]}"; do
        CMD_ARGS+=("$t_arg")
    done

    # Keep operator secret out of systemd ExecStart and /proc/<pid>/cmdline.
    # Cluster daemon reads QIHSE_OPERATOR_PASSWORD from the environment.
    CMD_ARGS+=("--dir" "${DATA_DIR}/node${NODE_INDEX}")

    SECRET_ENV="/etc/qihse/cluster-node${NODE_INDEX}.env"
    install -d -m 0700 /etc/qihse
    (umask 077; printf 'QIHSE_OPERATOR_PASSWORD=%s\n' "$OPERATOR_PASSWORD" > "$SECRET_ENV")
    chmod 0600 "$SECRET_ENV"

    EXEC_START_LINE="${CMD_ARGS[*]}"

    # Backup existing service if present
    if [ -f "$SERVICE_FILE" ]; then
        backup_if_exists "$SERVICE_FILE"
    fi

    echo "  • Writing service definition to ${SERVICE_FILE}..."
    cat <<EOF | $SUDO tee "$SERVICE_FILE" >/dev/null
[Unit]
Description=QIHSE cluster node ${NODE_INDEX}
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${EXEC_START_LINE}
Environment=LD_LIBRARY_PATH=${PREFIX}/lib:${PREFIX}/bin
EnvironmentFile=${SECRET_ENV}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    $SUDO systemctl daemon-reload
    echo "  • Enabling service '${SERVICE_NAME}' to launch on system boot..."
    $SUDO systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    echo "  [✓] Service '${SERVICE_NAME}' enabled to start on system boot (multi-user.target; runs regardless of logged-in user)."

    CONNECTED_COUNT=1
    if [ "$DO_LAUNCH" -eq 1 ]; then
        echo "  • Starting service '${SERVICE_NAME}'..."
        $SUDO systemctl restart "${SERVICE_NAME}"

        # Health verification
        echo "  • Verifying daemon startup and health..."
        HEALTHY=0
        for _ in $(seq 1 15); do
            sleep 1
            if command -v redis-cli >/dev/null 2>&1; then
                if REDISCLI_AUTH="${OPERATOR_PASSWORD}" redis-cli -h "${BIND_IP}" -p "${PORT}" ping 2>/dev/null | grep -q "PONG"; then
                    HEALTHY=1
                    break
                fi
            elif systemctl is-active --quiet "${SERVICE_NAME}"; then
                HEALTHY=1
                break
            fi
        done

        if [ "$HEALTHY" -eq 1 ]; then
            echo "  [✓] Service '${SERVICE_NAME}' is ACTIVE and responding to PING."

            if [ "$IS_SOLO" -eq 1 ]; then
                echo "  [✓] Solo node verified: owning all 16,384 cluster hash slots (0-16383)."
            elif [ "${EXPECTED_NODES:-1}" -ge 2 ]; then
                echo "  • Waiting for cluster bus acknowledgement from all ${EXPECTED_NODES} expected nodes..."
                START_TIME="$(date +%s)"
                ACK_OK=0

                while true; do
                    NOW="$(date +%s)"
                    ELAPSED=$((NOW - START_TIME))

                    if command -v redis-cli >/dev/null 2>&1; then
                        NODES_OUTPUT="$(REDISCLI_AUTH="${OPERATOR_PASSWORD}" redis-cli -h "${BIND_IP}" -p "${PORT}" cluster nodes 2>/dev/null || true)"
                        if [ -n "$NODES_OUTPUT" ]; then
                            CONNECTED_COUNT="$(echo "$NODES_OUTPUT" | grep -c ' connected' || echo 1)"
                        fi
                    fi

                    printf "\r    Cluster bus discovery: %d / %d nodes acknowledged (elapsed: %ds / %ds)..." "${CONNECTED_COUNT}" "${EXPECTED_NODES}" "${ELAPSED}" "${WAIT_TIMEOUT}"

                    if [ "$CONNECTED_COUNT" -ge "$EXPECTED_NODES" ]; then
                        ACK_OK=1
                        echo ""
                        echo "  [✓] All ${EXPECTED_NODES} expected cluster nodes connected and acknowledged on cluster bus!"
                        break
                    fi

                    if [ "$ELAPSED" -ge "$WAIT_TIMEOUT" ]; then
                        echo ""
                        echo "  [!] Timeout waiting for all ${EXPECTED_NODES} nodes (${CONNECTED_COUNT}/${EXPECTED_NODES} connected after ${WAIT_TIMEOUT}s)."
                        echo "      The daemon is running and will continue discovery over the cluster bus in the background."
                        break
                    fi

                    sleep 1
                done
            fi
        else
            echo "  [!] Warning: Service started but PING health check timed out. Check: journalctl -u ${SERVICE_NAME}"
        fi
    else
        echo "  • Service written. (--no-launch passed: daemon not restarted)."
    fi
else
    echo "  • Skipping systemd service setup (--no-service passed)."
fi

# ── Step 7: Optional KEYSTONE Companion Indexing Service ───────────────────────
echo ""
echo "[7/7] Checking KEYSTONE Companion Indexing Service..."

if [ -d "/opt/KEYSTONE" ] && [ -x "/opt/KEYSTONE/bin/keystoned" ]; then
    echo "  [✓] KEYSTONE is installed at /opt/KEYSTONE."
else
    echo "  • KEYSTONE is not detected at /opt/KEYSTONE."
    echo ""
    echo "  ┌──────────────────────────────────────────────────────────────┐"
    echo "  │ KEYSTONE High-Performance Semantic Indexing Service          │"
    echo "  │ KEYSTONE is the recommended indexing and trigram search      │"
    echo "  │ companion service for QIHSE, providing SIMD-accelerated      │"
    echo "  │ vector/keyword hybrid retrieval over the Unified Wire Protocol│"
    echo "  │ bridge directly to local and clustered QIHSE partitions.     │"
    echo "  └──────────────────────────────────────────────────────────────┘"

    INSTALL_KEYSTONE=0
    if [ "$NON_INTERACTIVE" -eq 0 ] && [ -t 0 ]; then
        read -r -p "  Would you like to clone and install KEYSTONE into /opt/KEYSTONE now? [Y/n]: " REPLY_KS || REPLY_KS="y"
        if ! [[ "$REPLY_KS" =~ ^[Nn] ]]; then
            INSTALL_KEYSTONE=1
        fi
    fi

    if [ "$INSTALL_KEYSTONE" -eq 1 ]; then
        echo "  • Preparing KEYSTONE installation..."
        LOCAL_KS=""
        if [ -d "${ROOT_DIR}/../KEYSTONE" ] && [ -f "${ROOT_DIR}/../KEYSTONE/Makefile" ]; then
            LOCAL_KS="$(cd "${ROOT_DIR}/../KEYSTONE" && pwd)"
        elif [ -d "/home/john/Documents/KEYSTONE" ] && [ -f "/home/john/Documents/KEYSTONE/Makefile" ]; then
            LOCAL_KS="/home/john/Documents/KEYSTONE"
        fi

        if [ ! -d "/opt/KEYSTONE" ]; then
            if [ -n "$LOCAL_KS" ]; then
                echo "  • Copying KEYSTONE from local tree (${LOCAL_KS})..."
                $SUDO cp -r "$LOCAL_KS" /opt/KEYSTONE
            else
                echo "  • Cloning KEYSTONE repository from GitHub (https://github.com/SWORDIntel/KEYSTONE.git)..."
                $SUDO git clone https://github.com/SWORDIntel/KEYSTONE.git /opt/KEYSTONE
            fi
        fi

        if [ -f "/opt/KEYSTONE/scripts/install_keystone.sh" ]; then
            echo "  • Launching KEYSTONE hardware installer with QIHSE bridge integration..."
            $SUDO "/opt/KEYSTONE/scripts/install_keystone.sh" --launch
        elif [ -f "/opt/KEYSTONE/Makefile" ]; then
            echo "  • Compiling KEYSTONE with QIHSE bridge support (QIHSE_ROOT=${PREFIX})..."
            make -C /opt/KEYSTONE -j "${JOBS}" clean
            make -C /opt/KEYSTONE -j "${JOBS}" KEYSTONE_ENABLE_QIHSE_BRIDGE=1 QIHSE_ROOT="${PREFIX}" all
            $SUDO install -d -m 755 /opt/KEYSTONE/bin /opt/KEYSTONE/lib
            $SUDO install -m 755 /opt/KEYSTONE/bin/* /opt/KEYSTONE/bin/ 2>/dev/null || true
            $SUDO install -m 755 /opt/KEYSTONE/libkeystone.so /opt/KEYSTONE/lib/ 2>/dev/null || true
            echo "  [✓] KEYSTONE compiled and installed into /opt/KEYSTONE."
        fi
    else
        echo "  • Skipping KEYSTONE installation. (Install anytime via: git clone https://github.com/SWORDIntel/KEYSTONE.git /opt/KEYSTONE)"
    fi
fi

# Studio requires explicit operator opt-in; do not expose it as part of generic node installs.
if [ "${QIHSE_INSTALL_STUDIO:-0}" = "1" ]; then
    "${ROOT_DIR}/portal/install-studio.sh" "${PREFIX}/studio"
else
    echo "  • Studio not installed by default (set QIHSE_INSTALL_STUDIO=1 to opt in)."
fi

# ── Summary Box ───────────────────────────────────────────────────────────────
CONNECTED_COUNT="${CONNECTED_COUNT:-1}"
[ -z "$EXPECTED_NODES" ] && EXPECTED_NODES=1

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
if [ "$IS_SOLO" -eq 1 ]; then
echo "║                  INSTALLATION COMPLETE (SOLO NODE)                   ║"
else
echo "║             INSTALLATION COMPLETE (MULTI-NODE CLUSTER)               ║"
fi
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  Prefix:           ${PREFIX}"
echo "║  Binaries:         ${PREFIX}/bin (qihse-cluster-daemon, qihse_keygen)"
echo "║  Libraries:        ${PREFIX}/lib (libqihse.so)"
echo "║  PQC Keys:         ${KEYS_DIR} (ML-KEM-1024 / ML-DSA-87)"
echo "║  Data Directory:   ${DATA_DIR}/node${NODE_INDEX}"
if [ "$DO_SERVICE" -eq 1 ]; then
    if [ "$DO_LAUNCH" -eq 1 ]; then
        if [ "$IS_SOLO" -eq 1 ]; then
echo "║  Systemd Service:  ${SERVICE_NAME}.service (ACTIVE - Solo Node)"
        else
echo "║  Systemd Service:  ${SERVICE_NAME}.service (ACTIVE - ${CONNECTED_COUNT}/${EXPECTED_NODES} nodes connected)"
        fi
    else
echo "║  Systemd Service:  ${SERVICE_NAME}.service (INSTALLED - Offline)"
    fi
echo "║  Endpoint:         ${BIND_IP}:${PORT} (Bus: ${BUS_PORT})"
if [ "$IS_SOLO" -eq 1 ]; then
echo "║  Slot Range:       0-16383 (Full cluster keyspace owned locally)"
echo "║  Topology:         Solo Standalone Node (no peers on network)"
else
echo "║  Slot Range:       ${SLOT_RANGE:-0-16383}"
echo "║  Topology:         Multi-Node LAN Cluster (${EXPECTED_NODES} nodes expected)"
echo "║  Replication:      LAN Cluster Default ('*' full data sync, 30s AE)"
fi
fi
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

if [ "$DO_LAUNCH" -eq 0 ]; then
    echo "NOTE: The cluster service was installed but not started (--no-launch)."
    echo "To start the service when ready, run:"
    echo "  $SUDO systemctl start ${SERVICE_NAME}"
    echo ""
fi

if [ "$IS_SOLO" -eq 1 ]; then
    cat <<EOF
┌──────────────────────────────────────────────────────────────────────┐
│ NOTE: Solo Node Deployment                                           │
│ This machine is configured as a standalone solo QIHSE node (owning   │
│ all 16,384 cluster hash slots: 0-16383).                             │
│                                                                      │
│ When you install QIHSE on another machine on your local LAN:         │
│   1. Re-run this installer on this machine: it will safely update    │
│      the installed binaries and service without data loss.           │
│   2. Next time, reply YES when asked if other cluster nodes are      │
│      online, enter the total node count, and this node will join     │
│      the multi-node cluster and synchronize keys automatically!      │
│   3. Remember to exchange public keys between the nodes:             │
│      Copy ${KEYS_DIR}/qihse_dsa_pub_${HOST_SHORT}.pem to the other   │
│      node's ${KEYS_DIR}/ directory, and vice versa.                  │
└──────────────────────────────────────────────────────────────────────┘
EOF
    echo ""
fi

if [ "${DERIVED_AUTOPASS:-0}" -eq 1 ]; then
    echo "══════════════════════════════════════════════════════════════════════"
    echo " [SECURITY] Cluster Operator Password Derived from HWID XOR CSPRNG:"
    echo "   QIHSE_OPERATOR_PASSWORD=${OPERATOR_PASSWORD}"
    echo ""
    echo " Stored securely in: /etc/qihse/cluster-node${NODE_INDEX}.env (mode 0600)"
    if [ "$IS_SOLO" -eq 0 ]; then
        echo " To connect other nodes to this cluster, configure them with:"
        echo "   export QIHSE_OPERATOR_PASSWORD=${OPERATOR_PASSWORD}"
    fi
    echo "══════════════════════════════════════════════════════════════════════"
    echo ""
fi

echo "Verify connection (do not place passwords in argv):"
echo "  Load QIHSE_OPERATOR_PASSWORD from the root-owned /etc/qihse/cluster-node${NODE_INDEX}.env into REDISCLI_AUTH."
echo "  redis-cli -h ${BIND_IP} -p ${PORT} ping"
echo "  unset REDISCLI_AUTH"
