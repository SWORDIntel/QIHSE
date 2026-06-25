#!/usr/bin/env bash
# scripts/qihse_keygen.sh — Generate QIHSE CNSA 2.0 key pairs
#
# Produces:
#   qihse_kem_key.pem / qihse_kem_pub.pem  — ML-KEM-1024  (FIPS 203)
#   qihse_dsa_key.pem / qihse_dsa_pub.pem  — ML-DSA-87    (FIPS 204)
#
# Requires: OpenSSL 3.5+
# Usage:    bash scripts/qihse_keygen.sh [--output-dir /path/to/dir]

set -euo pipefail

# ── Argument parsing ──────────────────────────────────────────────────────
OUTPUT_DIR="."
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--output-dir /path/to/dir]" >&2
            exit 1
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

# ── Version check ─────────────────────────────────────────────────────────
OPENSSL_VER=$(openssl version | awk '{print $2}')
MAJOR=$(echo "$OPENSSL_VER" | cut -d. -f1)
MINOR=$(echo "$OPENSSL_VER" | cut -d. -f2)

if [[ "$MAJOR" -lt 3 ]] || { [[ "$MAJOR" -eq 3 ]] && [[ "$MINOR" -lt 5 ]]; }; then
    echo "[ERROR] OpenSSL 3.5+ required for ML-KEM-1024 and ML-DSA-87." >&2
    echo "        Detected: OpenSSL $OPENSSL_VER" >&2
    exit 1
fi

echo "[QIHSE keygen] OpenSSL $OPENSSL_VER — OK"

# ── FIPS provider detection ───────────────────────────────────────────────
FIPS_ACTIVE=false
if openssl list -providers 2>/dev/null | grep -q "fips"; then
    FIPS_ACTIVE=true
    echo "[QIHSE keygen] FIPS 140-3 validated provider: ACTIVE"
else
    echo "[QIHSE keygen] FIPS provider: not installed (standard provider in use)"
    echo "               Install openssl-provider-fips for FIPS 140-3 validated key generation."
fi

echo "[QIHSE keygen] Output directory: $OUTPUT_DIR"
echo ""

# ── ML-KEM-1024 (FIPS 203) ───────────────────────────────────────────────
echo "[1/4] Generating ML-KEM-1024 private key..."
openssl genpkey -algorithm ML-KEM-1024 \
    -out "$OUTPUT_DIR/qihse_kem_key.pem" 2>/dev/null
chmod 600 "$OUTPUT_DIR/qihse_kem_key.pem"
echo "      Written: $OUTPUT_DIR/qihse_kem_key.pem"

echo "[2/4] Deriving ML-KEM-1024 public key..."
openssl pkey -in "$OUTPUT_DIR/qihse_kem_key.pem" \
    -pubout -out "$OUTPUT_DIR/qihse_kem_pub.pem" 2>/dev/null
echo "      Written: $OUTPUT_DIR/qihse_kem_pub.pem"

# ── ML-DSA-87 (FIPS 204) ─────────────────────────────────────────────────
echo "[3/4] Generating ML-DSA-87 private key..."
openssl genpkey -algorithm ML-DSA-87 \
    -out "$OUTPUT_DIR/qihse_dsa_key.pem" 2>/dev/null
chmod 600 "$OUTPUT_DIR/qihse_dsa_key.pem"
echo "      Written: $OUTPUT_DIR/qihse_dsa_key.pem"

echo "[4/4] Deriving ML-DSA-87 public key..."
openssl pkey -in "$OUTPUT_DIR/qihse_dsa_key.pem" \
    -pubout -out "$OUTPUT_DIR/qihse_dsa_pub.pem" 2>/dev/null
echo "      Written: $OUTPUT_DIR/qihse_dsa_pub.pem"

# ── Verify round-trip ─────────────────────────────────────────────────────
echo ""
echo "[QIHSE keygen] Verifying ML-KEM-1024 round-trip..."
TEST_CT=$(mktemp)
TEST_SS_ENC=$(mktemp)
TEST_SS_DEC=$(mktemp)

# Encapsulate
openssl pkeyutl -encap \
    -inkey "$OUTPUT_DIR/qihse_kem_pub.pem" -pubin \
    -out "$TEST_CT" -secret "$TEST_SS_ENC" 2>/dev/null

# Decapsulate
openssl pkeyutl -decap \
    -inkey "$OUTPUT_DIR/qihse_kem_key.pem" \
    -in "$TEST_CT" -out "$TEST_SS_DEC" 2>/dev/null

if cmp -s "$TEST_SS_ENC" "$TEST_SS_DEC"; then
    echo "              ML-KEM-1024 round-trip: PASS"
else
    echo "[ERROR] ML-KEM-1024 round-trip FAILED — shared secrets do not match." >&2
    rm -f "$TEST_CT" "$TEST_SS_ENC" "$TEST_SS_DEC"
    exit 1
fi
rm -f "$TEST_CT" "$TEST_SS_ENC" "$TEST_SS_DEC"

echo "[QIHSE keygen] Verifying ML-DSA-87 round-trip..."
TEST_DATA=$(mktemp)
TEST_SIG=$(mktemp)
echo "qihse-cnsa-2.0-selftest" > "$TEST_DATA"

openssl dgst -sign "$OUTPUT_DIR/qihse_dsa_key.pem" \
    -out "$TEST_SIG" "$TEST_DATA" 2>/dev/null

if openssl dgst -verify "$OUTPUT_DIR/qihse_dsa_pub.pem" \
    -signature "$TEST_SIG" "$TEST_DATA" 2>/dev/null | grep -q "Verified OK"; then
    echo "              ML-DSA-87 round-trip: PASS"
else
    echo "[ERROR] ML-DSA-87 round-trip FAILED." >&2
    rm -f "$TEST_DATA" "$TEST_SIG"
    exit 1
fi
rm -f "$TEST_DATA" "$TEST_SIG"

echo ""
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  QIHSE CNSA 2.0 Key Generation Complete                     │"
echo "│                                                              │"
echo "│  Algorithm         File                  Keep private?       │"
echo "│  ─────────────     ──────────────────    ────────────        │"
echo "│  ML-KEM-1024 priv  qihse_kem_key.pem     YES (chmod 600)    │"
echo "│  ML-KEM-1024 pub   qihse_kem_pub.pem      distribute freely  │"
echo "│  ML-DSA-87 priv    qihse_dsa_key.pem      YES (chmod 600)    │"
echo "│  ML-DSA-87 pub     qihse_dsa_pub.pem      distribute freely  │"
echo "│                                                              │"
echo "│  Both key pairs verified with round-trip tests.              │"
if [[ "$FIPS_ACTIVE" == "true" ]]; then
echo "│  ✓ Keys generated via FIPS 140-3 validated module.           │"
else
echo "│  ⚠ FIPS module not active — standard provider used.          │"
fi
echo "└──────────────────────────────────────────────────────────────┘"
