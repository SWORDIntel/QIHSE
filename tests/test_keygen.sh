#!/usr/bin/env bash
# tests/test_keygen.sh — QIHSE C keygen integration tests
#
# Tests:
#   1. Keygen without --bind-operator generates KEM + DSA keys
#   2. Keygen with --bind-operator also generates operator_password.key
#   3. operator_password.key is 32 bytes and chmod 600
#   4. KEM round-trip passes (encap/decap shared secrets match)
#   5. DSA round-trip passes (sign/verify)
#   6. Keygen box output is 64 chars wide (all lines aligned)
#   7. Keygen with no args uses QIHSE_KEYS_DIR env var
#
# Run: bash tests/test_keygen.sh
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYGEN="$ROOT/qihse_keygen"
TEST_DIR="$ROOT/.test_keygen_$$"
TESTS_RUN=0
TESTS_PASSED=0

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

pass() {
    echo "  [TEST] $1 ... PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo "  [TEST] $1 ... FAIL: $2"
    exit 1
}

assert_exists() {
    local file="$1"
    local name="$2"
    if [[ -f "$file" ]]; then
        pass "$name exists"
    else
        fail "$name exists" "file not found: $file"
    fi
}

assert_size() {
    local file="$1"
    local expected="$2"
    local name="$3"
    local actual
    actual=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    if [[ "$actual" == "$expected" ]]; then
        pass "$name size is $expected bytes"
    else
        fail "$name size" "expected $expected, got $actual"
    fi
}

assert_perms() {
    local file="$1"
    local expected="$2"
    local name="$3"
    local actual
    actual=$(stat -c%a "$file" 2>/dev/null || stat -f%Lp "$file" 2>/dev/null)
    if [[ "$actual" == "$expected" ]]; then
        pass "$name permissions are $expected"
    else
        fail "$name permissions" "expected $expected, got $actual"
    fi
}

echo "======================================"
echo "  QIHSE C Keygen Integration Tests    "
echo "======================================"
echo ""

# Build keygen if needed
if [[ ! -x "$KEYGEN" ]]; then
    echo "Building keygen..."
    (cd "$ROOT" && make keygen) >/dev/null 2>&1
fi

mkdir -p "$TEST_DIR"

# --- Test 1: Keygen without --bind-operator ---
echo "  [SUITE] Keygen without --bind-operator"
TESTS_RUN=$((TESTS_RUN + 1))
"$KEYGEN" "$TEST_DIR/basic" >/dev/null 2>&1
assert_exists "$TEST_DIR/basic/qihse_kem_key.pem" "KEM private key"
assert_exists "$TEST_DIR/basic/qihse_kem_pub.pem" "KEM public key"
assert_exists "$TEST_DIR/basic/qihse_dsa_key.pem" "DSA private key"
assert_exists "$TEST_DIR/basic/qihse_dsa_pub.pem" "DSA public key"
if [[ ! -f "$HOME/.ssh/qihse_operator_key" ]]; then
    pass "No operator key in ~/.ssh without --bind-operator"
else
    fail "No operator key without --bind-operator" "file should not exist"
    rm -f "$HOME/.ssh/qihse_operator_key"
fi

# --- Test 2: Keygen with --bind-operator ---
echo ""
echo "  [SUITE] Keygen with --bind-operator"
TESTS_RUN=$((TESTS_RUN + 1))
"$KEYGEN" "$TEST_DIR/bind" --bind-operator >/dev/null 2>&1
assert_exists "$TEST_DIR/bind/qihse_kem_key.pem" "KEM private key"
assert_exists "$TEST_DIR/bind/qihse_dsa_key.pem" "DSA private key"
assert_exists "$HOME/.ssh/qihse_operator_key" "Operator key in ~/.ssh"
assert_size "$HOME/.ssh/qihse_operator_key" "32" "Operator key"
assert_perms "$HOME/.ssh/qihse_operator_key" "600" "Operator key"
# Verify .ssh dir is 700
SSH_PERMS=$(stat -c%a "$HOME/.ssh" 2>/dev/null || stat -f%Lp "$HOME/.ssh" 2>/dev/null)
if [[ "${SSH_PERMS:0:3}" == "700" ]]; then
    pass ".ssh directory permissions are 700"
else
    fail ".ssh permissions" "expected 700, got $SSH_PERMS"
fi
# Clean up test key
rm -f "$HOME/.ssh/qihse_operator_key" "$HOME/.ssh/qihse_operator_key.sig"

# --- Test 3: KEM round-trip ---
echo ""
echo "  [SUITE] KEM round-trip"
TESTS_RUN=$((TESTS_RUN + 1))
CT="$TEST_DIR/kem_ct.bin"
SS_ENC="$TEST_DIR/kem_ss_enc.bin"
SS_DEC="$TEST_DIR/kem_ss_dec.bin"
openssl pkeyutl -encap \
    -inkey "$TEST_DIR/bind/qihse_kem_pub.pem" -pubin \
    -out "$CT" -secret "$SS_ENC" 2>/dev/null || true
openssl pkeyutl -decap \
    -inkey "$TEST_DIR/bind/qihse_kem_key.pem" \
    -in "$CT" -out "$SS_DEC" 2>/dev/null || true
if cmp -s "$SS_ENC" "$SS_DEC"; then
    pass "KEM shared secret round-trip"
else
    fail "KEM round-trip" "shared secrets don't match"
fi

# --- Test 4: DSA round-trip ---
echo ""
echo "  [SUITE] DSA round-trip"
TESTS_RUN=$((TESTS_RUN + 1))
DATA="$TEST_DIR/dsa_data.txt"
SIG="$TEST_DIR/dsa_sig.bin"
echo "qihse-test-verification" > "$DATA"
openssl dgst -sign "$TEST_DIR/bind/qihse_dsa_key.pem" \
    -out "$SIG" "$DATA" 2>/dev/null
if openssl dgst -verify "$TEST_DIR/bind/qihse_dsa_pub.pem" \
    -signature "$SIG" "$DATA" 2>/dev/null | grep -q "Verified OK"; then
    pass "DSA signature verification"
else
    fail "DSA round-trip" "signature verification failed"
fi

# --- Test 5: Box alignment (all lines 64 chars) ---
echo ""
echo "  [SUITE] Box alignment"
TESTS_RUN=$((TESTS_RUN + 1))
OUTPUT=$("$KEYGEN" "$TEST_DIR/align" --bind-operator 2>&1)
MISALIGNED=0
while IFS= read -r line; do
    if echo "$line" | grep -q '│'; then
        len=$(printf '%s' "$line" | python3 -c "import sys; print(len(sys.stdin.readline().rstrip()))")
        if [[ "$len" != "64" ]]; then
            echo "    MISALIGNED ($len): $line"
            MISALIGNED=$((MISALIGNED + 1))
        fi
    fi
done <<< "$OUTPUT"
if [[ "$MISALIGNED" == "0" ]]; then
    pass "All box lines are 64 chars"
else
    fail "Box alignment" "$MISALIGNED lines misaligned"
fi

# --- Test 6: QIHSE_KEYS_DIR env var ---
echo ""
echo "  [SUITE] QIHSE_KEYS_DIR env var"
TESTS_RUN=$((TESTS_RUN + 1))
export QIHSE_KEYS_DIR="$TEST_DIR/envdir"
"$KEYGEN" >/dev/null 2>&1
assert_exists "$TEST_DIR/envdir/qihse_kem_key.pem" "KEM key via env var"
unset QIHSE_KEYS_DIR

# --- Summary ---
echo ""
echo "======================================"
echo "  $TESTS_PASSED/$TESTS_RUN suites passed"
echo "======================================"
