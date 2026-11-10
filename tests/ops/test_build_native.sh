#!/usr/bin/env bash
# Verify build-native's make invocations without compiling or installing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

cat > "$TMP/bin/make" <<'MOCK'
#!/usr/bin/env bash
printf '%s\t%s\n' "$PWD" "$*" >> "$MOCK_MAKE_LOG"
MOCK
for tool in cmake ninja; do
    cat > "$TMP/bin/$tool" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
    chmod +x "$TMP/bin/$tool"
done
chmod +x "$TMP/bin/make"
export MOCK_MAKE_LOG="$TMP/make.log"
export QIHSE_BUILD_FLAGS_FILE="$TMP/no-config"

# Run from outside the checkout. The clean target must use ROOT_DIR, and the
# subsequent build must force make to discard potentially incompatible objects.
(cd "$TMP" && PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/build-native.sh" --none --clean)

[ "$(wc -l < "$MOCK_MAKE_LOG")" -eq 2 ] || {
    echo 'expected exactly clean and build make invocations' >&2
    exit 1
}
rg -q "^[^[:space:]]+\t-C $ROOT clean$" "$MOCK_MAKE_LOG" || {
    echo 'clean did not run against the script root' >&2
    cat "$MOCK_MAKE_LOG" >&2
    exit 1
}
rg -q "^$ROOT[[:space:]]+-B -j[0-9]+ all .*QIHSE_ENABLE_AVX=0" "$MOCK_MAKE_LOG" || {
    echo 'build did not force a rebuild from the script root' >&2
    cat "$MOCK_MAKE_LOG" >&2
    exit 1
}
if rg -q ' install([[:space:]]|$)' "$MOCK_MAKE_LOG"; then
    echo 'build-native unexpectedly invoked install' >&2
    exit 1
fi
printf 'build-native mock checks passed\n'
