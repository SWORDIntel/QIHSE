#!/bin/sh
# build_dex.sh -- rebuild tests/fixtures/dex/classes.dex from the synthetic
# Java sources next to this script.
#
# The fixture is the detector contract: 4 bug classes + 2 negative controls
# (com.kp14.synthetic.crypto.GoodCrypto uses SecureRandom ONLY and must stay
# clean; DerivedKeyCrypto.fromString builds SecretKeySpec from runtime string
# bytes and must stay clean; DerivedKeyCrypto.derivedKey mixes a constant
# into key material and is allowed to fire at confidence LOW "proximity
# heuristic" only).
#
# Toolchain (present on the VM host):
#   javac --release 8   (d8-era dexers reject newer class-file versions)
#   d8                  (/home/debian/android-sdk/build-tools/d8.jar, invoked
#                        via java -cp <jar> com.android.tools.r8.D8)
# A prebuilt classes.dex is committed; rerun this only when the sources
# change, then re-record expectations in test_dalvik_bug_patterns.py.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

javac --release 8 -d "$OUT/classes" "$HERE"/java/com/kp14/synthetic/*/*.java

# Locate a d8 jar dynamically (env override, then common SDK locations).
# No hardcoded host paths: D8_JAR env > $ANDROID_HOME > $HOME SDK > any
# /home/*/android-sdk found on the host.
D8_JAR="${D8_JAR:-}"
if [ -z "$D8_JAR" ]; then
    for cand in \
        "${ANDROID_HOME:-/nonexistent}/build-tools/d8.jar" \
        "$HOME/android-sdk/build-tools/d8.jar" \
        /home/*/android-sdk/build-tools/d8.jar; do
        if [ -f "$cand" ]; then D8_JAR="$cand"; break; fi
    done
fi
if [ -z "$D8_JAR" ]; then
    echo "error: no d8.jar found (set D8_JAR=/path/to/d8.jar)" >&2
    exit 1
fi
echo "using d8: $D8_JAR"
# shellcheck disable=SC2046
java -cp "$D8_JAR" com.android.tools.r8.D8 --release \
    --output "$OUT" $(find "$OUT/classes" -name '*.class')

cp "$OUT/classes.dex" "$HERE/classes.dex"
echo "rebuilt: $HERE/classes.dex ($(wc -c < "$HERE/classes.dex") bytes)"
