# Build one x86-64 baseline QIHSE mesh pair for nodes with different CPUs.
# Invoke from an isolated source checkout after the source has been frozen.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: bash scripts/build_portable_cluster_runtime.sh OUTPUT_DIR [REFERENCE_LIB]

OUTPUT_DIR receives libqihse.so, qihse-cluster-daemon, and build metadata.
REFERENCE_LIB, when supplied, must be the currently deployed libqihse.so;
the build stops if any of its exported dynamic symbols disappear.
EOF
}

if (( $# < 1 || $# > 2 )); then
    usage >&2
    exit 2
fi

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
output_dir="$1"
reference_lib="${2:-}"
mkdir -p -- "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"

if [[ "$output_dir" == "$source_dir" || "$output_dir" == "$source_dir/"* ]]; then
    echo "Output directory must be outside the source tree." >&2
    exit 2
fi
for command_name in make git sha256sum readelf nm awk sort comm cp; do
    command -v "$command_name" >/dev/null || {
        echo "Missing required command: $command_name" >&2
        exit 2
    }
done

source_commit="$(git -C "$source_dir" rev-parse HEAD)"
source_status="$(git -C "$source_dir" status --porcelain --untracked-files=normal)"
if [[ -n "$source_status" && "${QIHSE_ALLOW_DIRTY_SOURCE:-0}" != "1" ]]; then
    echo "Source has uncommitted changes. Freeze it first, or set QIHSE_ALLOW_DIRTY_SOURCE=1 for an explicitly dirty candidate." >&2
    exit 2
fi
if [[ -n "$reference_lib" && ! -f "$reference_lib" ]]; then
    echo "Reference library does not exist: $reference_lib" >&2
    exit 2
fi

jobs="${QIHSE_BUILD_JOBS:-4}"
if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]]; then
    echo "QIHSE_BUILD_JOBS must be a positive integer." >&2
    exit 2
fi

# -B is intentional: object files built with a different ISA cannot be reused
# merely because their source timestamps did not change.
make -B -C "$source_dir" -j "$jobs" \
    QIHSE_ARCH_FLAGS="-march=x86-64 -mtune=generic" \
    QIHSE_ENABLE_AVX2=0 \
    QIHSE_ENABLE_AVX512=0 \
    QIHSE_ENABLE_AVX_VNNI=0 \
    QIHSE_ENABLE_AMX=0 \
    cluster-daemon

library="$source_dir/libqihse.so"
daemon="$source_dir/qihse-cluster-daemon"
if [[ ! -s "$library" || ! -s "$daemon" ]]; then
    echo "Build did not produce both native artifacts." >&2
    exit 1
fi

if [[ -n "$reference_lib" ]]; then
    ref_symbols="$(mktemp)"
    new_symbols="$(mktemp)"
    missing_symbols="$(mktemp)"
    trap 'rm -f -- "$ref_symbols" "$new_symbols" "$missing_symbols"' EXIT
    nm -D --defined-only "$reference_lib" | awk 'NF >= 3 {print $3}' | sort -u > "$ref_symbols"
    nm -D --defined-only "$library" | awk 'NF >= 3 {print $3}' | sort -u > "$new_symbols"
    comm -23 "$ref_symbols" "$new_symbols" > "$missing_symbols"
    if [[ -s "$missing_symbols" ]]; then
        echo "The candidate removes exported symbols from the reference library:" >&2
        cat "$missing_symbols" >&2
        exit 1
    fi
fi

cp -- "$library" "$output_dir/libqihse.so"
cp -- "$daemon" "$output_dir/qihse-cluster-daemon"
chmod 0644 "$output_dir/libqihse.so"
chmod 0755 "$output_dir/qihse-cluster-daemon"
{
    printf 'source_commit=%s\n' "$source_commit"
    if [[ -n "$source_status" ]]; then
        printf 'source_dirty=1\n'
    else
        printf 'source_dirty=0\n'
    fi
    printf 'arch_flags=%s\n' '-march=x86-64 -mtune=generic'
    printf 'avx2=0\navx512=0\navx_vnni=0\namx=0\n'
    printf 'compiler_c=%s\n' "$(gcc --version | head -1)"
    printf 'compiler_cxx=%s\n' "$(g++ --version | head -1)"
    if [[ -n "$reference_lib" ]]; then
        printf 'reference_lib_sha256=%s\n' "$(sha256sum "$reference_lib" | awk '{print $1}')"
    fi
    sha256sum "$output_dir/libqihse.so" "$output_dir/qihse-cluster-daemon"
} > "$output_dir/build-manifest.txt"
readelf -d "$output_dir/libqihse.so" > "$output_dir/libqihse-dynamic.txt"
readelf --version-info "$output_dir/libqihse.so" > "$output_dir/libqihse-versions.txt"
readelf -d "$output_dir/qihse-cluster-daemon" > "$output_dir/daemon-dynamic.txt"
readelf --version-info "$output_dir/qihse-cluster-daemon" > "$output_dir/daemon-versions.txt"
echo "Portable native pair built in $output_dir"
