#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
prefix="$root/.qihse-pqc"

cmake -S "$root/vendor/liboqs" -B "$root/vendor/liboqs/build" -GNinja \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=ON
cmake --build "$root/vendor/liboqs/build" --parallel 4
cmake --install "$root/vendor/liboqs/build"

cmake -S "$root/vendor/oqs-provider" -B "$root/vendor/oqs-provider/build" -GNinja \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_INSTALL_RPATH="$prefix/lib" \
    -DOPENSSL_MODULES_PATH="$prefix/lib/ossl-modules" \
    -Dliboqs_DIR="$prefix/lib/cmake/liboqs"
cmake --build "$root/vendor/oqs-provider/build" --parallel 4
cmake --install "$root/vendor/oqs-provider/build"

OPENSSL_MODULES="$prefix/lib/ossl-modules" \
LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    openssl list -providers -provider oqsprovider >/dev/null
