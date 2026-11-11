#!/usr/bin/env bash
# Install the pinned Code Review Graph producer and QIHSE's native consumer.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 PREFIX" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PREFIX="$1"
SOURCE="${ROOT_DIR}/vendor/code-review-graph"

if [ ! -f "${SOURCE}/pyproject.toml" ]; then
    echo "Code Review Graph submodule is missing; run git submodule update --init vendor/code-review-graph" >&2
    exit 1
fi
if [ ! -x "${ROOT_DIR}/qihse-codegraph" ] || [ ! -f "${ROOT_DIR}/libqihse.so" ]; then
    echo "Build the native CodeGraph first: make qihse-codegraph" >&2
    exit 1
fi
if [ ! -f "${PREFIX}/lib/libqihse.so" ]; then
    echo "Install libqihse.so into the selected prefix before installing CodeGraph" >&2
    exit 1
fi
if [ ! -f "${ROOT_DIR}/tools/codegraph_xxh3/build/libqihse_xxh3.so" ]; then
    echo "Build the CodeGraph XXH3 library first: make codegraph-xxh3" >&2
    exit 1
fi

# A checkout with the wrong producer revision must not be installed by accident.
EXPECTED="$(git -C "${ROOT_DIR}" rev-parse HEAD:vendor/code-review-graph)"
ACTUAL="$(git -C "${SOURCE}" rev-parse HEAD)"
if [ "${EXPECTED}" != "${ACTUAL}" ]; then
    echo "Code Review Graph submodule is not at the QIHSE-pinned revision" >&2
    exit 1
fi

install -d -m 755 "${PREFIX}" "${PREFIX}/bin" "${PREFIX}/tools" "${PREFIX}/libexec"
install -m 755 "${ROOT_DIR}/tools/codegraph_xxh3/build/libqihse_xxh3.so" "${PREFIX}/lib/libqihse_xxh3.so"
ENV_NAME="code-review-graph-${EXPECTED:0:12}"
ENV_DIR="${PREFIX}/libexec/${ENV_NAME}"
if [ ! -x "${ENV_DIR}/bin/python" ]; then
    python3 -m venv "${ENV_DIR}"
fi
# Retry an interrupted install into the same pinned environment.
if command -v uv >/dev/null 2>&1; then
    uv pip install --link-mode=copy --python "${ENV_DIR}/bin/python" "${SOURCE}"
else
    "${ENV_DIR}/bin/python" -m pip install --disable-pip-version-check "${SOURCE}"
fi

QIHSE_CODEGRAPH_XXH3_LIBRARY="${PREFIX}/lib/libqihse_xxh3.so" \
"${ENV_DIR}/bin/python" -c '
import inspect
import igraph
from code_review_graph.communities import IGRAPH_AVAILABLE
from code_review_graph.exports import export_qihse
from code_review_graph.graph import GraphStore
from code_review_graph.incremental import assert_graph_serves_root, get_db_path
from code_review_graph.tools.build import build_or_update_graph, build_was_interrupted
from code_review_graph.qihse_xxh3 import hash_one
assert IGRAPH_AVAILABLE and GraphStore and assert_graph_serves_root and get_db_path and build_was_interrupted
assert "source_identity_provider" in inspect.signature(export_qihse).parameters
assert "exact_dependencies" in inspect.signature(build_or_update_graph).parameters
assert hash_one(b"abc") == "06b05ab6733a618578af5f94892f3950"
'
"${ENV_DIR}/bin/code-review-graph" --version >/dev/null

# Publish the tested environment only after all of its dependencies import.
ENV_LINK="${PREFIX}/libexec/code-review-graph"
if [ -e "${ENV_LINK}" ] && [ ! -L "${ENV_LINK}" ]; then
    echo "Cannot replace a non-symlink Code Review Graph environment" >&2
    exit 1
fi
TEMP_LINK="${PREFIX}/libexec/.code-review-graph-$$"
ln -s "${ENV_NAME}" "${TEMP_LINK}"
mv -Tf "${TEMP_LINK}" "${ENV_LINK}"

install -m 755 "${ROOT_DIR}/qihse-codegraph" "${PREFIX}/qihse-codegraph"
install -m 755 "${ROOT_DIR}/tools/qihse-codegraph-reindex" "${PREFIX}/tools/qihse-codegraph-reindex"
install -m 644 "${ROOT_DIR}/tools/qihse_codegraph_incremental.py" "${PREFIX}/tools/qihse_codegraph_incremental.py"
install -m 644 "${ROOT_DIR}/tools/qihse_codegraph_reindex_source.py" "${PREFIX}/tools/qihse_codegraph_reindex_source.py"
install -m 755 "${ROOT_DIR}/tools/qihse-codegraph-launch" "${PREFIX}/bin/qihse-codegraph"
ln -sfn ../tools/qihse-codegraph-reindex "${PREFIX}/bin/qihse-codegraph-reindex"
printf 'Installed pinned CodeGraph producer %s and native consumer in %s\n' "${EXPECTED:0:12}" "${PREFIX}"
