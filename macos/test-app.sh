#!/bin/bash
set -euo pipefail
MACOS_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$MACOS_DIR/toolchain.sh"
"$DAZZLE_SWIFT" test --package-path "$MACOS_DIR" ${DAZZLE_SWIFT_ARGS[@]+"${DAZZLE_SWIFT_ARGS[@]}"} "${DAZZLE_TEST_ARGS[@]}"
