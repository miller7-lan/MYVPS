#!/bin/bash
set -euo pipefail
MACOS_DIR="$(cd "$(dirname "$0")" && pwd)"
DAZZLE_DEVELOPER="$(xcode-select -p)"
DAZZLE_SDK="$(xcrun --sdk macosx --show-sdk-path)"
if [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk ]; then
    DAZZLE_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
fi
# Pass the framework path to SwiftPM's generated runner as well as test target;
# otherwise CLT's canImport(Testing) silently builds an empty runner.
swift test --package-path "$MACOS_DIR" --build-system native --sdk "$DAZZLE_SDK" \
    --disable-xctest --enable-swift-testing \
    -Xswiftc -F -Xswiftc "$DAZZLE_DEVELOPER/Library/Developer/Frameworks"
