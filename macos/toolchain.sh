#!/bin/bash
# Source this file so the manifest, compiler, SDK and Testing macro use one developer directory.
DAZZLE_DEVELOPER="${DEVELOPER_DIR:-$(xcode-select -p)}"
DAZZLE_DEVELOPER="${DAZZLE_DEVELOPER%/}"
export DEVELOPER_DIR="$DAZZLE_DEVELOPER"
DAZZLE_SWIFT="$(xcrun --find swift)"
DAZZLE_SDK="$(xcrun --sdk macosx --show-sdk-path)"
DAZZLE_SWIFT_ARGS=()
DAZZLE_TEST_ARGS=(--disable-xctest --enable-swift-testing)
if [[ "$DAZZLE_DEVELOPER" == */CommandLineTools ]]; then
    # Local CLT 27 omits the SwiftUI State macro plugin. Its bundled 26.5 SDK
    # retains the property-wrapper API; Swift Testing still comes from this same CLT.
    if [ -d "$DAZZLE_DEVELOPER/SDKs/MacOSX26.5.sdk" ]; then
        DAZZLE_SDK="$DAZZLE_DEVELOPER/SDKs/MacOSX26.5.sdk"
    fi
    DAZZLE_TESTING_FRAMEWORKS="$DAZZLE_DEVELOPER/Library/Developer/Frameworks"
    if [ ! -d "$DAZZLE_TESTING_FRAMEWORKS" ]; then
        printf '%s\n' 'Selected CLT is missing its Swift Testing developer frameworks.' >&2
        return 1
    fi
    DAZZLE_SWIFT_ARGS=(--build-system native --sdk "$DAZZLE_SDK")
    # The generated native test runner also needs this path; otherwise canImport(Testing) is false.
    DAZZLE_TEST_ARGS+=(-Xswiftc -F -Xswiftc "$DAZZLE_TESTING_FRAMEWORKS")
fi
