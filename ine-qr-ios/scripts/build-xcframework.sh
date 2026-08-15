#!/usr/bin/env bash
# Build IneQr.xcframework with iOS device, iOS simulator, and Mac Catalyst slices.
#
# Usage: ./scripts/build-xcframework.sh [output-dir]
#
# Requires: Xcode 15.4+, iOS 15 SDK or newer.
# Output: <output-dir>/IneQr.xcframework
#
# Distribute the xcframework via SwiftPM .binaryTarget(url:checksum:) — zip
# the framework, host the zip, paste the SHA-256.

set -euo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${PKG_DIR}/dist}"
BUILD_DIR="${PKG_DIR}/.build/xcframework"

rm -rf "${BUILD_DIR}" "${OUT_DIR}/IneQr.xcframework"
mkdir -p "${BUILD_DIR}" "${OUT_DIR}"

archive() {
    local destination="$1"
    local name="$2"
    xcodebuild archive \
        -workspace "${PKG_DIR}" \
        -scheme IneQr \
        -destination "${destination}" \
        -archivePath "${BUILD_DIR}/${name}.xcarchive" \
        SKIP_INSTALL=NO \
        BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
        ENABLE_BITCODE=NO
}

archive "generic/platform=iOS"                        ios
archive "generic/platform=iOS Simulator"              ios-sim
archive "generic/platform=macOS,variant=Mac Catalyst" maccatalyst

xcodebuild -create-xcframework \
    -framework "${BUILD_DIR}/ios.xcarchive/Products/Library/Frameworks/IneQr.framework" \
    -framework "${BUILD_DIR}/ios-sim.xcarchive/Products/Library/Frameworks/IneQr.framework" \
    -framework "${BUILD_DIR}/maccatalyst.xcarchive/Products/Library/Frameworks/IneQr.framework" \
    -output    "${OUT_DIR}/IneQr.xcframework"

echo
echo "Built ${OUT_DIR}/IneQr.xcframework"
du -sh "${OUT_DIR}/IneQr.xcframework"
