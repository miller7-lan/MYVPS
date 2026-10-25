#!/bin/bash
set -euo pipefail
MACOS_DIR="$(cd "$(dirname "$0")" && pwd)"
ICON_SOURCE="$MACOS_DIR/Assets/AppIcon.png"
ICON_OUTPUT="${1:-$MACOS_DIR/Assets/AppIcon.icns}"
if [ ! -f "$ICON_SOURCE" ]; then
    printf '%s\n' 'AppIcon.png is required.' >&2
    exit 1
fi
ICON_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/dazzle-icon.XXXXXX")"
trap 'rm -rf "$ICON_STAGE"' EXIT
ICON_SET="$ICON_STAGE/AppIcon.iconset"
mkdir -p "$ICON_SET"
for ICON_SIZE in 16 32 128 256 512; do
    sips -z "$ICON_SIZE" "$ICON_SIZE" "$ICON_SOURCE" --out "$ICON_SET/icon_${ICON_SIZE}x${ICON_SIZE}.png" >/dev/null
    ICON_RETINA=$((ICON_SIZE * 2))
    sips -z "$ICON_RETINA" "$ICON_RETINA" "$ICON_SOURCE" --out "$ICON_SET/icon_${ICON_SIZE}x${ICON_SIZE}@2x.png" >/dev/null
done
mkdir -p "$(dirname "$ICON_OUTPUT")"
iconutil -c icns "$ICON_SET" -o "$ICON_OUTPUT"
printf '%s\n' "$ICON_OUTPUT"
