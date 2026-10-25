#!/bin/bash
set -euo pipefail
MACOS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$MACOS_DIR/.." && pwd)"
APP_DIR="$MACOS_DIR/dist/DazzleVPS.app"
if [ ! -f "$REPO_DIR/third_party/NOTICE.md" ] || [ ! -f "$REPO_DIR/third_party/GPL-3.0.txt" ]; then
    printf '%s\n' 'Required third-party license notices are missing; app bundle was not built.' >&2
    exit 1
fi
DAZZLE_SDK="$(xcrun --sdk macosx --show-sdk-path)"
# CLT 27's SwiftUI State macro plugin is not bundled. The included 26.5 SDK
# retains the compatible property-wrapper API and runs normally on macOS 27.
if [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk ]; then
    DAZZLE_SDK=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
fi
swift build --package-path "$MACOS_DIR" --build-system native --sdk "$DAZZLE_SDK" -c release
DAZZLE_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/dazzle-app.XXXXXX")"
trap 'rm -rf "$DAZZLE_STAGE"' EXIT
STAGED_APP="$DAZZLE_STAGE/DazzleVPS.app"
mkdir -p "$STAGED_APP/Contents/MacOS" "$STAGED_APP/Contents/Resources"
cp "$MACOS_DIR/.build/release/DazzleVPS" "$STAGED_APP/Contents/MacOS/DazzleVPS"
bash "$MACOS_DIR/make-icon.sh" "$STAGED_APP/Contents/Resources/AppIcon.icns" >/dev/null
python3 - "$REPO_DIR" "$STAGED_APP" <<'PY'
from pathlib import Path
import plistlib,shutil,sys
repo,app=map(Path,sys.argv[1:])
licenses=app/'Contents'/'Resources'/'third_party'
if licenses.exists():shutil.rmtree(licenses)
shutil.copytree(repo/'third_party',licenses,ignore=shutil.ignore_patterns('__pycache__','*.pyc','.DS_Store'))
info={'CFBundleName':"Dazzle'VPS",'CFBundleDisplayName':"Dazzle'VPS",'CFBundleIdentifier':'com.dazzle.vps.manager',
      'CFBundleExecutable':'DazzleVPS','CFBundleIconFile':'AppIcon.icns','CFBundlePackageType':'APPL','CFBundleShortVersionString':'3.1',
      'CFBundleVersion':'31','LSMinimumSystemVersion':'14.0','NSHighResolutionCapable':True,
      'DazzleRPCSchemaVersion':1,
      'NSHumanReadableCopyright':'Dazzle VPS · Local administrator application'}
with (app/'Contents'/'Info.plist').open('wb') as handle:plistlib.dump(info,handle)
PY
# Sign outside Documents: File Provider can reattach FinderInfo during signing.
# Only generated output is replaced; sources and all local user state are untouched.
xattr -cr "$STAGED_APP"
codesign --force --sign - --timestamp=none "$STAGED_APP"
codesign --verify --strict "$STAGED_APP"
python3 - "$STAGED_APP" "$APP_DIR" <<'PY_PUBLISH'
from pathlib import Path
import shutil,subprocess,sys
source,destination=map(Path,sys.argv[1:])
destination.parent.mkdir(exist_ok=True)
backup=destination.parent/'.DazzleVPS.previous-build'
if backup.exists():shutil.rmtree(backup)
if destination.exists():destination.rename(backup)
try:
    shutil.move(str(source),str(destination))
    subprocess.run(['codesign','--verify','--strict',str(destination)],check=True)
except BaseException:
    if destination.exists():shutil.rmtree(destination)
    if backup.exists():backup.rename(destination)
    raise
if backup.exists():shutil.rmtree(backup)
PY_PUBLISH
printf '%s\n' "$APP_DIR"
