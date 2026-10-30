#!/usr/bin/env bash
# Build "Wi-Fi Intrusion Monitor.app" and a drag-to-Applications .dmg in dist/.
set -euo pipefail
cd "$(dirname "$0")"

NAME="Wi-Fi Intrusion Monitor"
VERSION=$(.venv/bin/python -c "import wimon; print(wimon.__version__)")
DMG="dist/WiFi-Intrusion-Monitor-${VERSION}-mac.dmg"

.venv/bin/python -m pytest -q
rm -rf build dist
.venv/bin/python setup.py py2app >/dev/null

# Ad-hoc signature: not notarised (that needs a paid Apple Developer account), but it keeps
# the bundle's code consistent so macOS can show the "Open Anyway" option.
codesign --force --deep --sign - "dist/${NAME}.app"

STAGE=$(mktemp -d)
cp -R "dist/${NAME}.app" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"
shasum -a 256 "$DMG"
