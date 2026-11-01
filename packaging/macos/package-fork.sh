#!/usr/bin/env bash
# Build the upstream macOS app, then an ad-hoc signed fork app with its own identity.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../env.sh
. "$HERE/../env.sh"
export MACOS_SIGN_IDENTITY=-
bash "$HERE/package.sh" --app-only "$@"

FORK_APP="$DIST/Craft Anything Fork.app"
STAGING=$(mktemp -d "$DIST/fork-app.XXXXXX")
trap 'rm -rf "$STAGING"' EXIT
APP="$STAGING/Craft Anything Fork.app"
ditto "$CARGO_TARGET_DIR/macos-package/Craft Anything.app" "$APP"
cp "$CARGO_TARGET_DIR/macos-package/bin/craft-anything-cli" "$APP/Contents/MacOS/craft-anything-cli"
for field in CFBundleDisplayName CFBundleName; do
  /usr/libexec/PlistBuddy -c "Set :$field Craft Anything Fork" "$APP/Contents/Info.plist"
done
/usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier ai.cgove.craft-anything' "$APP/Contents/Info.plist"
for bin in craft-anything craft-anything-cli; do
  codesign --force --sign - --timestamp=none --options runtime \
    --entitlements "$HERE/entitlements.plist" "$APP/Contents/MacOS/$bin"
done
codesign --force --sign - --timestamp=none --options runtime \
  --entitlements "$HERE/entitlements.plist" "$APP"
codesign --verify --strict --deep --verbose=2 "$APP"
# DIST is the generated-artifact folder, never /Applications. Installation is a separate step.
if [ -e "$FORK_APP" ]; then
  prior_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$FORK_APP/Contents/Info.plist")
  if [ "$prior_id" != "ai.cgove.craft-anything" ]; then
    echo "Refusing to replace an unrelated app at $FORK_APP." >&2
    exit 1
  fi
  mv "$FORK_APP" "$STAGING/previous.app"
fi
mv "$APP" "$FORK_APP"
echo "Fork app: $FORK_APP"
