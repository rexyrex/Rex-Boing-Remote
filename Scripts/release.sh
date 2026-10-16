#!/bin/bash
# The maintainer's release path. Builds everything, signs the app and the
# macOS agent with Developer ID, notarizes and staples the app, signs the
# checksums with the project's release key, and stages dist/release/ — then,
# with --publish, creates the GitHub release for the tag v$(cat VERSION).
#
#   Scripts/release.sh             stage dist/release/ only
#   Scripts/release.sh --publish   also push the tag and create the release
#
# Needs: a "Developer ID Application" certificate in the keychain;
# notarize.env (see notarize.env.example) with an App Store Connect API key;
# the release signing key at ~/.config/rex-boing-remote/release-signing-key;
# gh, signed in, for --publish.
set -euo pipefail
cd "$(dirname "$0")/.."

PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

VERSION=$(cat VERSION)
TAG="v$VERSION"
SIGNING_KEY="${SIGNING_KEY:-$HOME/.config/rex-boing-remote/release-signing-key}"
ENV_FILE="${NOTARIZE_ENV:-notarize.env}"

[ -f "$ENV_FILE" ] || { echo "Missing $ENV_FILE (copy notarize.env.example)." >&2; exit 1; }
# shellcheck disable=SC1090
source "$ENV_FILE"
: "${ASC_KEY_ID:?}" "${ASC_ISSUER_ID:?}" "${ASC_KEY_P8:?}"
[ -f "$SIGNING_KEY" ] || { echo "Missing release signing key $SIGNING_KEY" >&2; exit 1; }

IDENTITY=$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/ {print $2; exit}')
[ -n "$IDENTITY" ] || { echo "No Developer ID Application certificate in the keychain." >&2; exit 1; }
echo "==> Signing as: $IDENTITY"

Scripts/build.sh

APP="dist/Rex Boing Remote.app"
AGENT="$APP/Contents/Resources/Agents/darwin-universal/rex-boing-agent"

# The only Mach-O executables in the bundle must be the app and the agent
# under Agents/; anything else would be unsigned and fail notarization.
STRAY=$(find "$APP/Contents" -type f -perm -u+x ! -path "*/MacOS/*" ! -path "*/Agents/*" -exec file {} \; | grep -c "Mach-O" || true)
[ "$STRAY" -eq 0 ] || { echo "Unexpected executables in the bundle:" >&2; find "$APP/Contents" -type f -perm -u+x ! -path "*/MacOS/*" ! -path "*/Agents/*" >&2; exit 1; }

echo "==> Signing the macOS agent"
codesign --force --options runtime --timestamp \
    --identifier com.rexyrex.RexBoingRemote.agent --sign "$IDENTITY" "$AGENT"
echo "==> Signing the app"
codesign --force --options runtime --timestamp \
    --entitlements RexBoingRemote/RexBoingRemote.entitlements --sign "$IDENTITY" "$APP"
codesign --verify --strict --deep --verbose=2 "$APP"

OUT=dist/release
rm -rf "$OUT" && mkdir -p "$OUT"
ZIP="$OUT/Rex.Boing.Remote.zip"

echo "==> Notarizing (usually 1-5 minutes)"
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --key "$ASC_KEY_P8" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" --wait
xcrun stapler staple "$APP"
rm -f "$ZIP"
ditto -c -k --keepParent "$APP" "$ZIP"

echo "==> Collecting the agents"
cp "$AGENT" "$OUT/rex-boing-agent-darwin-universal"
for dir in build/agents/*/; do
    target=$(basename "$dir")
    for file in "$dir"*; do
        case "$file" in
            *.exe) cp "$file" "$OUT/rex-boing-agent-$target.exe" ;;
            *) cp "$file" "$OUT/rex-boing-agent-$target" ;;
        esac
    done
done
cp install.sh install.ps1 "$OUT/"

echo "==> Checksums and signature"
(cd "$OUT" && shasum -a 256 -- * | sed 's/  / /' > SHA256SUMS)
ssh-keygen -q -Y sign -f "$SIGNING_KEY" -n rex-boing-remote "$OUT/SHA256SUMS"
mv "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS.sig" 2>/dev/null || true
cat "$OUT/SHA256SUMS"

if [ "$PUBLISH" -eq 1 ]; then
    NOTES="docs/releases/$VERSION.md"
    [ -f "$NOTES" ] || { echo "Missing release notes $NOTES" >&2; exit 1; }
    git tag -a "$TAG" -m "Rex Boing Remote $VERSION" 2>/dev/null || true
    git push origin "$TAG"
    gh release create "$TAG" "$OUT"/* --title "Rex Boing Remote $VERSION" --notes-file "$NOTES"
fi
echo "Done: $OUT"
