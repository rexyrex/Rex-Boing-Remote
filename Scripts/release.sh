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
#
# Before anything is built it checks that the release will be what its tag
# says (see preflight), and it runs the agent's vet and tests.
set -euo pipefail
cd "$(dirname "$0")/.."

PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

VERSION=$(cat VERSION)
TAG="v$VERSION"
SIGNING_KEY="${SIGNING_KEY:-$HOME/.config/rex-boing-remote/release-signing-key}"
ENV_FILE="${NOTARIZE_ENV:-notarize.env}"

fail() { echo "$*" >&2; exit 1; }

# preflight refuses a release that would not be what its tag says: one built
# from uncommitted files, from a commit an existing tag does not name, or
# with a version the app does not carry; and, to publish, one from anything
# but origin/main, or for a tag that already has a release. A re-run after a
# failed publish passes: its tag names this commit and has no release yet.
preflight() {
    [ -z "$(git status --porcelain)" ] ||
        fail "The working tree has changes (git status). A release is built from a commit: commit or stash them first."
    local app_version
    app_version=$(sed -n 's/^[[:space:]]*MARKETING_VERSION:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' project.yml | head -n 1)
    [ "$app_version" = "$VERSION" ] ||
        fail "VERSION says $VERSION, but project.yml's MARKETING_VERSION is ${app_version:-missing}."
    # install.sh carries the signer it checks SHA256SUMS against.
    grep -qxF "SIGNER='$(cat docs/allowed_signers)'" install.sh ||
        fail "install.sh's SIGNER is not the key in docs/allowed_signers."
    local head tagged
    head=$(git rev-parse HEAD)
    if tagged=$(git rev-parse -q --verify "refs/tags/$TAG^{commit}"); then
        [ "$tagged" = "$head" ] || fail "The tag $TAG already names $tagged, not HEAD ($head)."
    fi
    if [ "$PUBLISH" -eq 1 ]; then
        [ -f "docs/releases/$VERSION.md" ] || fail "Missing release notes docs/releases/$VERSION.md"
        gh auth status >/dev/null 2>&1 || fail "gh is not signed in (gh auth login)."
        git fetch --quiet origin main
        [ "$(git rev-parse FETCH_HEAD)" = "$head" ] ||
            fail "HEAD ($head) is not origin/main ($(git rev-parse FETCH_HEAD)). Releases are published from origin/main."
        local remote
        remote=$(git ls-remote --tags origin "refs/tags/$TAG" "refs/tags/$TAG^{}" |
            awk -v t="refs/tags/$TAG" '$2 == t "^{}" { peeled = $1 } $2 == t { plain = $1 } END { print (peeled != "" ? peeled : plain) }')
        [ -z "$remote" ] || [ "$remote" = "$head" ] || fail "origin's tag $TAG names $remote, not HEAD ($head)."
        if gh release view "$TAG" >/dev/null 2>&1; then
            fail "GitHub already has a release for $TAG."
        fi
    fi
    echo "==> Vetting and testing the agent"
    (cd agent && go vet ./... && GOOS=windows go vet ./... && go test ./...)
}

[ -f "$ENV_FILE" ] || { echo "Missing $ENV_FILE (copy notarize.env.example)." >&2; exit 1; }
# shellcheck disable=SC1090
source "$ENV_FILE"
: "${ASC_KEY_ID:?}" "${ASC_ISSUER_ID:?}" "${ASC_KEY_P8:?}"
[ -f "$SIGNING_KEY" ] || { echo "Missing release signing key $SIGNING_KEY" >&2; exit 1; }

IDENTITY=$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/ {print $2; exit}')
[ -n "$IDENTITY" ] || { echo "No Developer ID Application certificate in the keychain." >&2; exit 1; }
echo "==> Signing as: $IDENTITY"

echo "==> Checking $TAG"
preflight

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
# Checked here as install.sh checks it on every server, so a signing key
# that is not the published one fails now rather than there.
ssh-keygen -Y verify -f docs/allowed_signers -I rex-boing-remote -n rex-boing-remote \
    -s "$OUT/SHA256SUMS.sig" < "$OUT/SHA256SUMS" >/dev/null ||
    fail "SHA256SUMS.sig does not verify against docs/allowed_signers: $SIGNING_KEY is not the project's key."
cat "$OUT/SHA256SUMS"

if [ "$PUBLISH" -eq 1 ]; then
    NOTES="docs/releases/$VERSION.md"
    [ -f "$NOTES" ] || { echo "Missing release notes $NOTES" >&2; exit 1; }
    # preflight made sure an existing tag names this commit.
    git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || git tag -a "$TAG" -m "Rex Boing Remote $VERSION"
    git push origin "$TAG"
    gh release create "$TAG" "$OUT"/* --title "Rex Boing Remote $VERSION" --notes-file "$NOTES"
fi
echo "Done: $OUT"
