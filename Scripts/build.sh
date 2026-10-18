#!/bin/bash
# Builds the agents and the app, and stages dist/Rex Boing Remote.app.
#
#   Scripts/build.sh            build only
#   Scripts/build.sh --install  also replace /Applications/Rex Boing Remote.app
#                               and relaunch it
#
# REX_BOING_PATH=/path/to/Rex-Boing builds against a local checkout of Rex
# Boing instead of the tagged package, for working on both at once.
#
# Requires Xcode, XcodeGen (brew install xcodegen) and Go.
set -euo pipefail
cd "$(dirname "$0")/.."

INSTALL=0
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=1 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

Scripts/build-agents.sh

echo "==> Generating project"
Scripts/generate.sh

echo "==> Building Release"
set +e
xcodebuild -project RexBoingRemote.xcodeproj -scheme RexBoingRemote -configuration Release \
    -derivedDataPath .build build > .build-log.txt 2>&1
STATUS=$?
set -e
# A filter, not a check: no match, or head closing the pipe early, is fine.
grep -E "error:|warning: .*(RexBoingRemote|MacAgent)|BUILD (SUCCEEDED|FAILED)" .build-log.txt | grep -v "^\s*$" | sort -u | head -60 || true
[ $STATUS -eq 0 ] || exit $STATUS

APP=".build/Build/Products/Release/Rex Boing Remote.app"
rm -rf dist && mkdir -p dist && cp -R "$APP" dist/
echo "==> Staged dist/Rex Boing Remote.app"

# The processes running from the installed app, and only those: a copy
# run from dist/ or anywhere else (a demo beside the real one) is not it.
installed_pids() {
    ps -axo pid=,comm= | awk -v dir="$TARGET/Contents/MacOS/" '
        { pid = $1; sub(/^[ \t]*[0-9]+[ \t]+/, ""); if (index($0, dir) == 1) print pid }'
}

if [ "$INSTALL" -eq 1 ]; then
    TARGET="/Applications/Rex Boing Remote.app"
    STAGED="/Applications/.Rex Boing Remote.app.new"
    OLD="/Applications/.Rex Boing Remote.app.old"
    # Copied beside the installed app first: a copy that fails leaves the
    # installed app as it was.
    rm -rf "$STAGED" "$OLD"
    ditto "dist/Rex Boing Remote.app" "$STAGED"
    PIDS=$(installed_pids)
    if [ -n "$PIDS" ]; then
        echo "==> Quitting the running copy (pid $(echo $PIDS))"
        for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
        for _ in $(seq 1 20); do
            [ -n "$(installed_pids)" ] || break
            sleep 0.25
        done
        if [ -n "$(installed_pids)" ]; then
            rm -rf "$STAGED"
            echo "Rex Boing Remote (pid $(echo $(installed_pids))) did not quit within 5 s; $TARGET was left as it was." >&2
            exit 1
        fi
    fi
    if [ -e "$TARGET" ]; then mv "$TARGET" "$OLD"; fi
    mv "$STAGED" "$TARGET"
    rm -rf "$OLD"
    open "$TARGET"
    echo "Done. Rex Boing Remote is running from $TARGET."
fi
