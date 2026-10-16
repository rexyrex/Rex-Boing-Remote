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
grep -E "error:|warning: .*(RexBoingRemote|MacAgent)|BUILD (SUCCEEDED|FAILED)" .build-log.txt | grep -v "^\s*$" | sort -u | head -60
[ $STATUS -eq 0 ] || exit $STATUS

APP=".build/Build/Products/Release/Rex Boing Remote.app"
rm -rf dist && mkdir -p dist && cp -R "$APP" dist/
echo "==> Staged dist/Rex Boing Remote.app"

if [ "$INSTALL" -eq 1 ]; then
    TARGET="/Applications/Rex Boing Remote.app"
    PID=$(pgrep -x "Rex Boing Remote" || true)
    if [ -n "$PID" ]; then
        echo "==> Quitting the running copy (pid $PID)"
        kill "$PID"
        for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 0.25; done
    fi
    rm -rf "$TARGET"
    ditto "dist/Rex Boing Remote.app" "$TARGET"
    open "$TARGET"
    echo "Done. Rex Boing Remote is running from $TARGET."
fi
