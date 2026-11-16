#!/bin/bash
# Cross-compiles the Go agent for every Linux and Windows target into
# build/agents/<os>-<arch>/, where the app build embeds them. The macOS agent
# is built by the Xcode project itself.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(cat VERSION)
OUT=build/agents
TARGETS="linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64"

# Checked before anything is removed: without Go this used to delete the
# agents already built and then stop, leaving a checkout that could not build
# the app at all. A Mac with no Go keeps the agents it has — enough to work
# on the app — and is told so; a release always has Go (release.sh tests the
# agent with it before it gets here).
if ! command -v go >/dev/null 2>&1; then
    for target in $TARGETS; do
        if [ -z "$(ls -A "$OUT/${target%/*}-${target#*/}" 2>/dev/null)" ]; then
            echo "Go is required to build the Linux and Windows agents: brew install go" >&2
            exit 1
        fi
    done
    echo "warning: go not found; keeping the agents already in $OUT, whatever source they were built from" >&2
    exit 0
fi

rm -rf "$OUT"
for target in $TARGETS; do
    os=${target%/*}
    arch=${target#*/}
    name=rex-boing-agent
    [ "$os" = windows ] && name=rex-boing-agent.exe
    mkdir -p "$OUT/$os-$arch"
    echo "==> agent $os/$arch"
    # GOARM=6 so one build runs on every Raspberry Pi, the original included.
    (cd agent && CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=6 go build -trimpath \
        -ldflags "-s -w -X main.version=$VERSION" \
        -o "../$OUT/$os-$arch/$name" ./cmd/rex-boing-agent)
done
