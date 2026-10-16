#!/bin/bash
# Cross-compiles the Go agent for every Linux and Windows target into
# build/agents/<os>-<arch>/, where the app build embeds them. The macOS agent
# is built by the Xcode project itself.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(cat VERSION)
OUT=build/agents
rm -rf "$OUT"
for target in linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64; do
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
