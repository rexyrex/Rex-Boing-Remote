#!/bin/bash
# Renders the README's pictures (Tools/render-figures.swift) from the app's own
# views in demo mode, against the RexBoingKit built by the Debug app (run
# Tools/check.sh or Scripts/build.sh first).
#
#   Tools/render-figures.sh [outdir]   default docs
set -euo pipefail
cd "$(dirname "$0")/.."
P=.build/Build/Products/Debug
[ -f "$P/RexBoingKit.o" ] || { echo "Build the Debug app first: Tools/check.sh" >&2; exit 1; }
mkdir -p .build/checks
# Every app source but the entry point, which the renderer replaces.
SOURCES=()
while IFS= read -r file; do SOURCES+=("$file"); done < <(find RexBoingRemote -name '*.swift' ! -name RemoteApp.swift | sort)
swiftc -O -swift-version 5 -parse-as-library -I "$P" -o .build/checks/render-figures \
    Tools/render-figures.swift "${SOURCES[@]}" Shared/History.swift "$P/RexBoingKit.o" \
    -framework AppKit -framework SwiftUI -framework IOKit -framework SystemConfiguration \
    -framework QuartzCore -framework Network -framework ServiceManagement
.build/checks/render-figures "${1:-docs}"
