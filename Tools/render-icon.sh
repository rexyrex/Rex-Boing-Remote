#!/bin/bash
# Regenerates the app icon from Tools/render-icon.swift, against the
# RexBoingKit built by the Debug app (run Tools/check.sh or Scripts/build.sh first).
set -euo pipefail
cd "$(dirname "$0")/.."
P=.build/Build/Products/Debug
mkdir -p .build/checks
swiftc -O -parse-as-library -I "$P" -o .build/checks/render-icon Tools/render-icon.swift "$P/RexBoingKit.o" \
    -framework AppKit -framework IOKit -framework SystemConfiguration -framework QuartzCore
.build/checks/render-icon RexBoingRemote/Assets.xcassets/AppIcon.appiconset
