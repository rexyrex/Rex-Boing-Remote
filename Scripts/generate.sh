#!/bin/bash
# Generates RexBoingRemote.xcodeproj from project.yml. With REX_BOING_PATH set,
# RexBoingKit comes from that local Rex Boing checkout instead of its tag.
set -euo pipefail
cd "$(dirname "$0")/.."
SPEC=project.yml
if [ -n "${REX_BOING_PATH:-}" ]; then
    SPEC=project.local.yml
    python3 - "$REX_BOING_PATH" <<'PY'
import re, sys
spec = open("project.yml").read()
spec = re.sub(r"url: https://github.com/rexyrex/Rex-Boing\n\s+from: [0-9.]+", "path: " + sys.argv[1], spec)
open("project.local.yml", "w").write(spec)
PY
fi
xcodegen generate --spec "$SPEC" --quiet
