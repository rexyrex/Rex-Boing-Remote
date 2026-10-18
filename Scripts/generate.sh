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
spec, n = re.subn(r"url: https://github.com/rexyrex/Rex-Boing\n\s+from: [0-9.]+", "path: " + sys.argv[1], spec)
# Otherwise the build would quietly use the tagged package instead.
if n != 1:
    sys.exit("generate.sh: project.yml's RexBoingKit package entry (url: …/Rex-Boing, from: …) was not found, "
             "so REX_BOING_PATH could not be applied. Update the pattern in Scripts/generate.sh.")
open("project.local.yml", "w").write(spec)
PY
fi
xcodegen generate --spec "$SPEC" --quiet
