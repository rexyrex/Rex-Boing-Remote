#!/bin/bash
# Headless checks for the Mac app. Builds the Debug app (for RexBoingKit),
# then runs the connection state machine against a fake ssh that drops,
# hangs, refuses and stays down on cue, and against demo mode's recordings.
# The agents have their own tests:
# cd agent && go test ./...
set -euo pipefail
cd "$(dirname "$0")/.."
Scripts/generate.sh
xcodebuild -project RexBoingRemote.xcodeproj -scheme RexBoingRemote -configuration Debug \
    -derivedDataPath .build build > .build-log.txt 2>&1 || { grep -E "error:" .build-log.txt; exit 1; }
P=.build/Build/Products/Debug
mkdir -p .build/checks
swiftc -swift-version 5 -parse-as-library -I "$P" -o .build/checks/connection-check \
    Tools/connection-check.swift \
    RexBoingRemote/Connection/SSH.swift RexBoingRemote/Connection/AgentSession.swift \
    RexBoingRemote/Connection/ServerConnection.swift RexBoingRemote/Connection/LocalNetwork.swift \
    RexBoingRemote/Model/Server.swift RexBoingRemote/Model/PairingCode.swift \
    RexBoingRemote/App/Paths.swift Shared/History.swift \
    RexBoingRemote/App/AppKey.swift RexBoingRemote/App/Askpass.swift \
    RexBoingRemote/Demo/Demo.swift RexBoingRemote/Demo/Replay.swift \
    MacAgent/AuthorizedKeys.swift MacAgent/CodeSignature.swift \
    "$P/RexBoingKit.o" \
    -framework AppKit -framework IOKit -framework SystemConfiguration -framework QuartzCore -framework Network \
    -framework Security
FAKE_SSH="$PWD/Tools/fake-ssh.sh" .build/checks/connection-check
