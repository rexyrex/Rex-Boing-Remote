#!/bin/bash
# Records a real agent stream for demo mode: hello, then a full-detail sample
# every second. The output is the raw stream, with everything the server says
# about itself — scrub it with Tools/demo-scrub.py before it goes anywhere
# near the repository.
#
#   Tools/demo-record.sh myserver [samples] > raw.jsonl   a server with the agent installed
#   Tools/demo-record.sh --local [samples] > raw.jsonl    this Mac, with the agent in dist/
#
# For a Windows server, set AGENT_PATH='.\AppData\Local\RexBoingRemote\rex-boing-agent.exe'.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET=${1:?usage: Tools/demo-record.sh <ssh destination|--local> [samples]}
COUNT=${2:-160}
AGENT_PATH=${AGENT_PATH:-./.local/share/rex-boing-remote/rex-boing-agent}

# The agents end the stream when their input closes, so it stays open for
# the whole recording.
if [ "$TARGET" = --local ]; then
    AGENT="dist/Rex Boing Remote.app/Contents/Resources/Agents/darwin-universal/rex-boing-agent"
    [ -x "$AGENT" ] || { echo "Build the app first: Scripts/build.sh" >&2; exit 1; }
    "$AGENT" stream --detail full --interval 1 --count "$COUNT" < <(sleep $((COUNT + 30)))
else
    ssh -T "$TARGET" "$AGENT_PATH stream --detail full --interval 1 --count $COUNT" < <(sleep $((COUNT + 30)))
fi
