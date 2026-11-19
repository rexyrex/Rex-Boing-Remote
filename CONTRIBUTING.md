# Contributing

Thanks for helping. Bug reports with the output of `rex-boing-agent doctor`
from the machine in question are the most useful thing of all: hardware varies
endlessly, and that report says exactly what the agent could and could not
read.

## Layout

| Path | What it is |
|---|---|
| `RexBoingRemote/` | The Mac app (Swift, SwiftUI and AppKit) |
| `RexBoingRemote/Demo/` | Demo mode: made-up servers whose agents are recordings |
| `RexBoingRemote/MCP/` | The MCP server: the `mcp` stdio bridge, the app's message port, the tools and their payloads |
| `MacAgent/` | The macOS agent: Rex Boing's samplers, headless |
| `Shared/` | Swift shared by the app and the macOS agent: background history's rings and message |
| `agent/` | The Linux and Windows agent (Go) |
| `PROTOCOL.md` | The contract between the app and every agent |
| `install.sh`, `install.ps1` | The installers for setting a server up from its own end |
| `Scripts/` | Build and release scripts |
| `Tools/` | Checks, the demo recording tools and the README's figure renderer |

The dashboard cards, the menu bar characters, the snapshot model and the wire
format's Swift types live in Rex Boing's repository as the `RexBoingKit` Swift
package, and are shared with Rex Boing itself.

## Building

Needs Xcode 26 or later, XcodeGen and Go 1.24 or later.

```bash
Scripts/build.sh                         # agents, app → dist/
REX_BOING_PATH=../Rex-Boing Scripts/build.sh   # against a local Rex Boing checkout
Tools/check.sh                           # the app's reconnection, demo and MCP checks
cd agent && go vet ./... && go test ./...
```

`Tools/check.sh` runs three headless checks: `connection-check` (the
reconnection logic against a fake ssh, and demo mode), `mcp-check` (the
MCP protocol against scripted lines, every tool's schema, payloads built from
the recordings and from synthetic samples, naming a server, and a bridge
reaching demo connections through the app's message port) and `update-check`
(the update check's version comparison and its reading of GitHub's release
JSON, without asking GitHub anything).

## The MCP server

`"Rex Boing Remote.app/Contents/MacOS/Rex Boing Remote" mcp` is the stdio MCP
server agents run; `RemoteApp.swift` hands over to `MCPBridge` before AppKit
starts. The bridge answers `initialize`, `server/discover`, `ping` and
`tools/list` itself and relays tool calls to the running app's
`MCPAppServer` over a `CFMessagePort`. The app answers on its main run loop
at once, so a call that needs a fresh full sample is answered "retry", and
the bridge asks again until it is ready. To try it without servers:

```bash
open "dist/Rex Boing Remote.app" --args --demo
"dist/Rex Boing Remote.app/Contents/MacOS/Rex Boing Remote" call list_servers --demo
```

A tool reads what the connections already hold and never asks a server for
anything a dashboard wouldn't. Payloads are built from the samples as the
agents sent them (`ServerConnection.lastSample`), not from `Snapshot`, so a
missing reading stays missing; key names carry their units.

## Demo mode: no servers needed

You don't need servers of your own to work on the app. Started with `--demo`,
it shows four made-up machines in place of your saved ones: a Linux home
server, a Windows gaming PC with an NVIDIA card, a Mac mini, and a Raspberry
Pi that is switched off.

```bash
Scripts/build.sh
open "dist/Rex Boing Remote.app" --args --demo
```

In Xcode, tick `--demo` under Product › Scheme › Edit Scheme › Run ›
Arguments.

Their agents are recordings, in `RexBoingRemote/Demo/Recordings/`: JSON lines
exactly as `rex-boing-agent stream` wrote them. `Replay` plays one into the
same pipes ssh would have used, so everything from `AgentSession` up — the
reconnection logic, the fleet list, the dashboards, the menu bar — runs
unchanged. It honours the app's requests as an agent does: an open dashboard
gets every second and the process table, the menu bar gets vitals. Each
recording plays forwards and then backwards, so the graphs never jump.

Demo mode never reads or writes your saved servers, never runs ssh, never
creates the app's key, and keeps its preferences apart from yours. A demo
copy can run beside your normal one.

### Recording a stream

```bash
Tools/demo-record.sh myserver > raw.jsonl     # a server with the agent; --local for this Mac
Tools/demo-scrub.py raw.jsonl RexBoingRemote/Demo/Recordings/linux-home-server.jsonl \
    --hostname home-server --model "Mini PC" --deny myserver --deny yourname
```

The scrubber turns hostnames, users, addresses, mount points, paths and
command lines into neutral examples, keeps only what the dashboard shows, and
writes nothing if anything passed with `--deny`, or anything that looks like a
real address or home folder, is still there. Read the result before you
commit it all the same.

The Windows gaming PC is reconstructed rather than recorded, because no
Windows machine with an NVIDIA card was at hand: `Tools/demo-windows.py`
writes it in the Windows agent's own fields, following the home server's
recording. A real recording to replace it would be welcome.

### The README's pictures

`Tools/render-figures.sh` renders them from the app's own views in demo mode,
in windows far off screen, so they show the real interface and nobody's real
machines:

```bash
Tools/check.sh            # builds the Debug app the renderer links against
Tools/render-figures.sh   # docs/menubar.png, fleet.png, dashboard*.png, add-server-*.png
```

The window's picture, `docs/window.png`, is the one exception: its sidebar and
toolbar are AppKit's and cannot be read back off screen, so it is a screenshot
of the demo window (`open "dist/Rex Boing Remote.app" --args --demo`, which
opens it by itself; `screencapture -o -l <window id>`).

## Adding a metric

1. Add the field to `PROTOCOL.md`, optional like every other.
2. Add it to `agent/internal/wire/wire.go` and to the Swift mirror in Rex
   Boing's `RexBoing/Metrics/Wire.swift`.
3. Read it in the agents (`agent/internal/collect/collect_<os>*.go`, or the
   samplers for macOS), with a fixture-based test.
4. Map it into the `Snapshot` (or `SnapshotExtras`) in `Wire.swift`, and extend
   Rex Boing's `Tools/wire-check.swift`.
5. Show it: a card that has no data for a server must not appear at all.

## Rules of thumb

- Missing is not zero. If a machine cannot report something, leave the key out.
- The agent never needs root and never listens on a port. Changes that would
  require either will not be merged.
- The app must never block on a prompt in the background, and must recover
  from every disconnection by itself.
- Keep the menu bar cheap: anything that runs every sample, on either side,
  should cost microseconds, not milliseconds.
