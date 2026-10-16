# Contributing

Thanks for helping. Bug reports with the output of `rex-boing-agent doctor`
from the machine in question are the most useful thing of all: hardware varies
endlessly, and that report says exactly what the agent could and could not
read.

## Layout

| Path | What it is |
|---|---|
| `RexBoingRemote/` | The Mac app (Swift, SwiftUI and AppKit) |
| `MacAgent/` | The macOS agent: Rex Boing's samplers, headless |
| `agent/` | The Linux and Windows agent (Go) |
| `PROTOCOL.md` | The contract between the app and every agent |
| `install.sh`, `install.ps1` | The installers for setting a server up from its own end |
| `Scripts/` | Build and release scripts |

The dashboard cards, the menu bar characters, the snapshot model and the wire
format's Swift types live in Rex Boing's repository as the `RexBoingKit` Swift
package, and are shared with Rex Boing itself.

## Building

Needs Xcode 26 or later, XcodeGen and Go 1.24 or later.

```bash
Scripts/build.sh                         # agents, app → dist/
REX_BOING_PATH=../Rex-Boing Scripts/build.sh   # against a local Rex Boing checkout
cd agent && go vet ./... && go test ./...
```

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
