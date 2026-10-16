# Rex Boing Remote protocol, version 1

This is the contract between the Rex Boing Remote app and an agent. Anything
that speaks it can be monitored: the agents in this repository, or one you
write for another system.

## Transport

The app starts the agent over SSH and talks to it through the session's
standard input and output. There is no network listener of any kind.

* The agent writes **one JSON object per line** to stdout, UTF-8, terminated by
  `\n`. Nothing else may be written to stdout. Diagnostics go to stderr.
* The app writes one JSON object per line to the agent's stdin.
* When stdin reaches end of file, the agent exits immediately. This is how an
  agent notices that the Mac slept, the network dropped or the app quit, so an
  agent must never outlive its session.
* A line may be at most 1 MiB. The app drops a session that sends a longer one.
* Unknown keys must be ignored by both sides. Missing keys mean "unknown" or
  "not available on this machine", never zero.

## Commands

The agent is one executable with these commands:

| Command | Purpose |
|---|---|
| `stream` | The live session described below. |
| `version` | Prints one line: `{"name":"rex-boing-agent","version":"0.1.0","protocol":1,"os":"linux","arch":"amd64"}` |
| `doctor` | A human-readable report of what this machine can and cannot report, and why. `doctor --json` prints the same as JSON. |
| `install` | Reads one OpenSSH public key line from stdin (or `--key`), adds it to the user's `authorized_keys` restricted to this agent, prints a JSON result. |
| `pair-code` | Prints a pairing code for this machine (see below). |
| `upgrade --sha256 HEX --size N` | Reads exactly N bytes of a new agent from stdin, verifies the hash, replaces itself, prints a JSON result. |
| `uninstall` | Removes the keys it installed and its own files, prints a JSON result. |
| `ssh` | Entry point used by the restricted key. Runs the command named in `SSH_ORIGINAL_COMMAND` if it is one of `stream`, `version`, `doctor`, `doctor --json`, `upgrade …` or `uninstall`, and refuses anything else. |

JSON results of `install`, `upgrade` and `uninstall` have the shape
`{"ok":true,"message":"…", …}` or `{"ok":false,"error":"code","message":"…"}`.

## The restricted key

`install` appends a line like this to `~/.ssh/authorized_keys`
(on Windows, `administrators_authorized_keys` for administrators):

```
restrict,command="'/home/alex/.local/share/rex-boing-remote/rex-boing-agent' ssh" ssh-ed25519 AAAA… rex-boing-remote:Alexs-MacBook
```

`restrict` turns off port, agent and X11 forwarding and the TTY. `command`
means the key can only ever run the agent, whatever the client asks for. The
comment always starts with `rex-boing-remote:`, which is how `uninstall` finds
its own lines.

Install locations:

| OS | Directory |
|---|---|
| Linux, macOS | `~/.local/share/rex-boing-remote/` |
| Windows | `%LOCALAPPDATA%\RexBoingRemote\` |

## Pairing code

A pairing code lets a server that installed the agent itself (with
`install.sh` or `install.ps1`) be added by pasting one string:

```
rbr1:<base64url without padding of the JSON below>
```

```json
{"v":1,"n":"homelab","u":"alex","p":22,"o":"linux",
 "a":["192.168.1.20","100.101.102.103","homelab.local"],
 "k":["ssh-ed25519 AAAAC3Nza…"]}
```

`n` hostname, `u` user, `p` SSH port, `o` OS, `a` addresses to try in order,
`k` the server's SSH host public keys. The app pins those keys, so the first
connection needs no fingerprint prompt and cannot be intercepted.

## Session

### hello (agent → app, first line)

```json
{"type":"hello","protocol":1,
 "agent":{"name":"rex-boing-agent","version":"0.1.0","os":"linux","arch":"amd64"},
 "host":{"hostname":"homelab","modelName":"NUC15CRHU7","vendor":"ASUSTeK","chipName":"Intel Core Ultra 7 255H",
         "osName":"Ubuntu","osVersion":"24.04.5 LTS","kernel":"6.8.0-146-generic",
         "physicalCores":16,"logicalCores":16,"performanceCores":6,"efficiencyCores":10,
         "memoryBytes":66701082624,"bootTime":1791327368000,"isAppleSilicon":false,
         "virtualization":"none"},
 "capabilities":["cpu","memory","gpu","sensors","fans","power","pressure","processes","system"],
 "interval":1.0}
```

`virtualization` is `none` or a short name such as `kvm`, `vmware`, `hyperv`,
`docker`, `lxc`, `wsl`. Capability names are informative; the app decides what
to draw from the samples themselves.

### Requests (app → agent, any time)

```json
{"want":"vitals"}
{"want":"full"}
{"interval":2}
```

* `vitals` (the default): the small set of numbers the menu bar and the fleet
  list show, and that history records.
* `full`: everything, including processes, for an open dashboard. Agents may
  sample processes and sensors less often than every tick and repeat the
  last values in between.
* `interval`: seconds between samples, clamped by the agent to 0.5–10.

The agent applies a request from its next sample on.

### sample (agent → app, every interval)

```json
{"type":"sample","seq":12,"t":1792141977889,"interval":1.002,"detail":"vitals","resync":false,
 "cpu":{…},"memory":{…},"gpus":[…],"thermal":{…},"power":{…},"network":{…},
 "disk":{…},"battery":{…},"pressure":{…},"system":{…},"processes":{…},"sleep":{…}}
```

* `seq` counts up from 1 within a session.
* `t` is the agent's wall clock in milliseconds since the Unix epoch.
* `interval` is the measured length of the window the rates cover, seconds.
* `resync` is true when the rates in this sample are not valid (first sample,
  or the window spans a pause). The app shows the sample but leaves it out of
  history.
* `detail` says which request the sample answers.

Every section and every key in it is optional. Units are fixed: fractions are
0–1, bytes are bytes, rates are bytes per second, temperatures are degrees
Celsius, power is watts, clocks are MHz, times are milliseconds since the
epoch unless noted.

`vitals` samples carry at least: `cpu.total`, `cpu.user`, `cpu.system`,
`memory.total`, `memory.used`, `memory.swap.total`, `memory.swap.used`,
`gpus[].utilization`, `thermal.cpuCelsius`, `thermal.gpuCelsius`,
`thermal.peakCelsius`, the `power` totals, `network.rx/tx`, `disk.read/write`
and `battery.percentage/charging` where they exist.

#### cpu

| Key | Meaning |
|---|---|
| `total`, `user`, `system`, `nice`, `iowait`, `steal`, `idle` | fractions of all cores |
| `perCore` | array of fractions, one per logical core |
| `kinds` | string, one character per core: `P` performance, `E` efficiency, `?` unknown |
| `clockMHz`, `performanceClockMHz`, `efficiencyClockMHz` | average clocks |
| `load` | `[one, five, fifteen]` load averages |
| `processes`, `threads`, `zombies` | counts |

#### memory

`total`, `used`, `available`, `free`, `app`, `wired`, `compressed`, `cached`,
`buffers`, `active`, `inactive`, `purgeable` (bytes); `pressure` (fraction of
memory the system cannot reclaim cheaply); `pressureLevel` (`normal`,
`warning`, `critical`); `swap` with `total`, `used`, `free` (bytes), `inRate`,
`outRate` (bytes/s), `encrypted`.

#### gpus

Array, most important GPU first. Each: `name`, `vendor` (`apple`, `intel`,
`amd`, `nvidia`, …), `utilization` (fraction), `engines` (object of engine
name → fraction, for example `render`, `media`, `compute`, `copy`, `tiler`),
`memoryUsed`, `memoryTotal`, `memoryAllocated` (bytes), `clockMHz`,
`maxClockMHz`, `celsius`, `watts`, `fanRPM`, `fanPercent`, `coreCount`.

#### thermal

`sensors`: array of `{"key","label","celsius","category","high","critical"}`.
`key` is short (it is shown in a dense grid), `label` is the full name.
`category` is one of `CPU`, `GPU`, `SoC`, `Memory`, `Storage`, `Battery`,
`Power`, `Ambient`, `Other`. `high` and `critical` are the hardware's own limits.

`fans`: array of `{"index","label","rpm","minRPM","maxRPM"}`.

Headline values: `cpuCelsius`, `gpuCelsius`, `socCelsius`, `batteryCelsius`,
`storageCelsius`, `peakCelsius`, and `state` (`nominal`, `fair`, `serious`,
`critical`).

#### power

`cpuWatts`, `gpuWatts`, `aneWatts`, `packageWatts`, `systemWatts`,
`systemTotalWatts`, `dcInWatts`, `adapterWatts`.

#### network

`rx`, `tx` (bytes/s, physical interfaces summed), `rxTotal`, `txTotal` (bytes
this session), `primaryInterface`, `localAddress`, and `interfaces`: array of
`{"name","rx","tx","speedMbps","up"}`.

#### disk

`read`, `write` (bytes/s, whole physical disks summed), `readTotal`,
`writeTotal` (bytes this session), and `volumes`: array of
`{"name","mount","fs","total","available"}`, the system volume first.

#### battery

`present`, `percentage` (fraction), `charging`, `pluggedIn`,
`timeRemainingMinutes`, `cycleCount`, `designCapacity`, `maxCapacity`,
`celsius`, `voltage`, `amperage`, `condition`, `systemWatts`, `chargingWatts`,
`adapterWatts`.

#### pressure

Percent of time work stalled over the last 10 seconds: `cpu`, `memory`, `io`
(some tasks waiting), `memoryFull`, `ioFull` (all tasks waiting).

#### system

`uptime` (seconds), `rebootRequired`, `rebootReason`, `updates`,
`securityUpdates`, `failedServices` (array of names), `containers` (count of
running containers).

#### processes

```json
{"count":742,"sampledAt":1792141977889,"interval":1.0,"gpuAttribution":false,
 "rows":[{"pid":123,"name":"node","user":"alex","start":1792137384775000,
          "path":"/usr/bin/node","cmd":"node server.js","cpu":5.8,"memory":433000000,
          "gpu":0,"energy":0,"diskRead":0,"diskWrite":0,"wakeups":0,"threads":11}],
 "rank":{"cpu":[123],"memory":[123],"disk":[123]}}
```

`rows` holds every process that placed in any ranking, once. `rank` lists pids
best first, at most 20 per metric (`cpu`, `memory`, `gpu`, `energy`, `disk`).
`cpu` is percent of one core, `memory` is resident bytes, `gpu` is percent,
disk rates are bytes/s, `start` is microseconds since the epoch. Agents strip
secrets (tokens, passwords, keys) from `cmd` before sending it.

#### sleep (macOS)

`{"sampled":true,"blockers":[{"pid","name","display","system","assertions":[…]}]}`

### notice (agent → app, optional)

```json
{"type":"notice","code":"rapl-denied","message":"CPU power needs read access to /sys/class/powercap. Run: rex-boing-agent doctor"}
```

## Versioning

`protocol` only changes for incompatible changes. Adding keys is not one. The
app accepts the current and the previous protocol version, and never forces an
agent upgrade.
