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
  agent must never outlive its session. "Immediately" is as soon as it is
  between samples: a sample being taken is finished first, and so is the
  history fetch at the start of a session (at most 2 seconds, see "Background
  history").
* A line may be at most 1 MiB. The app drops a session that sends a longer one.
* Unknown keys must be ignored by both sides. Missing keys mean "unknown" or
  "not available on this machine", never zero, with one exception: a few
  counters and flags whose zero is common are left out when they are zero
  (or false), and for those absent means zero or unknown. They are
  `network.rxTotal`/`txTotal`, `disk.readTotal`/`writeTotal`,
  `memory.swap.encrypted`, `host.isAppleSilicon` and the host's core counts,
  and in process rows `user`, `start`, `path`, `cmd`, `gpu`, `energy`,
  `diskRead`, `diskWrite`, `wakeups` and `threads`.

## Commands

The agent is one executable with these commands:

| Command | Purpose |
|---|---|
| `stream` | The live session described below. |
| `version` | Prints one line: `{"name":"rex-boing-agent","version":"0.1.0","protocol":1,"os":"linux","arch":"amd64"}` |
| `doctor` | A human-readable report of what this machine can and cannot report, and why. `doctor --json` prints the same as JSON. |
| `install [--label NAME]` | Reads one OpenSSH public key line from stdin (or `--key`), adds it to the user's `authorized_keys` restricted to this agent, prints a JSON result. `--label` names the Mac in the key's comment (default: the key's own comment). It copies itself into the install directory first, unless it already runs from there. When the Go agent did, its details say `"agentCopied":"true"`, and it restarts a running background service on the new binary, like `upgrade`. |
| `pair-code` | Prints a pairing code for this machine (see below). |
| `upgrade --sha256 HEX --size N` | Reads exactly N bytes of a new agent from stdin, verifies the hash, replaces itself, prints a JSON result. |
| `uninstall` | Removes the background service (if any), the keys it installed and its own files, prints a JSON result. |
| `serve [--interval S]` | Optional background mode: samples on its own and keeps history for `stream` to send (see "Background history"). Runs until stopped. |
| `install-service` | Registers `serve` with the user's own service manager, starts it, prints a JSON result. |
| `uninstall-service` | Stops and removes that service and deletes the history it kept, prints a JSON result. |
| `ssh` | Entry point used by the restricted key. Runs the command named in `SSH_ORIGINAL_COMMAND` if it is exactly one of `stream`, `version`, `doctor`, `doctor --json`, `upgrade --sha256 HEX --size N`, `uninstall`, `pair-code`, `install-service` or `uninstall-service`, and refuses anything else, `serve` included. |

JSON results of `install`, `upgrade`, `uninstall`, `install-service` and `uninstall-service` have the shape
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
{"want":"history"}
{"interval":2}
```

* `vitals` (the default): the small set of numbers the menu bar and the fleet
  list show, and that history records.
* `full`: everything, including processes, for an open dashboard. Agents may
  sample processes and sensors less often than every tick and repeat the
  last values in between.
* `history`: send a fresh history message now. It does not change the
  detail. The app only asks agents that sent a history message in this
  session; an agent without background history ignores it.
* `interval`: seconds between samples, clamped by the agent to 0.5–10. Apps
  should not send 0 or less: the Go agent takes it as its default (1 second),
  the macOS agent as 0.5.

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

### history (agent → app, optional)

Sent right after the hello, before the first sample, when a background agent
(`serve`) is running for the user, and again whenever the app asks with
`{"want":"history"}`. An agent without one sends nothing, so the app knows
from the first sample that there is none. Every key is optional.

```json
{"type":"history","started":1792201150897,"interval":2,
 "tiers":[
   {"step":2,  "t":[1792201152897,1792201154897], "cpu":[0.0269,0.0097], "memory":[0.4113,0.4114], "cpuCelsius":[53,null]},
   {"step":30, "t":[1792201170000], "cpu":[0.0183], "cpuPeak":[0.0291], "memory":[0.4113]},
   {"step":300,"t":[], "cpu":[]}],
 "processes":[{"count":755,"sampledAt":1792201166922,"interval":15.977,"gpuAttribution":false,
               "rows":[{"pid":3176958,"name":"node","user":"alex","cmd":"node server.js","cpu":5.9,"memory":568586240}],
               "rank":{"cpu":[3176958],"memory":[3176958]}}]}
```

* `started`: when this background agent began, ms since the epoch.
* `interval`: seconds between its samples.
* `tiers`: finest first. Each is columnar: `t` lists the points' times (ms
  since the epoch, oldest first), and every series has one value per time,
  `null` where that reading was unavailable. A series the machine never
  reported is left out. A point covers the `step` seconds that end at its
  time. Windows are aligned to the epoch, so 5-minute points fall on :00,
  :05 and so on. Gaps (the machine was off) are simply missing points.

  | Tier | Step | Kept |
  |---|---|---|
  | 1 | the background interval (2 s by default) | 15 minutes, every sample |
  | 2 | 30 s | 4 hours, means of the samples in each window |
  | 3 | 300 s | 48 hours, means of the samples in each window |

  Windows still open are not sent. Samples marked `resync` are not recorded.

  | Series | Meaning |
  |---|---|
  | `cpu`, `cpuUser`, `cpuSystem` | fractions of all cores (`cpu.total`, `user`, `system`) |
  | `cpuPeak` | the highest single-sample `cpu` in the window (tiers 2 and 3) |
  | `memory`, `swap` | fractions in use (`used / total`) |
  | `gpu` | the first GPU's utilization |
  | `cpuCelsius` | `thermal.cpuCelsius`, else `socCelsius` |
  | `gpuCelsius` | `thermal.gpuCelsius` |
  | `watts` | whole-machine power: `systemTotalWatts`, else `systemWatts`, else `packageWatts` |
  | `rx`, `tx`, `read`, `write` | network and disk bytes per second |

* `processes`: for every quarter hour of the last 24 hours, the process table
  of its busiest moment (the most CPU across the processes listed), in the
  same shape as a sample's `processes`, trimmed to the five leaders by CPU
  and the five by memory: `rank` has only `cpu` and `memory`, and the rows
  keep only `pid`, `name`, `user`, `start`, `cmd` (cut to 200 bytes, at a
  character boundary, with `…` after a cut), `cpu`, `memory` and `threads`;
  no `path`, and `gpuAttribution` is false. `interval` is the window that
  table measured.

The message fits in one line of at most 1 MiB: an agent leaves out the
process tables, then the finest tier, before it would exceed that.

## Background history

Without help, an agent only samples while the app is connected. Background
history keeps a server sampling while the Mac sleeps or is away, so the
dashboard can show what happened in the meantime. It is optional, and
everything else works without it.

`serve` samples vitals every 2 seconds (`--interval`, 0.5–10; to the Go
agent, 0 or less means the default), and the process table every 15 seconds,
into the rings the history message describes. It:

* saves them to `history.json` in the install directory, through a temporary
  file and a rename, every 10 minutes and when it stops (SIGTERM, Ctrl-C, or
  a `stop` request; the Go agent also on SIGHUP, unless started under nohup),
  and loads them when it starts, so history survives restarts and reboots.
  The file is the history message itself, mode 0600;
* answers on a local endpoint only, never a TCP port:
  * Linux and macOS: the Unix socket `<install dir>/run/serve.sock`, mode
    0600, in a directory of mode 0700 owned by the user. Connections from
    other users are refused (`SO_PEERCRED`, `getpeereid`). When a long home
    directory makes that path too long for a socket, the Go agent uses
    `/tmp/rex-boing-remote-<uid>/serve.sock` instead (a fixed `/tmp`, since a
    service and an SSH session may not share `$TMPDIR`), with the same
    checks, and removes that directory when history is turned off. The
    macOS agent uses the same name in the user's own temporary directory;
  * Windows: the named pipe `\\.\pipe\rex-boing-remote-<user SID>`, owned by
    the user, with an ACL that grants only the user, and closed to remote
    clients. Clients check the pipe's owner before they use it.
* runs once per user: a second `serve` waits up to 5 seconds for the first to
  finish (a restart), then exits cleanly.

The endpoint speaks one request line and one answer line per connection:
`{"want":"history"}` (the history message), `{"want":"status"}`
(`{"type":"status","pid":…,"version":…,"started":…,"interval":…,"oldest":…,"endpoint":…}`)
and `{"want":"stop"}` (`{"type":"stopping"}`, then save and exit). Anything
else gets `{"type":"error","message":"unknown request"}`.

`stream` asks the endpoint for the history (giving up after 2 seconds) and
sends it after its hello.

`install-service` runs the installed agent's `serve` with the user's own
service manager, as the user, without root:

| OS | Service | Notes |
|---|---|---|
| Linux | systemd user unit `~/.config/systemd/user/rex-boing-agent.service` | User services stop when the user's last session ends unless lingering is on. The agent turns it on where logind allows (`loginctl enable-linger`), and otherwise its result says to run `sudo loginctl enable-linger <user>` once. No systemd: the result says so. |
| macOS | LaunchAgent `~/Library/LaunchAgents/com.rexyrex.rex-boing-remote.agent.plist` | Loaded into the GUI session, or the background session when no one is logged in at the Mac, and again at every login. |
| Windows | Scheduled Task `\Rex Boing Remote agent`, at sign-in | Runs unelevated as the user, while the user is signed in (console or Remote Desktop). |

`upgrade` restarts a running service on the new binary, and so does the Go
agent's `install` when it replaced the binary. The Go agent answers once the
new `serve` answers (or after 8 seconds), so the next session's history fetch
finds it. On Linux the unit only starts while the agent's file is there
(`ConditionPathIsExecutable`).
`uninstall-service` and `uninstall` remove the service and the history.

## Versioning

`protocol` only changes for incompatible changes. Adding keys is not one. The
app accepts the current and the previous protocol version, and never forces an
agent upgrade.
