# Rex Boing Remote

Your servers in the Mac menu bar, each with its own running rex.

<p align="center"><img src="docs/menubar.png" width="584" alt="Three menu bar items, each with Remote's signal mark beside the character: a ninja for a gaming PC with its GPU load, a rex for a home server with its CPU, and the fleet rex with how many servers are live and the busiest one's CPU."></p>

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/fleet.png" alt="The fleet list: a home server flagged for a reboot, a gaming PC, and a Mac mini, each with CPU, memory, GPU, temperature and power, and a Raspberry Pi that isn't answering."></td>
    <td width="50%" valign="top"><img src="docs/dashboard.png" alt="The home server's dashboard: processor, graphics, memory and thermals cards with their history, pressure stall, a system card saying a restart is needed for a new kernel, and the top processes."></td>
  </tr>
</table>

<p align="center"><img src="docs/window.png" width="900" alt="The window: the servers down a sidebar, and all of them beside it as tiles, each with its character, a CPU trace and its vitals. One is flagged for a restart, one isn't answering."></p>

<sub>The pictures come from the app's own views in demo mode: the servers are made up, the interface is real. See <a href="CONTRIBUTING.md#demo-mode-no-servers-needed">CONTRIBUTING.md</a>.</sub>

Rex Boing Remote watches Linux, macOS and Windows machines over the SSH you
already use, and shows them with the cards and characters of
[Rex Boing](https://github.com/rexyrex/Rex-Boing): CPU per core, GPU engines,
memory and swap, every temperature sensor and fan, power, pressure stall,
network, disks and filesystems, the top processes, and whether a server needs
a reboot or has failed services.

- **Nothing to open on the server.** No port, no web server, no daemon. The
  app starts a small agent over SSH while it watches, and the agent exits
  when the session ends.
- **History while you're away, if you want it.** Turn on *Keep history while
  this Mac is away* for a server, and the agent keeps sampling there as a
  service of your user (still no port, no root), so the dashboard shows what
  happened overnight: 48 hours of vitals and the busiest processes, or up to
  30 days kept on the server for you (or an AI agent) to ask about.
- **No root.** The agent runs as the user you log in as. It can only read.
- **Reconnects by itself.** After your Mac sleeps, after either side reboots,
  after Wi-Fi or a VPN changes.
- **Works with your SSH setup.** Aliases, jump hosts, `ProxyCommand`,
  1Password and Secretive agents, hardware keys: if `ssh myserver` works in
  Terminal, it works here.
- **Ask an AI agent.** Claude Code, Codex and other MCP clients can read what
  the app holds: which servers are up, their readings, top processes and
  history. Read-only, over a port local to your Mac's login session.

macOS 14 or later on the Mac. Servers: Linux (x86-64, ARM64, ARMv6/7 —
Raspberry Pi included), macOS 14+, Windows 10/11 and Server 2019+.

## Install

```bash
brew install --cask rexyrex/tap/rex-boing-remote
```

Or download `Rex.Boing.Remote.zip` from the
[latest release](https://github.com/rexyrex/Rex-Boing-Remote/releases/latest),
unzip it and move it to Applications. It is signed and notarized.

When a new version is out, the menu bar popover, the window, the rexes'
right-click menu and Settings say so, with a link to the release
(`brew upgrade --cask rex-boing-remote` if you installed with Homebrew).

## Add a server

Open the app; the Add Server window comes up on its own the first time.

<table>
  <tr>
    <td width="50%" valign="top"><img src="docs/add-server-ssh.png" alt="Add a Server, over SSH: the hosts from ~/.ssh/config and the machines on the network that accept SSH, or a user@host to type."></td>
    <td width="50%" valign="top"><img src="docs/add-server-code.png" alt="Add a Server, from the server's own end: the one command to run there, with this Mac's key in it, and a field for the pairing code it prints."></td>
  </tr>
</table>

**If you can already `ssh` to it**, pick it from the list (your
`~/.ssh/config` hosts and the machines on your network that accept SSH) or
type `user@host`, and press Add. Any password, one-time code or new host key
is asked for in a dialog, once. The app copies the agent over, and adds its
own key to the server's `authorized_keys`, restricted so it can only ever
start the agent. Every later connection uses that key, so reconnecting never
needs you, your SSH agent or your hardware key again.

**If you can't ssh to it from this Mac yet**, choose *Set it up from the
server*. The app shows one command, with your Mac's key already in it. Run it
on the server:

```bash
curl -fsSL https://github.com/rexyrex/Rex-Boing-Remote/releases/latest/download/install.sh \
  | sh -s -- --key 'ssh-ed25519 AAAA… rex-boing-remote:Your-Mac'
```

or, on Windows, in PowerShell:

```powershell
& ([scriptblock]::Create((irm https://github.com/rexyrex/Rex-Boing-Remote/releases/latest/download/install.ps1))) -Key 'ssh-ed25519 AAAA… rex-boing-remote:Your-Mac'
```

It prints a pairing code (`rbr1:…`). Paste it into the app. The code carries
the server's addresses and its SSH host keys, so the first connection is
already verified, and if the server has several addresses (home network,
Tailscale, public), the app finds whichever one answers.

SSH has to be on: install `openssh-server` on Linux; turn on *Remote Login*
on a Mac (System Settings › General › Sharing); add *OpenSSH Server* on
Windows (Settings › System › Optional features).

## Using it

- The **fleet rex** stands for all your servers and runs at the busiest one's
  CPU. Its caption says how many are live.
- **Pin** a server (Settings › Servers) to give it a rex of its own, with a
  readout of your choice beside it. The first server you add is pinned.
- Click a rex for the fleet list; click a server for its dashboard.
- **Open the window** for the long look: the window button in the popover,
  *Open Window* in a rex's right-click menu, or opening the app again from
  Applications. It is an ordinary resizable window with the servers down a
  sidebar. *All Servers* shows the fleet as tiles; a server shows a strip of
  headline readings over every card with its detail open, in up to three
  columns, with five minutes of history in the graphs. While it is open the
  app is in the Dock and ⌘-Tab; Settings › General can open it at launch.
- Everything Remote draws about itself is violet — its name, its characters,
  the signal mark beside each rex in the menu bar — and every dashboard is
  headed by a banner naming the machine it is reading and how it gets there,
  so it is never mistaken for Rex Boing's view of this Mac.
- A server that drops off falls asleep in the menu bar, and its row says why
  and when the next try is. *Retry Now* skips the wait.

## History while your Mac is away

Each dashboard has a **History** card: the last 15 minutes, 4 hours or 48
hours of CPU, memory, temperature, power, network and disk. Point at a moment
to see the readings then and the busiest processes of that quarter hour.

On its own, the app can only record while it is connected. To fill the gaps
when your Mac sleeps or leaves home, turn on **Keep history while this Mac is
away** for a server in Settings › Servers. The app then asks the agent to run
in the background on that server, as your user:

| Server | Runs as |
|---|---|
| Linux | a systemd user service. Your services only keep running after you log out if *lingering* is on; the app says if it isn't, with the one command that turns it on (`sudo loginctl enable-linger <you>`). |
| macOS | a LaunchAgent, started again at every login. |
| Windows | a Scheduled Task, started when you sign in, running while you are signed in. |

It samples every 2 seconds, keeps 48 hours (in its own folder, so it survives
restarts), opens no port, and talks only to a socket only your user can reach.
On reconnect, the agent sends what it kept and the graphs fill in. Turning the
setting off removes the service and the history it kept.

**Keep on the server** (below the switch) keeps 7, 14 or 30 days instead:
the vitals, and for every quarter hour what each process used, CPU, memory,
disk and GPU. That takes about 0.7 MB a day on the server. The History card
still shows the last 48 hours; for the rest, ask the server, or have an AI
agent with SSH access ask it:

```
~/.local/share/rex-boing-remote/rex-boing-agent history --at 03:00
~/.local/share/rex-boing-remote/rex-boing-agent history --from 3d --json
```

The first prints a summary of that quarter hour: the vitals, and which
processes used the most CPU time, memory, disk and GPU. The second prints
everything kept over the last three days as JSON. `history --help` lists
every way to name a moment, and PROTOCOL.md ("Reading history on the server")
says what each value means.

## Ask an AI agent

Rex Boing Remote is also an MCP server, so an AI agent can answer questions
about your servers from what the app holds: "is anything down?", "what's
using the home server's CPU?", "what was busy at 3 a.m.?". Add it to Claude
Code or Codex with the command in Settings › General › AI agents, which
carries this copy's own path:

```bash
claude mcp add --scope user rex-boing-remote -- "/Applications/Rex Boing Remote.app/Contents/MacOS/Rex Boing Remote" mcp
codex mcp add rex-boing-remote -- "/Applications/Rex Boing Remote.app/Contents/MacOS/Rex Boing Remote" mcp
```

Any other MCP client (Claude Desktop, an IDE) takes the same executable with
the argument `mcp`. The tools:

| Tool | What it answers |
|---|---|
| `list_servers` | Every server: how it is reached, its OS and model, whether it is live or down (why, since when, the next try), its CPU, memory, GPU, temperature and power, what needs you (a reboot, failed services, updates, the agent's notices), and whether it keeps history in the background. |
| `get_server_snapshot` | Everything one server's dashboard shows now: CPU per core, GPUs, memory and swap, sensors and fans, power, pressure stall, network, disks and filesystems, battery and system, part by part if you like. |
| `get_server_processes` | Its top processes by CPU, memory, GPU or disk, with their command lines. |
| `get_server_history` | Its vitals over a window of up to the last 48 hours, evened out to a few dozen points with the mean, low and high of each. |
| `get_server_process_history` | The busiest processes of each quarter hour: what was running at a moment, or the busiest quarter hours of a window. |

Units are in the key names (`cpuPercent`, `memoryUsedBytes`, `cpuCelsius`),
times carry your Mac's UTC offset, and a reading a server can't report is
left out rather than sent as 0. A server that is down still answers with its
last readings and history, and says why it is down.

The app holds 48 hours. What a server keeps beyond that (*Keep on the
server*, up to 30 days) stays on the server: an agent with SSH access of its
own reads it there with `rex-boing-agent history`, as above. The MCP server
can't reach it, by design: the app's key is not allowed to run `history`.

How it works: the agent starts the app's executable with `mcp`, a small relay
on stdin and stdout that shows nothing. It answers the handshake and the
tool list itself, and passes each question to the running app over a local
Mach message port, starting the app in the background if it isn't running
(`mcp --no-launch` turns that off). There is no network listener, no socket
file and no TCP port: only programs running as you in your login session can
reach the port. Every tool only reads; none adds, removes or changes a
server or a setting. While an agent asks for a server's snapshot or
processes, the app asks that server for full detail, as an open dashboard
does, and goes back to the usual vitals some seconds after the last
question; nothing else is asked of a server, and the restricted key is
unchanged. Answers carry what the dashboards show and no more: never the
app's SSH key, key paths or pairing codes, and command lines arrive with
passwords and tokens already removed by the agent. What an agent reads goes
where that agent sends it, usually its model's provider. To stop it, turn off
*Let AI agents read your servers' readings*: the port goes away and agents
are told it is off.

From a shell, `"…/Rex Boing Remote" tools` lists the tools,
`"…/Rex Boing Remote" call list_servers` runs one, and `mcp --help` prints
the options and registration commands.

## What each kind of server reports

<p align="center"><img src="docs/dashboard-lower.png" width="440" alt="Further down a dashboard: the top processes, power, network with the server's address, storage, and every filesystem with its free space."></p>

| | Linux | macOS | Windows |
|---|---|---|---|
| CPU per core, load, processes | ✓ | ✓ | ✓ (no load average) |
| GPU busy, engines, memory | Intel, AMD, NVIDIA | Apple | any vendor (engines); NVIDIA temperature, power, fan |
| Temperatures, fans | hwmon, thermal zones | every SMC sensor | thermal zones; more with LibreHardwareMonitor |
| CPU power | RAPL, after one `udev` rule | ✓ | via LibreHardwareMonitor |
| Pressure stall | ✓ | memory pressure | — |
| Reboot needed, updates, failed services, containers | ✓ | — | reboot needed |

Run `~/.local/share/rex-boing-remote/rex-boing-agent doctor` on a server to see
what it can read and how to unlock the rest.

## How it works

```
Mac: Rex Boing Remote ──ssh (your route: LAN, VPN, jump host, tunnel)──▶ server: rex-boing-agent
                      ◀── one JSON line per sample ──
                      ── what's on screen ──▶
```

The agent is one static file in `~/.local/share/rex-boing-remote/` (Windows:
`%LOCALAPPDATA%\RexBoingRemote\`). It samples only what the screen shows: a
few hundred bytes every couple of seconds for the menu bar, everything once a
second while you look at that server's dashboard. The format is documented in
[PROTOCOL.md](PROTOCOL.md), so anyone can write an agent for another system.

The Linux and Windows agents are Go. The macOS agent is Rex Boing's own
sampling code, built headless, which is also why the dashboard cards look the
same as Rex Boing's: they are the same code, shared through the
`RexBoingKit` package in the Rex Boing repository.

## Security and privacy

- The app talks only to the servers you add, and to GitHub once a day to see
  whether a newer release is out (it carries nothing about your Mac or your
  servers; **Check for new versions** in Settings › General turns it off). No
  telemetry, no analytics.
- AI agents you add it to read what the dashboards show, through a port
  local to your login session, never the network; they can't change
  anything (see [Ask an AI agent](#ask-an-ai-agent)).
- The key the app installs is restricted on the server with `restrict` and a
  forced command: it cannot open a shell, forward ports or run anything but the
  agent.
- Host keys are never accepted silently: a new one is shown for you to
  confirm, and a changed one stops the connection.
- The agent removes passwords and tokens from command lines before they leave
  the server.
- Release files are checksummed, and the checksums signed with the project's
  key ([docs/allowed_signers](docs/allowed_signers)). `install.sh` checks
  both (the signature where OpenSSH 8.1 or later is installed); `install.ps1`
  checks the checksum only.

See [SECURITY.md](SECURITY.md) for the details and how to report a problem.

## Removing a server

Settings › Servers › select it › **−**. Leave *Also remove the agent* on and
the app asks the agent to delete itself and its key; nothing else on the
server is touched. On the server itself, `install.sh --uninstall` (or
`install.ps1 -Uninstall`) does the same.

## Building from source

Needs Xcode 26 or later, [XcodeGen](https://github.com/yonaskolb/XcodeGen) and Go 1.24 or later.
(Without Go, a build keeps the Linux and Windows agents already in
`build/agents` rather than rebuilding them — enough to work on the Mac app.)

```bash
Scripts/build.sh            # agents and app, into dist/
Scripts/build.sh --install  # and into /Applications
cd agent && go test ./...   # the Go agent's tests
```

To work on Rex Boing's shared code at the same time, point the build at your
checkout: `REX_BOING_PATH=../Rex-Boing Scripts/build.sh`. No servers to try it
on? `open "dist/Rex Boing Remote.app" --args --demo` starts it with made-up
ones, and `mcp --demo` lets an agent ask that copy only. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
