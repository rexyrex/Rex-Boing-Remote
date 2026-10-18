# Security

Rex Boing Remote is pointed at machines people care about, so its defaults are
meant to hold up to anyone reading the code.

## What the app does on your Mac

- Runs the system's `/usr/bin/ssh` and `/usr/bin/sftp` with your
  `~/.ssh/config`. It never edits `~/.ssh`; a host key you accept during setup
  is saved by ssh itself, as it would be from Terminal.
- Keeps its own files in `~/Library/Application Support/Rex Boing Remote/`:
  its SSH key pair (`id_ed25519`, mode 600), host keys pinned from pairing
  codes (`known_hosts`) and the server list.
- Connects only to the servers you add. There is no telemetry, analytics,
  crash reporting or update check.
- Answers ssh's prompts (passwords, codes, host keys) in its own dialogs during
  setup only, by acting as ssh's askpass helper. Answers go straight to ssh and
  are never stored. Background connections run with `BatchMode=yes` and can
  never prompt.

## What it does on a server

- Copies one executable into the user's home directory and appends one line
  to that user's `authorized_keys` (on Windows, for administrators,
  `%ProgramData%\ssh\administrators_authorized_keys`):

  ```
  restrict,command="'<agent path>' ssh" ssh-ed25519 AAAA… rex-boing-remote:<Mac name>
  ```

  `restrict` disables port, agent and X11 forwarding and the TTY. The forced
  command means the key can only run the agent, and the agent only accepts
  `stream`, `version`, `doctor`, `upgrade` (with a SHA-256 the new binary must
  match), `uninstall`, `pair-code`, `install-service` and `uninstall-service`,
  each in exactly that form. `upgrade` replaces the agent itself, so it is
  the one command that can put new code on the server; see below for what
  that means if the key is stolen.
- Runs as that user, never as root, and opens no network listener of any kind.
- Is read-only. It does not signal, change or start anything on the server,
  with one exception you opt into per server: background history.

## Background history (optional)

*Keep history while this Mac is away* (Settings › Servers) runs
`install-service` on the server. That registers the agent's `serve` command
with the user's own service manager (a systemd user unit, a LaunchAgent, or a
Scheduled Task at sign-in), as the user, without root. While it runs:

- It reads the same vitals the stream does, and the process table every 15
  seconds, with command lines redacted as in the stream.
- It keeps them in memory and in `history.json` in the agent's directory
  (mode 0600), at most 48 hours of vitals and 24 hours of process tables.
- It answers only on a Unix socket in a directory only the user can enter
  (mode 0700, socket 0600, peer user checked), or on Windows a named pipe
  whose ACL admits only the user and no remote clients. Never on a network
  port. `serve` cannot be started over the restricted key.
- On Linux, user services stop at logout unless lingering is on; turning it
  on (`loginctl enable-linger`) lets the user's services run while they are
  logged out.

Turning the setting off (`uninstall-service`), or removing the agent, stops
the service and deletes the history file.
- Strips secrets from process command lines (password and token flags,
  `*_TOKEN=` style variables, credentials in URLs, well-known token formats)
  before sending them.

## Trust and verification

- Pairing codes carry the server's SSH host keys, which the app pins under a
  per-server alias, so the first connection is verified rather than trusted.
- A host key that changes stops the connection until the user decides; the
  app never re-accepts it on its own.
- Release files are listed with their SHA-256 in `SHA256SUMS`, which is signed
  with the project key in [docs/allowed_signers](docs/allowed_signers)
  (`ssh-keygen -Y verify -n rex-boing-remote`). `install.sh` and
  `install.ps1` check the checksum, and `install.sh` checks the signature where
  OpenSSH 8.1 or later is present.
- The app and its macOS agent are signed with Developer ID and notarized. The
  agents the app copies to servers are the ones inside its signed bundle.

## What a compromise would mean

- **Someone with the app's private key** can do on your servers what the
  app does: read the same metrics and process lists, run `doctor` and
  `pair-code`, turn background history on or off, and `uninstall` the agent
  (with every Mac's key for it). The key gives no shell and no forwarding.
  What `upgrade` lets them do depends on the agent:
  - **Linux and Windows** (the Go agent), and **a macOS agent built from
    source**: `upgrade` installs whatever binary they send, as long as it
    matches the SHA-256 they also send, and runs it as that user. So the
    stolen key is, in the end, code execution as that user on every such
    server (on Windows, an administrator's account if that is where the
    agent was installed).
  - **macOS, with the signed agent from a release**: `upgrade` installs only
    a binary signed with the same Developer ID team as the agent already
    there, so the key can't put a program of its own in its place. (A
    build of your own is installed with your SSH access: Repair, or the
    install command.)

  Treat the key like an SSH key with a forced command, not like a read-only
  token. Remove a Mac's access by deleting its `rex-boing-remote:` line from
  `authorized_keys`, or with `rex-boing-agent uninstall`.
- **A compromised server** can send the app arbitrary data. The app treats
  every line as untrusted: lines over 1 MiB end the session, and nothing a
  server sends is executed or used as a path.

## Reporting a problem

Please open a [security advisory](https://github.com/rexyrex/Rex-Boing-Remote/security/advisories/new)
rather than a public issue.
