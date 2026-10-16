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
  match), `uninstall` and `pair-code`.
- Runs as that user, never as root, and opens no network listener of any kind.
- Is read-only. It does not signal, change or start anything on the server.
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

- **Someone with the app's private key** can start the agent on your servers
  and read the same metrics the app does. They cannot get a shell. Remove a
  Mac's access by deleting its `rex-boing-remote:` line from
  `authorized_keys`, or with `rex-boing-agent uninstall`.
- **A compromised server** can send the app arbitrary data. The app treats
  every line as untrusted: lines over 1 MiB end the session, and nothing a
  server sends is executed or used as a path.

## Reporting a problem

Please open a [security advisory](https://github.com/rexyrex/Rex-Boing-Remote/security/advisories/new)
rather than a public issue.
