#!/bin/sh
# Rex Boing Remote — agent installer for Linux and macOS.
#
# Installs the agent for the user who runs it (no root, nothing listening),
# authorises your Mac's key to start it, and prints a pairing code to paste
# into Rex Boing Remote. The app shows this exact command, key included:
#
#   curl -fsSL https://github.com/rexyrex/Rex-Boing-Remote/releases/latest/download/install.sh \
#     | sh -s -- --key 'ssh-ed25519 AAAA… rex-boing-remote:Your-Mac'
#
# Options:
#   --key KEY        the Mac's public key line (required unless --uninstall)
#   --label NAME     what to call that Mac on this server (default: from the key)
#   --version vX.Y.Z install a specific release instead of the latest
#   --uninstall      remove the agent, its background service and the keys
#                    it installed (fetching the agent first if its file is gone)
#
# Every download is checked against the release's SHA256SUMS, and that file
# against the project's signing key when ssh-keygen can verify signatures.
set -eu

REPO="rexyrex/Rex-Boing-Remote"
SIGNER='rex-boing-remote namespaces="rex-boing-remote" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGC8OLOTRQf2g4C0BGK978SmH6lCfXGb4E7wrN+KlnFf'
KEY=""
LABEL=""
VERSION="latest"
UNINSTALL=0
INSTALL_DIR="$HOME/.local/share/rex-boing-remote"

say() { printf '%s\n' "$*"; }
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --key) KEY="${2:-}"; shift 2 ;;
        --label) LABEL="${2:-}"; shift 2 ;;
        --version) VERSION="${2:-}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,19p' "$0" 2>/dev/null || true; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

# Root under a sudo that keeps HOME would put the agent and the key in
# another user's home as root's files, which that user cannot change and
# sshd, reading their keys as them, cannot read: their key logins would stop.
if [ "$(id -u)" -eq 0 ]; then
    HOME_OWNER=$(ls -ldnL "$HOME" 2>/dev/null | awk '{print $3}')
    if [ -n "$HOME_OWNER" ] && [ "$HOME_OWNER" != 0 ]; then
        fail "you are root, but HOME ($HOME) belongs to another user (uid $HOME_OWNER). Run this as that user, without sudo."
    fi
fi

# Whether the agent left anything to remove: its directory, a key line it
# installed, or its service.
agent_left_traces() {
    [ -e "$INSTALL_DIR" ] ||
        grep -qs 'rex-boing-remote:' "$HOME/.ssh/authorized_keys" ||
        [ -e "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/rex-boing-agent.service" ] ||
        [ -e "$HOME/Library/LaunchAgents/com.rexyrex.rex-boing-remote.agent.plist" ]
}

if [ "$UNINSTALL" -eq 1 ]; then
    if [ -x "$INSTALL_DIR/rex-boing-agent" ]; then
        "$INSTALL_DIR/rex-boing-agent" uninstall
        exit 0
    fi
    if ! agent_left_traces; then
        say "The agent isn't installed for $(id -un)."
        exit 0
    fi
    # Its keys or its service outlived the agent's own file: download the
    # agent (checked as for an install) to remove them.
    say "The agent's file is missing, but it left keys or a service behind."
else
    [ -n "$KEY" ] || fail "missing --key. Copy the full command from Rex Boing Remote › Add Server."

    if [ "$(id -u)" -eq 0 ]; then
        say "Note: you are root, so Rex Boing Remote will log in as root. Many servers forbid that;"
        say "running this as the normal user you want to monitor with is better."
    fi
fi

case "$(uname -s)" in
    Linux) OS=linux ;;
    Darwin) OS=darwin ;;
    *) fail "$(uname -s) isn't supported yet. The agent runs on Linux, macOS and Windows." ;;
esac
MACHINE=$(uname -m)
if [ "$OS" = darwin ]; then
    ASSET="rex-boing-agent-darwin-universal"
else
    case "$MACHINE" in
        x86_64|amd64) ASSET="rex-boing-agent-linux-amd64" ;;
        aarch64|arm64|armv8l) ASSET="rex-boing-agent-linux-arm64" ;;
        armv6*|armv7*|arm|armhf) ASSET="rex-boing-agent-linux-arm" ;;
        *) fail "this processor ($MACHINE) isn't supported yet." ;;
    esac
fi

if [ "$VERSION" = latest ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
fi

# Not in /tmp: the agent runs from here, and hardened systems mount /tmp
# noexec.
mkdir -p "$HOME/.local/share"
TMP=$(mktemp -d "$HOME/.local/share/.rex-boing-install.XXXXXX") || fail "couldn't create a temporary directory in $HOME/.local/share."
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        fail "needs curl or wget to download the agent."
    fi
}

say "Downloading the Rex Boing Remote agent ($ASSET)…"
fetch "$BASE/$ASSET" "$TMP/rex-boing-agent" || fail "couldn't download $BASE/$ASSET"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || fail "couldn't download the checksums."

# Signatures need OpenSSH 8.1 or later; older systems rely on the checksum.
# ssh-keygen cannot say its version, so ask ssh, or else sshd, which comes
# from the same release: a server can have openssh-server without the
# client (RHEL's openssh-clients). sshd -V prints the version, and an sshd
# too old to know -V prints it in its usage message.
openssh_version() {
    {
        ssh -V 2>&1 || true
        for sshd in "$(command -v sshd 2>/dev/null || true)" /usr/sbin/sshd /usr/local/sbin/sshd; do
            if [ -n "$sshd" ] && [ -x "$sshd" ]; then
                "$sshd" -V 2>&1 || true
                break
            fi
        done
    } | sed -n 's/^OpenSSH_\([0-9]*\)\.\([0-9]*\).*/\1 \2/p' | head -n 1
}
openssh_can_verify() {
    v=$(openssh_version)
    [ -n "$v" ] || return 1
    set -- $v
    [ "$1" -gt 8 ] || { [ "$1" -eq 8 ] && [ "$2" -ge 1 ]; }
}
if command -v ssh-keygen >/dev/null 2>&1 && openssh_can_verify; then
    fetch "$BASE/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" || fail "couldn't download the release's signature."
    printf '%s\n' "$SIGNER" > "$TMP/allowed_signers"
    ssh-keygen -Y verify -f "$TMP/allowed_signers" -I rex-boing-remote -n rex-boing-remote \
        -s "$TMP/SHA256SUMS.sig" < "$TMP/SHA256SUMS" >/dev/null 2>&1 \
        || fail "the release's signature doesn't match. Nothing was installed."
    say "Signature checked."
else
    say "This system's OpenSSH can't check signatures; relying on the checksum."
fi

EXPECTED=$(grep " $ASSET\$" "$TMP/SHA256SUMS" | awk '{print $1}')
[ -n "$EXPECTED" ] || fail "no checksum for $ASSET."
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$TMP/rex-boing-agent" | awk '{print $1}')
else
    ACTUAL=$(shasum -a 256 "$TMP/rex-boing-agent" | awk '{print $1}')
fi
[ "$EXPECTED" = "$ACTUAL" ] || fail "the download's checksum doesn't match. Nothing was installed."
chmod 755 "$TMP/rex-boing-agent"

if [ "$UNINSTALL" -eq 1 ]; then
    # It finds the keys and the service from HOME, not from where it runs.
    "$TMP/rex-boing-agent" uninstall
    exit 0
fi

if [ -n "$LABEL" ]; then
    printf '%s\n' "$KEY" | "$TMP/rex-boing-agent" install --label "$LABEL" >"$TMP/result" || { cat "$TMP/result"; fail "install failed."; }
else
    printf '%s\n' "$KEY" | "$TMP/rex-boing-agent" install >"$TMP/result" || { cat "$TMP/result"; fail "install failed."; }
fi

# SSH has to be on for the Mac to reach this machine.
if [ "$OS" = darwin ]; then
    say "Make sure Remote Login is on: System Settings › General › Sharing › Remote Login."
elif command -v ss >/dev/null 2>&1 && ! ss -ltn 2>/dev/null | grep -q ':22 \|:22$'; then
    if ! grep -qiE '^\s*Port\s+[0-9]+' /etc/ssh/sshd_config 2>/dev/null; then
        say "Note: nothing seems to listen for SSH on port 22. Install and start openssh-server."
    fi
fi

CODE=$("$INSTALL_DIR/rex-boing-agent" pair-code)
say ""
say "Installed for $(id -un). Paste this into Rex Boing Remote › Add Server › Set it up from the server:"
say ""
say "  $CODE"
say ""
