// Package manage installs, upgrades and removes the agent and its restricted
// SSH key, and produces pairing codes. OS-specific pieces live in
// manage_unix.go and manage_windows.go; the exported API is here.
package manage

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// KeyCommentPrefix starts the comment of every key line this agent installs.
// uninstall finds its own lines by it, and never touches any other line.
const KeyCommentPrefix = "rex-boing-remote:"

// InstallOptions configures Install.
type InstallOptions struct {
	// Key is one OpenSSH public key line ("ssh-ed25519 AAAA… comment").
	Key string
	// Label names the Mac the key belongs to; it becomes the key's comment
	// after KeyCommentPrefix. Defaults to the key's own comment.
	Label string
}

// Install copies the running executable to the install directory if it is
// not already there, and adds Key to the user's authorized keys, restricted
// to running this agent. Idempotent: an existing line for the same key is
// replaced, not duplicated. The result's details say "agentCopied" when the
// installed binary was replaced.
func Install(o InstallOptions) wire.Result { return install(o) }

// Uninstall removes every key line this agent installed and the install
// directory.
func Uninstall() wire.Result { return uninstall() }

// Upgrade reads exactly size bytes of a new agent from r, checks the SHA-256,
// and replaces the installed executable with it.
func Upgrade(r io.Reader, sha256Hex string, size int64) wire.Result {
	return upgrade(r, sha256Hex, size)
}

// PairCode returns an "rbr1:" pairing code for this machine.
func PairCode() (string, error) { return pairCode() }

// InstallDir is where the agent lives on this OS.
func InstallDir() string { return installDir() }

// ExecutableName is the agent's file name on this OS.
func ExecutableName() string { return executableName() }

// staleAfter is how old a temporary file must be before CleanupOld takes it
// for one that a killed upgrade, install or history save left behind, and
// not one that a run in progress is still writing.
const staleAfter = time.Hour

// removeStale deletes the files in dir whose names (lower-cased) match and
// that are older than staleAfter.
func removeStale(dir string, match func(name string) bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !match(strings.ToLower(e.Name())) {
			continue
		}
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > staleAfter {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
