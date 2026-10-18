//go:build !linux && !windows

package service

import (
	"runtime"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/serve"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// Installed is always false: this agent has no service manager to use here.
func Installed() bool { return false }

// Install explains that there is no service manager to install into. On
// macOS the Swift agent installs a LaunchAgent; this Go build is for tests.
func Install(agentPath, dir string) wire.Result {
	return wire.Result{OK: false, Error: "unsupported",
		Message: "This agent cannot install itself as a service on " + runtime.GOOS + ". Run \"" + agentPath + " serve\" from your init system instead."}
}

// Uninstall stops a serve started by hand.
func Uninstall(dir string) wire.Result {
	if serve.Stop(dir, 2*time.Second) == nil {
		serve.WaitStopped(dir, 5*time.Second)
		serve.RemoveEndpoint(dir)
		return wire.Result{OK: true, Message: "History is off: the background agent was stopped."}
	}
	serve.RemoveEndpoint(dir)
	return wire.Result{OK: true, Message: "History was already off."}
}

// Restart has nothing to restart.
func Restart(dir string) (bool, error) { return false, nil }

// Describe has nothing to describe.
func Describe(dir string) (bool, string) { return false, "" }
