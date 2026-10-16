//go:build !linux && !windows

package collect

// A minimal collector so the agent builds (and can be tested) on macOS and
// the BSDs. Macs are monitored by Rex Boing Remote natively; other systems
// need an agent of their own.

import (
	"os"
	"runtime"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

type otherCollector struct {
	window Window
}

func newCollector() Collector { return &otherCollector{} }

func (c *otherCollector) Host() wire.Host {
	name, _ := os.Hostname()
	return wire.Host{Hostname: name, LogicalCores: runtime.NumCPU(), Virtualization: "none"}
}

func (c *otherCollector) Capabilities() []string { return []string{} }

func (c *otherCollector) Sample(detail wire.Detail) *wire.Sample {
	interval, resync := c.window.Next(1)
	return &wire.Sample{Interval: interval, Resync: resync}
}

func (c *otherCollector) Doctor() []Check {
	return []Check{{
		Name:   "OS",
		OK:     false,
		Detail: "This agent cannot read " + runtime.GOOS + " machines; samples carry no readings.",
		Fix:    "Use the agent built for this OS, or the Rex Boing Remote app itself on a Mac.",
	}}
}

func (c *otherCollector) Notices() []wire.Notice {
	return []wire.Notice{{Type: "notice", Code: "unsupported-os",
		Message: "This agent cannot read " + runtime.GOOS + "; it needs the native agent for this OS."}}
}

func (c *otherCollector) Close() {}
