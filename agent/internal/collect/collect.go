// Package collect reads the machine. Each OS has its own implementation of
// newCollector in a build-tagged file (collect_linux.go, collect_windows.go,
// collect_other.go); everything above this package is OS-independent.
package collect

import "github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"

// Collector produces samples. It owns every counter baseline, so it also
// decides the interval a sample's rates cover and whether they are valid.
//
// Sample is called from one goroutine only. It must never block for long:
// slow sources (process scans, nvidia-smi, package-manager state) are
// refreshed on their own cadence and their last values reused in between.
type Collector interface {
	// Host describes the machine; called once per stream, for hello.
	Host() wire.Host
	// Capabilities lists what this machine can report (informative).
	Capabilities() []string
	// Sample reads the machine. It fills every section the detail level asks
	// for and sets Interval and Resync; the caller sets Type, Seq, T, Detail.
	Sample(detail wire.Detail) *wire.Sample
	// Doctor explains what can and cannot be read, and how to fix it.
	Doctor() []Check
	// Notices returns one-off hints for the user (for example "CPU power
	// needs read access"); called after the first sample.
	Notices() []wire.Notice
	Close()
}

// Check is one line of the doctor report.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// New returns the collector for this OS.
func New() Collector { return newCollector() }

// ProcessScanner is implemented by collectors that can read the process
// table on its own, without the rest of a full sample. The background agent
// uses it to keep the busiest processes without paying for sensor lists and
// volumes. Rates in the table cover the time since the previous scan (or
// full sample).
type ProcessScanner interface {
	ScanProcesses() *wire.Processes
}
