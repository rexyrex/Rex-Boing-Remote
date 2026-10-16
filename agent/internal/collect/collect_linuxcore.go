package collect

// The Linux collector itself: state, discovery cadence and the Sample loop
// body. No build tag: see collect_linuxfs.go. newCollector, which points it
// at the real root and wires the system calls in, is in collect_linux.go.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/nvidia"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxCollector reads a Linux machine from the files under root.
type linuxCollector struct {
	root string
	// When vitals last carried the system section.
	systemSentAt time.Time
	pageSize     uint64
	clkTck       float64

	// Wired in by newCollector; nil in fixture tests unless a test sets them.
	statfs      func(path string) (total, avail uint64, err error)
	ifaceIPv4   func(name string) string
	lookupUser  func(uid string) string
	failedUnits func(ctx context.Context) ([]string, error)
	nvidia      *nvidia.Reader

	window Window
	buf    []byte // scratch for the per-sample /proc reads

	host     wire.Host
	hostDone bool

	discoveredAt time.Time

	cpu     linuxCPUState
	mem     linuxMemState
	gpu     linuxGPUState
	thermal linuxThermalState
	power   linuxPowerState
	battery linuxBatteryState
	net     linuxNetState
	disk    linuxDiskState
	sys     linuxSystemState
	procs   linuxProcState

	panicked map[string]bool
}

// newLinuxCollector returns a collector for the tree under root with
// portable defaults (4 KiB pages, 100 ticks per second).
func newLinuxCollector(root string) *linuxCollector {
	return &linuxCollector{root: root, pageSize: 4096, clkTck: 100}
}

// path joins parts under the root.
func (c *linuxCollector) path(parts ...string) string { return linuxJoin(c.root, parts...) }

func linuxJoin(root string, parts ...string) string {
	return filepath.Join(append([]string{root}, parts...)...)
}

// guard runs one section's sampler. A panic drops that section from this
// sample, never the session, and is logged once per section to stderr
// (stdout carries only protocol lines). reset, when given, clears the
// section's baselines so a corrupt state cannot fail every later sample.
func (c *linuxCollector) guard(section string, fn func(), reset ...func()) {
	defer func() {
		if r := recover(); r != nil {
			if c.panicked == nil {
				c.panicked = map[string]bool{}
			}
			if !c.panicked[section] {
				c.panicked[section] = true
				fmt.Fprintf(os.Stderr, "rex-boing-agent: %s sampler failed: %v\n", section, r)
			}
			for _, fn := range reset {
				fn()
			}
		}
	}()
	fn()
}

// rediscoverNext forces discovery on the next sample.
func (c *linuxCollector) rediscoverNext() { c.discoveredAt = time.Time{} }

// discover refreshes the cached sensor, GPU, RAPL and battery paths every
// linuxRediscover.
func (c *linuxCollector) discover(now time.Time) {
	if !c.discoveredAt.IsZero() && now.Sub(c.discoveredAt) < linuxRediscover {
		return
	}
	c.discoveredAt = now
	c.guard("gpu discovery", c.discoverGPUs)
	c.guard("sensor discovery", func() { c.discoverThermal(now) })
	c.guard("power discovery", func() { c.discoverRAPL(now) })
	c.guard("battery discovery", func() { c.discoverBatteries(now) })
}

// Host describes the machine (computed once).
func (c *linuxCollector) Host() wire.Host {
	if !c.hostDone {
		c.hostDone = true
		c.guard("host", func() { c.host = c.buildHost() })
	}
	return c.host
}

// Capabilities lists what this machine can report.
func (c *linuxCollector) Capabilities() []string {
	c.discover(time.Now())
	caps := []string{"cpu", "memory"}
	if len(c.gpu.cards) > 0 || c.nvidia != nil {
		caps = append(caps, "gpu")
	}
	if len(c.thermal.sensors) > 0 {
		caps = append(caps, "sensors")
	}
	if len(c.thermal.fans) > 0 {
		caps = append(caps, "fans")
	}
	if c.power.packages > 0 || len(c.battery.batteries) > 0 {
		caps = append(caps, "power")
	}
	if len(c.battery.batteries) > 0 {
		caps = append(caps, "battery")
	}
	if linuxExists(c.path("proc/pressure/cpu")) {
		caps = append(caps, "pressure")
	}
	return append(caps, "network", "disk", "processes", "system")
}

// Notices returns one-off hints, after the first sample.
func (c *linuxCollector) Notices() []wire.Notice {
	var out []wire.Notice
	if c.power.present && c.power.packages == 0 && c.power.deniedPackages > 0 {
		out = append(out, wire.Notice{Type: "notice", Code: "rapl-denied",
			Message: "CPU power needs read access to /sys/class/powercap. Run: rex-boing-agent doctor"})
	}
	return out
}

// Close releases nothing: background work (nvidia-smi, systemctl, statfs of
// network mounts) is bounded by its own timeouts.
func (c *linuxCollector) Close() {}

// Sample reads the machine.
func (c *linuxCollector) Sample(detail wire.Detail) *wire.Sample {
	interval, resync := c.window.Next(1)
	now := time.Now()
	full := detail == wire.DetailFull
	s := &wire.Sample{Interval: interval, Resync: resync}
	if !c.hostDone {
		c.Host() // the process table needs the boot time
	}
	c.discover(now)

	c.guard("cpu", func() { s.CPU = c.sampleCPU(resync, now) }, func() { c.cpu = linuxCPUState{} })
	var psi linuxPSI
	havePSI := false
	c.guard("pressure", func() {
		if psi, havePSI = c.readPSI(); havePSI {
			s.Pressure = linuxPressureSection(psi)
		}
	})
	c.guard("memory", func() {
		var p *linuxPSI
		if havePSI {
			p = &psi
		}
		s.Memory = c.sampleMemory(interval, resync, p)
	}, func() { c.mem = linuxMemState{} })
	c.guard("gpu", func() { s.GPUs = c.sampleGPUs(interval, resync, full) }, func() { c.gpu = linuxGPUState{}; c.rediscoverNext() })
	c.guard("battery", func() { s.Battery = c.sampleBattery(full) }, c.rediscoverNext)
	c.guard("thermal", func() { s.Thermal = c.sampleThermal(full, s.GPUs, now) }, func() { c.thermal = linuxThermalState{}; c.rediscoverNext() })
	c.guard("power", func() { s.Power = c.samplePower(interval, resync, s.GPUs, s.Battery) }, func() { c.power = linuxPowerState{}; c.rediscoverNext() })
	c.guard("network", func() { s.Network = c.sampleNetwork(interval, resync, full, now) }, func() { c.net = linuxNetState{} })
	c.guard("disk", func() { s.Disk = c.sampleDisk(interval, resync, full, now) }, func() { c.disk.devs, c.disk.volumes = nil, nil })
	// The system facts (restart needed, updates, failed services) change on
	// the scale of minutes, but the fleet list shows them, and it only asks
	// for vitals: so vitals carry them too, every half minute.
	if full || c.systemSentAt.IsZero() || now.Sub(c.systemSentAt) >= linuxSystemEvery {
		c.guard("system", func() { s.System = c.sampleSystem(now) })
		if s.System != nil {
			c.systemSentAt = now
		}
	}
	if full {
		c.guard("processes", func() { s.Processes = c.sampleProcesses(now) }, func() { c.procs = linuxProcState{} })
	}
	if s.Battery != nil && s.Battery.Celsius != nil {
		if s.Thermal == nil {
			s.Thermal = &wire.Thermal{}
		}
		if s.Thermal.BatteryCelsius == nil {
			s.Thermal.BatteryCelsius = s.Battery.Celsius
		}
	}
	return s
}

// samplePower combines RAPL, GPU and battery power.
func (c *linuxCollector) samplePower(interval float64, resync bool, gpus []wire.GPU, bat *wire.Battery) *wire.Power {
	p := &wire.Power{}
	p.PackageWatts, p.CPUWatts = c.sampleRAPL(interval, resync)
	var gpuW float64
	haveGPU := false
	for _, g := range gpus {
		if g.Watts != nil {
			gpuW += *g.Watts
			haveGPU = true
		}
	}
	if haveGPU {
		p.GPUWatts = wire.F(float64(int(gpuW*100+0.5)) / 100)
	}
	if bat != nil && bat.SystemWatts != nil {
		p.SystemWatts = bat.SystemWatts
	}
	if p.PackageWatts == nil && p.CPUWatts == nil && p.GPUWatts == nil && p.SystemWatts == nil {
		return nil
	}
	return p
}
