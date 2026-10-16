//go:build windows

package collect

// The Windows collector. Sources, by section:
//
//	cpu        NtQuerySystemInformation(SystemProcessorPerformanceInformation)
//	           per logical processor; kinds from GetLogicalProcessorInformationEx
//	           EfficiencyClass; clocks from PDH Processor Information
//	memory     GlobalMemoryStatusEx, GetPerformanceInfo, PDH Paging File
//	gpus       DXGI adapters + PDH GPU Engine / GPU Adapter Memory, nvidia-smi
//	network    PDH Network Interface + GetAdaptersAddresses
//	disk       PDH PhysicalDisk(_Total); volumes from GetDiskFreeSpaceExW
//	battery    GetSystemPowerStatus
//	thermal    PDH Thermal Zone Information, LibreHardwareMonitor if running
//	processes  Toolhelp snapshot + OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)
//	system     uptime, reboot-pending registry keys
//
// Every source runs under recover: a failing source drops its own section
// for that sample and is logged to stderr once; it never ends the stream.

import (
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/nvidia"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// Counter paths. Missing objects (no GPU Engine on old Windows or in some
// VMs, no Thermal Zone Information on most desktops) are simply not added.
const (
	winCtrNetRX     = `\Network Interface(*)\Bytes Received/sec`
	winCtrNetTX     = `\Network Interface(*)\Bytes Sent/sec`
	winCtrDiskRead  = `\PhysicalDisk(_Total)\Disk Read Bytes/sec`
	winCtrDiskWrite = `\PhysicalDisk(_Total)\Disk Write Bytes/sec`
	winCtrProcPerf  = `\Processor Information(*)\% Processor Performance`
	winCtrProcFreq  = `\Processor Information(*)\Processor Frequency`
	winCtrPageUsage = `\Paging File(_Total)\% Usage`
	winCtrThermal   = `\Thermal Zone Information(*)\Temperature`
	winCtrGPUEngine = `\GPU Engine(*)\Utilization Percentage`
	winCtrGPUDed    = `\GPU Adapter Memory(*)\Dedicated Usage`
	winCtrGPUShared = `\GPU Adapter Memory(*)\Shared Usage`
)

// winPDHValues holds one collection's parsed values.
type winPDHValues struct {
	rx, tx, perf, freq, thermal []winPDHValue
	diskRead, diskWrite         *float64
	pageUsage                   *float64
}

type winCollector struct {
	// When vitals last carried the system section.
	systemSentAt time.Time
	win          Window
	nominal      float64

	groupCounts         []int
	cores               []winCore
	kinds               string
	hetero              bool
	perfCores, effCores int
	nominalMHz          float64
	topologyErr         string

	host wire.Host
	caps []string

	cpuPrev []winCPUTimes
	cpuErr  string
	pi      *winPerfInfo

	fast                                                    *winPDHQuery
	netRX, netTX, diskR, diskW, procPerf, procFreq, pageUse *winPDHCounter
	gpuQ, thermQ                                            winTimedQuery
	gpuEngine, gpuDed, gpuShared, therm                     *winPDHCounter
	pdhErr                                                  string
	missing                                                 []string
	vals                                                    winPDHValues
	thermVals                                               []winPDHValue

	gpuCollected bool
	gpuUsage     map[uint64]*winGPUUsage
	gpuPerPID    map[int32]float64
	gpuDedVals   map[uint64]uint64
	gpuShVals    map[uint64]uint64

	adapters []winAdapter
	dxgiErr  string

	nv  *nvidia.Reader
	lhm *winLHM

	netAdapters   []winAdapterInfo
	netAdaptersAt time.Time

	vols  winVolumeCache
	procs winProcState

	reboot       bool
	rebootReason string
	rebootAt     time.Time

	rxTotal, txTotal, readTotal, writeTotal float64

	noticeSent bool
	logMu      sync.Mutex
	logged     map[string]bool
}

func newCollector() Collector {
	c := &winCollector{
		nominal: 1,
		logged:  map[string]bool{},
		gpuQ:    winTimedQuery{min: time.Second, max: 10 * time.Second},
		thermQ:  winTimedQuery{min: 5 * time.Second, max: 30 * time.Second},
	}
	// No "insert a disk" or "drive not ready" dialogs from drive queries.
	windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOOPENFILEERRORBOX)

	c.safe("topology", func() {
		c.groupCounts = winGroupCounts()
		cores, err := winProcessorCores()
		if err != nil {
			c.topologyErr = err.Error()
		}
		c.cores = cores
		c.kinds, c.perfCores, c.effCores, c.hetero = winCoreKinds(cores, c.groupCounts)
	})
	c.safe("dxgi", func() {
		a, err := winDXGIAdapters()
		if err != nil {
			c.dxgiErr = err.Error()
		}
		c.adapters = a
	})
	c.safe("pdh", c.openPDH)
	c.nominalMHz = winNominalMHz()
	c.safe("nvidia", func() { c.nv = nvidia.NewReader() })
	c.safe("lhm", func() { c.lhm = newWinLHM() })
	c.safe("host", func() { c.host = winHostInfo(c.groupCounts, c.cores, c.perfCores, c.effCores) })

	// Baselines, so the first sample's rates already cover a real window.
	c.safe("cpu", func() {
		t, err := winReadCPUTimes(c.groupCounts)
		if err != nil {
			c.cpuErr = err.Error()
		}
		c.cpuPrev = t
	})
	c.safe("pdh", func() {
		_ = c.fast.collect()
		c.gpuQ.collect() // baseline for the rate counters
	})
	if c.nv != nil {
		c.nv.GPUs() // starts the first nvidia-smi run in the background
	}
	c.caps = c.capabilities()
	return c
}

// safe runs one source; a panic drops that source's output and is logged
// to stderr once per source.
func (c *winCollector) safe(source string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			c.logMu.Lock()
			first := !c.logged[source]
			c.logged[source] = true
			c.logMu.Unlock()
			if first {
				fmt.Fprintf(os.Stderr, "rex-boing-agent: %s source failed: %v\n", source, r)
			}
		}
	}()
	f()
}

func (c *winCollector) openPDH() {
	q, err := winOpenPDHQuery()
	if err != nil {
		c.pdhErr = err.Error()
		return
	}
	c.fast = q
	add := func(q *winPDHQuery, path string) *winPDHCounter {
		ctr, err := q.add(path)
		if err != nil {
			c.missing = append(c.missing, path)
			return nil
		}
		return ctr
	}
	c.netRX = add(q, winCtrNetRX)
	c.netTX = add(q, winCtrNetTX)
	c.diskR = add(q, winCtrDiskRead)
	c.diskW = add(q, winCtrDiskWrite)
	c.procPerf = add(q, winCtrProcPerf)
	c.procFreq = add(q, winCtrProcFreq)
	c.pageUse = add(q, winCtrPageUsage)

	// Counters that can be slow live in queries of their own, collected on
	// an adaptive cadence: with many processes the GPU Engine object has
	// thousands of instances, and thermal zones evaluate ACPI methods.
	if gq, err := winOpenPDHQuery(); err == nil {
		c.gpuEngine = add(gq, winCtrGPUEngine)
		c.gpuDed = add(gq, winCtrGPUDed)
		c.gpuShared = add(gq, winCtrGPUShared)
		if c.gpuEngine == nil && c.gpuDed == nil && c.gpuShared == nil {
			gq.close()
		} else {
			c.gpuQ.q = gq
		}
	}
	if tq, err := winOpenPDHQuery(); err == nil {
		if c.therm = add(tq, winCtrThermal); c.therm == nil {
			tq.close()
		} else {
			c.thermQ.q = tq
		}
	}
}

// winTimedQuery is a PDH query collected at most every `every`, which
// adapts to how long a collection takes: a collection that took d is
// repeated no sooner than 20·d (about 5 % of one core), within [min, max].
type winTimedQuery struct {
	q             *winPDHQuery
	min, max      time.Duration
	every, dur    time.Duration
	last          time.Time
	everCollected bool
}

// collect samples the query if it is due. due reports that it was
// sampled now (its values are fresh); err is PdhCollectQueryData's verdict,
// which can be PDH_NO_DATA while some counters still have values.
func (t *winTimedQuery) collect() (due bool, err error) {
	if t.q == nil || (t.everCollected && time.Since(t.last) < t.every) {
		return false, nil
	}
	start := time.Now()
	err = t.q.collect()
	t.dur, t.last, t.everCollected = time.Since(start), start, true
	t.every = time.Duration(math.Max(float64(t.min), math.Min(float64(t.max), float64(20*t.dur))))
	return true, err
}

// collectPDH samples the counters once and parses what this sample needs.
func (c *winCollector) collectPDH() {
	// A collection error (PDH_NO_DATA when one wildcard counter has no
	// instances) does not invalidate the other counters: values() checks
	// each instance's own status.
	c.vals = winPDHValues{}
	if c.fast != nil {
		if err := c.fast.collect(); err != nil {
			c.pdhErr = err.Error()
		}
		c.vals.rx, c.vals.tx = c.netRX.values(), c.netTX.values()
		c.vals.diskRead, c.vals.diskWrite = winSingle(c.diskR), winSingle(c.diskW)
		c.vals.perf, c.vals.freq = c.procPerf.values(), c.procFreq.values()
		c.vals.pageUsage = winSingle(c.pageUse)
	}
	if due, err := c.gpuQ.collect(); due {
		engines := c.gpuEngine.values()
		c.gpuUsage, c.gpuPerPID = winAggregateGPUEngines(engines)
		c.gpuDedVals = winSumByLUID(c.gpuDed.values())
		c.gpuShVals = winSumByLUID(c.gpuShared.values())
		// An idle GPU has no engine instances; only a clean collection
		// makes "no instances" mean 0 % rather than unknown.
		c.gpuCollected = err == nil || len(engines) > 0
	}
	if due, _ := c.thermQ.collect(); due {
		c.thermVals = c.therm.values()
	}
	c.vals.thermal = c.thermVals
}

func (c *winCollector) Host() wire.Host { return c.host }

func (c *winCollector) Capabilities() []string { return c.caps }

func (c *winCollector) capabilities() []string {
	caps := []string{"cpu", "memory"}
	if c.gpuEngine != nil || c.nv != nil {
		caps = append(caps, "gpu")
	}
	lhmOK, _ := c.lhm.status()
	if c.therm != nil || lhmOK {
		caps = append(caps, "sensors")
	}
	if lhmOK {
		caps = append(caps, "fans")
	}
	if lhmOK || c.nv != nil {
		caps = append(caps, "power")
	}
	if b, err := winPowerStatus(); err == nil && b.BatteryFlag&128 == 0 {
		caps = append(caps, "battery")
	}
	return append(caps, "network", "disk", "processes", "system")
}

func (c *winCollector) Sample(detail wire.Detail) *wire.Sample {
	s := &wire.Sample{}
	interval, resync := c.win.Next(c.nominal)
	if !resync {
		c.nominal = interval
	}
	s.Interval, s.Resync = interval, resync
	full := detail == wire.DetailFull

	c.safe("pdh", c.collectPDH)
	c.pi = nil
	c.safe("performance info", func() { c.pi, _ = winGetPerformanceInfo() })
	c.safe("cpu", func() { s.CPU = c.sampleCPU() })
	c.safe("memory", func() { s.Memory = c.sampleMemory() })
	c.safe("network", func() { s.Network = c.sampleNetwork(interval, resync, full) })
	c.safe("disk", func() { s.Disk = c.sampleDisk(interval, resync, full) })
	c.safe("battery", func() { s.Battery = c.sampleBattery() })
	var lhm *winLHMReading
	c.safe("lhm", func() { lhm = c.lhm.reading() })
	c.safe("gpu", func() { s.GPUs = c.sampleGPUs(lhm) })
	c.safe("thermal", func() { s.Thermal = c.sampleThermal(lhm, s.GPUs, full) })
	c.safe("power", func() { s.Power = c.samplePower(lhm, s.GPUs) })
	if full {
		c.safe("processes", func() {
			p, err := c.procs.scan(c.gpuPerPID, c.gpuEngine != nil && c.gpuCollected, resync)
			if err != nil {
				return
			}
			s.Processes = p
			if s.CPU != nil {
				s.CPU.Processes, s.CPU.Threads = wire.I(c.procs.count), wire.I(c.procs.threads)
			}
		})
	}
	// Restart-needed is shown in the fleet list, which only asks for vitals,
	// so vitals carry the system section every half minute too.
	if full || c.systemSentAt.IsZero() || time.Since(c.systemSentAt) >= 30*time.Second {
		c.safe("system", func() { s.System = c.sampleSystem() })
		if s.System != nil {
			c.systemSentAt = time.Now()
		}
	}
	return s
}

func (c *winCollector) sampleCPU() *wire.CPU {
	cur, err := winReadCPUTimes(c.groupCounts)
	if err != nil {
		c.cpuErr = err.Error()
		return nil
	}
	total, user, system, idle, per, ok := winCPUUsage(c.cpuPrev, cur)
	c.cpuPrev = cur
	if !ok {
		return nil
	}
	cpu := &wire.CPU{Total: total, User: user, System: system, Idle: idle, PerCore: per}
	if c.hetero && len(c.kinds) == len(per) {
		cpu.Kinds = c.kinds
	}
	cpu.ClockMHz, cpu.PerformanceClockMHz, cpu.EfficiencyClockMHz = winClocks(c.vals.perf, c.vals.freq, cpu.Kinds, c.groupCounts, c.nominalMHz)
	if c.pi != nil {
		cpu.Processes, cpu.Threads = wire.I(int(c.pi.ProcessCount)), wire.I(int(c.pi.ThreadCount))
	}
	return cpu
}

func (c *winCollector) sampleMemory() *wire.Memory {
	m, err := winGlobalMemoryStatus()
	if err != nil {
		return nil
	}
	return winBuildMemory(m.TotalPhys, m.AvailPhys, m.MemoryLoad, c.pi, c.vals.pageUsage)
}

func (c *winCollector) sampleNetwork(interval float64, resync, full bool) *wire.Network {
	if c.netAdaptersAt.IsZero() || time.Since(c.netAdaptersAt) > 30*time.Second {
		c.netAdaptersAt = time.Now()
		if a, err := winReadAdapters(); err == nil {
			c.netAdapters = a
		}
	}
	if c.netRX == nil && c.netTX == nil {
		return nil
	}
	ifaces, rx, tx := winNetwork(c.vals.rx, c.vals.tx, c.netAdapters)
	if resync {
		rx, tx = 0, 0
		for i := range ifaces {
			ifaces[i].RX, ifaces[i].TX = 0, 0
		}
	} else {
		c.rxTotal += rx * interval
		c.txTotal += tx * interval
	}
	n := &wire.Network{RX: rx, TX: tx, RXTotal: uint64(c.rxTotal), TXTotal: uint64(c.txTotal)}
	n.PrimaryInterface, n.LocalAddress = winPrimaryAdapter(c.netAdapters)
	if full {
		n.Interfaces = ifaces
	}
	return n
}

func (c *winCollector) sampleDisk(interval float64, resync, full bool) *wire.Disk {
	if c.diskR == nil && c.diskW == nil && !full {
		return nil
	}
	d := &wire.Disk{}
	if c.vals.diskRead != nil {
		d.Read = math.Max(0, *c.vals.diskRead)
	}
	if c.vals.diskWrite != nil {
		d.Write = math.Max(0, *c.vals.diskWrite)
	}
	if resync {
		d.Read, d.Write = 0, 0
	} else {
		c.readTotal += d.Read * interval
		c.writeTotal += d.Write * interval
	}
	d.ReadTotal, d.WriteTotal = uint64(c.readTotal), uint64(c.writeTotal)
	if full {
		d.Volumes = c.vols.get()
	}
	return d
}

func (c *winCollector) sampleBattery() *wire.Battery {
	ps, err := winPowerStatus()
	if err != nil || ps.BatteryFlag&128 != 0 || ps.BatteryLifePercent > 100 {
		return nil // no battery, or nothing Windows can tell
	}
	b := &wire.Battery{
		Present:    true,
		Percentage: float64(ps.BatteryLifePercent) / 100,
		Charging:   ps.BatteryFlag&8 != 0,
		PluggedIn:  ps.ACLineStatus == 1,
	}
	if ps.BatteryLifeTime != 0xFFFFFFFF && !b.PluggedIn {
		b.TimeRemainingMinutes = wire.I(int(ps.BatteryLifeTime / 60))
	}
	return b
}

func (c *winCollector) sampleGPUs(lhm *winLHMReading) []wire.GPU {
	var gpus []wire.GPU
	if c.gpuCollected {
		gpus = winBuildGPUs(c.adapters, c.gpuUsage, c.gpuDedVals, c.gpuShVals, c.gpuEngine != nil)
	}
	if c.nv != nil {
		gpus = winMergeNvidia(gpus, c.nv.GPUs())
	}
	if lhm != nil {
		for i := range gpus {
			if gpus[i].Celsius != nil {
				continue
			}
			for name, t := range lhm.GPUCelsius {
				a, b := winGPUNameKey(gpus[i].Name), winGPUNameKey(name)
				if a != "" && b != "" && (strings.Contains(a, b) || strings.Contains(b, a)) {
					gpus[i].Celsius = wire.F(t)
					break
				}
			}
		}
	}
	return gpus
}

func (c *winCollector) sampleThermal(lhm *winLHMReading, gpus []wire.GPU, full bool) *wire.Thermal {
	t := &wire.Thermal{}
	sensors := winThermalZoneSensors(c.vals.thermal)
	var fans []wire.Fan
	if lhm != nil {
		sensors = append(sensors, lhm.Sensors...)
		fans = lhm.Fans
		t.CPUCelsius = lhm.CPUCelsius
	}
	var peak *float64
	bump := func(v float64) {
		if peak == nil || v > *peak {
			peak = wire.F(v)
		}
	}
	maxOf := func(cat string) *float64 {
		var m *float64
		for _, s := range sensors {
			if s.Category == cat && (m == nil || s.Celsius > *m) {
				m = wire.F(s.Celsius)
			}
		}
		return m
	}
	for _, s := range sensors {
		bump(s.Celsius)
	}
	for _, g := range gpus {
		if g.Celsius != nil {
			if t.GPUCelsius == nil {
				t.GPUCelsius = wire.F(*g.Celsius)
			}
			bump(*g.Celsius)
		}
	}
	if t.CPUCelsius != nil {
		bump(*t.CPUCelsius)
	}
	t.StorageCelsius = maxOf("Storage")
	t.BatteryCelsius = maxOf("Battery")
	t.PeakCelsius = peak
	if peak == nil && len(fans) == 0 {
		return nil
	}
	t.State = "nominal" // Windows exposes no thermal pressure state
	if full {
		t.Sensors, t.Fans = sensors, fans
	}
	return t
}

func (c *winCollector) samplePower(lhm *winLHMReading, gpus []wire.GPU) *wire.Power {
	p := &wire.Power{}
	if lhm != nil {
		if lhm.PackageWatts != nil {
			p.CPUWatts, p.PackageWatts = lhm.PackageWatts, lhm.PackageWatts
		} else if lhm.CoresWatts != nil {
			p.CPUWatts = lhm.CoresWatts
		}
	}
	for _, g := range gpus {
		if g.Watts != nil {
			if p.GPUWatts == nil {
				p.GPUWatts = wire.F(0)
			}
			*p.GPUWatts += *g.Watts
		}
	}
	if p.CPUWatts == nil && p.GPUWatts == nil {
		return nil
	}
	return p
}

func (c *winCollector) sampleSystem() *wire.System {
	if c.rebootAt.IsZero() || time.Since(c.rebootAt) > 30*time.Second {
		c.rebootAt = time.Now()
		c.reboot, c.rebootReason = winRebootPending()
	}
	s := &wire.System{Uptime: math.Round(windows.DurationSinceBoot().Seconds()), RebootRequired: wire.B(c.reboot)}
	if c.reboot {
		s.RebootReason = c.rebootReason
	}
	return s
}

func (c *winCollector) Notices() []wire.Notice {
	if c.noticeSent {
		return nil
	}
	c.noticeSent = true
	if ok, _ := c.lhm.status(); ok {
		return nil
	}
	return []wire.Notice{{
		Type: "notice",
		Code: "cpu-temperature",
		Message: "Windows has no standard way to read CPU temperatures and fans. To add them, run LibreHardwareMonitor " +
			"and enable Options → Remote Web Server (port 8085). Run: rex-boing-agent doctor",
	}}
}

func (c *winCollector) Close() {
	c.fast.close()
	c.gpuQ.q.close()
	c.thermQ.q.close()
	c.fast, c.gpuQ.q, c.thermQ.q = nil, nil, nil
}

// ---------------------------------------------------------------- volumes

// winVolumeCache refreshes the volume list in the background, at most
// every 15 seconds, because a dead network drive can stall the query.
type winVolumeCache struct {
	mu      sync.Mutex
	vols    []wire.Volume
	at      time.Time
	loaded  bool
	running bool
	done    chan struct{}
}

func (v *winVolumeCache) get() []wire.Volume {
	v.mu.Lock()
	if !v.running && (v.at.IsZero() || time.Since(v.at) >= 15*time.Second) {
		v.running, v.at = true, time.Now()
		done := make(chan struct{})
		v.done = done
		go func() {
			defer close(done)
			var vols []wire.Volume
			func() {
				defer func() { _ = recover() }()
				vols = winVolumes()
			}()
			v.mu.Lock()
			v.vols, v.loaded, v.running = vols, true, false
			v.mu.Unlock()
		}()
	}
	wait := !v.loaded
	done := v.done
	v.mu.Unlock()
	if wait && done != nil {
		select { // the first call waits briefly so the first full sample has volumes
		case <-done:
		case <-time.After(250 * time.Millisecond):
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.vols
}

// ---------------------------------------------------------------- doctor

func (c *winCollector) Doctor() []Check {
	var checks []Check
	add := func(name string, ok bool, detail, fix string) {
		if ok {
			fix = "" // advice is only for what does not work
		}
		checks = append(checks, Check{Name: name, OK: ok, Detail: detail, Fix: fix})
	}
	c.safe("pdh", c.collectPDH)

	// CPU
	logical := 0
	for _, n := range c.groupCounts {
		logical += n
	}
	if c.cpuPrev == nil {
		add("CPU usage", false, "NtQuerySystemInformation failed: "+c.cpuErr, "")
	} else {
		detail := fmt.Sprintf("%d logical processors in %d group(s), %d physical cores", logical, len(c.groupCounts), len(c.cores))
		ok := len(c.cpuPrev) == logical
		if !ok {
			detail += fmt.Sprintf("; only %d are measured (processor groups beyond the first need NtQuerySystemInformationEx)", len(c.cpuPrev))
		}
		add("CPU usage", ok, detail, "")
	}
	switch {
	case c.hetero:
		add("Core types", true, fmt.Sprintf("%d performance and %d efficiency cores", c.perfCores, c.effCores), "")
	case len(c.cores) > 0:
		add("Core types", true, "All cores are the same kind", "")
	default:
		add("Core types", false, "GetLogicalProcessorInformationEx failed: "+c.topologyErr, "")
	}

	// PDH
	if c.fast == nil {
		add("Performance counters", false, "PDH is unavailable: "+c.pdhErr,
			"Rebuild the performance counters from an elevated prompt: lodctr /R, then winmgmt /resyncperf")
	} else if len(c.missing) > 0 {
		add("Performance counters", true, "Not on this machine (their readings are skipped): "+strings.Join(c.missing, ", "),
			"If network, disk or GPU counters are missing on a physical PC, rebuild them from an elevated prompt: lodctr /R")
	} else {
		add("Performance counters", true, "All counters available", "")
	}
	if c.netRX == nil {
		add("Network", false, "Network Interface counters are missing", "Rebuild the performance counters: lodctr /R")
	} else {
		name, addr := winPrimaryAdapter(c.netAdapters)
		if c.netAdapters == nil {
			if a, err := winReadAdapters(); err == nil {
				name, addr = winPrimaryAdapter(a)
			}
		}
		add("Network", true, fmt.Sprintf("primary interface %q, address %s", name, addr), "")
	}

	// GPU
	var names []string
	hasNvidia := false
	for _, a := range c.adapters {
		if a.Software {
			continue
		}
		names = append(names, a.Name)
		if a.VendorID == 0x10DE {
			hasNvidia = true
		}
	}
	switch {
	case len(c.adapters) == 0:
		add("GPU names", false, "DXGI listed no adapters: "+c.dxgiErr, "")
	default:
		add("GPU names", true, strings.Join(names, ", "), "")
	}
	if c.gpuEngine == nil {
		add("GPU utilization", false, "The GPU Engine performance counters are missing",
			"GPU utilization needs Windows 10 1709 or later with a WDDM 2.x graphics driver")
	} else {
		add("GPU utilization", true, fmt.Sprintf("GPU Engine counters available (one collection takes %v)", c.gpuQ.dur.Round(time.Millisecond)), "")
	}
	switch {
	case c.nv != nil:
		add("NVIDIA", true, "nvidia-smi found: temperature, power, fan and clocks for NVIDIA GPUs", "")
	case hasNvidia:
		add("NVIDIA", false, "nvidia-smi was not found",
			"Install the NVIDIA driver (it includes nvidia-smi) for GPU temperature, power and fan readings")
	}

	// Temperatures
	lhmOK, lhmErr := c.lhm.status()
	if lhmOK {
		add("CPU temperature and fans", true, "Reading LibreHardwareMonitor at "+winLHMURL, "")
	} else {
		add("CPU temperature and fans", false, "Windows has no built-in API for CPU temperatures and fans; LibreHardwareMonitor is not reachable at "+winLHMURL+" ("+lhmErr+")",
			"Run LibreHardwareMonitor (as administrator, so it can read the sensors), enable Options → Remote Web Server on port 8085 without a password, and keep it running, for example started at logon. The agent only reads its local JSON; it installs no driver.")
	}
	if c.therm == nil {
		add("Thermal zones", true, "No ACPI thermal zones on this machine", "")
	} else {
		add("Thermal zones", true, fmt.Sprintf("%d ACPI thermal zone(s)", len(winThermalZoneSensors(c.vals.thermal))), "")
	}

	// Battery
	if b := c.sampleBattery(); b != nil {
		add("Battery", true, fmt.Sprintf("%.0f%%, plugged in: %v", b.Percentage*100, b.PluggedIn), "")
	} else {
		add("Battery", true, "No battery", "")
	}

	// Processes
	elevated := windows.GetCurrentProcessToken().IsElevated()
	var probe winProcState
	if _, err := probe.scan(nil, false, true); err != nil {
		add("Processes", false, "Process snapshot failed: "+err.Error(), "")
	} else if probe.denied > 0 && !elevated {
		add("Processes", true, fmt.Sprintf("%d processes; %d of them (other users' and protected ones) show name only", probe.count, probe.denied),
			"Connect as an administrator (an administrator's SSH session is elevated) to see CPU and memory of every process")
	} else {
		add("Processes", true, fmt.Sprintf("%d processes, %d not readable", probe.count, probe.denied), "")
	}

	// OpenSSH
	state := winServiceState("sshd")
	add("OpenSSH Server", state == "running", "Service sshd: "+state,
		"Install OpenSSH Server (Settings → System → Optional features), then in an elevated PowerShell: Start-Service sshd; Set-Service sshd -StartupType Automatic")
	shell := winRegString(`SOFTWARE\OpenSSH`, "DefaultShell")
	if shell == "" {
		shell = "cmd.exe (default)"
	}
	add("OpenSSH default shell", true, shell, "")

	if pending, reason := winRebootPending(); pending {
		add("Reboot", true, "A reboot is pending ("+reason+")", "")
	} else {
		add("Reboot", true, "No reboot pending", "")
	}
	return checks
}
