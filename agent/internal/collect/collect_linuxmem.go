package collect

// Memory, swap and pressure stall information. No build tag: see
// collect_linuxfs.go.

import (
	"bytes"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxMeminfo is the part of /proc/meminfo the collector uses, in bytes.
type linuxMeminfo struct {
	total, free, available, buffers, cached, sreclaimable, shmem uint64
	active, inactive, swapTotal, swapFree                        uint64
	hasTotal, hasAvailable                                       bool
}

// linuxParseMeminfo parses "MemTotal:  65137776 kB" lines.
func linuxParseMeminfo(data []byte) linuxMeminfo {
	var m linuxMeminfo
	for len(data) > 0 {
		var line []byte
		line, data = linuxNextLine(data)
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		rest := bytes.TrimSpace(line[colon+1:])
		num := rest
		unit := uint64(1)
		if i := bytes.IndexByte(rest, ' '); i >= 0 {
			num = rest[:i]
			if bytes.Equal(bytes.TrimSpace(rest[i:]), []byte("kB")) {
				unit = 1024
			}
		}
		v, ok := linuxAtou(num)
		if !ok {
			continue
		}
		v *= unit
		switch string(key) { // no allocation: the compiler special-cases switch on string(bytes)
		case "MemTotal":
			m.total, m.hasTotal = v, true
		case "MemFree":
			m.free = v
		case "MemAvailable":
			m.available, m.hasAvailable = v, true
		case "Buffers":
			m.buffers = v
		case "Cached":
			m.cached = v
		case "SReclaimable":
			m.sreclaimable = v
		case "Shmem":
			m.shmem = v
		case "Active":
			m.active = v
		case "Inactive":
			m.inactive = v
		case "SwapTotal":
			m.swapTotal = v
		case "SwapFree":
			m.swapFree = v
		}
	}
	return m
}

// linuxPSI holds the avg10 values of /proc/pressure.
type linuxPSI struct {
	cpu, memory, io float64
	memFull, ioFull float64
	hasMem, hasIO   bool
	hasMemF, hasIOF bool
	hasCPU          bool
}

// linuxParsePSI parses "some avg10=0.86 avg60=…" and "full avg10=…" lines.
func linuxParsePSI(data []byte) (some, full float64, hasSome, hasFull bool) {
	for len(data) > 0 {
		var line []byte
		line, data = linuxNextLine(data)
		i := bytes.Index(line, []byte("avg10="))
		if i < 0 {
			continue
		}
		v := line[i+6:]
		if j := bytes.IndexByte(v, ' '); j >= 0 {
			v = v[:j]
		}
		f, ok := linuxAtof(v)
		if !ok {
			continue
		}
		switch {
		case bytes.HasPrefix(line, []byte("some")):
			some, hasSome = f, true
		case bytes.HasPrefix(line, []byte("full")):
			full, hasFull = f, true
		}
	}
	return
}

// readPSI reads all three pressure files. ok is false when the kernel has
// no PSI (older than 4.20, built without it, or booted with psi=0).
func (c *linuxCollector) readPSI() (p linuxPSI, ok bool) {
	read := func(name string) (some, full float64, hasSome, hasFull bool) {
		data, err := linuxReadInto(c.path("proc/pressure", name), &c.buf)
		if err != nil {
			return
		}
		return linuxParsePSI(data)
	}
	p.cpu, _, p.hasCPU, _ = read("cpu")
	p.memory, p.memFull, p.hasMem, p.hasMemF = read("memory")
	p.io, p.ioFull, p.hasIO, p.hasIOF = read("io")
	return p, p.hasCPU || p.hasMem || p.hasIO
}

// linuxPressureSection turns PSI into the wire section.
func linuxPressureSection(p linuxPSI) *wire.Pressure {
	out := &wire.Pressure{CPU: p.cpu, Memory: p.memory, IO: p.io}
	if p.hasMemF {
		out.MemoryFull = wire.F(p.memFull)
	}
	if p.hasIOF {
		out.IOFull = wire.F(p.ioFull)
	}
	return out
}

// linuxMemState keeps the swap counters between samples.
type linuxMemState struct {
	prevIn, prevOut uint64
	have            bool
}

// sampleMemory reads /proc/meminfo and the swap counters of /proc/vmstat.
func (c *linuxCollector) sampleMemory(interval float64, resync bool, psi *linuxPSI) *wire.Memory {
	data, err := linuxReadInto(c.path("proc/meminfo"), &c.buf)
	if err != nil {
		return nil
	}
	m := linuxParseMeminfo(data)
	if !m.hasTotal || m.total == 0 {
		return nil
	}
	avail := m.available
	if !m.hasAvailable { // kernels before 3.14
		avail = m.free + m.buffers + m.cached
	}
	if avail > m.total {
		avail = m.total
	}
	used := m.total - avail
	cached := int64(m.cached) + int64(m.sreclaimable) - int64(m.shmem)
	if cached < 0 {
		cached = 0
	}
	out := &wire.Memory{
		Total:     m.total,
		Used:      used,
		Available: wire.U(avail),
		Free:      wire.U(m.free),
		App:       wire.U(used),
		Cached:    wire.U(uint64(cached)),
		Buffers:   wire.U(m.buffers),
		Active:    wire.U(m.active),
		Inactive:  wire.U(m.inactive),
		Pressure:  wire.F(float64(used) / float64(m.total)),
	}
	out.PressureLevel = linuxPressureLevel(float64(avail)/float64(m.total), psi)

	swap := &wire.Swap{Total: m.swapTotal, Free: m.swapFree}
	if m.swapFree <= m.swapTotal {
		swap.Used = m.swapTotal - m.swapFree
	}
	if vm, err := linuxReadInto(c.path("proc/vmstat"), &c.buf); err == nil {
		in, out2, ok := linuxParseSwapCounters(vm)
		ms := &c.mem
		if ok {
			if ms.have && !resync && interval > 0 {
				swap.InRate = wire.F(Rate(ms.prevIn, in, interval) * float64(c.pageSize))
				swap.OutRate = wire.F(Rate(ms.prevOut, out2, interval) * float64(c.pageSize))
			}
			ms.prevIn, ms.prevOut, ms.have = in, out2, true
		}
	}
	out.Swap = swap
	return out
}

// linuxPressureLevel grades memory pressure. With PSI: stalls of some tasks
// for 10 % of the last ten seconds is a warning; all tasks stalled 5 % of the
// time, or under 5 % of memory available, is critical. Without PSI the
// available fraction alone decides (under 10 % warning, under 5 % critical).
func linuxPressureLevel(availFrac float64, psi *linuxPSI) string {
	if availFrac < 0.05 {
		return "critical"
	}
	if psi != nil && psi.hasMem {
		switch {
		case psi.hasMemF && psi.memFull >= 5:
			return "critical"
		case psi.memory >= 10:
			return "warning"
		}
		return "normal"
	}
	if availFrac < 0.10 {
		return "warning"
	}
	return "normal"
}

// linuxParseSwapCounters finds pswpin and pswpout (pages) in /proc/vmstat.
func linuxParseSwapCounters(data []byte) (in, out uint64, ok bool) {
	var haveIn, haveOut bool
	for len(data) > 0 && !(haveIn && haveOut) {
		var line []byte
		line, data = linuxNextLine(data)
		switch {
		case bytes.HasPrefix(line, []byte("pswpin ")):
			in, haveIn = linuxAtou(bytes.TrimSpace(line[7:]))
		case bytes.HasPrefix(line, []byte("pswpout ")):
			out, haveOut = linuxAtou(bytes.TrimSpace(line[8:]))
		}
	}
	return in, out, haveIn && haveOut
}
