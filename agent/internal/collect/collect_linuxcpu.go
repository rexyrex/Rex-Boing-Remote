package collect

// CPU time, core kinds, clocks and load from /proc and /sys. No build tag:
// see collect_linuxfs.go.

import (
	"bytes"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxCPUTimes holds one /proc/stat cpu line in USER_HZ ticks.
type linuxCPUTimes [8]uint64

const (
	linuxTUser = iota
	linuxTNice
	linuxTSystem
	linuxTIdle
	linuxTIOWait
	linuxTIRQ
	linuxTSoftIRQ
	linuxTSteal
)

// linuxStat is the part of /proc/stat the collector uses.
type linuxStat struct {
	all   linuxCPUTimes
	ids   []int // logical cpu numbers, in file order
	cores []linuxCPUTimes
	btime int64 // seconds since the epoch, 0 when not parsed
}

// linuxParseStat parses the cpu lines of /proc/stat into st, reusing its
// slices. guest and guest_nice are left out on purpose: the kernel already
// counts them inside user and nice.
func linuxParseStat(data []byte, st *linuxStat) {
	st.ids, st.cores, st.btime = st.ids[:0], st.cores[:0], 0
	st.all = linuxCPUTimes{}
	for len(data) > 0 {
		var line []byte
		line, data = linuxNextLine(data)
		if bytes.HasPrefix(line, []byte("cpu")) {
			var name []byte
			var t linuxCPUTimes
			field := 0
			for len(line) > 0 {
				i := bytes.IndexByte(line, ' ')
				var tok []byte
				if i < 0 {
					tok, line = line, nil
				} else {
					tok, line = line[:i], line[i+1:]
				}
				if len(tok) == 0 {
					continue
				}
				if field == 0 {
					name = tok
				} else if field <= len(t) {
					t[field-1], _ = linuxAtou(tok)
				}
				field++
			}
			if field < 5 {
				continue
			}
			if len(name) == 3 {
				st.all = t
				continue
			}
			id, ok := linuxAtou(name[3:])
			if !ok {
				continue
			}
			st.ids = append(st.ids, int(id))
			st.cores = append(st.cores, t)
			continue
		}
		if bytes.HasPrefix(line, []byte("btime ")) {
			if v, ok := linuxAtou(bytes.TrimSpace(line[6:])); ok {
				st.btime = int64(v)
			}
		}
	}
}

// linuxCPUDelta returns per-field deltas and their sum. A field that went
// backwards (iowait does on some NOHZ kernels) contributes nothing.
func linuxCPUDelta(prev, cur *linuxCPUTimes) (d [8]float64, total float64) {
	for i := range cur {
		if cur[i] > prev[i] {
			d[i] = float64(cur[i] - prev[i])
			total += d[i]
		}
	}
	return d, total
}

// linuxCPUState is the collector's CPU baseline and topology cache.
type linuxCPUState struct {
	stat      linuxStat // scratch for the current read
	prevAll   linuxCPUTimes
	prevIDs   []int
	prevCores []linuxCPUTimes
	have      bool

	topoIDs    []int  // the cpu set the topology below was built for
	kinds      string // one byte per entry of topoIDs
	hybrid     bool   // kinds names at least one P or E core
	kindSource string
	freqPaths  []string // scaling_cur_freq per entry of topoIDs, "" when absent
	hasFreq    bool

	// Reading scaling_cur_freq costs an IPI per core on some kernels. The
	// app uses the clocks of vitals samples only for the history behind the
	// dashboard's clock graph, so vitals read them every linuxClockEvery and
	// repeat them in between; full samples read them every time.
	clocks   [3]*float64 // all, P, E
	clocksAt time.Time

	// Listing /proc costs about as much as the rest of a vitals sample on a
	// box with a thousand processes, so the count is refreshed every
	// linuxProcCountEvery (process scans in full mode refresh it too).
	procCount   int
	procCountAt time.Time
}

const (
	linuxProcCountEvery = 5 * time.Second
	linuxClockEvery     = 5 * time.Second
)

// sampleCPU reads /proc/stat, the clocks and the load average.
func (c *linuxCollector) sampleCPU(resync, full bool, now time.Time) *wire.CPU {
	data, err := linuxReadInto(c.path("proc/stat"), &c.buf)
	if err != nil {
		return nil
	}
	cs := &c.cpu
	linuxParseStat(data, &cs.stat)
	st := &cs.stat
	if len(st.ids) == 0 {
		return nil
	}
	if !linuxSameInts(cs.topoIDs, st.ids) {
		c.discoverCPUTopology(st.ids)
	}

	out := &wire.CPU{}
	if cs.hybrid {
		// A homogeneous machine sends no kinds, as on Windows: every core
		// alike reads the same as every core unknown.
		out.Kinds = cs.kinds
	}
	valid := cs.have && !resync
	var iowait, steal float64
	if valid {
		d, dt := linuxCPUDelta(&cs.prevAll, &st.all)
		if dt > 0 {
			out.User = d[linuxTUser] / dt
			out.Nice = d[linuxTNice] / dt
			out.System = (d[linuxTSystem] + d[linuxTIRQ] + d[linuxTSoftIRQ]) / dt
			out.Idle = d[linuxTIdle] / dt
			iowait = d[linuxTIOWait] / dt
			steal = d[linuxTSteal] / dt
			out.Total = linuxClamp01(1 - (d[linuxTIdle]+d[linuxTIOWait])/dt)
		} else {
			valid = false
		}
	}
	if !valid {
		// A fresh baseline: nothing measured yet, so report an idle machine.
		out.Idle = 1
	}
	out.IOWait, out.Steal = &iowait, &steal

	out.PerCore = make([]float64, len(st.cores))
	if valid && linuxSameInts(cs.prevIDs, st.ids) {
		for i := range st.cores {
			d, dt := linuxCPUDelta(&cs.prevCores[i], &st.cores[i])
			if dt > 0 {
				out.PerCore[i] = linuxClamp01(1 - (d[linuxTIdle]+d[linuxTIOWait])/dt)
			}
		}
	}
	cs.prevAll = st.all
	cs.prevIDs = append(cs.prevIDs[:0], st.ids...)
	cs.prevCores = append(cs.prevCores[:0], st.cores...)
	cs.have = true

	if full || cs.clocksAt.IsZero() || now.Sub(cs.clocksAt) >= linuxClockEvery {
		c.sampleClocks(out)
		cs.clocks, cs.clocksAt = [3]*float64{out.ClockMHz, out.PerformanceClockMHz, out.EfficiencyClockMHz}, now
	} else {
		out.ClockMHz, out.PerformanceClockMHz, out.EfficiencyClockMHz = linuxCopyF(cs.clocks[0]), linuxCopyF(cs.clocks[1]), linuxCopyF(cs.clocks[2])
	}
	c.sampleLoad(out)
	if cs.procCountAt.IsZero() || now.Sub(cs.procCountAt) >= linuxProcCountEvery {
		cs.procCount, cs.procCountAt = c.countProcesses(), now
	}
	if cs.procCount > 0 {
		n := cs.procCount
		out.Processes = &n
	}
	if c.procs.zombies != nil {
		z := *c.procs.zombies
		out.Zombies = &z
	}
	return out
}

// linuxCopyF copies a reading so samples never share one.
func linuxCopyF(p *float64) *float64 {
	if p == nil {
		return nil
	}
	return wire.F(*p)
}

func linuxSameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// discoverCPUTopology works out core kinds and clock files for a cpu set.
// It runs once, and again only when cpus go on or offline.
func (c *linuxCollector) discoverCPUTopology(ids []int) {
	cs := &c.cpu
	cs.topoIDs = append(cs.topoIDs[:0], ids...)
	kinds, source := linuxDetectKinds(c.root, ids)
	b := make([]byte, len(ids))
	for i, id := range ids {
		b[i] = '?'
		if k, ok := kinds[id]; ok {
			b[i] = k
		}
	}
	cs.kinds, cs.kindSource = string(b), source
	p, e := linuxKindCounts(cs.kinds)
	cs.hybrid = p+e > 0
	cs.freqPaths = make([]string, len(ids))
	cs.hasFreq = false
	for i, id := range ids {
		p := c.path("sys/devices/system/cpu", "cpu"+strconv.Itoa(id), "cpufreq/scaling_cur_freq")
		if linuxExists(p) {
			cs.freqPaths[i] = p
			cs.hasFreq = true
		}
	}
}

// linuxDetectKinds labels cpus 'P' or 'E', or returns an empty map when the
// machine is not hybrid or the kernel does not say. Sources, best first:
//
//  1. Intel hybrid PMUs: /sys/devices/cpu_core/cpus and cpu_atom/cpus (and
//     cpu_lowpower on newer kernels for the low-power E-cores).
//  2. Arm capacities: cpu_capacity per cpu; the biggest are P, and so are
//     big cores binned a little lower (1001 beside 1024).
//  3. cpufreq base_frequency (intel_pstate): the highest group is P. Base
//     clocks are immune to the favoured-core turbo differences that make
//     maximum clocks of identical cores disagree.
//  4. cpufreq cpuinfo_max_freq: the highest group is P, but only when the
//     slowest core tops out well below the fastest (< 80 %), so favoured
//     cores of a homogeneous chip are not mistaken for P-cores.
func linuxDetectKinds(root string, ids []int) (map[int]byte, string) {
	kinds := map[int]byte{}
	pmu := func(name string) []int {
		s, err := linuxReadValue(linuxJoin(root, "sys/devices", name, "cpus"))
		if err != nil {
			return nil
		}
		return linuxParseCPUList(s)
	}
	if p := pmu("cpu_core"); len(p) > 0 {
		for _, id := range p {
			kinds[id] = 'P'
		}
		for _, name := range []string{"cpu_atom", "cpu_lowpower"} {
			for _, id := range pmu(name) {
				kinds[id] = 'E'
			}
		}
		return kinds, "hybrid PMU (cpu_core/cpu_atom)"
	}

	perCPU := func(file string) (map[int]uint64, bool) {
		vals := map[int]uint64{}
		for _, id := range ids {
			v, ok := linuxReadUint(linuxJoin(root, "sys/devices/system/cpu", "cpu"+strconv.Itoa(id), file))
			if !ok || v == 0 {
				return nil, false
			}
			vals[id] = v
		}
		return vals, len(vals) > 0
	}
	// split labels cpus within a tenth of the fastest P, the rest E, unless
	// even the slowest reaches ratio of the fastest (a homogeneous chip).
	split := func(vals map[int]uint64, ratio float64) bool {
		var lo, hi uint64
		for _, v := range vals {
			if lo == 0 || v < lo {
				lo = v
			}
			if v > hi {
				hi = v
			}
		}
		if lo == hi || float64(lo) >= ratio*float64(hi) {
			return false
		}
		for id, v := range vals {
			if float64(v) >= 0.9*float64(hi) {
				kinds[id] = 'P'
			} else {
				kinds[id] = 'E'
			}
		}
		return true
	}
	if vals, ok := perCPU("cpu_capacity"); ok {
		if split(vals, 0.9) {
			return kinds, "cpu_capacity"
		}
		return kinds, "uniform cpu_capacity"
	}
	if vals, ok := perCPU("cpufreq/base_frequency"); ok {
		if split(vals, 0.9) {
			return kinds, "cpufreq base_frequency"
		}
		return kinds, "uniform base_frequency"
	}
	if vals, ok := perCPU("cpufreq/cpuinfo_max_freq"); ok {
		if split(vals, 0.8) {
			return kinds, "cpufreq cpuinfo_max_freq"
		}
		return kinds, "uniform cpuinfo_max_freq"
	}
	return kinds, ""
}

// sampleClocks averages scaling_cur_freq overall and per core kind.
func (c *linuxCollector) sampleClocks(out *wire.CPU) {
	cs := &c.cpu
	if !cs.hasFreq {
		return
	}
	var all, p, e linuxMean
	for i, path := range cs.freqPaths {
		if path == "" {
			continue
		}
		khz, ok := linuxReadUint(path)
		if !ok || khz == 0 {
			continue
		}
		mhz := float64(khz) / 1000
		all.add(mhz)
		switch cs.kinds[i] {
		case 'P':
			p.add(mhz)
		case 'E':
			e.add(mhz)
		}
	}
	out.ClockMHz, out.PerformanceClockMHz, out.EfficiencyClockMHz = all.ptr(), p.ptr(), e.ptr()
}

// linuxMean accumulates an average.
type linuxMean struct {
	sum float64
	n   int
}

func (m *linuxMean) add(v float64) { m.sum += v; m.n++ }

func (m *linuxMean) ptr() *float64 {
	if m.n == 0 {
		return nil
	}
	v := float64(int(m.sum/float64(m.n)*10+0.5)) / 10
	return &v
}

// sampleLoad reads /proc/loadavg: "0.48 0.95 0.81 1/3172 151094". The
// number after the slash counts every scheduling entity, i.e. threads.
func (c *linuxCollector) sampleLoad(out *wire.CPU) {
	s, err := linuxReadValue(c.path("proc/loadavg"))
	if err != nil {
		return
	}
	f := strings.Fields(s)
	if len(f) < 4 {
		return
	}
	var load [3]float64
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return
		}
		load[i] = v
	}
	out.Load = &load
	if _, total, ok := strings.Cut(f[3], "/"); ok {
		if n, err := strconv.Atoi(total); err == nil {
			out.Threads = &n
		}
	}
}

// countProcesses counts the numeric directories of /proc. Readdirnames
// skips the lstat per entry that os.ReadDir would sort and type.
func (c *linuxCollector) countProcesses() int {
	f, err := os.Open(c.path("proc"))
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	for {
		names, err := f.Readdirnames(512)
		for _, name := range names {
			if linuxNumeric(name) {
				n++
			}
		}
		if err != nil || len(names) == 0 {
			break
		}
	}
	return n
}

// linuxKindCounts counts P and E cores in a kinds string.
func linuxKindCounts(kinds string) (p, e int) {
	for i := 0; i < len(kinds); i++ {
		switch kinds[i] {
		case 'P':
			p++
		case 'E':
			e++
		}
	}
	return p, e
}

// linuxSortedKeys returns the keys of m in order (doctor output).
func linuxSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
