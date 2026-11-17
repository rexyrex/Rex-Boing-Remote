package history

import (
	"math"
	"sort"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// Usage is what processes used over one quarter hour, from every process
// table read in it (PROTOCOL.md, "history", usage). A process table says
// what was running at its busiest moment; usage says what did the work over
// the whole window, CPU, memory, disk and GPU alike.
type Usage struct {
	// End is the end of the window, ms since the epoch: windows are the
	// process tables' quarter hours.
	End int64 `json:"end"`
	// Seconds is how much of the window the scans covered, and Scans how
	// many there were.
	Seconds float64 `json:"seconds"`
	Scans   int     `json:"scans"`
	// Count is how many processes were seen in the window.
	Count int        `json:"count"`
	Rows  []UsageRow `json:"rows"`
	// Rank lists the leaders' pids by cpu, memory, disk (read and write)
	// and gpu, busiest first.
	Rank map[string][]int32 `json:"rank"`
}

// UsageRow is one process over a window. CPU, disk and GPU are means over
// the seconds the window's scans covered (a process that ran for part of
// the window counts as idle for the rest), so CPU × Seconds / 100 is the
// CPU time it used, in core-seconds.
type UsageRow struct {
	PID   int32  `json:"pid"`
	Name  string `json:"name"`
	User  string `json:"user,omitempty"`
	Start uint64 `json:"start,omitempty"` // µs since epoch
	Cmd   string `json:"cmd,omitempty"`
	// CPU is percent of one core; CPUPeak the highest one scan measured.
	CPU     float64 `json:"cpu"`
	CPUPeak float64 `json:"cpuPeak"`
	// Memory is the most resident bytes any scan saw.
	Memory uint64 `json:"memory"`
	// DiskRead and DiskWrite are bytes per second.
	DiskRead  float64 `json:"diskRead,omitempty"`
	DiskWrite float64 `json:"diskWrite,omitempty"`
	GPU       float64 `json:"gpu,omitempty"`
	// Seen is how many of the window's scans listed the process.
	Seen int `json:"seen"`
}

// usageKey is one process: a pid with its start time, so a reused pid is a
// different process.
type usageKey struct {
	pid   int32
	start uint64
}

// usageAcc sums one process over a window. cpu, read, write and gpu are
// sums of value × seconds.
type usageAcc struct {
	name, user, cmd       string
	cpu, read, write, gpu float64
	cpuPeak               float64
	memory                uint64
	seen                  int
}

// usageWindow is the window still open.
type usageWindow struct {
	end     int64 // ms; 0 when none is open
	seconds float64
	scans   int
	procs   map[usageKey]*usageAcc
}

// addUsage folds one process table into the open window's usage.
func (r *Recorder) addUsage(p *wire.Processes) {
	end := bucketEnd(p.SampledAt, ProcessStep)
	if r.open.end != 0 && end < r.open.end {
		// The clock went back: drop the usage from the old timeline.
		i := sort.Search(len(r.usage), func(i int) bool { return r.usage[i].End >= end })
		r.usage = r.usage[:i]
		r.open = usageWindow{}
	}
	if r.open.end != 0 && end != r.open.end {
		r.usage = append(r.usage, r.open.summary())
		r.open = usageWindow{}
	}
	if r.open.end == 0 {
		r.open = usageWindow{end: end, procs: map[usageKey]*usageAcc{}}
	}
	w := &r.open
	dt := finite(p.Interval)
	w.seconds += dt
	w.scans++
	for i := range p.Rows {
		row := &p.Rows[i]
		key := usageKey{row.PID, row.Start}
		a := w.procs[key]
		if a == nil {
			if len(w.procs) >= maxUsageProcesses {
				continue
			}
			a = &usageAcc{name: row.Name, user: row.User, cmd: truncate(row.Cmd, maxCmd)}
			w.procs[key] = a
		}
		cpu := max(finite(row.CPU), 0)
		a.cpu += cpu * dt
		a.cpuPeak = max(a.cpuPeak, cpu)
		a.read += max(finite(row.DiskRead), 0) * dt
		a.write += max(finite(row.DiskWrite), 0) * dt
		a.gpu += max(finite(row.GPU), 0) * dt
		a.memory = max(a.memory, row.Memory)
		a.seen++
	}
}

// round rounds v to the given decimals.
func round(v float64, decimals int) float64 {
	scale := math.Pow(10, float64(decimals))
	return math.Round(v*scale) / scale
}

// summary is the window's usage: the processRows leaders by each measure,
// busiest by CPU first.
func (w *usageWindow) summary() Usage {
	u := Usage{End: w.end, Seconds: round(w.seconds, 3), Scans: w.scans, Count: len(w.procs),
		Rows: []UsageRow{}, Rank: map[string][]int32{}}
	if w.seconds <= 0 {
		return u
	}
	type entry struct {
		key usageKey
		row UsageRow
	}
	all := make([]entry, 0, len(w.procs))
	for key, a := range w.procs {
		all = append(all, entry{key, UsageRow{PID: key.pid, Name: a.name, User: a.user, Start: key.start, Cmd: a.cmd,
			CPU: round(a.cpu/w.seconds, 1), CPUPeak: round(a.cpuPeak, 1), Memory: a.memory,
			DiskRead: math.Round(a.read / w.seconds), DiskWrite: math.Round(a.write / w.seconds),
			GPU: round(a.gpu/w.seconds, 1), Seen: a.seen}})
	}
	// A stable order first, so ties rank the same way every time.
	sort.Slice(all, func(i, j int) bool {
		if all[i].key.pid != all[j].key.pid {
			return all[i].key.pid < all[j].key.pid
		}
		return all[i].key.start < all[j].key.start
	})
	keep := map[usageKey]bool{}
	for _, m := range []struct {
		name  string
		value func(*UsageRow) float64
	}{
		{"cpu", func(r *UsageRow) float64 { return r.CPU }},
		{"memory", func(r *UsageRow) float64 { return float64(r.Memory) }},
		{"disk", func(r *UsageRow) float64 { return r.DiskRead + r.DiskWrite }},
		{"gpu", func(r *UsageRow) float64 { return r.GPU }},
	} {
		idx := make([]int, len(all))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return m.value(&all[idx[a]].row) > m.value(&all[idx[b]].row) })
		var pids []int32
		for _, i := range idx {
			if len(pids) == processRows || m.value(&all[i].row) <= 0 {
				break
			}
			pids = append(pids, all[i].row.PID)
			keep[all[i].key] = true
		}
		if len(pids) > 0 {
			u.Rank[m.name] = pids
		}
	}
	for _, e := range all {
		if keep[e.key] {
			u.Rows = append(u.Rows, e.row)
		}
	}
	sort.SliceStable(u.Rows, func(i, j int) bool { return u.Rows[i].CPU > u.Rows[j].CPU })
	return u
}

// loadUsage restores saved usage: what the retention keeps and is not in
// the future. A last entry for the window now open is that window so far,
// and goes on collecting.
func (r *Recorder) loadUsage(saved []Usage, nowMS int64) {
	r.usage, r.open = r.usage[:0], usageWindow{}
	cut := nowMS - r.keep.Processes.Milliseconds()
	for _, u := range saved {
		if u.End > cut && u.End-ProcessStep.Milliseconds() < nowMS && u.Seconds > 0 &&
			(len(r.usage) == 0 || u.End > r.usage[len(r.usage)-1].End) {
			if u.Rows == nil {
				u.Rows = []UsageRow{}
			}
			if u.Rank == nil {
				u.Rank = map[string][]int32{}
			}
			r.usage = append(r.usage, u)
		}
	}
	n := len(r.usage)
	if n == 0 || r.usage[n-1].End < bucketEnd(nowMS, ProcessStep) {
		return
	}
	last := r.usage[n-1]
	r.usage = r.usage[:n-1]
	// Only the leaders were saved: the rest of the window starts over.
	r.open = usageWindow{end: last.End, seconds: last.Seconds, scans: last.Scans, procs: map[usageKey]*usageAcc{}}
	for _, row := range last.Rows {
		r.open.procs[usageKey{row.PID, row.Start}] = &usageAcc{name: row.Name, user: row.User, cmd: row.Cmd,
			cpu: row.CPU * last.Seconds, read: row.DiskRead * last.Seconds, write: row.DiskWrite * last.Seconds,
			gpu: row.GPU * last.Seconds, cpuPeak: row.CPUPeak, memory: row.Memory, seen: row.Seen}
	}
}
