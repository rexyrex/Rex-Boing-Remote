package collect

import (
	"sort"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// RankDepth is how many processes each ranking lists (PROTOCOL.md: at most 20).
const RankDepth = 20

// MaxGap is the longest window whose rates are still trusted. Longer means
// the machine or the agent was paused, and the deltas span work that belongs
// to no single moment.
const MaxGap = 30 * time.Second

// Window measures the time between samples on the monotonic clock and
// decides whether a sample's rates are valid. Every collector embeds one.
type Window struct {
	last    time.Time // carries a monotonic reading
	started bool
}

// Next returns the seconds since the previous call and whether the rates
// over that window should be dropped (first call, a gap, or a clock step).
func (w *Window) Next(nominal float64) (interval float64, resync bool) {
	now := time.Now()
	if !w.started {
		w.started, w.last = true, now
		return nominal, true
	}
	elapsed := now.Sub(w.last) // monotonic
	w.last = now
	if elapsed <= 0 || elapsed > MaxGap {
		return nominal, true
	}
	return elapsed.Seconds(), false
}

// Rank builds the ranked union PROTOCOL.md describes from a full process
// table: the top RankDepth pids by each metric, and every row that placed in
// any ranking, once. Metrics whose values are all zero are left out.
func Rank(all []wire.ProcessRow, metrics ...string) (rows []wire.ProcessRow, rank map[string][]int32) {
	if len(metrics) == 0 {
		metrics = []string{"cpu", "memory", "gpu", "energy", "disk"}
	}
	value := func(r *wire.ProcessRow, m string) float64 {
		switch m {
		case "cpu":
			return r.CPU
		case "memory":
			return float64(r.Memory)
		case "gpu":
			return r.GPU
		case "energy":
			return r.Energy
		case "disk":
			return r.DiskRead + r.DiskWrite
		}
		return 0
	}
	rank = map[string][]int32{}
	placed := map[int32]bool{}
	idx := make([]int, len(all))
	for m := range metrics {
		metric := metrics[m]
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool {
			return value(&all[idx[a]], metric) > value(&all[idx[b]], metric)
		})
		var pids []int32
		for _, i := range idx {
			if len(pids) == RankDepth || value(&all[i], metric) <= 0 {
				break
			}
			pids = append(pids, all[i].PID)
			placed[all[i].PID] = true
		}
		if len(pids) > 0 {
			rank[metric] = pids
		}
	}
	for _, r := range all {
		if placed[r.PID] {
			rows = append(rows, r)
		}
	}
	sort.SliceStable(rows, func(a, b int) bool { return rows[a].CPU > rows[b].CPU })
	return rows, rank
}

// Rate returns a non-negative per-second rate from two counter readings. A
// counter that went backwards (reset, device replaced) yields 0 rather than
// a huge number; one that wrapped at 32 bits is followed across the wrap.
func Rate(previous, current uint64, seconds float64) float64 {
	d, ok := counterDelta(previous, current)
	if seconds <= 0 || !ok {
		return 0
	}
	return float64(d) / seconds
}

// counterDelta returns how far a counter advanced between two readings. 32-bit
// kernels keep most /proc counters (interface bytes, disk sectors) in an
// unsigned long, as do some NIC drivers on any kernel, so they wrap at 4 GiB:
// a reading below a previous one under 2^32 is a wrap when the distance
// across it is under 2^31. Anything else that went backwards was reset and
// reports no progress (ok false).
func counterDelta(previous, current uint64) (delta uint64, ok bool) {
	if current >= previous {
		return current - previous, true
	}
	if previous < 1<<32 {
		if d := 1<<32 - previous + current; d < 1<<31 {
			return d, true
		}
	}
	return 0, false
}
