package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// Range is the history kept between two moments: what the history command
// prints (PROTOCOL.md, "Reading history on the server").
type Range struct {
	From, To  int64 // ms since the epoch
	Started   int64
	Interval  float64
	KeepDays  int
	Oldest    int64 // the oldest point kept at all, ms, or 0
	Tiers     []RangeTier
	Processes []wire.Processes
	Usage     []Usage
}

// RangeTier is one tier's points whose windows overlap the range.
type RangeTier struct {
	Step   float64 // seconds
	Points []Point
}

// Select reads an exported history message (Export, or a saved file) and
// keeps what overlaps (from, to]: the points, process tables and usage
// whose windows reach into it.
func Select(data []byte, from, to int64) (*Range, error) {
	var m wireMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Type != "history" {
		return nil, errors.New("not a history message")
	}
	r := &Range{From: from, To: to, Started: m.Started, Interval: m.Interval, KeepDays: max(m.KeepDays, DefaultKeepDays)}
	overlaps := func(end int64, step float64) bool {
		return end > from && float64(end)-step*1000 < float64(to)
	}
	for _, raw := range m.Tiers {
		step, points, err := decodeTier(raw)
		if err != nil {
			return nil, err
		}
		if len(points) > 0 && (r.Oldest == 0 || points[0].T < r.Oldest) {
			r.Oldest = points[0].T
		}
		t := RangeTier{Step: step}
		for _, p := range points {
			if overlaps(p.T, step) {
				t.Points = append(t.Points, p)
			}
		}
		r.Tiers = append(r.Tiers, t)
	}
	sort.Slice(r.Tiers, func(i, j int) bool { return r.Tiers[i].Step < r.Tiers[j].Step })
	quarter := ProcessStep.Seconds()
	for _, p := range m.Processes {
		if overlaps(bucketEnd(p.SampledAt, ProcessStep), quarter) {
			r.Processes = append(r.Processes, p)
		}
	}
	for _, u := range m.Usage {
		if overlaps(u.End, quarter) {
			r.Usage = append(r.Usage, u)
		}
	}
	return r, nil
}

// JSON is the range as a history message, with "from" and "to".
func (r *Range) JSON() []byte {
	b := []byte(`{"type":"history","started":`)
	b = strconv.AppendInt(b, r.Started, 10)
	b = append(b, `,"interval":`...)
	b = appendNumber(b, r.Interval, 3)
	b = append(b, `,"keepDays":`...)
	b = strconv.AppendInt(b, int64(r.KeepDays), 10)
	b = append(b, `,"from":`...)
	b = strconv.AppendInt(b, r.From, 10)
	b = append(b, `,"to":`...)
	b = strconv.AppendInt(b, r.To, 10)
	b = append(b, `,"tiers":[`...)
	for i, t := range r.Tiers {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendTier(b, t.Step, t.Points)
	}
	b = append(b, ']')
	for _, part := range []struct {
		key   string
		value any
		n     int
	}{{"processes", r.Processes, len(r.Processes)}, {"usage", r.Usage, len(r.Usage)}} {
		if part.n == 0 {
			continue
		}
		if data, err := json.Marshal(part.value); err == nil {
			b = append(b, `,"`+part.key+`":`...)
			b = append(b, data...)
		}
	}
	return append(b, '}')
}

// vitals is the tier that best covers the range: the one whose points reach
// back furthest into it, the finer of two that reach as far.
func (r *Range) vitals() RangeTier {
	best := RangeTier{}
	bestStart := int64(math.MaxInt64)
	for _, t := range r.Tiers {
		if len(t.Points) == 0 {
			continue
		}
		start := t.Points[0].T - int64(t.Step*1000)
		if start < r.From {
			start = r.From
		}
		if start < bestStart {
			best, bestStart = t, start
		}
	}
	return best
}

// Text is the range for people (and for agents that would rather read):
// the vitals, the processes that used the most over the range, and the
// busiest quarter hours. Times are in loc.
func (r *Range) Text(loc *time.Location) string {
	var b strings.Builder
	sameDay := time.UnixMilli(r.From).In(loc).Format("2006-01-02") == time.UnixMilli(r.To).In(loc).Format("2006-01-02")
	at := func(ms int64) string {
		t := time.UnixMilli(ms).In(loc)
		if sameDay {
			return t.Format("15:04")
		}
		return t.Format("Mon Jan 2 15:04")
	}
	full := func(ms int64) string { return time.UnixMilli(ms).In(loc).Format("Mon Jan 2 15:04") }
	// A window, from its end and length: "03:30–03:45".
	window := func(end int64, step time.Duration) string {
		return at(end-step.Milliseconds()) + "–" + time.UnixMilli(end).In(loc).Format("15:04")
	}
	zone, offset := time.UnixMilli(r.To).In(loc).Zone()
	zoneText := "UTC"
	if offset != 0 || zone != "UTC" {
		zoneText = zone + ", UTC" + utcOffset(offset)
	}
	fmt.Fprintf(&b, "History from %s to %s (%s).\n", full(r.From), full(r.To), zoneText)
	fmt.Fprintf(&b, "The background agent samples every %g s and keeps %s", r.Interval, KeepDays(r.KeepDays).Text())
	if r.Oldest > 0 {
		fmt.Fprintf(&b, "; it has history back to %s", full(r.Oldest))
	}
	b.WriteString(".\n")

	v := r.vitals()
	if len(v.Points) == 0 {
		b.WriteString("\nNo vitals were recorded in this time.\n")
	} else {
		fmt.Fprintf(&b, "\nVitals (%s), %s to %s:\n", stepName(v.Step), at(v.Points[0].T-int64(v.Step*1000)), at(v.Points[len(v.Points)-1].T))
		r.writeVitals(&b, v, at, window)
	}

	if len(r.Usage) == 0 {
		if len(r.Processes) == 0 {
			b.WriteString("\nNo processes were recorded in this time.\n")
			return b.String()
		}
		b.WriteString("\nBusiest moment of each quarter hour (no per-process usage was recorded; an older agent?):\n")
		for _, p := range r.Processes {
			fmt.Fprintf(&b, "  %s  %s\n", at(p.SampledAt), leadersText(p.Rows, func(row wire.ProcessRow) (float64, string) {
				return row.CPU, fmt.Sprintf("%.0f%%", row.CPU)
			}))
		}
		return b.String()
	}
	r.writeProcesses(&b, window)
	r.writeQuarters(&b, v, window)
	return b.String()
}

func utcOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign, seconds = "-", -seconds
	}
	return fmt.Sprintf("%s%02d:%02d", sign, seconds/3600, seconds%3600/60)
}

func stepName(step float64) string {
	switch {
	case step >= 60:
		return fmt.Sprintf("%g-minute means", step/60)
	case step >= 30:
		return fmt.Sprintf("%g-second means", step)
	}
	return fmt.Sprintf("every sample, %g s apart", step)
}

// vitalRows are the series the text shows, how, and under what name.
var vitalRows = []struct {
	series Series
	name   string
	format func(float64) string
}{
	{CPU, "CPU", percent},
	{Memory, "Memory", percent},
	{Swap, "Swap", percent},
	{GPU, "GPU", percent},
	{CPUCelsius, "CPU temperature", func(v float64) string { return fmt.Sprintf("%.1f °C", v) }},
	{GPUCelsius, "GPU temperature", func(v float64) string { return fmt.Sprintf("%.1f °C", v) }},
	{Watts, "Power", func(v float64) string { return fmt.Sprintf("%.1f W", v) }},
	{RX, "Network in", rate},
	{TX, "Network out", rate},
	{Read, "Disk read", rate},
	{Write, "Disk write", rate},
}

func percent(v float64) string { return fmt.Sprintf("%.0f%%", v*100) }
func rate(v float64) string    { return bytesText(v) + "/s" }

// bytesText is a size in decimal units, as the app shows them.
func bytesText(v float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", v)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func (r *Range) writeVitals(b *strings.Builder, v RangeTier, at func(int64) string, window func(int64, time.Duration) string) {
	width := 0
	for _, row := range vitalRows {
		width = max(width, len(row.name))
	}
	step := time.Duration(v.Step * float64(time.Second))
	when := func(end int64) string {
		if step < time.Minute {
			return "at " + at(end)
		}
		return "in " + window(end, step)
	}
	for _, row := range vitalRows {
		sum, n := 0.0, 0
		peak, peakAt := math.Inf(-1), int64(0)
		for _, p := range v.Points {
			value := p.V[row.series]
			if math.IsNaN(value) {
				continue
			}
			sum += value
			n++
			high := value
			if row.series == CPU && !math.IsNaN(p.V[CPUPeak]) {
				high = p.V[CPUPeak]
			}
			if high > peak {
				peak, peakAt = high, p.T
			}
		}
		if n == 0 {
			continue
		}
		fmt.Fprintf(b, "  %-*s  mean %-9s peak %s %s\n", width, row.name, row.format(sum/float64(n)),
			row.format(peak), when(peakAt))
	}
}

// processTotal is one process name's work over the range, summed from the
// quarter hours it led in.
type processTotal struct {
	name, user, cmd string
	pids            map[int32]bool
	cpuSeconds      float64 // core-seconds
	gpuSeconds      float64
	read, write     float64 // bytes
	memory          uint64
	memoryAt        int64
	cpuPeak         float64
	cpuPeakAt       int64
}

func (r *Range) totals() []*processTotal {
	byName := map[string]*processTotal{}
	for _, u := range r.Usage {
		for _, row := range u.Rows {
			key := row.Name + "\x00" + row.User
			t := byName[key]
			if t == nil {
				t = &processTotal{name: row.Name, user: row.User, cmd: row.Cmd, pids: map[int32]bool{}}
				byName[key] = t
			}
			t.pids[row.PID] = true
			t.cpuSeconds += row.CPU / 100 * u.Seconds
			t.gpuSeconds += row.GPU / 100 * u.Seconds
			t.read += row.DiskRead * u.Seconds
			t.write += row.DiskWrite * u.Seconds
			if row.Memory > t.memory {
				t.memory, t.memoryAt = row.Memory, u.End
			}
			if row.CPUPeak > t.cpuPeak {
				t.cpuPeak, t.cpuPeakAt = row.CPUPeak, u.End
			}
		}
	}
	out := make([]*processTotal, 0, len(byName))
	for _, t := range byName {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// duration is core-seconds as hours, minutes or seconds.
func duration(seconds float64) string {
	switch {
	case seconds >= 3600:
		return fmt.Sprintf("%.1f h", seconds/3600)
	case seconds >= 60:
		return fmt.Sprintf("%.0f min", seconds/60)
	}
	return fmt.Sprintf("%.0f s", seconds)
}

func (t *processTotal) who() string {
	parts := []string{}
	if t.user != "" {
		parts = append(parts, t.user)
	}
	if n := len(t.pids); n > 1 {
		parts = append(parts, fmt.Sprintf("%d processes", n))
	} else {
		for pid := range t.pids {
			parts = append(parts, fmt.Sprintf("pid %d", pid))
		}
	}
	return t.name + " (" + strings.Join(parts, ", ") + ")"
}

func (r *Range) writeProcesses(b *strings.Builder, window func(int64, time.Duration) string) {
	at := func(end int64) string { return window(end, ProcessStep) }
	totals := r.totals()
	quarters := fmt.Sprintf("%d quarter hours", len(r.Usage))
	if len(r.Usage) == 1 {
		quarters = "1 quarter hour"
	}
	fmt.Fprintf(b, "\nProcesses that used the most, over %s (each quarter hour keeps its top %d by CPU, memory, disk and GPU):\n",
		quarters, processRows)
	// least is the smallest value worth a line: a second of CPU or GPU
	// time, a byte.
	section := func(title string, least float64, value func(*processTotal) float64, line func(*processTotal) string) {
		list := append([]*processTotal(nil), totals...)
		sort.SliceStable(list, func(i, j int) bool { return value(list[i]) > value(list[j]) })
		var lines []string
		for _, t := range list {
			if len(lines) == 8 || value(t) < least {
				break
			}
			lines = append(lines, "    "+line(t))
		}
		if len(lines) == 0 {
			return
		}
		b.WriteString("  " + title + ":\n")
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
	}
	section("CPU time (core-hours: 1 h is one core busy for an hour)", 1, func(t *processTotal) float64 { return t.cpuSeconds },
		func(t *processTotal) string {
			return fmt.Sprintf("%-8s %s, peak %.0f%% of a core in %s%s", duration(t.cpuSeconds), t.who(), t.cpuPeak, at(t.cpuPeakAt), cmdText(t))
		})
	section("Memory (most resident at once)", 1, func(t *processTotal) float64 { return float64(t.memory) },
		func(t *processTotal) string {
			return fmt.Sprintf("%-8s %s, in %s%s", bytesText(float64(t.memory)), t.who(), at(t.memoryAt), cmdText(t))
		})
	section("Disk (read + written)", 1, func(t *processTotal) float64 { return t.read + t.write },
		func(t *processTotal) string {
			return fmt.Sprintf("%-8s %s: %s read, %s written%s", bytesText(t.read+t.write), t.who(), bytesText(t.read), bytesText(t.write), cmdText(t))
		})
	section("GPU time", 1, func(t *processTotal) float64 { return t.gpuSeconds },
		func(t *processTotal) string {
			return fmt.Sprintf("%-8s %s%s", duration(t.gpuSeconds), t.who(), cmdText(t))
		})
}

func cmdText(t *processTotal) string {
	if t.cmd == "" || t.cmd == t.name {
		return ""
	}
	cmd := t.cmd
	if len(cmd) > 80 {
		cmd = truncate(cmd, 80)
	}
	return "\n             " + cmd
}

// writeQuarters lists the quarter hours: all of them for a short range,
// otherwise the busiest by CPU.
func (r *Range) writeQuarters(b *strings.Builder, v RangeTier, window func(int64, time.Duration) string) {
	type quarter struct {
		u   Usage
		cpu float64 // mean machine CPU, or NaN
	}
	quarters := make([]quarter, 0, len(r.Usage))
	step := ProcessStep.Milliseconds()
	for _, u := range r.Usage {
		sum, n := 0.0, 0
		for _, p := range v.Points {
			if p.T > u.End-step && p.T <= u.End && !math.IsNaN(p.V[CPU]) {
				sum += p.V[CPU]
				n++
			}
		}
		q := quarter{u: u, cpu: math.NaN()}
		if n > 0 {
			q.cpu = sum / float64(n)
		}
		quarters = append(quarters, q)
	}
	const shown = 12
	if len(quarters) > shown {
		sort.SliceStable(quarters, func(i, j int) bool {
			return busy(quarters[i].u, quarters[i].cpu) > busy(quarters[j].u, quarters[j].cpu)
		})
		quarters = quarters[:shown]
		sort.SliceStable(quarters, func(i, j int) bool { return quarters[i].u.End < quarters[j].u.End })
		fmt.Fprintf(b, "\nThe %d busiest quarter hours by CPU, in time order:\n", shown)
	} else {
		b.WriteString("\nEach quarter hour:\n")
	}
	for _, q := range quarters {
		head := window(q.u.End, ProcessStep)
		if !math.IsNaN(q.cpu) {
			head += fmt.Sprintf("  CPU %s", percent(q.cpu))
		}
		if q.u.Seconds < 0.9*ProcessStep.Seconds() {
			// Still open, or the agent was not running for all of it.
			head += fmt.Sprintf("  (%s of it recorded)", duration(q.u.Seconds))
		}
		b.WriteString("  " + head + "\n")
		byCPU := leaders(q.u, "cpu", func(row UsageRow) string { return fmt.Sprintf("%s %.0f%%", row.Name, row.CPU) })
		byMemory := leaders(q.u, "memory", func(row UsageRow) string { return fmt.Sprintf("%s %s", row.Name, bytesText(float64(row.Memory))) })
		byDisk := leaders(q.u, "disk", func(row UsageRow) string { return fmt.Sprintf("%s %s", row.Name, rate(row.DiskRead+row.DiskWrite)) })
		byGPU := leaders(q.u, "gpu", func(row UsageRow) string { return fmt.Sprintf("%s %.0f%%", row.Name, row.GPU) })
		for _, line := range [][2]string{{"cpu", byCPU}, {"memory", byMemory}, {"disk", byDisk}, {"gpu", byGPU}} {
			if line[1] != "" {
				fmt.Fprintf(b, "    %-7s %s\n", line[0], line[1])
			}
		}
	}
}

// busy orders quarter hours: by the machine's CPU where it was recorded,
// else by the CPU of the processes listed.
func busy(u Usage, cpu float64) float64 {
	if !math.IsNaN(cpu) {
		return cpu
	}
	sum := 0.0
	for _, row := range u.Rows {
		sum += row.CPU
	}
	return sum / 1e4
}

// leaders lists the first three of a usage ranking.
func leaders(u Usage, metric string, text func(UsageRow) string) string {
	rows := map[int32]UsageRow{}
	for _, row := range u.Rows {
		rows[row.PID] = row
	}
	var parts []string
	for _, pid := range u.Rank[metric] {
		if len(parts) == 3 {
			break
		}
		if row, ok := rows[pid]; ok {
			parts = append(parts, text(row))
		}
	}
	return strings.Join(parts, ", ")
}

// leadersText lists the first three rows of a process table by value.
func leadersText(rows []wire.ProcessRow, value func(wire.ProcessRow) (float64, string)) string {
	sorted := append([]wire.ProcessRow(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, _ := value(sorted[i])
		c, _ := value(sorted[j])
		return a > c
	})
	var parts []string
	for _, row := range sorted {
		if len(parts) == 3 {
			break
		}
		_, text := value(row)
		parts = append(parts, row.Name+" "+text)
	}
	return strings.Join(parts, ", ")
}
