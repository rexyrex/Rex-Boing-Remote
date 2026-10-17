// Package history is what the background agent (serve) remembers about a
// machine: three rings of vitals at falling resolution, and the busiest
// process table of every quarter hour. PROTOCOL.md's "history" message is
// its wire form, and the same JSON is what serve saves to disk.
//
// Missing is not zero here either: a series a machine cannot report is left
// out of the message, and a point where one reading was unavailable carries
// null for it.
package history

import (
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// Series names one value a point records.
type Series int

const (
	CPU Series = iota
	CPUPeak
	CPUUser
	CPUSystem
	Memory
	Swap
	GPU
	CPUCelsius
	GPUCelsius
	Watts
	RX
	TX
	Read
	Write
	numSeries
)

// Names are the series' keys in the history message.
var Names = [numSeries]string{"cpu", "cpuPeak", "cpuUser", "cpuSystem", "memory", "swap", "gpu",
	"cpuCelsius", "gpuCelsius", "watts", "rx", "tx", "read", "write"}

// decimals rounds each series on the wire: fractions to 0.01 %, degrees to
// a tenth, watts to a hundredth, byte rates to whole bytes.
var decimals = [numSeries]int{4, 4, 4, 4, 4, 4, 4, 1, 1, 2, 0, 0, 0, 0}

// Point is the machine over one window ending at T (ms since the epoch). A
// NaN value is a reading that was not available.
type Point struct {
	T int64
	V [numSeries]float64
}

// Missing returns a point at t with every value unavailable.
func Missing(t int64) Point {
	p := Point{T: t}
	for i := range p.V {
		p.V[i] = math.NaN()
	}
	return p
}

// FromSample takes the vitals history records from one sample.
func FromSample(s *wire.Sample) Point {
	p := Missing(s.T)
	set := func(series Series, v float64) {
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			p.V[series] = v
		}
	}
	if c := s.CPU; c != nil {
		set(CPU, c.Total)
		set(CPUUser, c.User)
		set(CPUSystem, c.System)
	}
	if m := s.Memory; m != nil && m.Total > 0 {
		set(Memory, float64(m.Used)/float64(m.Total))
		if m.Swap != nil && m.Swap.Total > 0 {
			set(Swap, float64(m.Swap.Used)/float64(m.Swap.Total))
		}
	}
	if len(s.GPUs) > 0 {
		set(GPU, s.GPUs[0].Utilization)
	}
	if t := s.Thermal; t != nil {
		if v := firstOf(t.CPUCelsius, t.SoCCelsius); v != nil {
			set(CPUCelsius, *v)
		}
		if t.GPUCelsius != nil {
			set(GPUCelsius, *t.GPUCelsius)
		}
	}
	// Whole-machine draw, in the order the app's power graph prefers it.
	if pw := s.Power; pw != nil {
		if v := firstOf(pw.SystemTotalWatts, pw.SystemWatts, pw.PackageWatts); v != nil {
			set(Watts, *v)
		}
	}
	if n := s.Network; n != nil {
		set(RX, n.RX)
		set(TX, n.TX)
	}
	if d := s.Disk; d != nil {
		set(Read, d.Read)
		set(Write, d.Write)
	}
	return p
}

func firstOf(values ...*float64) *float64 {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

// Tier spans and steps (PROTOCOL.md, "history").
const (
	FineSpan   = 15 * time.Minute
	MediumStep = 30 * time.Second
	MediumSpan = 4 * time.Hour
	CoarseStep = 5 * time.Minute
	CoarseSpan = 48 * time.Hour
	// ProcessStep is the window each kept process table stands for, and
	// ProcessSpan how far back they go.
	ProcessStep = 15 * time.Minute
	ProcessSpan = 24 * time.Hour
	// processRows is how many processes each ranking keeps.
	processRows = 5
	// maxCmd caps a kept command line, in bytes.
	maxCmd = 200
)

// tier is one ring: points in time order, none older than span.
type tier struct {
	step   time.Duration // 0 for the finest tier, whose step is the interval
	span   time.Duration
	points []Point
}

func (t *tier) add(p Point) {
	// A wall clock that stepped back would otherwise leave points out of
	// order; the newer timeline wins.
	t.truncateFrom(p.T)
	t.points = append(t.points, p)
	t.prune(p.T)
}

// truncateFrom drops the points at or after ms.
func (t *tier) truncateFrom(ms int64) {
	i := sort.Search(len(t.points), func(i int) bool { return t.points[i].T >= ms })
	t.points = t.points[:i]
}

// prune drops points older than span before now (ms).
func (t *tier) prune(now int64) {
	cut := now - t.span.Milliseconds()
	i := sort.Search(len(t.points), func(i int) bool { return t.points[i].T > cut })
	if i == 0 {
		return
	}
	// Copy down rather than reslice, so the backing array does not grow
	// without bound under a ring that only ever appends.
	n := copy(t.points, t.points[i:])
	t.points = t.points[:n]
}

// bucket averages the fine points of one window of a coarser tier.
type bucket struct {
	end   int64 // ms; 0 when empty
	sum   [numSeries]float64
	count [numSeries]int
	peak  float64
}

func (b *bucket) add(p Point) {
	for i, v := range p.V {
		if Series(i) == CPUPeak || math.IsNaN(v) {
			continue
		}
		b.sum[i] += v
		b.count[i]++
	}
	if c := p.V[CPU]; !math.IsNaN(c) && (b.count[CPU] == 1 || c > b.peak) {
		b.peak = c
	}
}

func (b *bucket) point() Point {
	p := Missing(b.end)
	for i := range p.V {
		if b.count[i] > 0 {
			p.V[i] = b.sum[i] / float64(b.count[i])
		}
	}
	if b.count[CPU] > 0 {
		p.V[CPUPeak] = b.peak
	}
	return p
}

// bucketEnd is the end of the step-long window holding ms: windows are
// aligned to the epoch, so every agent's 5-minute points fall on :00, :05….
func bucketEnd(ms int64, step time.Duration) int64 {
	s := step.Milliseconds()
	return (ms + s - 1) / s * s
}

// Recorder keeps the rings. It is not safe for concurrent use.
type Recorder struct {
	// Interval is the seconds between the samples given to Add.
	Interval float64
	// Started is when this recorder began, ms since the epoch.
	Started int64

	fine, medium, coarse tier
	mediumBucket         bucket
	coarseBucket         bucket

	procs     []wire.Processes // one per ProcessStep window, oldest first
	procBest  *wire.Processes  // the busiest table of the open window
	procScore float64
	procEnd   int64
}

// NewRecorder returns empty rings for samples interval seconds apart.
func NewRecorder(interval float64, now time.Time) *Recorder {
	return &Recorder{
		Interval: interval,
		Started:  now.UnixMilli(),
		fine:     tier{span: FineSpan},
		medium:   tier{step: MediumStep, span: MediumSpan},
		coarse:   tier{step: CoarseStep, span: CoarseSpan},
	}
}

// Add records one sample's vitals. Samples whose rates are not valid
// (resync) are skipped, as the app skips them.
func (r *Recorder) Add(s *wire.Sample) {
	if s == nil || s.Resync || s.T <= 0 {
		return
	}
	r.AddPoint(FromSample(s))
}

// AddPoint records one fine point and folds it into the coarser windows.
func (r *Recorder) AddPoint(p Point) {
	if n := len(r.fine.points); n > 0 && p.T < r.fine.points[n-1].T {
		// The clock went back: everything recorded "after" now is from
		// the old timeline, open windows included.
		r.medium.truncateFrom(p.T)
		r.coarse.truncateFrom(p.T)
		r.mediumBucket, r.coarseBucket = bucket{}, bucket{}
	}
	r.fine.add(p)
	r.fold(&r.medium, &r.mediumBucket, p)
	r.fold(&r.coarse, &r.coarseBucket, p)
}

func (r *Recorder) fold(t *tier, b *bucket, p Point) {
	end := bucketEnd(p.T, t.step)
	if b.end != 0 && end != b.end {
		t.add(b.point())
		*b = bucket{}
	}
	b.end = end
	b.add(p)
	t.prune(p.T)
}

// AddProcesses offers one process table. Each ProcessStep window keeps the
// table of its busiest moment (the most CPU across the processes listed),
// trimmed to the leaders by CPU and by memory: the table that answers "what
// was running when the graph peaked".
func (r *Recorder) AddProcesses(p *wire.Processes) {
	if p == nil || p.SampledAt <= 0 || p.Interval <= 0 || len(p.Rows) == 0 {
		return
	}
	if p.SampledAt < r.procEnd-ProcessStep.Milliseconds() {
		// The clock went back: drop the tables from the old timeline.
		i := sort.Search(len(r.procs), func(i int) bool { return r.procs[i].SampledAt >= p.SampledAt })
		r.procs = r.procs[:i]
		r.procBest, r.procEnd = nil, 0
	}
	end := bucketEnd(p.SampledAt, ProcessStep)
	if r.procBest != nil && end != r.procEnd {
		r.procs = append(r.procs, *r.procBest)
		r.procBest = nil
	}
	r.procEnd = end
	score := 0.0
	for _, row := range p.Rows {
		score += row.CPU
	}
	if r.procBest == nil || score > r.procScore {
		trimmed := trimProcesses(p)
		r.procBest, r.procScore = &trimmed, score
	}
	cut := p.SampledAt - ProcessSpan.Milliseconds()
	i := sort.Search(len(r.procs), func(i int) bool { return r.procs[i].SampledAt > cut })
	if i > 0 {
		r.procs = append(r.procs[:0], r.procs[i:]...)
	}
}

// trimProcesses keeps the processRows leaders by CPU and by memory, with
// only the columns history shows.
func trimProcesses(p *wire.Processes) wire.Processes {
	leaders := func(value func(*wire.ProcessRow) float64) []int32 {
		idx := make([]int, len(p.Rows))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return value(&p.Rows[idx[a]]) > value(&p.Rows[idx[b]]) })
		var pids []int32
		for _, i := range idx {
			if len(pids) == processRows || value(&p.Rows[i]) <= 0 {
				break
			}
			pids = append(pids, p.Rows[i].PID)
		}
		return pids
	}
	rank := map[string][]int32{}
	keep := map[int32]bool{}
	for metric, value := range map[string]func(*wire.ProcessRow) float64{
		"cpu":    func(r *wire.ProcessRow) float64 { return r.CPU },
		"memory": func(r *wire.ProcessRow) float64 { return float64(r.Memory) },
	} {
		if pids := leaders(value); len(pids) > 0 {
			rank[metric] = pids
			for _, pid := range pids {
				keep[pid] = true
			}
		}
	}
	rows := []wire.ProcessRow{}
	for _, row := range p.Rows {
		if !keep[row.PID] {
			continue
		}
		rows = append(rows, wire.ProcessRow{PID: row.PID, Name: row.Name, User: row.User, Start: row.Start,
			Cmd: truncate(row.Cmd, maxCmd), CPU: row.CPU, Memory: row.Memory, Threads: row.Threads})
	}
	return wire.Processes{Count: p.Count, SampledAt: p.SampledAt, Interval: p.Interval,
		GPUAttribution: false, Rows: rows, Rank: rank}
}

// truncate cuts s to at most n bytes without splitting a character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// Oldest is the time of the oldest point kept, ms since the epoch, or 0.
func (r *Recorder) Oldest() int64 {
	oldest := int64(0)
	for _, t := range []*tier{&r.fine, &r.medium, &r.coarse} {
		if len(t.points) > 0 && (oldest == 0 || t.points[0].T < oldest) {
			oldest = t.points[0].T
		}
	}
	return oldest
}

// Empty reports whether nothing has been recorded.
func (r *Recorder) Empty() bool {
	return len(r.fine.points) == 0 && len(r.medium.points) == 0 && len(r.coarse.points) == 0 &&
		len(r.procs) == 0 && r.procBest == nil
}

// Message is the history message, one JSON object without the newline. It
// stays under maxLen bytes by leaving out the process tables, then the
// finest tier, if it must. Windows still open are not included, except the
// busiest process table so far, which is a real table already.
func (r *Recorder) Message(maxLen int) []byte {
	b := r.encode(true, true)
	if maxLen > 0 && len(b) > maxLen {
		b = r.encode(false, true)
	}
	if maxLen > 0 && len(b) > maxLen {
		b = r.encode(false, false)
	}
	return b
}

func (r *Recorder) encode(withProcesses, withFine bool) []byte {
	b := make([]byte, 0, 64<<10)
	b = append(b, `{"type":"history","started":`...)
	b = strconv.AppendInt(b, r.Started, 10)
	b = append(b, `,"interval":`...)
	b = appendNumber(b, r.Interval, 3)
	b = append(b, `,"tiers":[`...)
	first := true
	for _, t := range []*tier{&r.fine, &r.medium, &r.coarse} {
		if t == &r.fine && !withFine {
			continue
		}
		if !first {
			b = append(b, ',')
		}
		first = false
		step := t.step.Seconds()
		if t.step == 0 {
			step = r.Interval
		}
		b = appendTier(b, step, t.points)
	}
	b = append(b, ']')
	if withProcesses {
		tables := r.procs
		if r.procBest != nil {
			tables = append(tables[:len(tables):len(tables)], *r.procBest)
		}
		if len(tables) > 0 {
			if data, err := json.Marshal(tables); err == nil {
				b = append(b, `,"processes":`...)
				b = append(b, data...)
			}
		}
	}
	return append(b, '}')
}

func appendTier(b []byte, step float64, points []Point) []byte {
	b = append(b, `{"step":`...)
	b = appendNumber(b, step, 3)
	b = append(b, `,"t":[`...)
	for i, p := range points {
		if i > 0 {
			b = append(b, ',')
		}
		b = strconv.AppendInt(b, p.T, 10)
	}
	b = append(b, ']')
	for s := Series(0); s < numSeries; s++ {
		present := false
		for _, p := range points {
			if !math.IsNaN(p.V[s]) {
				present = true
				break
			}
		}
		if !present {
			continue // a series this machine never reported is left out
		}
		b = append(b, `,"`...)
		b = append(b, Names[s]...)
		b = append(b, `":[`...)
		for i, p := range points {
			if i > 0 {
				b = append(b, ',')
			}
			if v := p.V[s]; math.IsNaN(v) || math.IsInf(v, 0) {
				b = append(b, "null"...)
			} else {
				b = appendNumber(b, v, decimals[s])
			}
		}
		b = append(b, ']')
	}
	return append(b, '}')
}

// appendNumber writes v rounded to the given decimals, without trailing
// zeros ("0.5", "12", "0.0125").
func appendNumber(b []byte, v float64, decimals int) []byte {
	scale := math.Pow(10, float64(decimals))
	v = math.Round(v*scale) / scale
	if v == 0 {
		return append(b, '0') // also turns -0 into 0
	}
	return strconv.AppendFloat(b, v, 'f', -1, 64)
}

// wireMessage is the history message as it is read back from disk.
type wireMessage struct {
	Type      string                       `json:"type"`
	Started   int64                        `json:"started"`
	Interval  float64                      `json:"interval"`
	Tiers     []map[string]json.RawMessage `json:"tiers"`
	Processes []wire.Processes             `json:"processes"`
}

// Load restores rings saved by Message, dropping whatever has aged out
// since (or lies in the future: a clock that was wrong when they were
// saved). Started keeps its own value: it is when this recorder began.
func (r *Recorder) Load(data []byte, now time.Time) error {
	var m wireMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m.Type != "history" {
		return errors.New("not a history file")
	}
	nowMS := now.UnixMilli()
	for _, raw := range m.Tiers {
		step, points, err := decodeTier(raw)
		if err != nil {
			return err
		}
		var t *tier
		switch {
		case step == MediumStep.Seconds():
			t = &r.medium
		case step == CoarseStep.Seconds():
			t = &r.coarse
		case step > 0 && step <= 10:
			t = &r.fine
		default:
			continue // a tier this version does not keep
		}
		t.points = t.points[:0]
		for _, p := range points {
			if p.T <= nowMS && (len(t.points) == 0 || p.T > t.points[len(t.points)-1].T) {
				t.points = append(t.points, p)
			}
		}
		t.prune(nowMS)
	}
	r.procs = r.procs[:0]
	cut := nowMS - ProcessSpan.Milliseconds()
	for _, p := range m.Processes {
		if p.SampledAt > cut && p.SampledAt <= nowMS &&
			(len(r.procs) == 0 || p.SampledAt > r.procs[len(r.procs)-1].SampledAt) {
			r.procs = append(r.procs, p)
		}
	}
	if n := len(r.procs); n > 0 {
		// The last saved table may be an open window's best so far: let
		// it go on competing if this recorder's first tables land in the
		// same quarter hour.
		last := r.procs[n-1]
		r.procs = r.procs[:n-1]
		score := 0.0
		for _, row := range last.Rows {
			score += row.CPU
		}
		r.procBest, r.procScore, r.procEnd = &last, score, bucketEnd(last.SampledAt, ProcessStep)
	}
	return nil
}

func decodeTier(raw map[string]json.RawMessage) (step float64, points []Point, err error) {
	if err := json.Unmarshal(raw["step"], &step); err != nil {
		return 0, nil, errors.New("a tier without a step")
	}
	var times []int64
	if err := json.Unmarshal(raw["t"], &times); err != nil {
		return 0, nil, errors.New("a tier without times")
	}
	points = make([]Point, len(times))
	for i, t := range times {
		points[i] = Missing(t)
	}
	for s := Series(0); s < numSeries; s++ {
		data, ok := raw[Names[s]]
		if !ok {
			continue
		}
		var values []*float64
		if err := json.Unmarshal(data, &values); err != nil || len(values) != len(times) {
			return 0, nil, errors.New("tier series " + Names[s] + " does not match its times")
		}
		for i, v := range values {
			if v != nil {
				points[i].V[s] = *v
			}
		}
	}
	return step, points, nil
}
