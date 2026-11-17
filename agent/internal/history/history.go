// Package history is what the background agent (serve) remembers about a
// machine: three rings of vitals at falling resolution, the busiest process
// table of every quarter hour, and what each process used over every quarter
// hour. PROTOCOL.md's "history" message is its wire form; serve saves the
// whole of it to disk, and sends the app the part the app shows.
//
// Missing is not zero here either: a series a machine cannot report is left
// out of the message, and a point where one reading was unavailable carries
// null for it.
package history

import (
	"encoding/json"
	"errors"
	"fmt"
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
	// maxUsageProcesses bounds the processes one quarter hour's usage
	// tracks, on a machine that starts many short-lived ones.
	maxUsageProcesses = 20000
	// maxCmd caps a kept command line, in bytes.
	maxCmd = 200
)

// Retention is how far back the coarsest tier and the quarter-hour process
// records go. The finer tiers keep their fixed spans.
type Retention struct {
	Days      int
	Vitals    time.Duration
	Processes time.Duration
}

const (
	// DefaultKeepDays is the retention without a setting: 48 hours of
	// vitals and 24 hours of process records, as much as the app shows.
	DefaultKeepDays = 2
	// MaxKeepDays bounds a setting (PROTOCOL.md, "Background history"):
	// a month is about 22 MB on disk, rewritten whole on every save.
	MaxKeepDays = 30
)

// KeepDays is the retention for a setting of days: the default for
// DefaultKeepDays or less, otherwise that many days of both.
func KeepDays(days int) Retention {
	if days <= DefaultKeepDays {
		return Retention{Days: DefaultKeepDays, Vitals: CoarseSpan, Processes: ProcessSpan}
	}
	days = min(days, MaxKeepDays)
	d := time.Duration(days) * 24 * time.Hour
	return Retention{Days: days, Vitals: d, Processes: d}
}

// Text says what the retention keeps, for messages.
func (rt Retention) Text() string {
	if rt.Days <= DefaultKeepDays {
		return "48 hours of vitals and 24 hours of process records"
	}
	return fmt.Sprintf("%d days of vitals and process records", rt.Days)
}

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

	usage []Usage     // one per ProcessStep window, oldest first
	open  usageWindow // the window still open

	keep Retention
}

// NewRecorder returns empty rings for samples interval seconds apart, with
// the default retention.
func NewRecorder(interval float64, now time.Time) *Recorder {
	keep := KeepDays(DefaultKeepDays)
	return &Recorder{
		Interval: interval,
		Started:  now.UnixMilli(),
		fine:     tier{span: FineSpan},
		medium:   tier{step: MediumStep, span: MediumSpan},
		coarse:   tier{step: CoarseStep, span: keep.Vitals},
		keep:     keep,
	}
}

// Retention is how far back this recorder keeps history.
func (r *Recorder) Retention() Retention { return r.keep }

// SetKeepDays changes the retention, dropping at once whatever a shorter
// one no longer keeps. now is ms since the epoch.
func (r *Recorder) SetKeepDays(days int, now int64) {
	r.keep = KeepDays(days)
	r.coarse.span = r.keep.Vitals
	r.coarse.prune(now)
	r.pruneProcesses(now)
}

// pruneProcesses drops the process tables and usage older than the
// retention before now (ms).
func (r *Recorder) pruneProcesses(now int64) {
	cut := now - r.keep.Processes.Milliseconds()
	if i := sort.Search(len(r.procs), func(i int) bool { return r.procs[i].SampledAt > cut }); i > 0 {
		r.procs = append(r.procs[:0], r.procs[i:]...)
	}
	if i := sort.Search(len(r.usage), func(i int) bool { return r.usage[i].End > cut }); i > 0 {
		r.usage = append(r.usage[:0], r.usage[i:]...)
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
	// NaN fails "<= 0" as well as "> 0": a table whose interval is not a
	// positive number is not a measurement, and JSON could not carry it.
	if p == nil || p.SampledAt <= 0 || !(finite(p.Interval) > 0) || len(p.Rows) == 0 {
		return
	}
	r.addUsage(p)
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
	score := processScore(p.Rows)
	if r.procBest == nil || score > r.procScore {
		trimmed := trimProcesses(p)
		r.procBest, r.procScore = &trimmed, score
	}
	r.pruneProcesses(p.SampledAt)
}

// finite returns v, or 0 for NaN and the infinities.
func finite(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

// processScore is how busy a table's moment was: the CPU across its rows.
// A row whose CPU is not a number counts as idle, so one bad reading cannot
// make the score NaN (which loses every comparison).
func processScore(rows []wire.ProcessRow) float64 {
	score := 0.0
	for _, row := range rows {
		score += finite(row.CPU)
	}
	return score
}

// trimProcesses keeps the processRows leaders by CPU and by memory, with
// only the columns history shows. A CPU that is not a number is kept as 0:
// a table holding NaN could not be encoded, and would take every table
// with it out of the history message for as long as it was kept.
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
		"cpu":    func(r *wire.ProcessRow) float64 { return finite(r.CPU) },
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
			Cmd: truncate(row.Cmd, maxCmd), CPU: finite(row.CPU), Memory: row.Memory, Threads: row.Threads})
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
		len(r.procs) == 0 && r.procBest == nil && len(r.usage) == 0 && r.open.scans == 0
}

// latest is the time of the newest thing recorded, ms since the epoch, or 0.
func (r *Recorder) latest() int64 {
	var t int64
	for _, tr := range []*tier{&r.fine, &r.medium, &r.coarse} {
		if n := len(tr.points); n > 0 {
			t = max(t, tr.points[n-1].T)
		}
	}
	if r.procBest != nil {
		t = max(t, r.procBest.SampledAt)
	}
	if n := len(r.procs); n > 0 {
		t = max(t, r.procs[n-1].SampledAt)
	}
	return t
}

// Message is the history message the app is sent: the last CoarseSpan of
// vitals and ProcessSpan of process tables, however long the retention,
// and no usage. It stays under maxLen bytes by leaving out the process
// tables, then the finest tier, if it must. Windows still open are not
// included, except the busiest process table so far, which is a real table
// already.
func (r *Recorder) Message(maxLen int) []byte {
	b := r.encode(encoding{processes: true, fine: true})
	if maxLen > 0 && len(b) > maxLen {
		b = r.encode(encoding{fine: true})
	}
	if maxLen > 0 && len(b) > maxLen {
		b = r.encode(encoding{})
	}
	return b
}

// Export is everything kept, with the retention and the usage: what serve
// saves to disk, and what the history command reads. The open window's
// usage so far is the last entry of usage.
func (r *Recorder) Export() []byte {
	return r.encode(encoding{processes: true, fine: true, all: true})
}

// encoding chooses what encode writes: the process tables, the finest
// tier, and everything kept (all) or only what the app shows.
type encoding struct{ processes, fine, all bool }

func (r *Recorder) encode(e encoding) []byte {
	vitalsCut, procCut := int64(math.MinInt64), int64(math.MinInt64)
	if !e.all {
		latest := r.latest()
		vitalsCut = latest - CoarseSpan.Milliseconds()
		procCut = latest - ProcessSpan.Milliseconds()
	}
	b := make([]byte, 0, 64<<10)
	b = append(b, `{"type":"history","started":`...)
	b = strconv.AppendInt(b, r.Started, 10)
	b = append(b, `,"interval":`...)
	b = appendNumber(b, r.Interval, 3)
	if e.all {
		b = append(b, `,"keepDays":`...)
		b = strconv.AppendInt(b, int64(r.keep.Days), 10)
	}
	b = append(b, `,"tiers":[`...)
	first := true
	for _, t := range []*tier{&r.fine, &r.medium, &r.coarse} {
		if t == &r.fine && !e.fine {
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
		points := t.points
		if i := sort.Search(len(points), func(i int) bool { return points[i].T > vitalsCut }); i > 0 {
			points = points[i:]
		}
		b = appendTier(b, step, points)
	}
	b = append(b, ']')
	if e.processes {
		tables := r.procs
		if r.procBest != nil {
			tables = append(tables[:len(tables):len(tables)], *r.procBest)
		}
		if i := sort.Search(len(tables), func(i int) bool { return tables[i].SampledAt > procCut }); i > 0 {
			tables = tables[i:]
		}
		if len(tables) > 0 {
			if data, err := json.Marshal(tables); err == nil {
				b = append(b, `,"processes":`...)
				b = append(b, data...)
			}
		}
	}
	if e.all {
		usage := r.usage
		if r.open.scans > 0 {
			usage = append(usage[:len(usage):len(usage)], r.open.summary())
		}
		if len(usage) > 0 {
			if data, err := json.Marshal(usage); err == nil {
				b = append(b, `,"usage":`...)
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
	KeepDays  int                          `json:"keepDays"`
	Tiers     []map[string]json.RawMessage `json:"tiers"`
	Processes []wire.Processes             `json:"processes"`
	Usage     []Usage                      `json:"usage"`
}

// Load restores rings saved by Export (or Message), dropping whatever has
// aged out since under this recorder's retention (or lies in the future: a
// clock that was wrong when they were saved). Started and the retention
// keep their own values.
func (r *Recorder) Load(data []byte, now time.Time) error {
	var m wireMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m.Type != "history" {
		return errors.New("not a history file")
	}
	nowMS := now.UnixMilli()
	// The finest tier, and the time of each tier's last point, as saved:
	// before anything has aged out.
	var fine []Point
	var savedMedium, savedCoarse int64
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
		var last int64
		if n := len(t.points); n > 0 {
			last = t.points[n-1].T
		}
		switch t {
		case &r.fine:
			fine = append([]Point(nil), t.points...)
		case &r.medium:
			savedMedium = last
		case &r.coarse:
			savedCoarse = last
		}
		t.prune(nowMS)
	}
	// The windows still open when the rings were saved are in no coarser
	// tier yet, only in the finest. Fold its points into them again (not
	// into the finest tier, which has them), so the window that spans a
	// restart ends with the same point as if serve had kept running. This
	// goes by the rings as saved: a window that closed while serve was down
	// still gets all of its points, even where the finest tier no longer
	// reaches back that far.
	r.mediumBucket, r.coarseBucket = bucket{}, bucket{}
	r.refold(&r.medium, &r.mediumBucket, fine, savedMedium)
	r.refold(&r.coarse, &r.coarseBucket, fine, savedCoarse)
	r.medium.prune(nowMS)
	r.coarse.prune(nowMS)

	r.procs = r.procs[:0]
	cut := nowMS - r.keep.Processes.Milliseconds()
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
		r.procBest, r.procScore, r.procEnd = &last, processScore(last.Rows), bucketEnd(last.SampledAt, ProcessStep)
	}
	r.loadUsage(m.Usage, nowMS)
	return nil
}

// refold folds the fine points after last, the end of t's last saved
// window, into b, the window t has open.
func (r *Recorder) refold(t *tier, b *bucket, fine []Point, last int64) {
	for _, p := range fine {
		if p.T > last {
			r.fold(t, b, p)
		}
	}
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
