package history

import (
	"encoding/json"
	"flag"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// base is a moment aligned to every window, so tests can count points.
var base = time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC)

func ms(d time.Duration) int64 { return base.Add(d).UnixMilli() }

func sample(t int64, cpu float64) *wire.Sample {
	return &wire.Sample{T: t, Interval: 2,
		CPU:     &wire.CPU{Total: cpu, User: cpu * 0.75, System: cpu * 0.25},
		Memory:  &wire.Memory{Total: 1000, Used: 250},
		Network: &wire.Network{RX: 1000, TX: 10},
		Disk:    &wire.Disk{Read: 5, Write: 7}}
}

func TestFromSample(t *testing.T) {
	s := sample(ms(0), 0.5)
	s.Memory.Swap = &wire.Swap{Total: 0, Used: 0}
	s.Thermal = &wire.Thermal{SoCCelsius: wire.F(61.25)}
	s.Power = &wire.Power{PackageWatts: wire.F(12), SystemWatts: wire.F(20)}
	s.GPUs = []wire.GPU{{Utilization: 0.3}, {Utilization: 0.9}}
	p := FromSample(s)
	want := map[Series]float64{CPU: 0.5, CPUUser: 0.375, CPUSystem: 0.125, Memory: 0.25, GPU: 0.3,
		CPUCelsius: 61.25, Watts: 20, RX: 1000, TX: 10, Read: 5, Write: 7}
	for s := Series(0); s < numSeries; s++ {
		v, ok := want[s]
		switch {
		case ok && p.V[s] != v:
			t.Errorf("%s = %v, want %v", Names[s], p.V[s], v)
		case !ok && !math.IsNaN(p.V[s]):
			t.Errorf("%s = %v, want missing", Names[s], p.V[s])
		}
	}
	if p := FromSample(&wire.Sample{T: 1}); !math.IsNaN(p.V[CPU]) || !math.IsNaN(p.V[Memory]) {
		t.Errorf("an empty sample recorded readings: %v", p.V)
	}
}

func TestAggregation(t *testing.T) {
	r := NewRecorder(2, base)
	// Ten minutes of samples every two seconds: CPU 0.2, except one second
	// at 0.9 in the third half-minute.
	for i := 1; i <= 300; i++ {
		cpu := 0.2
		if i == 40 {
			cpu = 0.9
		}
		r.Add(sample(ms(time.Duration(i)*2*time.Second), cpu))
	}
	// The window holding the last sample is still open.
	if n := len(r.medium.points); n != 19 {
		t.Fatalf("%d half-minute points, want 19", n)
	}
	if n := len(r.coarse.points); n != 1 {
		t.Fatalf("%d five-minute points, want 1", n)
	}
	third := r.medium.points[2]
	if third.T != ms(90*time.Second) {
		t.Errorf("third half-minute point ends at %v", time.UnixMilli(third.T).UTC())
	}
	if got, want := third.V[CPU], (0.2*14+0.9)/15; math.Abs(got-want) > 1e-9 {
		t.Errorf("average %v, want %v", got, want)
	}
	if third.V[CPUPeak] != 0.9 || r.medium.points[0].V[CPUPeak] != 0.2 {
		t.Errorf("peaks %v and %v", third.V[CPUPeak], r.medium.points[0].V[CPUPeak])
	}
	if !math.IsNaN(r.fine.points[0].V[CPUPeak]) {
		t.Errorf("fine points carry a peak")
	}
	if v := r.coarse.points[0].V[Memory]; v != 0.25 {
		t.Errorf("five-minute memory %v", v)
	}
	// Resync samples are not history.
	before := len(r.fine.points)
	s := sample(ms(1000*time.Second), 0.5)
	s.Resync = true
	r.Add(s)
	if len(r.fine.points) != before {
		t.Errorf("a resync sample was recorded")
	}
}

func TestSpans(t *testing.T) {
	r := NewRecorder(2, base)
	step := 20 * time.Second
	for d := step; d <= 50*time.Hour; d += step {
		r.AddPoint(Point{T: ms(d), V: FromSample(sample(0, 0.1)).V})
	}
	last := ms(50 * time.Hour)
	check := func(name string, tr *tier, max int) {
		if len(tr.points) == 0 || len(tr.points) > max {
			t.Errorf("%s holds %d points, want 1…%d", name, len(tr.points), max)
			return
		}
		if age := last - tr.points[0].T; age > tr.span.Milliseconds() {
			t.Errorf("%s reaches back %v, past its %v", name, time.Duration(age)*time.Millisecond, tr.span)
		}
	}
	check("fine", &r.fine, 45)
	check("medium", &r.medium, 480)
	check("coarse", &r.coarse, 576)
	if cap(r.fine.points) > 4*45 {
		t.Errorf("the fine ring's storage grew to %d", cap(r.fine.points))
	}
}

func TestClockStepsBack(t *testing.T) {
	r := NewRecorder(2, base)
	for i := 1; i <= 100; i++ {
		r.Add(sample(ms(time.Duration(i)*2*time.Second), 0.1))
	}
	r.Add(sample(ms(60*time.Second), 0.7))
	for _, tr := range []*tier{&r.fine, &r.medium, &r.coarse} {
		for i := 1; i < len(tr.points); i++ {
			if tr.points[i].T <= tr.points[i-1].T {
				t.Fatalf("points out of order after the clock stepped back")
			}
		}
		if n := len(tr.points); n > 0 && tr.points[n-1].T > ms(60*time.Second) {
			t.Errorf("a point from the old timeline survived: %v", time.UnixMilli(tr.points[n-1].T).UTC())
		}
	}
}

func processes(at int64, rows ...wire.ProcessRow) *wire.Processes {
	return &wire.Processes{Count: 300, SampledAt: at, Interval: 15, Rows: rows}
}

func TestProcessTables(t *testing.T) {
	r := NewRecorder(2, base)
	quiet := []wire.ProcessRow{{PID: 1, Name: "init", CPU: 0.1, Memory: 10}}
	var busy []wire.ProcessRow
	for i := int32(10); i < 30; i++ {
		busy = append(busy, wire.ProcessRow{PID: i, Name: "worker", Path: "/usr/bin/worker", CPU: float64(i), Memory: uint64(100 - i),
			Cmd: "worker " + strings.Repeat("x", 300), DiskRead: 5})
	}
	r.AddProcesses(processes(ms(1*time.Minute), quiet...))
	r.AddProcesses(processes(ms(5*time.Minute), busy...))
	r.AddProcesses(processes(ms(9*time.Minute), quiet...))
	// The next quarter hour closes the first.
	r.AddProcesses(processes(ms(16*time.Minute), quiet...))
	if len(r.procs) != 1 {
		t.Fatalf("%d closed tables, want 1", len(r.procs))
	}
	got := r.procs[0]
	if got.SampledAt != ms(5*time.Minute) {
		t.Errorf("kept the table from %v, not the busiest", time.UnixMilli(got.SampledAt).UTC())
	}
	if len(got.Rank["cpu"]) != processRows || got.Rank["cpu"][0] != 29 {
		t.Errorf("cpu rank %v", got.Rank["cpu"])
	}
	if len(got.Rank["memory"]) != processRows || got.Rank["memory"][0] != 10 {
		t.Errorf("memory rank %v", got.Rank["memory"])
	}
	if len(got.Rows) != 2*processRows {
		t.Errorf("%d rows, want %d", len(got.Rows), 2*processRows)
	}
	rows := map[int32]wire.ProcessRow{}
	for _, row := range got.Rows {
		rows[row.PID] = row
		if row.Path != "" || row.DiskRead != 0 || len(row.Cmd) > maxCmd+len("…") {
			t.Errorf("row kept more than history shows: %+v", row)
		}
	}
	for metric, pids := range got.Rank {
		for _, pid := range pids {
			if _, ok := rows[pid]; !ok {
				t.Errorf("rank.%s names pid %d, which has no row", metric, pid)
			}
		}
	}
	// A day later the old tables are gone.
	r.AddProcesses(processes(ms(25*time.Hour), quiet...))
	r.AddProcesses(processes(ms(26*time.Hour), quiet...))
	for _, p := range r.procs {
		if ms(26*time.Hour)-p.SampledAt > ProcessSpan.Milliseconds() {
			t.Errorf("a table from %v outlived the span", time.UnixMilli(p.SampledAt).UTC())
		}
	}
}

// One process reading that is not a number must not cost history its
// process tables: a table holding NaN cannot be encoded.
func TestProcessTablesSurviveNaN(t *testing.T) {
	r := NewRecorder(2, base)
	r.AddProcesses(processes(ms(1*time.Minute), wire.ProcessRow{PID: 1, Name: "init", CPU: 3, Memory: 10}))
	r.AddProcesses(processes(ms(16*time.Minute), wire.ProcessRow{PID: 2, Name: "odd", CPU: math.NaN(), Memory: 20},
		wire.ProcessRow{PID: 3, Name: "busy", CPU: 9, Memory: 5}))
	if math.IsNaN(r.procScore) || r.procScore != 9 {
		t.Errorf("score %v, want 9: a NaN row counts as idle", r.procScore)
	}
	odd := processes(ms(17*time.Minute), wire.ProcessRow{PID: 4, Name: "x", CPU: 50, Memory: 1})
	odd.Interval = math.NaN()
	r.AddProcesses(odd)
	r.AddProcesses(processes(ms(31*time.Minute), wire.ProcessRow{PID: 1, Name: "init", CPU: 1, Memory: 10}))
	var m struct{ Processes []wire.Processes }
	if err := json.Unmarshal(r.Message(0), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Processes) != 3 {
		t.Fatalf("%d process tables, want 3: %+v", len(m.Processes), m.Processes)
	}
	second := m.Processes[1]
	if second.SampledAt != ms(16*time.Minute) {
		t.Errorf("the table with no interval was kept: %+v", second)
	}
	for _, row := range second.Rows {
		if row.PID == 2 && row.CPU != 0 {
			t.Errorf("a NaN CPU became %v, want 0", row.CPU)
		}
	}
	if cpu := second.Rank["cpu"]; len(cpu) != 1 || cpu[0] != 3 {
		t.Errorf("cpu rank %v, want only the busy process", cpu)
	}
}

// A serve that restarts in the middle of a window ends that window with
// the same point as one that kept running: the restored finest tier is
// folded into the open windows again, and not recorded twice. That holds
// after a short restart and after one long enough for the finest tier to
// age out.
func TestRestartKeepsOpenWindows(t *testing.T) {
	cpu := func(i int) float64 { return float64(i%13) / 13 }
	for _, gap := range []time.Duration{0, 20 * time.Minute} {
		whole, before := NewRecorder(2, base), NewRecorder(2, base)
		// 400 s in: inside the half minute that ends at 420 s, and the
		// five minutes that end at 600 s.
		for i := 1; i <= 200; i++ {
			whole.Add(sample(ms(time.Duration(i)*2*time.Second), cpu(i)))
			before.Add(sample(ms(time.Duration(i)*2*time.Second), cpu(i)))
		}
		resumed := NewRecorder(2, base)
		if err := resumed.Load(before.Message(0), base.Add(400*time.Second+gap)); err != nil {
			t.Fatal(err)
		}
		first := 201 + int(gap/(2*time.Second))
		for i := first; i < first+300; i++ {
			whole.Add(sample(ms(time.Duration(i)*2*time.Second), cpu(i)))
			resumed.Add(sample(ms(time.Duration(i)*2*time.Second), cpu(i)))
		}
		if got, want := resumed.Message(0), whole.Message(0); string(got) != string(want) {
			t.Errorf("after a %v restart the rings differ from ones that kept running:\n got %s\nwant %s", gap, got, want)
		}
	}
}

func TestMessageRoundTrip(t *testing.T) {
	r := NewRecorder(2, base)
	for i := 1; i <= 400; i++ {
		s := sample(ms(time.Duration(i)*2*time.Second), float64(i%10)/10)
		if i%7 == 0 {
			s.Disk = nil // a reading that was missing once
		}
		r.Add(s)
	}
	r.AddProcesses(processes(ms(100*time.Second), wire.ProcessRow{PID: 7, Name: "rsync", CPU: 80, Memory: 5e6}))
	msg := r.Message(0)
	var m struct {
		Type      string
		Started   int64
		Interval  float64
		Tiers     []map[string]any
		Processes []wire.Processes
	}
	if err := json.Unmarshal(msg, &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, msg)
	}
	if m.Type != "history" || m.Started != base.UnixMilli() || m.Interval != 2 || len(m.Tiers) != 3 || len(m.Processes) != 1 {
		t.Fatalf("message head: %+v", m)
	}
	if m.Tiers[0]["step"] != 2.0 || m.Tiers[1]["step"] != 30.0 || m.Tiers[2]["step"] != 300.0 {
		t.Errorf("steps %v %v %v", m.Tiers[0]["step"], m.Tiers[1]["step"], m.Tiers[2]["step"])
	}
	for _, missing := range []string{"gpu", "cpuCelsius", "watts", "swap"} {
		if _, ok := m.Tiers[0][missing]; ok {
			t.Errorf("series %s was never reported but is in the message", missing)
		}
	}
	if _, ok := m.Tiers[0]["cpuPeak"]; ok {
		t.Errorf("the finest tier carries cpuPeak")
	}
	if !strings.Contains(string(msg), "null") {
		t.Errorf("a missing reading did not become null")
	}
	if strings.ContainsAny(string(msg), "\n") {
		t.Errorf("the message spans lines")
	}

	restored := NewRecorder(2, base.Add(time.Hour))
	if err := restored.Load(msg, base.Add(801*time.Second)); err != nil {
		t.Fatal(err)
	}
	if again := restored.Message(0); string(again[strings.Index(string(again), `"interval"`):]) !=
		string(msg[strings.Index(string(msg), `"interval"`):]) {
		t.Errorf("a saved and loaded history changed:\n%s\n%s", msg, again)
	}
	if restored.Started != base.Add(time.Hour).UnixMilli() {
		t.Errorf("Load replaced Started")
	}
}

func TestLoadDropsStaleAndFuture(t *testing.T) {
	r := NewRecorder(2, base)
	for i := 1; i <= 100; i++ {
		r.Add(sample(ms(time.Duration(i)*2*time.Second), 0.3))
	}
	msg := r.Message(0)
	// Twenty minutes later the finest tier (15 minutes) has aged out.
	later := NewRecorder(2, base)
	if err := later.Load(msg, base.Add(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(later.fine.points) != 0 || len(later.medium.points) == 0 {
		t.Errorf("after 20 min: %d fine, %d medium", len(later.fine.points), len(later.medium.points))
	}
	// Loaded by a clock that is behind the one that saved it: nothing
	// from "the future" is kept.
	earlier := NewRecorder(2, base)
	if err := earlier.Load(msg, base.Add(60*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, p := range earlier.fine.points {
		if p.T > ms(60*time.Second) {
			t.Fatalf("kept a point from the future")
		}
	}
	for _, bad := range []string{"", "{", `{"type":"sample"}`, `{"type":"history","tiers":[{"step":2,"t":[1,2],"cpu":[1]}]}`} {
		if err := NewRecorder(2, base).Load([]byte(bad), base); err == nil {
			t.Errorf("loaded %q", bad)
		}
	}
}

func TestMessageFitsLimit(t *testing.T) {
	r := NewRecorder(2, base)
	for i := 1; i <= 400; i++ {
		r.Add(sample(ms(time.Duration(i)*2*time.Second), 0.5))
	}
	for i := 0; i < 50; i++ {
		var rows []wire.ProcessRow
		for p := int32(0); p < 10; p++ {
			rows = append(rows, wire.ProcessRow{PID: p, Name: "x", Cmd: strings.Repeat("y", 200), CPU: 1, Memory: 1})
		}
		r.AddProcesses(processes(ms(time.Duration(i)*15*time.Minute), rows...))
	}
	full := r.Message(0)
	limited := r.Message(len(full) - 1)
	if len(limited) >= len(full) || strings.Contains(string(limited), `"processes"`) {
		t.Errorf("an over-long message kept its process tables (%d of %d bytes)", len(limited), len(full))
	}
	if !json.Valid(limited) {
		t.Errorf("the shortened message is not JSON")
	}
}

func TestNumbers(t *testing.T) {
	for _, c := range []struct {
		v    float64
		d    int
		want string
	}{{0.5, 4, "0.5"}, {0.123456, 4, "0.1235"}, {12, 2, "12"}, {-0.00001, 4, "0"}, {1234567.6, 0, "1234568"}, {61.25, 1, "61.3"}} {
		if got := string(appendNumber(nil, c.v, c.d)); got != c.want {
			t.Errorf("appendNumber(%v, %d) = %s, want %s", c.v, c.d, got, c.want)
		}
	}
}

var update = flag.Bool("update", false, "rewrite testdata/history.json")

// golden is a small, fixed history: 3 minutes of samples every 2 seconds
// with every series, one missing disk reading, and one process table.
func golden() *Recorder {
	r := NewRecorder(2, base)
	for i := 1; i <= 90; i++ {
		s := sample(ms(time.Duration(i)*2*time.Second), float64(i%20)/20)
		s.Memory.Swap = &wire.Swap{Total: 400, Used: 100}
		s.GPUs = []wire.GPU{{Utilization: 0.125}}
		s.Thermal = &wire.Thermal{CPUCelsius: wire.F(50 + float64(i%5)), GPUCelsius: wire.F(45)}
		s.Power = &wire.Power{PackageWatts: wire.F(12.5)}
		if i == 45 {
			s.Disk = nil
		}
		r.Add(s)
	}
	r.AddProcesses(&wire.Processes{Count: 200, SampledAt: ms(100 * time.Second), Interval: 15,
		Rows: []wire.ProcessRow{{PID: 7, Name: "rsync", User: "alex", Cmd: "rsync -a /srv /backup", CPU: 80.5, Memory: 5e6},
			{PID: 9, Name: "postgres", User: "postgres", CPU: 2, Memory: 9e8}}})
	return r
}

// TestGolden pins the wire form. The app's decoder is checked against the
// same file (Tools/connection-check.swift), so the two cannot drift apart.
func TestGolden(t *testing.T) {
	got := golden().Message(0)
	path := filepath.Join("testdata", "history.json")
	if *update {
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/history -update)", err)
	}
	if string(got)+"\n" != string(want) {
		t.Errorf("the history message changed; if on purpose, run go test ./internal/history -update and check the app still reads it\n got: %s\nwant: %s", got, want)
	}
}
