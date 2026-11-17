package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

func row(pid int32, name string, cpu float64, memory uint64, read, write float64) wire.ProcessRow {
	return wire.ProcessRow{PID: pid, Name: name, User: "alex", Start: uint64(pid) * 1000, Cmd: name + " --work",
		CPU: cpu, Memory: memory, DiskRead: read, DiskWrite: write}
}

func TestUsageOverAQuarterHour(t *testing.T) {
	r := NewRecorder(2, base)
	// Two scans in the first quarter hour: ffmpeg is busy in one and idle
	// in the other; rsync reads in both; postgres holds memory.
	r.AddProcesses(processes(ms(5*time.Minute), row(10, "ffmpeg", 300, 100, 0, 0), row(11, "rsync", 2, 10, 4000, 0),
		row(12, "postgres", 1, 5000, 0, 0)))
	r.AddProcesses(processes(ms(10*time.Minute), row(10, "ffmpeg", 0, 200, 0, 0), row(11, "rsync", 2, 10, 2000, 1000),
		row(12, "postgres", 1, 4000, 0, 0)))
	if len(r.usage) != 0 || r.open.scans != 2 {
		t.Fatalf("%d closed windows and %d scans open, want 0 and 2", len(r.usage), r.open.scans)
	}
	// The first scan of the next quarter hour closes it.
	r.AddProcesses(processes(ms(16*time.Minute), row(10, "ffmpeg", 50, 100, 0, 0)))
	if len(r.usage) != 1 {
		t.Fatalf("%d closed windows, want 1", len(r.usage))
	}
	u := r.usage[0]
	if u.End != ms(15*time.Minute) || u.Seconds != 30 || u.Scans != 2 || u.Count != 3 {
		t.Errorf("window end %v, %v s, %d scans, %d processes", time.UnixMilli(u.End).UTC(), u.Seconds, u.Scans, u.Count)
	}
	rows := map[string]UsageRow{}
	for _, row := range u.Rows {
		rows[row.Name] = row
	}
	if f := rows["ffmpeg"]; f.CPU != 150 || f.CPUPeak != 300 || f.Memory != 200 || f.Seen != 2 {
		t.Errorf("ffmpeg %+v, want a mean of 150 %%, peak 300 %%, 200 bytes at most", f)
	}
	if r := rows["rsync"]; r.DiskRead != 3000 || r.DiskWrite != 500 {
		t.Errorf("rsync read %v and wrote %v bytes a second, want 3000 and 500", r.DiskRead, r.DiskWrite)
	}
	want := map[string][]int32{"cpu": {10, 11, 12}, "memory": {12, 10, 11}, "disk": {11}}
	got, _ := json.Marshal(u.Rank)
	if wantJSON, _ := json.Marshal(want); string(got) != string(wantJSON) {
		t.Errorf("ranks %s, want %s", got, wantJSON)
	}
	if u.Rows[0].Name != "ffmpeg" {
		t.Errorf("rows are not busiest first: %s first", u.Rows[0].Name)
	}
}

func TestRetention(t *testing.T) {
	r := NewRecorder(2, base)
	r.SetKeepDays(7, ms(0))
	if r.Retention().Days != 7 || r.coarse.span != 7*24*time.Hour {
		t.Fatalf("retention %+v", r.Retention())
	}
	// Four days of samples a minute apart, and a process table every
	// quarter hour.
	end := 4 * 24 * time.Hour
	for d := time.Minute; d <= end; d += time.Minute {
		r.AddPoint(Point{T: ms(d), V: FromSample(sample(0, 0.1)).V})
		if d%(15*time.Minute) == 0 {
			r.AddProcesses(processes(ms(d), row(10, "ffmpeg", 100, 100, 0, 0)))
		}
	}
	if age := ms(end) - r.coarse.points[0].T; age < (4*24-1)*time.Hour.Milliseconds() {
		t.Errorf("seven days keep only %v of vitals", time.Duration(age)*time.Millisecond)
	}
	if n := len(r.procs); n < 4*24*4-2 {
		t.Errorf("seven days keep only %d process tables", n)
	}
	if n := len(r.usage); n < 4*24*4-2 {
		t.Errorf("seven days keep only %d quarter hours of usage", n)
	}

	// The app is sent what it shows: 48 hours and 24 hours, no usage.
	var app wireMessage
	if err := json.Unmarshal(r.Message(0), &app); err != nil {
		t.Fatal(err)
	}
	coarse := app.Tiers[2]
	var times []int64
	json.Unmarshal(coarse["t"], &times)
	if age := ms(end) - times[0]; age > CoarseSpan.Milliseconds() {
		t.Errorf("the app is sent %v of five-minute points", time.Duration(age)*time.Millisecond)
	}
	if age := ms(end) - app.Processes[0].SampledAt; age > ProcessSpan.Milliseconds() {
		t.Errorf("the app is sent %v of process tables", time.Duration(age)*time.Millisecond)
	}
	if app.Usage != nil || app.KeepDays != 0 {
		t.Errorf("the app's message carries usage or the retention")
	}

	// The export has it all, and loads back.
	export := r.Export()
	if !strings.Contains(string(export), `"keepDays":7`) || !strings.Contains(string(export), `"usage":[`) {
		t.Errorf("the export lacks the retention or the usage")
	}
	back := NewRecorder(2, base)
	back.SetKeepDays(7, ms(end))
	if err := back.Load(export, base.Add(end)); err != nil {
		t.Fatal(err)
	}
	if len(back.coarse.points) != len(r.coarse.points) || len(back.usage) != len(r.usage) || back.open.scans != r.open.scans {
		t.Errorf("loaded %d five-minute points, %d usage windows and %d open scans; saved %d, %d and %d",
			len(back.coarse.points), len(back.usage), back.open.scans, len(r.coarse.points), len(r.usage), r.open.scans)
	}

	// Back to the default: what it no longer keeps goes at once.
	r.SetKeepDays(DefaultKeepDays, ms(end))
	if age := ms(end) - r.coarse.points[0].T; age > CoarseSpan.Milliseconds() {
		t.Errorf("after going back to the default, %v of vitals remain", time.Duration(age)*time.Millisecond)
	}
	if age := ms(end) - r.usage[0].End; age > ProcessSpan.Milliseconds() {
		t.Errorf("after going back to the default, %v of usage remains", time.Duration(age)*time.Millisecond)
	}
	if KeepDays(1000).Days != MaxKeepDays || KeepDays(0).Days != DefaultKeepDays {
		t.Errorf("KeepDays does not clamp")
	}
}

func TestOpenUsageSurvivesARestart(t *testing.T) {
	r := NewRecorder(2, base)
	r.AddProcesses(processes(ms(2*time.Minute), row(10, "ffmpeg", 200, 100, 0, 0)))
	r.AddProcesses(processes(ms(3*time.Minute), row(10, "ffmpeg", 100, 100, 0, 0)))
	back := NewRecorder(2, base)
	if err := back.Load(r.Export(), base.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if back.open.scans != 2 || len(back.usage) != 0 {
		t.Fatalf("the open window did not carry over: %d scans, %d closed", back.open.scans, len(back.usage))
	}
	back.AddProcesses(processes(ms(5*time.Minute), row(10, "ffmpeg", 0, 100, 0, 0)))
	back.AddProcesses(processes(ms(16*time.Minute), row(10, "ffmpeg", 0, 100, 0, 0)))
	if len(back.usage) != 1 || back.usage[0].Rows[0].CPU != 100 || back.usage[0].Scans != 3 {
		t.Errorf("after a restart the window holds %+v, want a mean of 100 %% over 3 scans", back.usage)
	}
}

func TestSelectAndText(t *testing.T) {
	r := NewRecorder(2, base)
	for d := 2 * time.Second; d <= 2*time.Hour; d += 2 * time.Second {
		cpu := 0.1
		if d > 30*time.Minute && d <= 45*time.Minute {
			cpu = 0.9
		}
		r.AddPoint(Point{T: ms(d), V: FromSample(sample(0, cpu)).V})
		if d%(15*time.Second) == 0 {
			busy := 5.0
			if cpu > 0.5 {
				busy = 700
			}
			r.AddProcesses(processes(ms(d), row(10, "ffmpeg", busy, 1<<30, 0, 5e6), row(11, "node", 20, 1<<28, 0, 0)))
		}
	}
	sel, err := Select(r.Export(), ms(30*time.Minute), ms(60*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Usage) != 2 || len(sel.Processes) != 2 {
		t.Fatalf("selected %d quarter hours of usage and %d tables, want 2 and 2", len(sel.Usage), len(sel.Processes))
	}
	text := sel.Text(time.UTC)
	for _, want := range []string{"History from Sat Oct 17 03:30 to Sat Oct 17 04:00", "Vitals (30-second means)",
		"CPU time", "ffmpeg (alex, pid 10)", "Memory (most resident at once)", "1.1 GB", "Disk (read + written)",
		"03:30–03:45  CPU 90%", "cpu     ffmpeg 700%, node 20%"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text lacks %q:\n%s", want, text)
		}
	}
	var back wireMessage
	if err := json.Unmarshal(sel.JSON(), &back); err != nil || back.Type != "history" || len(back.Usage) != 2 {
		t.Errorf("the JSON does not read back as history: %v", err)
	}
}

// goldenUsage is a small, fixed run of process tables: three scans of one
// quarter hour, and one of the next, still open.
func goldenUsage() *Recorder {
	r := NewRecorder(2, base)
	r.SetKeepDays(7, ms(0))
	scans := [][]wire.ProcessRow{
		{{PID: 7, Name: "rsync", User: "alex", Start: 1_792_000_000_000_000, Cmd: "rsync -a /srv /backup", CPU: 80.5, Memory: 5e6, DiskRead: 4e6, DiskWrite: 1e6},
			{PID: 9, Name: "postgres", User: "postgres", CPU: 2, Memory: 9e8},
			{PID: 11, Name: "ffmpeg", User: "alex", CPU: 390, Memory: 3e8, GPU: 40}},
		{{PID: 7, Name: "rsync", User: "alex", Start: 1_792_000_000_000_000, Cmd: "rsync -a /srv /backup", CPU: 60, Memory: 6e6, DiskRead: 2e6},
			{PID: 9, Name: "postgres", User: "postgres", CPU: 4, Memory: 9.1e8, DiskWrite: 3e5}},
		{{PID: 9, Name: "postgres", User: "postgres", CPU: 1, Memory: 9e8},
			{PID: 12, Name: "sh", User: "alex", Cmd: "sh -c true"}},
		{{PID: 9, Name: "postgres", User: "postgres", CPU: 3, Memory: 9e8}},
	}
	for i, rows := range scans {
		at := ms(time.Duration(100+i*15) * time.Second)
		if i == 3 {
			at = ms(16 * time.Minute)
		}
		r.AddProcesses(&wire.Processes{Count: 200, SampledAt: at, Interval: 15, Rows: rows})
	}
	return r
}

// TestGoldenUsage pins the usage's wire form and arithmetic. The macOS
// agent's Swift rings are checked against the same file
// (Tools/connection-check.swift).
func TestGoldenUsage(t *testing.T) {
	var m wireMessage
	if err := json.Unmarshal(goldenUsage().Export(), &m); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(m.Usage)
	path := filepath.Join("testdata", "usage.json")
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
		t.Errorf("the usage changed; if on purpose, run go test ./internal/history -update and check the Swift rings agree\n got: %s\nwant: %s", got, want)
	}
}
