package stream

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/collect"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// fakeCollector records the detail of every sample it is asked for.
type fakeCollector struct {
	mu       sync.Mutex
	details  []wire.Detail
	panicOn  int // panic on this sample number (1-based), 0 never
	nan      bool
	notices  []wire.Notice
	closed   bool
	sampleAt []time.Time
}

func (f *fakeCollector) Host() wire.Host        { return wire.Host{Hostname: "fake", LogicalCores: 2} }
func (f *fakeCollector) Capabilities() []string { return []string{"cpu"} }
func (f *fakeCollector) Doctor() []collect.Check {
	return nil
}
func (f *fakeCollector) Notices() []wire.Notice { return f.notices }
func (f *fakeCollector) Close()                 { f.closed = true }

func (f *fakeCollector) Sample(d wire.Detail) *wire.Sample {
	f.mu.Lock()
	f.details = append(f.details, d)
	f.sampleAt = append(f.sampleAt, time.Now())
	n := len(f.details)
	f.mu.Unlock()
	if n == f.panicOn {
		panic("sampler exploded")
	}
	s := &wire.Sample{Interval: 1, Resync: n == 1, CPU: &wire.CPU{Total: 0.25}}
	if f.nan {
		s.CPU.Total = math.NaN()
	}
	return s
}

func (f *fakeCollector) seen() []wire.Detail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wire.Detail(nil), f.details...)
}

// message is the union of the line types, enough to check them.
type message struct {
	Type     string      `json:"type"`
	Protocol int         `json:"protocol"`
	Seq      uint64      `json:"seq"`
	T        int64       `json:"t"`
	Detail   wire.Detail `json:"detail"`
	Resync   bool        `json:"resync"`
	Code     string      `json:"code"`
	Interval float64     `json:"interval"`
	CPU      *wire.CPU   `json:"cpu"`
	Host     wire.Host   `json:"host"`
}

// session runs Run on pipes and hands back a line reader.
type session struct {
	in    *io.PipeWriter
	lines chan string
	done  chan error
}

func start(t *testing.T, c collect.Collector, opts Options) *session {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &session{in: inW, lines: make(chan string, 64), done: make(chan error, 1)}
	go func() {
		err := Run(c, inR, outW, opts)
		outW.Close()
		s.done <- err
	}()
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
		for sc.Scan() {
			s.lines <- sc.Text()
		}
		close(s.lines)
	}()
	t.Cleanup(func() { inW.Close() })
	return s
}

func (s *session) next(t *testing.T) message {
	t.Helper()
	select {
	case line, ok := <-s.lines:
		if !ok {
			t.Fatal("stream ended")
		}
		var m message
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no line within 5 s")
	}
	return message{}
}

func TestHelloFirstThenSamples(t *testing.T) {
	f := &fakeCollector{notices: []wire.Notice{{Code: "rapl-denied", Message: "m"}}}
	s := start(t, f, Options{Agent: wire.AgentInfo{Name: "rex-boing-agent", Version: "test"}, Interval: 0.5, Count: 3})
	hello := s.next(t)
	if hello.Type != "hello" || hello.Protocol != 1 || hello.Host.Hostname != "fake" || hello.Interval != 0.5 {
		t.Fatalf("first line %+v", hello)
	}
	first := s.next(t)
	if first.Type != "sample" || first.Seq != 1 || first.Detail != wire.DetailVitals || !first.Resync || first.T == 0 {
		t.Errorf("first sample %+v", first)
	}
	if n := s.next(t); n.Type != "notice" || n.Code != "rapl-denied" {
		t.Errorf("notice after the first sample: %+v", n)
	}
	for seq := uint64(2); seq <= 3; seq++ {
		if m := s.next(t); m.Type != "sample" || m.Seq != seq {
			t.Errorf("sample %d: %+v", seq, m)
		}
	}
	if err := <-s.done; err != nil {
		t.Errorf("Run: %v", err)
	}
	if _, ok := <-s.lines; ok {
		t.Errorf("lines after the count")
	}
}

func TestRequestSwitchesDetail(t *testing.T) {
	f := &fakeCollector{}
	s := start(t, f, Options{Interval: 0.5})
	s.next(t) // hello
	s.next(t) // sample 1, vitals
	io.WriteString(s.in, `{"want":"full"}`+"\n")
	var m message
	for i := 0; i < 4; i++ {
		if m = s.next(t); m.Detail == wire.DetailFull {
			break
		}
	}
	if m.Detail != wire.DetailFull {
		t.Fatalf("detail never switched: %+v", m)
	}
	d := f.seen()
	if d[len(d)-1] != wire.DetailFull {
		t.Errorf("collector asked for %v", d)
	}
	io.WriteString(s.in, `{"want":"vitals","interval":0.5}`+"\n")
	for i := 0; i < 4; i++ {
		if m = s.next(t); m.Detail == wire.DetailVitals {
			break
		}
	}
	if m.Detail != wire.DetailVitals {
		t.Errorf("detail did not switch back: %+v", m)
	}
}

func TestEOFExitsFast(t *testing.T) {
	s := start(t, &fakeCollector{}, Options{Interval: 10})
	s.next(t)
	s.next(t)
	began := time.Now()
	s.in.Close()
	select {
	case err := <-s.done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		// PROTOCOL.md: exit immediately. Normally well under a millisecond;
		// the margin is for loaded CI machines.
		if d := time.Since(began); d > 200*time.Millisecond {
			t.Errorf("exit took %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run outlived its stdin")
	}
}

func TestMalformedRequestsIgnored(t *testing.T) {
	f := &fakeCollector{}
	s := start(t, f, Options{Interval: 0.5})
	s.next(t)
	s.next(t)
	io.WriteString(s.in, "not json\n{\"want\":\n[]\n{\"want\":\"everything\"}\n\n")
	io.WriteString(s.in, `{"interval":"fast"}`+"\n")
	io.WriteString(s.in, "{\"want\":\""+strings.Repeat("x", MaxLine+10)+"\"}\n") // too long: dropped whole
	io.WriteString(s.in, `{"want":"full","extra":{"nested":[1,2]}}`+"\n")
	var m message
	for i := 0; i < 6; i++ {
		if m = s.next(t); m.Detail == wire.DetailFull {
			break
		}
	}
	if m.Detail != wire.DetailFull || m.Type != "sample" {
		t.Errorf("valid request after garbage not applied: %+v", m)
	}
}

func TestIntervalRequest(t *testing.T) {
	f := &fakeCollector{}
	s := start(t, f, Options{Interval: 10})
	s.next(t)
	s.next(t)
	// A 10 s wait is cut short by a request for 0.1 s (clamped to 0.5 s).
	began := time.Now()
	io.WriteString(s.in, `{"interval":0.1}`+"\n")
	s.next(t)
	if d := time.Since(began); d > 2*time.Second {
		t.Errorf("new interval applied after %v", d)
	}
	s.next(t)
	f.mu.Lock()
	gap := f.sampleAt[len(f.sampleAt)-1].Sub(f.sampleAt[len(f.sampleAt)-2])
	f.mu.Unlock()
	if gap < 400*time.Millisecond || gap > 1500*time.Millisecond {
		t.Errorf("gap between samples %v, want about 0.5 s", gap)
	}
	for in, want := range map[float64]float64{0.1: 0.5, 3: 3, 60: 10, -1: 1, math.NaN(): 1} {
		if got := ClampInterval(in); got != want {
			t.Errorf("ClampInterval(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestPanickingSamplerKeepsSession(t *testing.T) {
	f := &fakeCollector{panicOn: 2}
	s := start(t, f, Options{Interval: 0.5, Count: 3, Log: io.Discard})
	s.next(t)
	s.next(t)
	bare := s.next(t)
	if bare.Type != "sample" || bare.Seq != 2 || !bare.Resync || bare.CPU != nil {
		t.Errorf("sample after a panic %+v", bare)
	}
	if m := s.next(t); m.Seq != 3 || m.CPU == nil {
		t.Errorf("sampling did not continue: %+v", m)
	}
}

func TestUnencodableSampleDegrades(t *testing.T) {
	f := &fakeCollector{nan: true}
	s := start(t, f, Options{Interval: 0.5, Count: 1})
	s.next(t)
	if m := s.next(t); m.Type != "sample" || m.Seq != 1 || m.CPU != nil || !m.Resync {
		t.Errorf("NaN sample %+v", m)
	}
}

type failWriter struct{ n int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.n == 0 {
		return 0, errors.New("broken pipe")
	}
	w.n--
	return len(p), nil
}

func TestWriteFailureEnds(t *testing.T) {
	inR, inW := io.Pipe()
	defer inW.Close()
	done := make(chan error, 1)
	go func() { done <- Run(&fakeCollector{}, inR, &failWriter{n: 2}, Options{Interval: 0.5}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("Run ignored a failed write")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run kept going after stdout failed")
	}
}

// With --count the stream runs to the count even when stdin is already at
// end of file (CI, ssh without a terminal, a pipe of canned requests).
func TestCountIgnoresEOF(t *testing.T) {
	var out strings.Builder
	err := Run(&fakeCollector{}, strings.NewReader(`{"want":"full"}`+"\n"), &lockedWriter{w: &out}, Options{Interval: 0.5, Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines: %q", len(lines), out.String())
	}
	var last message
	json.Unmarshal([]byte(lines[3]), &last)
	if last.Seq != 3 || last.Detail != wire.DetailFull {
		t.Errorf("last sample %+v", last)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") || !strings.HasSuffix(l, "}") {
			t.Errorf("non-JSON output %q", l)
		}
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestHistoryAfterHello(t *testing.T) {
	calls := 0
	var mu sync.Mutex
	history := func() []byte {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return []byte(`{"type":"history","started":1,"interval":2,"tiers":[]}`)
	}
	s := start(t, &fakeCollector{}, Options{Interval: 0.5, History: history})
	if m := s.next(t); m.Type != "hello" {
		t.Fatalf("first line %+v", m)
	}
	if m := s.next(t); m.Type != "history" {
		t.Fatalf("second line %+v, want the history", m)
	}
	if m := s.next(t); m.Type != "sample" {
		t.Fatalf("third line %+v", m)
	}
	// Asked for again, it comes again; the detail is untouched.
	io.WriteString(s.in, `{"want":"full"}`+"\n"+`{"want":"history"}`+"\n")
	sawHistory, sawFull := false, false
	for i := 0; i < 6 && !(sawHistory && sawFull); i++ {
		m := s.next(t)
		sawHistory = sawHistory || m.Type == "history"
		sawFull = sawFull || (m.Type == "sample" && m.Detail == wire.DetailFull)
	}
	if !sawHistory || !sawFull {
		t.Errorf("after a history request: history %v, full samples %v", sawHistory, sawFull)
	}
}

func TestNoHistoryWithoutServe(t *testing.T) {
	for name, h := range map[string]func() []byte{
		"none":      func() []byte { return nil },
		"two lines": func() []byte { return []byte("{\"type\":\"history\"}\n{}") },
	} {
		s := start(t, &fakeCollector{}, Options{Interval: 0.5, Count: 1, History: h})
		s.next(t)
		if m := s.next(t); m.Type != "sample" {
			t.Errorf("%s: second line %+v, want a sample", name, m)
		}
	}
}
