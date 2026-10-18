package nvidia

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	out := "NVIDIA GeForce RTX 4090, 78, 30, 10240, 24564, 64, 186.52, 45, 2520, 3105, 0, 12\nTesla T4, [N/A], 0, 0, 15360, 40, [Not Supported], [N/A], 300, 1590, 0, 0\n"
	gpus := Parse(out)
	if len(gpus) != 2 {
		t.Fatalf("got %d gpus", len(gpus))
	}
	g := gpus[0]
	if g.Name != "NVIDIA GeForce RTX 4090" || g.Utilization != 0.78 || *g.Celsius != 64 || *g.Watts != 186.52 || *g.MaxClockMHz != 3105 {
		t.Errorf("unexpected first gpu: %+v", g)
	}
	if *g.MemoryTotal != 24564*1024*1024 || g.Engines["decode"] != 0.12 {
		t.Errorf("memory/engines wrong: %+v", g)
	}
	if gpus[1].Watts != nil || gpus[1].FanPercent != nil || gpus[1].Utilization != 0 {
		t.Errorf("N/A fields should be absent: %+v", gpus[1])
	}
}

// fakeSMI stands in for nvidia-smi: each run waits for the answer the test
// gives it by number (a run stuck in the kernel ignores its context, so the
// fake does too).
type fakeSMI struct {
	mu    sync.Mutex
	clock time.Time
	calls []chan answer // one per run, in the order the runs reached the fake
	next  int           // the first run not yet answered by answerRun
	r     *Reader
}

type answer struct {
	out string
	err error
}

const smiLine = "NVIDIA GeForce RTX 4090, 78, 30, 10240, 24564, 64, 186.52, 45, 2520, 3105, 0, 12\n"

func newFakeReader() (*Reader, *fakeSMI) {
	f := &fakeSMI{clock: time.Unix(1_800_000_000, 0)}
	r := &Reader{path: "nvidia-smi", minInterval: 2 * time.Second}
	r.now = func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.clock
	}
	r.run = func(ctx context.Context) ([]byte, error) {
		ch := make(chan answer)
		f.mu.Lock()
		f.calls = append(f.calls, ch)
		f.mu.Unlock()
		a := <-ch
		return []byte(a.out), a.err
	}
	f.r = r
	return r, f
}

func (f *fakeSMI) advance(d time.Duration) {
	f.mu.Lock()
	f.clock = f.clock.Add(d)
	f.mu.Unlock()
}

// started counts the runs the reader has started (its goroutines may not
// have reached the fake yet).
func (f *fakeSMI) started() int {
	f.r.mu.Lock()
	defer f.r.mu.Unlock()
	return int(f.r.seq)
}

// arrived waits until run i (0-based) has reached the fake.
func (f *fakeSMI) arrived(t *testing.T, i int) chan answer {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		if len(f.calls) > i {
			ch := f.calls[i]
			f.mu.Unlock()
			return ch
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("run %d never started", i)
		}
		time.Sleep(time.Millisecond)
	}
}

// answerRun answers run i and waits until the reader has used the answer.
func (f *fakeSMI) answerRun(t *testing.T, i int, a answer) {
	t.Helper()
	ch := f.arrived(t, i)
	f.r.mu.Lock()
	before := f.r.inflight
	f.r.mu.Unlock()
	ch <- a
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.r.mu.Lock()
		n := f.r.inflight
		f.r.mu.Unlock()
		if n < before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the reader never took the answer")
		}
		time.Sleep(time.Millisecond)
	}
}

// answer answers the oldest run not yet answered.
func (f *fakeSMI) answer(t *testing.T, a answer) {
	t.Helper()
	f.answerRun(t, f.next, a)
	f.next++
}

func TestReaderFailureClearsAndBacksOff(t *testing.T) {
	r, f := newFakeReader()
	if g := r.GPUs(); g != nil {
		t.Fatalf("first call returned %+v before any run finished", g)
	}
	f.answer(t, answer{out: smiLine})
	f.advance(2 * time.Second)
	if g := r.GPUs(); len(g) != 1 || g[0].Utilization != 0.78 {
		t.Fatalf("after a good run: %+v", g)
	}

	// A driver/library mismatch: the old reading must not stay on screen.
	f.answer(t, answer{out: "Failed to initialize NVML: Driver/library version mismatch\nNVML library version: 550.120\n", err: errors.New("exit status 18")})
	if g := r.GPUs(); g != nil {
		t.Errorf("a failed run left %+v in place", g)
	}
	if r.Err() != "nvidia-smi failed: exit status 18 (Failed to initialize NVML: Driver/library version mismatch)" {
		t.Errorf("Err() = %q", r.Err())
	}

	// Retries back off (2, 4, 8 … s) but never stop.
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	for i, wait := range want {
		runs := f.started()
		f.advance(wait - time.Second)
		r.GPUs()
		if f.started() != runs {
			t.Fatalf("retry %d started %v early", i+1, time.Second)
		}
		f.advance(time.Second)
		r.GPUs()
		if f.started() != runs+1 {
			t.Fatalf("retry %d did not start after %v", i+1, wait)
		}
		f.answer(t, answer{err: errors.New("exit status 18")})
	}
	for i := 0; i < 10; i++ {
		f.advance(maxBackoff)
		runs := f.started()
		r.GPUs()
		if f.started() != runs+1 {
			t.Fatalf("no retry after %d failures", 5+i)
		}
		f.answer(t, answer{err: errors.New("exit status 18")})
	}
	if backoff(40) != maxBackoff {
		t.Errorf("backoff(40) = %v", backoff(40))
	}

	// Recovery: the next good run brings the GPU back and resets the backoff.
	f.advance(maxBackoff)
	r.GPUs()
	f.answer(t, answer{out: smiLine})
	if g := r.GPUs(); len(g) != 1 || r.Err() != "" {
		t.Errorf("after recovery: %+v, err %q", g, r.Err())
	}
	f.advance(2 * time.Second)
	runs := f.started()
	r.GPUs()
	if f.started() != runs+1 {
		t.Errorf("the backoff outlived a good run")
	}
	f.answer(t, answer{out: smiLine})
}

func TestReaderHungRun(t *testing.T) {
	r, f := newFakeReader()
	r.GPUs()
	f.answer(t, answer{out: smiLine})
	f.advance(2 * time.Second)
	r.GPUs() // starts a run that never returns (D state after an Xid)
	f.arrived(t, 1)

	f.advance(r.hangAfter() - time.Second)
	if g := r.GPUs(); len(g) != 1 {
		t.Fatalf("within the deadline the last reading stays: %+v", g)
	}
	f.advance(2 * time.Second)
	if g := r.GPUs(); g != nil {
		t.Errorf("a hung run's GPU still shown as live: %+v", g)
	}
	if !strings.Contains(r.Err(), "did not finish") {
		t.Errorf("Err() = %q", r.Err())
	}
	// One more attempt may start after the backoff, then no more while both
	// are stuck.
	f.advance(2 * time.Second)
	r.GPUs()
	if f.started() != 3 {
		t.Fatalf("%d runs started, want a second attempt beside the hung one", f.started())
	}
	for i := 0; i < 5; i++ {
		f.advance(maxBackoff)
		r.GPUs()
	}
	if f.started() != 3 {
		t.Errorf("%d runs started while %d were stuck", f.started(), maxRuns)
	}
	// The newer run answers first; the hung one's late answer is ignored.
	f.arrived(t, 2)
	f.answerRun(t, 2, answer{out: strings.Replace(smiLine, ", 78,", ", 10,", 1)})
	f.answerRun(t, 1, answer{out: smiLine})
	if g := r.GPUs(); len(g) != 1 || g[0].Utilization != 0.10 {
		t.Errorf("a stale run's late answer replaced a newer one: %+v", g)
	}
}

func TestReaderAsleep(t *testing.T) {
	r, f := newFakeReader()
	if g := r.Asleep(); g != nil {
		t.Errorf("never read, yet asleep GPUs %+v", g)
	}
	r.GPUs()
	f.answer(t, answer{out: smiLine})
	runs := f.started()
	for i := 0; i < 5; i++ {
		f.advance(10 * time.Second)
		g := r.Asleep()
		if len(g) != 1 || g[0].Name != "NVIDIA GeForce RTX 4090" || g[0].Utilization != 0 || g[0].Celsius != nil ||
			g[0].MaxClockMHz == nil || *g[0].MaxClockMHz != 3105 {
			t.Fatalf("asleep GPUs %+v", g)
		}
	}
	if f.started() != runs {
		t.Errorf("nvidia-smi ran while the GPU slept")
	}
	// Waking up: the reading from before the sleep is not reused.
	if g := r.GPUs(); g != nil {
		t.Errorf("pre-sleep reading returned after waking: %+v", g)
	}
	f.answer(t, answer{out: smiLine})
}
