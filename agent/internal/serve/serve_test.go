package serve

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/collect"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

type fakeCollector struct {
	mu sync.Mutex
	n  int
}

func (f *fakeCollector) Host() wire.Host        { return wire.Host{Hostname: "fake"} }
func (f *fakeCollector) Capabilities() []string { return nil }
func (f *fakeCollector) Doctor() []collect.Check {
	return nil
}
func (f *fakeCollector) Notices() []wire.Notice { return nil }
func (f *fakeCollector) Close()                 {}
func (f *fakeCollector) Sample(wire.Detail) *wire.Sample {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return &wire.Sample{Interval: 0.5, Resync: f.n == 1,
		CPU: &wire.CPU{Total: 0.25, User: 0.2, System: 0.05}, Memory: &wire.Memory{Total: 100, Used: 40}}
}
func (f *fakeCollector) ScanProcesses() *wire.Processes {
	return &wire.Processes{Count: 3, SampledAt: time.Now().UnixMilli(), Interval: 15,
		Rows: []wire.ProcessRow{{PID: 42, Name: "busy", CPU: 50, Memory: 1000}}}
}

// shortDir is a temporary directory with a path short enough for a socket
// on every Unix (t.TempDir on macOS is not).
func shortDir(t *testing.T) string {
	t.Helper()
	base := ""
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "rbr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func start(t *testing.T, dir string) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, &fakeCollector{}, Options{Agent: wire.AgentInfo{Version: "test"}, Interval: 0.5, Dir: dir})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := Query(dir, time.Second); err == nil {
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("serve ended at once: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("serve never answered")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			return errors.New("serve did not stop")
		}
	}
}

func TestServeRoundTrip(t *testing.T) {
	dir := shortDir(t)
	stop := start(t, dir)

	st, err := Query(dir, time.Second)
	if err != nil || st.PID != os.Getpid() || st.Version != "test" || st.Interval != 0.5 {
		t.Fatalf("status %+v, %v", st, err)
	}
	// A second serve for the same user steps aside.
	if err := Run(context.Background(), &fakeCollector{}, Options{Interval: 0.5, Dir: dir}); !errors.Is(err, ErrRunning) {
		t.Errorf("a second serve: %v, want ErrRunning", err)
	}

	time.Sleep(1600 * time.Millisecond)
	msg := History(dir, 2*time.Second)
	if msg == nil {
		t.Fatal("no history")
	}
	var m struct {
		Type      string
		Interval  float64
		Tiers     []map[string]json.RawMessage
		Processes []wire.Processes
	}
	if err := json.Unmarshal(msg, &m); err != nil || m.Type != "history" || m.Interval != 0.5 {
		t.Fatalf("history %s: %v", msg, err)
	}
	var times []int64
	json.Unmarshal(m.Tiers[0]["t"], &times)
	if len(times) < 2 {
		t.Errorf("only %d fine points after 1.6 s at 0.5 s", len(times))
	}
	if len(m.Processes) != 1 || m.Processes[0].Rows[0].Name != "busy" {
		t.Errorf("process tables %+v", m.Processes)
	}

	if err := stop(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, HistoryFile)
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatalf("history was not saved: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("history file mode %v", fi.Mode().Perm())
	}
	if History(dir, 200*time.Millisecond) != nil {
		t.Errorf("a stopped serve still answers")
	}

	// The next serve starts from the saved rings.
	stop = start(t, dir)
	again := History(dir, 2*time.Second)
	var n struct{ Tiers []map[string]json.RawMessage }
	json.Unmarshal(again, &n)
	var restored []int64
	if len(n.Tiers) > 0 {
		json.Unmarshal(n.Tiers[0]["t"], &restored)
	}
	if len(restored) < len(times) || restored[0] != times[0] {
		t.Errorf("history did not survive a restart: %d points from %v, had %d from %v", len(restored), restored, len(times), times)
	}

	// A client may ask it to stop.
	if err := Stop(dir, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatalf("stop request: %v", err)
	}
}

func TestUnknownAndSilentClients(t *testing.T) {
	dir := shortDir(t)
	stop := start(t, dir)
	defer stop()
	b, err := ask(dir, "frobnicate", time.Second)
	if err != nil || !strings.Contains(string(b), `"error"`) {
		t.Errorf("unknown request: %s %v", b, err)
	}
	// A client that connects and says nothing does not block the others.
	for i := 0; i < maxClients+2; i++ {
		c, err := dial(dir, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := Query(dir, time.Second); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("silent clients starved the endpoint")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestNoServe(t *testing.T) {
	dir := shortDir(t)
	if History(dir, 300*time.Millisecond) != nil {
		t.Errorf("history without a serve")
	}
	if _, err := Query(dir, 300*time.Millisecond); err == nil {
		t.Errorf("status without a serve")
	}
}
