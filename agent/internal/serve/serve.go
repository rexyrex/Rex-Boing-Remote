// Package serve is the agent's optional background mode (PROTOCOL.md,
// "Background history"): it samples vitals on its own, keeps them in
// history.Recorder's rings, saves the rings to the install directory, and
// answers on a local endpoint only this user can reach. stream reads it to
// send the app what happened while the Mac was away.
package serve

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/collect"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/history"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

const (
	// DefaultInterval is the seconds between background samples: the same
	// cadence the app's menu bar uses by default.
	DefaultInterval = 2.0
	// ProcessEvery is how often the process table is read. Under
	// collect.MaxGap, so every scan's rates are valid.
	ProcessEvery = 15 * time.Second
	// SaveEvery is how often the rings are written to disk while running;
	// they are also written when serve stops.
	SaveEvery = 10 * time.Minute
	// HistoryFile is the rings' file in the install directory.
	HistoryFile = "history.json"
	// MaxLine is the protocol's longest line (PROTOCOL.md, "Transport").
	MaxLine = 1 << 20
	// maxRequest bounds a request line on the endpoint.
	maxRequest = 4 << 10
	// maxClients bounds connections handled at once.
	maxClients = 8
)

// Options configures Run.
type Options struct {
	Agent    wire.AgentInfo
	Interval float64 // seconds; 0 means DefaultInterval
	// Dir holds the history file and, on Unix, the socket.
	Dir string
	Log io.Writer
}

// Status is the answer to {"want":"status"}.
type Status struct {
	Type     string  `json:"type"` // "status"
	PID      int     `json:"pid"`
	Version  string  `json:"version"`
	Started  int64   `json:"started"` // ms since the epoch
	Interval float64 `json:"interval"`
	// Oldest is the time of the oldest point kept, ms since the epoch.
	Oldest   int64  `json:"oldest,omitempty"`
	Endpoint string `json:"endpoint"`
}

type request struct {
	Want string `json:"want"`
}

// Run samples c until ctx ends or a client asks it to stop. It returns
// ErrRunning, without sampling, when another serve already runs.
func Run(ctx context.Context, c collect.Collector, opts Options) error {
	log := opts.Log
	if log == nil {
		log = io.Discard
	}
	interval := opts.Interval
	if interval <= 0 || math.IsNaN(interval) {
		interval = DefaultInterval
	}
	interval = math.Min(10, math.Max(0.5, interval))

	// A serve that was just asked to stop may still be finishing; wait a
	// moment for it rather than giving up at once.
	var l listener
	var err error
	for deadline := time.Now().Add(5 * time.Second); ; {
		l, err = listen(opts.Dir)
		if !errors.Is(err, ErrRunning) || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	defer l.Close()

	ctx, stop := context.WithCancel(ctx)
	defer stop()

	s := &server{
		rec:  history.NewRecorder(interval, time.Now()),
		file: filepath.Join(opts.Dir, HistoryFile),
		log:  log,
		stop: stop,
		status: Status{Type: "status", PID: os.Getpid(), Version: opts.Agent.Version,
			Interval: interval, Endpoint: l.Address()},
	}
	s.status.Started = s.rec.Started
	if data, err := os.ReadFile(s.file); err == nil {
		if err := s.rec.Load(data, time.Now()); err != nil {
			fmt.Fprintf(log, "rex-boing-agent: ignoring %s: %v\n", s.file, err)
		}
	}
	fmt.Fprintf(log, "rex-boing-agent: keeping history every %gs, on %s\n", interval, l.Address())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.accept(l)
	}()

	s.sample(ctx, c, interval)
	// Saved before the endpoint closes: whoever waits for it to go away
	// (a restart) then finds the file complete.
	if err := s.save(); err != nil {
		fmt.Fprintf(log, "rex-boing-agent: could not save history: %v\n", err)
	}
	l.Close()
	wg.Wait()
	return nil
}

type server struct {
	mu     sync.Mutex
	rec    *history.Recorder
	status Status
	file   string
	log    io.Writer
	stop   context.CancelFunc
}

func (s *server) sample(ctx context.Context, c collect.Collector, interval float64) {
	scanner, _ := c.(collect.ProcessScanner)
	tick := time.NewTicker(time.Duration(interval * float64(time.Second)))
	defer tick.Stop()
	var lastScan, lastSave time.Time
	lastSave = time.Now()
	for {
		now := time.Now()
		sample := safeSample(c, s.log)
		sample.T = now.UnixMilli()
		var procs *wire.Processes
		if scanner != nil && now.Sub(lastScan) >= ProcessEvery-time.Second/2 {
			lastScan = now
			procs = safeScan(scanner, s.log)
		}
		s.mu.Lock()
		s.rec.Add(sample)
		s.rec.AddProcesses(procs)
		s.mu.Unlock()
		if now.Sub(lastSave) >= SaveEvery {
			lastSave = now
			if err := s.save(); err != nil {
				fmt.Fprintf(s.log, "rex-boing-agent: could not save history: %v\n", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// save writes the rings through a temporary file, so a crash or a power
// cut leaves the previous file or the new one, never half of one.
func (s *server) save() error {
	s.mu.Lock()
	data := s.rec.Message(0)
	s.mu.Unlock()
	dir := filepath.Dir(s.file)
	f, err := os.CreateTemp(dir, "."+HistoryFile+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.file)
}

func (s *server) accept(l listener) {
	slots := make(chan struct{}, maxClients)
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, errClosed) {
				return
			}
			fmt.Fprintf(s.log, "rex-boing-agent: accept: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				s.handle(c)
			}()
		default:
			c.Close() // busy; the client tries again on its next session
		}
	}
}

// handle answers one request line with one line, then waits briefly for the
// client to hang up, so the answer is read in full before the connection
// closes.
func (s *server) handle(c conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReaderSize(io.LimitReader(c, maxRequest), maxRequest).ReadSlice('\n')
	if err != nil {
		return
	}
	var req request
	_ = json.Unmarshal(line, &req)
	var answer []byte
	stopping := false
	s.mu.Lock()
	switch req.Want {
	case "history":
		answer = s.rec.Message(MaxLine - 1)
	case "status":
		st := s.status
		st.Oldest = s.rec.Oldest()
		answer, _ = json.Marshal(st)
	case "stop":
		answer = []byte(`{"type":"stopping"}`)
		stopping = true
	default:
		answer = []byte(`{"type":"error","message":"unknown request"}`)
	}
	s.mu.Unlock()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(append(answer, '\n')); err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(c, maxRequest))
	if stopping {
		s.stop()
	}
}

// ask sends one request to the serve for dir and returns its one-line answer.
func ask(dir, want string, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	c, err := dial(dir, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(deadline)
	if _, err := c.Write([]byte(`{"want":"` + want + `"}` + "\n")); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(c, 64<<10)
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxLine {
			return nil, errors.New("the answer is longer than a protocol line")
		}
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
	return line[:len(line)-1], nil
}

// History returns the history message of this user's running serve, or nil
// when there is none (or it does not answer within timeout). The message is
// checked to be one JSON object of type history, so whatever stream passes
// on is a protocol line.
func History(dir string, timeout time.Duration) []byte {
	b, err := ask(dir, "history", timeout)
	if err != nil || !json.Valid(b) {
		return nil
	}
	var head struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(b, &head) != nil || head.Type != "history" {
		return nil
	}
	return b
}

// Query returns the running serve's status.
func Query(dir string, timeout time.Duration) (Status, error) {
	b, err := ask(dir, "status", timeout)
	if err != nil {
		return Status{}, err
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil || st.Type != "status" {
		return Status{}, errors.New("the background agent gave an answer that is not a status")
	}
	return st, nil
}

// Stop asks the running serve to save its history and exit. It returns
// once the serve has answered, not once it has exited.
func Stop(dir string, timeout time.Duration) error {
	_, err := ask(dir, "stop", timeout)
	return err
}

// RemoveEndpoint deletes what the endpoint left outside dir: on Unix, the
// directory in /tmp that holds the socket when a long home directory makes
// <dir>/run/serve.sock too long for one. Turning history off and
// uninstalling call it once the serve has stopped; while one still runs,
// it leaves the endpoint alone.
func RemoveEndpoint(dir string) error { return removeEndpoint(dir) }

// WaitStopped waits until no serve answers, up to timeout.
func WaitStopped(dir string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := Query(dir, 500*time.Millisecond); err != nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func safeSample(c collect.Collector, log io.Writer) (s *wire.Sample) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(log, "rex-boing-agent: sample failed: %v\n", r)
			s = &wire.Sample{Resync: true}
		}
	}()
	if s = c.Sample(wire.DetailVitals); s == nil {
		s = &wire.Sample{Resync: true}
	}
	return s
}

func safeScan(p collect.ProcessScanner, log io.Writer) (out *wire.Processes) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(log, "rex-boing-agent: process scan failed: %v\n", r)
			out = nil
		}
	}()
	return p.ScanProcesses()
}
