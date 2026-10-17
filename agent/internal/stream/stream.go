// Package stream runs a protocol session (PROTOCOL.md, "Session"): a hello,
// then one sample per interval, until the app closes stdin.
package stream

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/collect"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

const (
	// DefaultInterval is the sample interval until the app asks otherwise.
	DefaultInterval = 1.0
	// MinInterval and MaxInterval bound requested intervals (PROTOCOL.md).
	MinInterval = 0.5
	MaxInterval = 10.0
	// MaxLine is the longest line either side may send.
	MaxLine = 1 << 20
)

// Options configures Run.
type Options struct {
	// Agent identifies this build in the hello.
	Agent wire.AgentInfo
	// Interval is the starting interval in seconds; 0 means DefaultInterval.
	Interval float64
	// Detail is the starting detail; "" means vitals.
	Detail wire.Detail
	// Count stops the stream after that many samples (tests, CI). With a
	// count, end of file on in no longer ends the stream, so it works with
	// stdin at /dev/null or a pipe of canned requests. 0 runs until in ends.
	Count int
	// Log receives diagnostics (stderr in the agent); nil discards them.
	Log io.Writer
	// History returns the background agent's history message, or nil when
	// none is running. It is sent right after the hello, and again when the
	// app asks for it ({"want":"history"}). Nil means never.
	History func() []byte
}

// WantHistory is the request for a fresh history message.
const WantHistory wire.Detail = "history"

// ClampInterval keeps an interval inside MinInterval…MaxInterval.
func ClampInterval(v float64) float64 {
	switch {
	case math.IsNaN(v) || v <= 0:
		return DefaultInterval
	case v < MinInterval:
		return MinInterval
	case v > MaxInterval:
		return MaxInterval
	}
	return v
}

// Run writes a hello, the background agent's history if one is running, and
// then samples to out until in reaches end of file,
// a write fails, or Count samples were sent. It returns nil when in ended or
// the count was reached, and the write error otherwise.
//
// Every line goes out in a single Write ending in "\n", and nothing but
// protocol JSON is ever written to out. Requests are read from in on a
// goroutine; malformed lines are ignored. Run does not close in: when it
// returns early (Count), the reader goroutine ends at in's next EOF or error.
func Run(c collect.Collector, in io.Reader, out io.Writer, opts Options) error {
	log := opts.Log
	if log == nil {
		log = io.Discard
	}
	interval := DefaultInterval
	if opts.Interval != 0 {
		interval = ClampInterval(opts.Interval)
	}
	detail := wire.DetailVitals
	if opts.Detail == wire.DetailFull {
		detail = wire.DetailFull
	}
	w := &writer{out: out, log: log}

	hello := wire.Hello{
		Type:         "hello",
		Protocol:     wire.ProtocolVersion,
		Agent:        opts.Agent,
		Host:         safeHost(c, log),
		Capabilities: safeCapabilities(c, log),
		Interval:     interval,
	}
	if err := w.line(hello); err != nil {
		return err
	}
	sendHistory := func() error {
		if opts.History == nil {
			return nil
		}
		h := opts.History()
		if len(h) == 0 || len(h)+1 > MaxLine || bytes.IndexByte(h, '\n') >= 0 {
			return nil
		}
		return w.write(h)
	}
	if err := sendHistory(); err != nil {
		return err
	}

	done := make(chan struct{})
	defer close(done)
	requests := make(chan wire.Request, 16)
	inEnded := make(chan struct{})
	go readRequests(in, requests, inEnded, done)
	eof := (<-chan struct{})(inEnded)
	if opts.Count > 0 {
		eof = nil // a nil channel never fires: the count alone ends the stream
	}

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var seq uint64
	for {
		started := time.Now()
		seq++
		s := safeSample(c, detail, log)
		s.Type, s.Seq, s.T, s.Detail = "sample", seq, started.UnixMilli(), detail
		if err := w.sample(s); err != nil {
			return err
		}
		if seq == 1 {
			for _, n := range safeNotices(c, log) {
				if n.Type == "" {
					n.Type = "notice"
				}
				if err := w.line(n); err != nil {
					return err
				}
			}
		}
		if opts.Count > 0 && seq >= uint64(opts.Count) {
			return nil
		}

		next := started.Add(seconds(interval))
		if now := time.Now(); next.Before(now) {
			// Behind schedule (a slow sample, or the process was stopped):
			// restart the cadence rather than sampling back to back.
			next = now.Add(seconds(interval))
		}
		timer.Reset(time.Until(next))
	wait:
		for {
			select {
			case <-eof:
				return nil
			case r := <-requests:
				if r.Want == wire.DetailVitals || r.Want == wire.DetailFull {
					detail = r.Want
				}
				if r.Want == WantHistory {
					if err := sendHistory(); err != nil {
						return err
					}
				}
				if r.Interval != nil && !math.IsInf(*r.Interval, 0) && !math.IsNaN(*r.Interval) {
					if v := ClampInterval(*r.Interval); v != interval {
						interval = v
						next = started.Add(seconds(interval))
						if !timer.Stop() {
							select {
							case <-timer.C:
							default:
							}
						}
						timer.Reset(time.Until(next))
					}
				}
			case <-timer.C:
				break wait
			}
		}
	}
}

func seconds(v float64) time.Duration { return time.Duration(v * float64(time.Second)) }

// readRequests parses one request per line. Lines that are not JSON objects,
// or longer than MaxLine, are skipped. It closes eof when in ends.
func readRequests(in io.Reader, requests chan<- wire.Request, eof chan<- struct{}, done <-chan struct{}) {
	defer close(eof)
	r := bufio.NewReaderSize(in, 64<<10)
	var line []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > MaxLine {
			tooLong, line = true, line[:0]
		} else if !tooLong {
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // the rest of this line is still coming
		}
		if !tooLong && len(line) > 0 {
			var req wire.Request
			if json.Unmarshal(line, &req) == nil {
				select {
				case requests <- req:
				case <-done:
					return
				}
			}
		}
		line, tooLong = line[:0], false
		if err != nil {
			return
		}
	}
}

// writer marshals messages and writes each as one line.
type writer struct {
	out    io.Writer
	log    io.Writer
	warned bool
}

func (w *writer) line(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return w.write(b)
}

// sample writes a sample, degrading it rather than dropping the session when
// it cannot be encoded (a NaN slipped through) or is too long for the app.
func (w *writer) sample(s *wire.Sample) error {
	b, err := json.Marshal(s)
	if err == nil && len(b)+1 > MaxLine {
		s.Processes = nil
		if s.Thermal != nil {
			s.Thermal.Sensors = nil
		}
		b, err = json.Marshal(s)
	}
	if err != nil || len(b)+1 > MaxLine {
		if !w.warned {
			w.warned = true
			fmt.Fprintf(w.log, "rex-boing-agent: sample %d could not be sent whole (%v); sending it empty\n", s.Seq, err)
		}
		bare := wire.Sample{Type: s.Type, Seq: s.Seq, T: s.T, Interval: s.Interval, Detail: s.Detail, Resync: true}
		if b, err = json.Marshal(bare); err != nil {
			return err
		}
	}
	return w.write(b)
}

func (w *writer) write(b []byte) error {
	b = append(b, '\n')
	n, err := w.out.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}

// The collector calls below recover from panics: a broken sampler must cost
// one sample (or one hello field), never the session.

func safeSample(c collect.Collector, detail wire.Detail, log io.Writer) (s *wire.Sample) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(log, "rex-boing-agent: sample failed: %v\n", r)
			s = &wire.Sample{Interval: DefaultInterval, Resync: true}
		}
	}()
	if s = c.Sample(detail); s == nil {
		s = &wire.Sample{Interval: DefaultInterval, Resync: true}
	}
	return s
}

func safeHost(c collect.Collector, log io.Writer) (h wire.Host) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(log, "rex-boing-agent: host description failed: %v\n", r)
		}
	}()
	return c.Host()
}

func safeCapabilities(c collect.Collector, log io.Writer) (caps []string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(log, "rex-boing-agent: capabilities failed: %v\n", r)
		}
		if caps == nil {
			caps = []string{}
		}
	}()
	return c.Capabilities()
}

func safeNotices(c collect.Collector, log io.Writer) (n []wire.Notice) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(log, "rex-boing-agent: notices failed: %v\n", r)
			n = nil
		}
	}()
	return c.Notices()
}
