// Package nvidia reads NVIDIA GPUs through nvidia-smi, which ships with the
// driver on Linux and Windows. It needs no special rights and no cgo.
package nvidia

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

const query = "name,utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw,fan.speed,clocks.gr,clocks.max.gr,utilization.encoder,utilization.decoder"

const (
	// timeout bounds one nvidia-smi run; the process is killed after it.
	timeout = 5 * time.Second
	// maxBackoff caps the wait between attempts while nvidia-smi keeps
	// failing (a driver/library mismatch after an update, a GPU that fell
	// off the bus). It never stops trying: a reboot or a driver reload fixes
	// those, and the readings should come back without restarting the agent.
	maxBackoff = 300 * time.Second
	// maxRuns caps the runs in flight. A run stuck in the kernel (a hung GPU)
	// cannot be killed, and every retry would hang the same way, so after a
	// hang one more attempt may start, but no further ones until one returns.
	maxRuns = 2
)

// Reader caches nvidia-smi output; one call costs tens of milliseconds, so it
// runs at most every minInterval and in the background.
type Reader struct {
	mu          sync.Mutex
	path        string
	minInterval time.Duration
	// run executes nvidia-smi and now reads the clock; tests replace both.
	run func(ctx context.Context) ([]byte, error)
	now func() time.Time

	last    []wire.GPU // the latest good reading; nil after a failure or a hang
	known   []wire.GPU // the GPUs of the latest good reading, for Asleep
	lastErr string

	lastRun  time.Time // when the newest run started
	retryAt  time.Time // no new run before this after a failure
	inflight int
	seq      uint64 // number of the newest run started
	applied  uint64 // number of the newest run whose result was used
	hung     uint64 // number of the newest run counted as hung
	failures int    // consecutive failed or hung runs
}

// NewReader returns nil when nvidia-smi is not installed.
func NewReader() *Reader {
	path := find()
	if path == "" {
		return nil
	}
	r := &Reader{path: path, minInterval: 2 * time.Second, now: time.Now}
	r.run = func(ctx context.Context) ([]byte, error) {
		return exec.CommandContext(ctx, r.path, "--query-gpu="+query, "--format=csv,noheader,nounits").Output()
	}
	return r
}

func find() string {
	if p, err := exec.LookPath("nvidia-smi"); err == nil {
		return p
	}
	if runtime.GOOS == "windows" {
		for _, p := range []string{`C:\Windows\System32\nvidia-smi.exe`, `C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe`} {
			if _, err := exec.LookPath(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// hangAfter is how long a run may go unanswered before its GPUs count as
// unknown: the timeout plus two refresh intervals of slack.
func (r *Reader) hangAfter() time.Duration { return timeout + 2*r.minInterval }

// backoff is the wait after the given number of consecutive failures: 2 s,
// doubling, at most maxBackoff.
func backoff(failures int) time.Duration {
	d := 2 * time.Second
	for i := 1; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// GPUs returns the latest readings, starting a refresh when they are older
// than the minimum interval. The first call may return nil, and so does any
// call after nvidia-smi failed or stopped answering: a reading it can no
// longer refresh must not be shown as live.
func (r *Reader) GPUs() []wire.GPU {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	newestHung := r.inflight > 0 && now.Sub(r.lastRun) > r.hangAfter()
	if newestHung && r.hung != r.seq {
		r.hung = r.seq
		r.failures++
		r.last = nil
		r.lastErr = "nvidia-smi did not finish within " + r.hangAfter().String()
		r.retryAt = now.Add(backoff(r.failures))
	}
	if (r.inflight == 0 || newestHung) && r.inflight < maxRuns &&
		now.Sub(r.lastRun) >= r.minInterval && !now.Before(r.retryAt) {
		r.inflight++
		r.seq++
		r.lastRun = now
		go r.refresh(r.seq)
	}
	return r.last
}

// Asleep stands in for GPUs while the caller knows every NVIDIA GPU is
// runtime-suspended: running nvidia-smi would wake them, so no run starts.
// The reading taken before they slept is dropped, and the GPUs it listed
// are reported idle by name, the way a suspended AMD or Intel GPU is. It
// returns nil when nvidia-smi has never answered.
func (r *Reader) Asleep() []wire.GPU {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = nil
	var out []wire.GPU
	for _, g := range r.known {
		idle := wire.GPU{Name: g.Name, Vendor: g.Vendor}
		if g.MaxClockMHz != nil {
			idle.MaxClockMHz = wire.F(*g.MaxClockMHz)
		}
		out = append(out, idle)
	}
	return out
}

// Err describes the latest failure, or is "" while nvidia-smi answers.
func (r *Reader) Err() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

func (r *Reader) refresh(seq uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := r.run(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inflight--
	if seq < r.applied {
		return // a hung run that finally returned, after a newer one answered
	}
	r.applied = seq
	var gpus []wire.GPU
	if err == nil {
		if gpus = Parse(string(out)); len(gpus) == 0 {
			err = errors.New("no GPUs in the output")
		}
	}
	if err != nil {
		if seq != r.hung { // a hang was already counted when it was noticed
			r.failures++
		}
		r.last = nil
		r.lastErr = "nvidia-smi failed: " + strings.TrimSpace(err.Error())
		// nvidia-smi prints its reason ("Failed to initialize NVML:
		// Driver/library version mismatch") on stdout.
		var exit *exec.ExitError
		if line := firstLine(out); line != "" {
			r.lastErr += " (" + line + ")"
		} else if errors.As(err, &exit) && firstLine(exit.Stderr) != "" {
			r.lastErr += " (" + firstLine(exit.Stderr) + ")"
		}
		r.retryAt = r.now().Add(backoff(r.failures))
		return
	}
	r.failures, r.lastErr, r.retryAt = 0, "", time.Time{}
	r.last, r.known = gpus, gpus
}

// firstLine returns the first non-empty line of b, at most 200 bytes of it.
func firstLine(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if len(line) > 200 {
				line = line[:200]
			}
			return line
		}
	}
	return ""
}

// Parse turns nvidia-smi CSV output into GPUs. Exported for tests.
func Parse(csv string) []wire.GPU {
	var gpus []wire.GPU
	for _, line := range strings.Split(strings.TrimSpace(csv), "\n") {
		f := strings.Split(line, ",")
		if len(f) < 10 {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		num := func(i int) *float64 {
			if i >= len(f) {
				return nil
			}
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return nil // "[N/A]", "[Not Supported]"
			}
			return &v
		}
		g := wire.GPU{Name: f[0], Vendor: "nvidia"}
		if u := num(1); u != nil {
			g.Utilization = *u / 100
		}
		engines := map[string]float64{}
		if u := num(1); u != nil {
			engines["compute"] = *u / 100
		}
		if u := num(10); u != nil {
			engines["encode"] = *u / 100
		}
		if u := num(11); u != nil {
			engines["decode"] = *u / 100
		}
		if len(engines) > 0 {
			g.Engines = engines
		}
		if v := num(3); v != nil {
			b := uint64(*v * 1024 * 1024)
			g.MemoryUsed = &b
		}
		if v := num(4); v != nil {
			b := uint64(*v * 1024 * 1024)
			g.MemoryTotal = &b
		}
		g.Celsius = num(5)
		g.Watts = num(6)
		g.FanPercent = num(7)
		g.ClockMHz = num(8)
		g.MaxClockMHz = num(9)
		gpus = append(gpus, g)
	}
	return gpus
}
