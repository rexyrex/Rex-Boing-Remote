// Package nvidia reads NVIDIA GPUs through nvidia-smi, which ships with the
// driver on Linux and Windows. It needs no special rights and no cgo.
package nvidia

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

const query = "name,utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw,fan.speed,clocks.gr,clocks.max.gr,utilization.encoder,utilization.decoder"

// Reader caches nvidia-smi output; one call costs tens of milliseconds, so it
// runs at most every minInterval and in the background.
type Reader struct {
	mu          sync.Mutex
	path        string
	last        []wire.GPU
	lastRun     time.Time
	running     bool
	minInterval time.Duration
	failures    int
}

// NewReader returns nil when nvidia-smi is not installed.
func NewReader() *Reader {
	path := find()
	if path == "" {
		return nil
	}
	return &Reader{path: path, minInterval: 2 * time.Second}
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

// GPUs returns the latest readings, starting a refresh when they are older
// than the minimum interval. The first call may return nil.
func (r *Reader) GPUs() []wire.GPU {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running && time.Since(r.lastRun) >= r.minInterval && r.failures < 5 {
		r.running = true
		r.lastRun = time.Now()
		go r.refresh()
	}
	return r.last
}

func (r *Reader) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.path, "--query-gpu="+query, "--format=csv,noheader,nounits").Output()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	if err != nil {
		r.failures++
		return
	}
	r.failures = 0
	r.last = Parse(string(out))
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
