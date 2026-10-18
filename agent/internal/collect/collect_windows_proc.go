//go:build windows

package collect

// The process table: a Toolhelp snapshot for every process, plus times,
// memory, I/O and path from a PROCESS_QUERY_LIMITED_INFORMATION handle where
// Windows grants one. Per-process baselines are keyed by pid and creation
// time, so a reused pid never inherits another process's counters, and are
// dropped as soon as the process is gone.

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

type winProcKey struct {
	pid     uint32
	created uint64 // FILETIME
}

type winProcPrev struct {
	cpu         uint64 // kernel+user, 100 ns
	read, write uint64
	haveIO      bool
	path        string
	pathTried   bool
}

type winProcState struct {
	prev     map[winProcKey]*winProcPrev
	lastScan time.Time
	last     *wire.Processes
	count    int
	threads  int
	denied   int
}

// winProcMinGap is the shortest time between two scans; faster samples
// repeat the last table, as PROTOCOL.md allows.
const winProcMinGap = 900 * time.Millisecond

func winFiletime(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// scan reads every process. gpuPerPID comes from the GPU Engine counters;
// resync zeroes the rates.
func (s *winProcState) scan(gpuPerPID map[int32]float64, gpuAttribution, resync bool) (*wire.Processes, error) {
	now := time.Now()
	if s.last != nil && now.Sub(s.lastScan) < winProcMinGap {
		return s.last, nil
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	elapsed := now.Sub(s.lastScan).Seconds()
	rates := !resync && !s.lastScan.IsZero() && elapsed > 0 && elapsed < MaxGap.Seconds()
	prevFT := winFiletime(windows.NsecToFiletime(s.lastScan.UnixNano()))
	nowFT := winFiletime(windows.NsecToFiletime(now.UnixNano()))
	next := make(map[winProcKey]*winProcPrev, len(s.prev)+16)
	var all []wire.ProcessRow
	threads, denied := 0, 0

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		pid := e.ProcessID
		threads += int(e.Threads)
		if pid == 0 {
			continue // System Idle Process: its "CPU" is idle time
		}
		row := wire.ProcessRow{
			PID:     int32(pid),
			Name:    windows.UTF16ToString(e.ExeFile[:]),
			Threads: int(e.Threads),
		}
		if g, ok := gpuPerPID[int32(pid)]; ok {
			row.GPU = g
		}
		if !s.fill(&row, pid, next, rates, elapsed, prevFT, nowFT) {
			denied++
		}
		all = append(all, row)
	}

	s.prev = next // exited processes fall out here
	interval := 0.0
	if rates {
		interval = elapsed
	}
	s.lastScan = now
	s.count, s.threads, s.denied = len(all), threads, denied
	rows, rank := Rank(all)
	if rows == nil {
		rows = []wire.ProcessRow{}
	}
	s.last = &wire.Processes{
		Count:          len(all),
		SampledAt:      now.UnixMilli(),
		Interval:       interval,
		GPUAttribution: gpuAttribution,
		Rows:           rows,
		Rank:           rank,
	}
	return s.last, nil
}

// fill adds what an open handle tells about one process. It returns false
// when Windows refuses the handle (other users' or protected processes for
// a non-elevated agent); the row then keeps name, pid and threads only.
// prevFT and nowFT are the previous scan's time and this one's, as FILETIMEs.
func (s *winProcState) fill(row *wire.ProcessRow, pid uint32, next map[winProcKey]*winProcPrev, rates bool, elapsed float64, prevFT, nowFT uint64) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return true // opened, but no times: nothing to key state by
	}
	key := winProcKey{pid, winFiletime(created)}
	cur := &winProcPrev{cpu: winFiletime(kernel) + winFiletime(user)}
	prev := s.prev[key]
	row.Start = winFiletimeToUnixMicros(key.created)
	if rates && prev != nil && cur.cpu >= prev.cpu {
		row.CPU = float64(cur.cpu-prev.cpu) / 1e7 / elapsed * 100
	} else if rates && prev == nil {
		// Created since the previous scan: no baseline, so not 0 % either.
		if v, ok := winYoungProcessCPU(cur.cpu, key.created, prevFT, nowFT, elapsed); ok {
			row.CPU = v
		}
	}
	if ws, ok := winProcessWorkingSet(h); ok {
		row.Memory = ws
	}
	if r, w, ok := winProcessIO(h); ok {
		cur.read, cur.write, cur.haveIO = r, w, true
		if rates && prev != nil && prev.haveIO {
			row.DiskRead = Rate(prev.read, r, elapsed)
			row.DiskWrite = Rate(prev.write, w, elapsed)
		}
	}
	if prev != nil && prev.pathTried {
		cur.path, cur.pathTried = prev.path, true
	} else {
		cur.path, cur.pathTried = winImagePath(h), true
	}
	row.Path = cur.path
	next[key] = cur
	return true
}

func winImagePath(h windows.Handle) string {
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil || n == 0 || int(n) > len(buf) {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
