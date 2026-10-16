package collect

// The process table from /proc/[pid]. No build tag: see collect_linuxfs.go.

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/redact"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxProcKey identifies a process across pid reuse.
type linuxProcKey struct {
	pid   int32
	start uint64 // starttime, ticks after boot
}

// linuxProcInfo is what is kept per process between scans. Names, owner and
// command line are read once per process (again only after an exec changes
// its comm); each scan then costs one stat read, plus io for our own
// processes.
type linuxProcInfo struct {
	ticks       uint64
	read, write uint64
	ioOK        bool
	ioDenied    bool
	comm        string
	name        string
	user        string
	path        string
	cmd         string
}

// linuxProcState keeps the per-process baselines and the last table.
type linuxProcState struct {
	prev     map[linuxProcKey]*linuxProcInfo
	last     *wire.Processes
	lastScan time.Time
	lastDur  time.Duration
	zombies  *int
	users    map[string]string
	passwd   map[string]string
	buf      []byte
	argBuf   []byte
}

// linuxStatFields parses /proc/[pid]/stat. comm is everything between the
// first "(" and the last ")", because it may itself contain spaces and
// parentheses.
func linuxStatFields(data []byte) (comm string, state byte, ticks uint64, threads int, start uint64, rssPages uint64, ok bool) {
	open := bytes.IndexByte(data, '(')
	closing := bytes.LastIndexByte(data, ')')
	if open < 0 || closing < open || closing+2 >= len(data) {
		return
	}
	comm = string(data[open+1 : closing])
	rest := data[closing+2:]
	// rest[0] is field 3 (state); utime is 14, stime 15, num_threads 20,
	// starttime 22, rss 24.
	var f [22][]byte
	n := 0
	for len(rest) > 0 && n < len(f) {
		i := bytes.IndexByte(rest, ' ')
		if i < 0 {
			f[n], rest = bytes.TrimSpace(rest), nil
		} else {
			f[n], rest = rest[:i], rest[i+1:]
		}
		n++
	}
	if n < 22 || len(f[0]) == 0 {
		return
	}
	state = f[0][0]
	utime, ok1 := linuxAtou(f[11])
	stime, ok2 := linuxAtou(f[12])
	th, ok3 := linuxAtou(f[17])
	start, ok4 := linuxAtou(f[19])
	rssPages, ok5 := linuxAtou(f[21])
	if !(ok1 && ok2 && ok3 && ok4) {
		return
	}
	if !ok5 {
		rssPages = 0
	}
	return comm, state, utime + stime, int(th), start, rssPages, true
}

// linuxProcMinGap is the shortest time between two process scans. Just under
// a second, so a 1 s stream whose ticks land a little early still scans
// every tick.
const linuxProcMinGap = 900 * time.Millisecond

// sampleProcesses scans /proc at most every linuxProcMinGap (and never more
// than a tenth of the time, on machines where a scan is slow) and repeats
// the last table in between.
func (c *linuxCollector) sampleProcesses(now time.Time) *wire.Processes {
	ps := &c.procs
	gap := linuxProcMinGap
	if g := 10 * ps.lastDur; g > gap {
		gap = g
	}
	if ps.last != nil && now.Sub(ps.lastScan) < gap {
		return ps.last
	}
	began := time.Now()
	elapsed := now.Sub(ps.lastScan).Seconds()
	valid := !ps.lastScan.IsZero() && elapsed > 0 && elapsed <= MaxGap.Seconds()
	if !valid {
		elapsed = 1
	}

	dir, err := os.Open(c.path("proc"))
	if err != nil {
		return nil
	}
	names, _ := dir.Readdirnames(-1)
	dir.Close()

	next := make(map[linuxProcKey]*linuxProcInfo, len(names))
	all := make([]wire.ProcessRow, 0, len(names))
	zombies := 0
	btime := c.cpu.stat.btime
	if btime == 0 {
		btime = c.host.BootTime / 1000
	}
	for _, name := range names {
		if !linuxNumeric(name) {
			continue
		}
		pid64, err := strconv.ParseInt(name, 10, 32)
		if err != nil {
			continue
		}
		base := c.path("proc", name)
		data, err := linuxReadProc(filepath.Join(base, "stat"), &ps.buf)
		if err != nil {
			continue // exited since the directory was listed
		}
		comm, state, ticks, threads, start, rss, ok := linuxStatFields(data)
		if !ok {
			continue
		}
		if state == 'Z' {
			zombies++
		}
		key := linuxProcKey{pid: int32(pid64), start: start}
		old := ps.prev[key]
		var prevTicks, prevRead, prevWrite uint64
		prevIO := false
		info := old
		if old != nil {
			prevTicks, prevRead, prevWrite, prevIO = old.ticks, old.read, old.write, old.ioOK
		}
		if info == nil || info.comm != comm {
			// New, or it exec'd something else: describe it again. The
			// counters carry over, it is still the same process.
			fresh := c.describeProcess(base, comm)
			if old != nil {
				fresh.read, fresh.write, fresh.ioOK, fresh.ioDenied = old.read, old.write, old.ioOK, old.ioDenied
			}
			info = fresh
		}
		info.ticks = ticks

		row := wire.ProcessRow{
			PID:     key.pid,
			Name:    info.name,
			User:    info.user,
			Path:    info.path,
			Cmd:     info.cmd,
			Memory:  rss * c.pageSize,
			Threads: threads,
		}
		if btime > 0 {
			row.Start = uint64(btime)*1e6 + uint64(float64(start)/c.clkTck*1e6)
		}
		if valid && old != nil && ticks >= prevTicks {
			row.CPU = float64(int(float64(ticks-prevTicks)/c.clkTck/elapsed*1000+0.5)) / 10
		}
		if !info.ioDenied {
			r, w, err := linuxReadProcIO(filepath.Join(base, "io"), &ps.buf)
			switch {
			case err == nil:
				if valid && old != nil && prevIO {
					row.DiskRead = Rate(prevRead, r, elapsed)
					row.DiskWrite = Rate(prevWrite, w, elapsed)
				}
				info.read, info.write, info.ioOK = r, w, true
			case linuxDenied(err):
				info.ioDenied = true // another user's process; do not ask again
			}
		}
		next[key] = info
		all = append(all, row)
	}
	ps.prev = next // drops every process that exited

	rows, rank := Rank(all)
	if rows == nil {
		rows = []wire.ProcessRow{}
	}
	out := &wire.Processes{
		Count:          len(all),
		SampledAt:      time.Now().UnixMilli(),
		Interval:       float64(int(elapsed*1000+0.5)) / 1000,
		GPUAttribution: false,
		Rows:           rows,
		Rank:           rank,
	}
	ps.zombies = &zombies
	ps.lastScan, ps.lastDur, ps.last = now, time.Since(began), out
	c.cpu.procCount, c.cpu.procCountAt = len(all), now
	return out
}

// describeProcess reads the parts of a process that do not change while it
// runs: owner, executable and command line.
func (c *linuxCollector) describeProcess(base, comm string) *linuxProcInfo {
	ps := &c.procs
	info := &linuxProcInfo{comm: comm, name: comm}
	if data, err := linuxReadProc(filepath.Join(base, "status"), &ps.buf); err == nil {
		for len(data) > 0 {
			var line []byte
			line, data = linuxNextLine(data)
			if bytes.HasPrefix(line, []byte("Uid:")) {
				if f := bytes.Fields(line[4:]); len(f) > 0 {
					info.user = c.userName(string(f[0]))
				}
				break
			}
		}
	}
	if target, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		info.path = strings.TrimSuffix(target, " (deleted)")
	}
	argv0, title := "", ""
	if args, err := linuxReadLimited(filepath.Join(base, "cmdline"), 4096, &ps.argBuf); err == nil && len(args) > 0 {
		args = bytes.TrimRight(args, "\x00")
		if i := bytes.IndexByte(args, 0); i >= 0 {
			argv0 = string(args[:i])
		} else if bytes.IndexByte(args, ' ') >= 0 {
			title = string(args) // the process rewrote its argv into a title
		} else {
			argv0 = string(args)
		}
		info.cmd = redact.CommandLine(string(bytes.ReplaceAll(args, []byte{0}, []byte{' '})))
	}
	info.name = linuxProcessName(comm, info.path, argv0, title)
	return info
}

// linuxProcessName expands comm, which the kernel cuts at 15 bytes, from
// the executable or argv[0] ("gnome-shell-cal" → "gnome-shell-calendar-
// server"). A process that rewrote its command line into a title ("node
// /srv/app.js", "gunicorn: worker [app]") is named by the title's first word.
func linuxProcessName(comm, exe, argv0, title string) string {
	if len(comm) != 15 {
		return comm
	}
	for _, full := range []string{filepath.Base(exe), filepath.Base(argv0)} {
		if len(full) > len(comm) && strings.HasPrefix(full, comm) {
			return full
		}
	}
	if strings.HasPrefix(title, comm) {
		if f := strings.Fields(title); len(f) > 0 {
			if name := strings.TrimRight(filepath.Base(f[0]), ":"); name != "" {
				return name
			}
		}
	}
	return comm
}

// linuxReadProcIO reads read_bytes and write_bytes from /proc/[pid]/io.
func linuxReadProcIO(path string, buf *[]byte) (read, write uint64, err error) {
	data, err := linuxReadProc(path, buf)
	if err != nil {
		return 0, 0, err
	}
	for len(data) > 0 {
		var line []byte
		line, data = linuxNextLine(data)
		switch {
		case bytes.HasPrefix(line, []byte("read_bytes: ")):
			read, _ = linuxAtou(bytes.TrimSpace(line[12:]))
		case bytes.HasPrefix(line, []byte("write_bytes: ")):
			write, _ = linuxAtou(bytes.TrimSpace(line[13:]))
		}
	}
	return read, write, nil
}

// linuxReadLimited reads at most n bytes of a file (a command line can be
// megabytes long; the wire carries 512 characters of it).
func linuxReadLimited(path string, n int, buf *[]byte) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if cap(*buf) < n {
		*buf = make([]byte, n)
	}
	b := (*buf)[:n]
	total := 0
	for total < n {
		m, err := f.Read(b[total:])
		total += m
		if err == io.EOF || m == 0 {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return b[:total], nil
}

// userName maps a uid to a name through /etc/passwd under the root, then the
// system's resolver (LDAP, sssd) when that is wired in. Unknown uids stay
// numeric. The cache is small (one entry per distinct owner) and reset if
// it ever grows large.
func (c *linuxCollector) userName(uid string) string {
	ps := &c.procs
	if name, ok := ps.users[uid]; ok {
		return name
	}
	if ps.users == nil || len(ps.users) > 4096 {
		ps.users = map[string]string{}
	}
	if ps.passwd == nil {
		ps.passwd = map[string]string{}
		if data, err := linuxReadFile(c.path("etc/passwd")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				f := strings.Split(line, ":")
				if len(f) >= 3 && f[0] != "" {
					if _, dup := ps.passwd[f[2]]; !dup {
						ps.passwd[f[2]] = f[0]
					}
				}
			}
		}
	}
	name := ps.passwd[uid]
	if name == "" && c.lookupUser != nil {
		name = c.lookupUser(uid)
	}
	if name == "" {
		name = uid
	}
	ps.users[uid] = name
	return name
}
