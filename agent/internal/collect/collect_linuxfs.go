package collect

// The Linux collector is spread over collect_linux*.go. Only collect_linux.go
// carries a build tag: it holds the system calls (statfs) and wires the
// collector to the real root. Every other collect_linux*.go file only parses
// Linux text formats from a configurable root directory and uses no Linux
// system calls, so it builds on every OS and its fixture tests (testdata/
// linux-*) run on a Mac too. Every identifier in these files starts with
// "linux" so the Windows files can never collide with them.

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// linuxMaxFile caps how much of any one file is read. /proc/self/mountinfo on
// a busy container host is the largest thing we read, at a few hundred KiB.
const linuxMaxFile = 8 << 20

// linuxReadValue reads a small sysfs or procfs attribute (a number, a name, a
// label) with one read into a fixed buffer and trims it. sysfs hands back a
// whole attribute in one read, and the fixed buffer keeps a misbehaving file
// from costing more than one page.
func linuxReadValue(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var buf [512]byte
	n, err := f.Read(buf[:])
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(bytes.TrimSpace(buf[:n])), nil
}

// linuxReadUint reads an unsigned decimal attribute.
func linuxReadUint(path string) (uint64, bool) {
	s, err := linuxReadValue(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// linuxReadInt reads a signed decimal attribute (temperatures can be negative).
func linuxReadInt(path string) (int64, bool) {
	s, err := linuxReadValue(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

// linuxReadInto reads a whole file into *buf, growing it as needed, and
// returns the filled slice. The slice is only valid until the next call with
// the same buffer; callers parse it straight away. Reusing one buffer keeps
// the per-sample reads of /proc/stat, /proc/net/dev and friends free of
// allocations.
func linuxReadInto(path string, buf *[]byte) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := (*buf)[:0]
	if cap(b) < 4096 {
		b = make([]byte, 0, 4096)
	}
	for {
		if len(b) == cap(b) {
			if len(b) >= linuxMaxFile {
				break
			}
			b = append(b, 0)[:len(b)]
		}
		n, err := f.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			*buf = b
			return nil, err
		}
		if n == 0 {
			break
		}
	}
	*buf = b
	return b, nil
}

// linuxReadProc reads a small procfs file with a single read when it fits
// the buffer. procfs builds such files whole on the first read, so the usual
// second read that only confirms end of file can be skipped: a process scan
// opens a thousand of them every second.
func linuxReadProc(path string, buf *[]byte) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if cap(*buf) < 4096 {
		*buf = make([]byte, 4096)
	}
	b := (*buf)[:cap(*buf)]
	n, err := f.Read(b)
	f.Close()
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n < len(b) {
		return b[:n], nil
	}
	return linuxReadInto(path, buf) // did not fit: read it properly
}

// linuxReadFile reads a whole file into a fresh slice (for one-off reads).
func linuxReadFile(path string) ([]byte, error) {
	var b []byte
	data, err := linuxReadInto(path, &b)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// linuxExists reports whether path exists, following symlinks.
func linuxExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// linuxDenied reports whether err is a permission error.
func linuxDenied(err error) bool {
	return err != nil && errors.Is(err, fs.ErrPermission)
}

// linuxDirNames lists a directory, sorted. Missing directories are empty.
func linuxDirNames(path string) []string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// linuxAtou parses an unsigned decimal number from b without allocating.
func linuxAtou(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	return v, true
}

// linuxAtof parses a decimal like "0.86" from b. Only PSI and loadavg need
// it, so the allocating strconv path is fine.
func linuxAtof(b []byte) (float64, bool) {
	v, err := strconv.ParseFloat(string(b), 64)
	return v, err == nil
}

// linuxNextLine splits the first line off data.
func linuxNextLine(data []byte) (line, rest []byte) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return data[:i], data[i+1:]
	}
	return data, nil
}

// linuxNumeric reports whether s is all ASCII digits (a pid, a cpu number).
func linuxNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// linuxParseCPUList parses a kernel cpu list such as "0-5,12-13".
func linuxParseCPUList(s string) []int {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				continue
			}
		}
		// A list never names more cpus than the machine has; the cap only
		// guards against a corrupt file.
		for i := a; i <= b && len(out) < 1<<14; i++ {
			out = append(out, i)
		}
	}
	return out
}

// linuxParseKV parses KEY=value lines (os-release, uevent), unquoting values.
func linuxParseKV(data []byte) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
			v = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`").Replace(v)
		}
		kv[strings.TrimSpace(k)] = v
	}
	return kv
}

// linuxCompareVersions compares kernel-style version strings naturally:
// runs of digits compare as numbers, everything else byte by byte.
func linuxCompareVersions(a, b string) int {
	for a != "" && b != "" {
		da, db := a[0] >= '0' && a[0] <= '9', b[0] >= '0' && b[0] <= '9'
		switch {
		case da && db:
			i, j := 0, 0
			for i < len(a) && a[i] >= '0' && a[i] <= '9' {
				i++
			}
			for j < len(b) && b[j] >= '0' && b[j] <= '9' {
				j++
			}
			na, nb := strings.TrimLeft(a[:i], "0"), strings.TrimLeft(b[:j], "0")
			if len(na) != len(nb) {
				if len(na) < len(nb) {
					return -1
				}
				return 1
			}
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			a, b = a[i:], b[j:]
		case a[0] != b[0]:
			if a[0] < b[0] {
				return -1
			}
			return 1
		default:
			a, b = a[1:], b[1:]
		}
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	}
	return 1
}

// linuxClamp01 keeps a fraction inside 0…1 (counter jitter can overshoot).
func linuxClamp01(v float64) float64 {
	if v < 0 || v != v {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
