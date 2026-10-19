//go:build linux

package collect

// The only Linux file with a build tag: it points the collector at the real
// root and wires in what needs Linux system calls or the live system.

import (
	"encoding/binary"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/nvidia"
)

func newCollector() Collector {
	c := newLinuxCollector("/")
	c.pageSize = uint64(os.Getpagesize())
	c.clkTck = linuxClockTicks()
	c.statfs = linuxStatfs
	c.ifaceIPv4 = linuxInterfaceIPv4
	c.lookupUser = func(uid string) string {
		if u, err := user.LookupId(uid); err == nil {
			return u.Username
		}
		return ""
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		c.failedUnits = linuxSystemctlFailed
	}
	if r := nvidia.NewReader(); r != nil {
		c.nvidia = r // never a nil *Reader inside the interface
	}
	return c
}

// linuxStatfs sizes a mounted filesystem the way df does.
func linuxStatfs(path string) (linuxFSSize, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return linuxFSSize{}, err
	}
	frsize := uint64(st.Frsize)
	if frsize == 0 {
		frsize = uint64(st.Bsize)
	}
	return linuxFSSize{
		total: uint64(st.Blocks) * frsize,
		avail: uint64(st.Bavail) * frsize,
		free:  uint64(st.Bfree) * frsize,
	}, nil
}

// linuxClockTicks reads AT_CLKTCK (USER_HZ, the unit of /proc/[pid]/stat
// times) from the auxiliary vector. It is 100 on every mainstream kernel,
// which is also the fallback.
func linuxClockTicks() float64 {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 100
	}
	word := strconv.IntSize / 8
	for i := 0; i+2*word <= len(data); i += 2 * word {
		var key, val uint64
		if word == 8 {
			key, val = binary.NativeEndian.Uint64(data[i:]), binary.NativeEndian.Uint64(data[i+8:])
		} else {
			key, val = uint64(binary.NativeEndian.Uint32(data[i:])), uint64(binary.NativeEndian.Uint32(data[i+4:]))
		}
		if key == 0 {
			break
		}
		if key == 17 && val > 0 { // AT_CLKTCK
			return float64(val)
		}
	}
	return 100
}
