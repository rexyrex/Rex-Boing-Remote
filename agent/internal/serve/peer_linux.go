//go:build linux

package serve

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the user id of the process at the other end of c.
func peerUID(c *net.UnixConn) (int, bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, false
	}
	uid, ok := 0, false
	raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			uid, ok = int(cred.Uid), true
		}
	})
	return uid, ok
}
