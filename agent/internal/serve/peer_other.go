//go:build !linux && !darwin && !windows

package serve

import "net"

// peerUID is not available here; the private directory alone keeps other
// users out.
func peerUID(c *net.UnixConn) (int, bool) { return 0, false }
