//go:build !windows

package serve

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// maxSocketPath is the longest socket path every Unix accepts (sun_path is
// 104 bytes on macOS and the BSDs, 108 on Linux, including the NUL).
const maxSocketPath = 100

// socketPath is where serve listens: <dir>/run/serve.sock, or, when a long
// home directory makes that too long for a socket, a per-user directory in
// the temporary directory.
func socketPath(dir string) string {
	p := filepath.Join(dir, "run", "serve.sock")
	if len(p) <= maxSocketPath {
		return p
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("rex-boing-remote-%d", os.Getuid()), "serve.sock")
}

// privateDir makes sure path is a real directory (not a symlink) owned by
// this user that no one else can enter, creating it if it is missing.
func privateDir(path string, create bool) error {
	if create {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a directory owned by this user; refusing to use it", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if !create {
			return fmt.Errorf("%s can be entered by other users; refusing to use it", path)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

type unixListener struct {
	l    *net.UnixListener
	lock *os.File
	path string
}

func listen(dir string) (listener, error) {
	path := socketPath(dir)
	run := filepath.Dir(path)
	if err := privateDir(run, true); err != nil {
		return nil, err
	}
	// The lock, not the socket, decides who runs: two serves started at
	// the same moment must not both remove "a stale socket" and bind.
	lock, err := os.OpenFile(filepath.Join(run, "serve.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		lock.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		lock.Close()
		return nil, err
	}
	return &unixListener{l: l, lock: lock, path: path}, nil
}

func (u *unixListener) Accept() (conn, error) {
	for {
		c, err := u.l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, errClosed
			}
			return nil, err
		}
		// The directory already keeps other users out; checking the peer
		// as well costs one system call.
		if uid, ok := peerUID(c); ok && uid != os.Getuid() {
			c.Close()
			continue
		}
		return c, nil
	}
}

func (u *unixListener) Close() error {
	err := u.l.Close() // also removes the socket file
	u.lock.Close()
	return err
}

func (u *unixListener) Address() string { return u.path }

// dial connects to the serve for dir.
func dial(dir string, timeout time.Duration) (conn, error) {
	path := socketPath(dir)
	if err := privateDir(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, err
	}
	return c, nil
}
