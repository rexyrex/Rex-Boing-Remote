//go:build windows

package serve

// A named pipe per user, \\.\pipe\rex-boing-remote-<user SID>. Its security
// descriptor makes this user the owner and gives no one else any access;
// remote clients are rejected; and the first instance is created with
// FILE_FLAG_FIRST_PIPE_INSTANCE, so a pipe someone else made first is never
// served on. Clients check the owner before they talk, so they never read a
// pipe another user planted under the name either.
//
// All I/O is overlapped, so every wait has a timeout and Close can always
// interrupt Accept.

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pipeBuffer = 64 << 10

func userSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid.Copy()
}

func pipeName() (string, *windows.SID, error) {
	sid, err := userSID()
	if err != nil {
		return "", nil, err
	}
	return `\\.\pipe\rex-boing-remote-` + sid.String(), sid, nil
}

type pipeListener struct {
	name string
	sa   *windows.SecurityAttributes
	stop windows.Handle // event, set by Close

	mu sync.Mutex
	// next is the instance waiting to be taken by Accept. Accept takes it
	// (setting next to 0) before it waits on it, so Close only ever closes
	// an instance no one is using, and no handle is closed twice.
	next   windows.Handle
	closed bool
}

func createInstance(name string, sa *windows.SecurityAttributes, first bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	return windows.CreateNamedPipe(p, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, pipeBuffer, pipeBuffer, 0, sa)
}

// listen ignores dir: the pipe's name comes from the user, not a path.
func listen(dir string) (listener, error) {
	name, sid, err := pipeName()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;GA;;;" + sid.String() + ")")
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	h, err := createInstance(name, sa, true)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
			// The name is taken: by our own serve, or by someone else.
			if c, derr := dial(dir, time.Second); derr == nil {
				c.Close()
				return nil, ErrRunning
			}
			return nil, fmt.Errorf("the pipe %s already exists and is not this user's", name)
		}
		return nil, err
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return &pipeListener{name: name, sa: sa, stop: stop, next: h}, nil
}

func (l *pipeListener) Accept() (conn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, errClosed
		}
		h := l.next
		l.next = 0
		if h == 0 {
			var err error
			if h, err = createInstance(l.name, l.sa, false); err != nil {
				l.mu.Unlock()
				return nil, err
			}
		}
		l.mu.Unlock()

		// Close interrupts the wait through the stop event; h stays this
		// loop's to close.
		err := l.connect(h)
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			windows.CloseHandle(h)
			return nil, errClosed
		}
		if err == nil {
			// The next instance is made while this one still holds the
			// name, so the name is never free for someone else to take.
			if next, cerr := createInstance(l.name, l.sa, false); cerr == nil {
				l.next = next
			}
		}
		l.mu.Unlock()
		if err != nil {
			windows.CloseHandle(h)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		return &pipeConn{h: h, server: true}, nil
	}
}

// connect waits for a client on h, or for Close.
func (l *pipeListener) connect(h windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	o := &windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, o)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return err
	}
	which, err := windows.WaitForMultipleObjects([]windows.Handle{ev, l.stop}, false, windows.INFINITE)
	if err != nil || which != windows.WAIT_OBJECT_0 {
		windows.CancelIoEx(h, o)
		var n uint32
		windows.GetOverlappedResult(h, o, &n, true)
		return errClosed
	}
	var n uint32
	return windows.GetOverlappedResult(h, o, &n, false)
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	windows.SetEvent(l.stop)
	// Only an instance Accept has not taken: one it waits on, it closes.
	if l.next != 0 {
		windows.CloseHandle(l.next)
		l.next = 0
	}
	return nil
}

func (l *pipeListener) Address() string { return l.name }

// removeEndpoint has nothing to remove: a pipe goes away with its last
// handle.
func removeEndpoint(dir string) error { return nil }

// dial connects to this user's serve, refusing a pipe this user does not own.
func dial(dir string, timeout time.Duration) (conn, error) {
	name, sid, err := pipeName()
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	var h windows.Handle
	for {
		h, err = windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		// Every instance is busy for a moment: wait for the next one.
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(sid) {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("the pipe %s does not belong to this user", name)
	}
	return &pipeConn{h: h}, nil
}

type pipeConn struct {
	h        windows.Handle
	server   bool
	mu       sync.Mutex
	deadline time.Time
	closed   bool
}

var errTimeout = errors.New("timed out")

func (c *pipeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// io runs one overlapped read or write, waiting until the deadline.
func (c *pipeConn) io(op func(o *windows.Overlapped) error) (int, error) {
	c.mu.Lock()
	deadline, closed := c.deadline, c.closed
	c.mu.Unlock()
	if closed {
		return 0, errClosed
	}
	wait := uint32(windows.INFINITE)
	if !deadline.IsZero() {
		left := time.Until(deadline)
		if left <= 0 {
			return 0, errTimeout
		}
		wait = uint32(left / time.Millisecond)
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(ev)
	o := &windows.Overlapped{HEvent: ev}
	err = op(o)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	var n uint32
	if r, _ := windows.WaitForSingleObject(ev, wait); r != windows.WAIT_OBJECT_0 {
		windows.CancelIoEx(c.h, o)
		windows.GetOverlappedResult(c.h, o, &n, true)
		return int(n), errTimeout
	}
	err = windows.GetOverlappedResult(c.h, o, &n, false)
	return int(n), err
}

func (c *pipeConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := c.io(func(o *windows.Overlapped) error { return windows.ReadFile(c.h, b, nil, o) })
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) || (err == nil && n == 0) {
		return n, io.EOF
	}
	return n, err
}

func (c *pipeConn) Write(b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n, err := c.io(func(o *windows.Overlapped) error { return windows.WriteFile(c.h, b[written:], nil, o) })
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.server {
		windows.DisconnectNamedPipe(c.h)
	}
	return windows.CloseHandle(c.h)
}
