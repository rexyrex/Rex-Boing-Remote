package serve

// The local endpoint between serve and the commands that read it: a Unix
// socket in a directory only this user can enter, or on Windows a named pipe
// whose ACL admits only this user. Never a TCP port.

import (
	"errors"
	"io"
	"time"
)

// ErrRunning is returned by listen when another serve already holds the
// endpoint.
var ErrRunning = errors.New("another rex-boing-agent serve is already running for this user")

// errClosed is returned by Accept after Close.
var errClosed = errors.New("the endpoint is closed")

// conn is one local connection.
type conn interface {
	io.ReadWriteCloser
	// SetDeadline bounds every later Read and Write; the zero time removes
	// the bound.
	SetDeadline(t time.Time) error
}

// listener accepts connections from processes of this user only.
type listener interface {
	Accept() (conn, error)
	Close() error
	// Address names the endpoint, for messages.
	Address() string
}
