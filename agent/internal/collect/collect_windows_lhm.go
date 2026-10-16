//go:build windows

package collect

// Optional CPU temperatures, fans and CPU package power from
// LibreHardwareMonitor's "Remote Web Server" (Options → Remote Web Server,
// default port 8085). Windows has no standard API for these and the agent
// never loads a driver of its own; when the user already runs
// LibreHardwareMonitor, its JSON is read from loopback only, at most every
// 5 seconds, in the background, each request capped at 300 ms.

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	winLHMURL       = "http://127.0.0.1:8085/data.json"
	winLHMTimeout   = 300 * time.Millisecond
	winLHMEvery     = 5 * time.Second  // while it answers
	winLHMRetry     = 30 * time.Second // while it does not
	winLHMStale     = 20 * time.Second // older readings are dropped
	winLHMMaxBody   = 8 << 20
	winLHMMaxHeader = 64 << 10
)

type winLHM struct {
	client *http.Client

	mu      sync.Mutex
	last    *winLHMReading
	lastOK  time.Time
	lastTry time.Time
	running bool
	failed  bool
	lastErr string
}

func newWinLHM() *winLHM {
	tr := &http.Transport{
		Proxy:                  nil, // loopback only, never through a proxy
		DialContext:            (&net.Dialer{Timeout: winLHMTimeout}).DialContext,
		ResponseHeaderTimeout:  winLHMTimeout,
		MaxResponseHeaderBytes: winLHMMaxHeader,
		DisableKeepAlives:      true,
	}
	l := &winLHM{client: &http.Client{
		Timeout:       winLHMTimeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	// One synchronous probe so hello's capabilities and the first notices
	// know whether it is there. A closed loopback port refuses instantly.
	l.mu.Lock()
	l.running, l.lastTry = true, time.Now()
	l.mu.Unlock()
	l.refresh()
	return l
}

func (l *winLHM) refresh() {
	var reading *winLHMReading
	errText := ""
	func() {
		defer func() {
			if r := recover(); r != nil {
				errText = "parse failure"
			}
		}()
		resp, err := l.client.Get(winLHMURL)
		if err != nil {
			errText = err.Error()
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			errText = resp.Status
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, winLHMMaxBody))
		if err != nil {
			errText = err.Error()
			return
		}
		r, err := winParseLHM(body)
		if err != nil {
			errText = "unexpected data: " + err.Error()
			return
		}
		reading = r
	}()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false
	if reading != nil {
		l.last, l.lastOK, l.failed, l.lastErr = reading, time.Now(), false, ""
	} else {
		l.failed, l.lastErr = true, errText
	}
}

// reading returns the latest fresh reading, or nil, and schedules a
// background refresh when one is due. It never blocks on the network.
func (l *winLHM) reading() *winLHMReading {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	every := winLHMEvery
	if l.failed {
		every = winLHMRetry
	}
	if !l.running && time.Since(l.lastTry) >= every {
		l.running, l.lastTry = true, time.Now()
		go l.refresh()
	}
	if l.last != nil && time.Since(l.lastOK) < winLHMStale {
		return l.last
	}
	return nil
}

// status reports whether LibreHardwareMonitor answered recently, and the
// last error otherwise.
func (l *winLHM) status() (ok bool, detail string) {
	if l == nil {
		return false, "not probed"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last != nil && time.Since(l.lastOK) < winLHMStale {
		return true, ""
	}
	return false, l.lastErr
}
