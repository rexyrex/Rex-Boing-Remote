//go:build windows

package collect

// A small wrapper over the Performance Data Helper (pdh.dll). One query is
// opened per group of counters and collected once per sample; rate counters
// need two collections, so a counter's first values appear one collection
// after it was added. Counters are added with PdhAddEnglishCounterW so the
// English paths work on localized Windows, and with wildcard instances so
// PdhGetFormattedCounterArrayW returns every instance in one call.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procPdhOpenQueryW                = winPdh.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounterW        = winPdh.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData          = winPdh.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterArrayW = winPdh.NewProc("PdhGetFormattedCounterArrayW")
	procPdhCloseQuery                = winPdh.NewProc("PdhCloseQuery")
)

const (
	winPdhFmtDouble       = 0x00000200 // PDH_FMT_DOUBLE
	winPdhFmtNoCap100     = 0x00008000 // PDH_FMT_NOCAP100
	winPdhMoreData        = 0x800007D2 // PDH_MORE_DATA
	winPdhMaxBufferBytes  = 64 << 20   // a sanity cap; GPU Engine on a busy PC is ~100 KB
	winPdhMaxArrayRetries = 4
)

// winPDHQuery is one PDH query and its counters.
type winPDHQuery struct {
	h        uintptr
	counters []*winPDHCounter
}

// winPDHCounter is one (usually wildcard) counter in a query.
type winPDHCounter struct {
	Path string
	h    uintptr
}

func winPdhErr(name string, status uintptr) error {
	return fmt.Errorf("%s: PDH status 0x%08X", name, uint32(status))
}

// winOpenPDHQuery opens a real-time query.
func winOpenPDHQuery() (*winPDHQuery, error) {
	for _, p := range []*windows.LazyProc{procPdhOpenQueryW, procPdhAddEnglishCounterW, procPdhCollectQueryData, procPdhGetFormattedCounterArrayW, procPdhCloseQuery} {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("pdh.dll unavailable: %v", err)
		}
	}
	var h uintptr
	st, _, _ := procPdhOpenQueryW.Call(0, 0, uintptr(unsafe.Pointer(&h)))
	if uint32(st) != 0 || h == 0 {
		return nil, winPdhErr("PdhOpenQueryW", st)
	}
	return &winPDHQuery{h: h}, nil
}

// add adds an English counter path. A counter or object that does not
// exist on this machine returns an error and is simply not added.
func (q *winPDHQuery) add(path string) (*winPDHCounter, error) {
	if q == nil || q.h == 0 {
		return nil, fmt.Errorf("no query")
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var h uintptr
	st, _, _ := procPdhAddEnglishCounterW.Call(q.h, uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&h)))
	if uint32(st) != 0 || h == 0 {
		return nil, winPdhErr("PdhAddEnglishCounterW "+path, st)
	}
	c := &winPDHCounter{Path: path, h: h}
	q.counters = append(q.counters, c)
	return c, nil
}

// collect samples every counter of the query once.
func (q *winPDHQuery) collect() error {
	if q == nil || q.h == 0 || len(q.counters) == 0 {
		return nil
	}
	st, _, _ := procPdhCollectQueryData.Call(q.h)
	if uint32(st) != 0 {
		return winPdhErr("PdhCollectQueryData", st)
	}
	return nil
}

// values returns every instance of the counter with valid data, formatted
// as doubles without the 100 cap. Instances whose CStatus is not valid
// (first collection of a rate counter, an instance that just appeared) are
// skipped. A nil counter yields nil.
func (c *winPDHCounter) values() []winPDHValue {
	if c == nil || c.h == 0 {
		return nil
	}
	const format = winPdhFmtDouble | winPdhFmtNoCap100
	var size, count uint32
	st, _, _ := procPdhGetFormattedCounterArrayW.Call(c.h, format, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	for attempt := 0; attempt < winPdhMaxArrayRetries; attempt++ {
		if uint32(st) != winPdhMoreData || size == 0 || size > winPdhMaxBufferBytes {
			return nil // no data yet, or an error: the counter just has no values
		}
		// The buffer receives the items followed by their names; uint64
		// elements keep it 8-byte aligned for the doubles. Some headroom
		// absorbs instances that appear between the two calls.
		bufSize := size + size/4 + 256
		buf := make([]uint64, (bufSize+7)/8)
		size = uint32(len(buf) * 8)
		st, _, _ = procPdhGetFormattedCounterArrayW.Call(c.h, format, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
		if uint32(st) == 0 {
			return winPdhParseItems(buf, count)
		}
		// PDH_MORE_DATA again: the instance list grew; size holds the new
		// requirement (or is unreliable: re-ask with a zero size).
		size, count = 0, 0
		st, _, _ = procPdhGetFormattedCounterArrayW.Call(c.h, format, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	}
	return nil
}

// close releases the query and all its counters.
func (q *winPDHQuery) close() {
	if q == nil || q.h == 0 {
		return
	}
	procPdhCloseQuery.Call(q.h)
	q.h = 0
	q.counters = nil
}

// winSingle returns the value of a single-instance counter (such as
// "_Total"), or nil.
func winSingle(c *winPDHCounter) *float64 {
	v := c.values()
	if len(v) == 0 {
		return nil
	}
	x := v[0].Value
	return &x
}
