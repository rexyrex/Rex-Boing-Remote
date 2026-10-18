//go:build windows

package serve

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Close must leave the instance Accept waits on to Accept, which closes it
// once it wakes. Closed by both, the second close would hit whatever handle
// Windows gave out in between: here, one of the events made right after
// Close.
func TestCloseLeavesAcceptItsInstance(t *testing.T) {
	for i := 0; i < 50; i++ {
		l, err := listen("")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := l.Accept()
			done <- err
		}()
		time.Sleep(5 * time.Millisecond)
		l.Close()
		var events []windows.Handle
		for j := 0; j < 8; j++ {
			ev, err := windows.CreateEvent(nil, 1, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, ev)
		}
		select {
		case err := <-done:
			if !errors.Is(err, errClosed) {
				t.Fatalf("Accept after Close: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Accept outlived Close")
		}
		for _, ev := range events {
			if err := windows.SetEvent(ev); err != nil {
				t.Fatalf("a handle made after Close was closed under its owner: %v", err)
			}
			windows.CloseHandle(ev)
		}
	}
}
