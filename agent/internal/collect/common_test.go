package collect

import (
	"testing"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

func TestRank(t *testing.T) {
	all := []wire.ProcessRow{
		{PID: 1, CPU: 50, Memory: 10},
		{PID: 2, CPU: 0, Memory: 900},
		{PID: 3, CPU: 0, Memory: 0},
		{PID: 4, CPU: 10, DiskWrite: 5},
	}
	rows, rank := Rank(all)
	if len(rows) != 3 {
		t.Fatalf("rows = %v", rows)
	}
	if got := rank["cpu"]; len(got) != 2 || got[0] != 1 || got[1] != 4 {
		t.Errorf("cpu rank = %v", got)
	}
	if got := rank["memory"]; len(got) != 2 || got[0] != 2 {
		t.Errorf("memory rank = %v", got)
	}
	if _, ok := rank["gpu"]; ok {
		t.Errorf("all-zero metric should be absent")
	}
	if Rate(10, 5, 1) != 0 || Rate(5, 15, 2) != 5 {
		t.Errorf("Rate wrong")
	}
	// A 32-bit counter that wrapped is followed across the wrap; a 64-bit
	// one, or one that fell back further than half the 32-bit range, was
	// reset and reports nothing.
	for _, tc := range []struct {
		prev, cur, want uint64
		ok              bool
	}{
		{1<<32 - 100, 50, 150, true},
		{1<<32 - 1, 0, 1, true},
		{3_000_000_000, 100, 1<<32 - 3_000_000_000 + 100, true},
		{1_000_000_000, 5, 0, false},
		{5_000_000_000, 10, 0, false},
		{7, 7, 0, true},
	} {
		if d, ok := counterDelta(tc.prev, tc.cur); d != tc.want || ok != tc.ok {
			t.Errorf("counterDelta(%d, %d) = %d %v, want %d %v", tc.prev, tc.cur, d, ok, tc.want, tc.ok)
		}
	}
	if Rate(1<<32-100, 50, 2) != 75 {
		t.Errorf("Rate across a 32-bit wrap = %v", Rate(1<<32-100, 50, 2))
	}
}
