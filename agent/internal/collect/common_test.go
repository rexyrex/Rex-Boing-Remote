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
}
