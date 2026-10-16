package nvidia

import "testing"

func TestParse(t *testing.T) {
	out := "NVIDIA GeForce RTX 4090, 78, 30, 10240, 24564, 64, 186.52, 45, 2520, 3105, 0, 12\nTesla T4, [N/A], 0, 0, 15360, 40, [Not Supported], [N/A], 300, 1590, 0, 0\n"
	gpus := Parse(out)
	if len(gpus) != 2 {
		t.Fatalf("got %d gpus", len(gpus))
	}
	g := gpus[0]
	if g.Name != "NVIDIA GeForce RTX 4090" || g.Utilization != 0.78 || *g.Celsius != 64 || *g.Watts != 186.52 || *g.MaxClockMHz != 3105 {
		t.Errorf("unexpected first gpu: %+v", g)
	}
	if *g.MemoryTotal != 24564*1024*1024 || g.Engines["decode"] != 0.12 {
		t.Errorf("memory/engines wrong: %+v", g)
	}
	if gpus[1].Watts != nil || gpus[1].FanPercent != nil || gpus[1].Utilization != 0 {
		t.Errorf("N/A fields should be absent: %+v", gpus[1])
	}
}
