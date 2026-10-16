package collect

// Fixture tests for the Linux collector. testdata/linux-* are trimmed copies
// of four machines' /proc and /sys: a hybrid Intel laptop, an AMD desktop
// with an amdgpu card, a Raspberry Pi whose only sensor is a thermal zone,
// and a KVM guest with no sensors at all. Each test copies its tree to a
// temporary directory, so it can change counters between samples.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// copyFixture copies testdata/name into a temporary directory. Paths in
// testdata spell ":" as "%3A" (Windows cannot check out a colon); the copy
// restores it where the OS allows.
func linuxTCopyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", name)
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		if runtime.GOOS != "windows" {
			rel = strings.ReplaceAll(rel, "%3A", ":")
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if d.Name() == ".keep" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func linuxTNeedColons(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sysfs names with ':' cannot exist on Windows")
	}
}

// fixture returns a collector over a fresh copy of a fixture tree.
func linuxTFixture(t *testing.T, name string) (*linuxCollector, string) {
	t.Helper()
	root := linuxTCopyFixture(t, name)
	c := newLinuxCollector(root)
	c.statfs = func(path string) (uint64, uint64, error) { return 100 << 30, 40 << 30, nil }
	return c, root
}

func linuxTPut(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// pause makes the next sample's window about d long, without sleeping.
func linuxTPause(c *linuxCollector, d time.Duration) {
	c.window.last = c.window.last.Add(-d)
	c.procs.lastScan = c.procs.lastScan.Add(-d)
}

func linuxTNear(t *testing.T, what string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s = %v, want %v ± %v", what, got, want, tol)
	}
}

func linuxTF64(p *float64) float64 {
	if p == nil {
		return math.NaN()
	}
	return *p
}

// statLines builds a /proc/stat with the given total and per-core lines.
func linuxTStatLines(all [8]uint64, cores [][8]uint64) string {
	line := func(name string, v [8]uint64) string {
		return fmt.Sprintf("%s %d %d %d %d %d %d %d %d 0 0\n", name, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])
	}
	s := line("cpu ", all)
	for i, c := range cores {
		s += line(fmt.Sprintf("cpu%d", i), c)
	}
	return s + "intr 1 2 3\nctxt 4\nbtime 1791327353\nprocesses 5\n"
}

func TestLinuxHost(t *testing.T) {
	cases := []struct {
		fixture string
		want    wire.Host
	}{
		{"linux-intel-hybrid", wire.Host{Hostname: "carbon", ModelName: "ThinkPad X1 Carbon Gen 10", Vendor: "Lenovo",
			ChipName: "12th Gen Intel Core i7-1260P", OSName: "Fedora Linux", OSVersion: "40", Kernel: "6.9.7-200.fc40.x86_64",
			PhysicalCores: 12, LogicalCores: 16, PerformanceCores: 4, EfficiencyCores: 8, MemoryBytes: 32_000_000 * 1024,
			BootTime: 1791327353000, Virtualization: "none"}},
		{"linux-amd-desktop", wire.Host{Hostname: "ryzen", ModelName: "X670E Taichi", Vendor: "ASRock", ChipName: "AMD Ryzen 7 7700X",
			OSName: "Ubuntu", OSVersion: "24.04.1 LTS", Kernel: "6.8.0-45-generic", PhysicalCores: 8, LogicalCores: 16,
			MemoryBytes: 65_000_000 * 1024, BootTime: 1791327353000, Virtualization: "none"}},
		{"linux-rpi", wire.Host{Hostname: "pi", ModelName: "Raspberry Pi 4 Model B Rev 1.4", ChipName: "Cortex-A72",
			OSName: "Debian GNU/Linux", OSVersion: "12", Kernel: "6.6.51+rpt-rpi-v8", PhysicalCores: 4, LogicalCores: 4,
			MemoryBytes: 3_884_000 * 1024, BootTime: 1791327353000, Virtualization: "none"}},
		{"linux-vm", wire.Host{Hostname: "vps", ModelName: "Standard PC (Q35 + ICH9, 2009)", Vendor: "QEMU", ChipName: "AMD EPYC 7763",
			OSName: "Debian GNU/Linux", OSVersion: "12", Kernel: "6.1.0-25-cloud-amd64", PhysicalCores: 2, LogicalCores: 2,
			MemoryBytes: 2_000_000 * 1024, BootTime: 1791327353000, Virtualization: "kvm"}},
	}
	for _, tc := range cases {
		c, _ := linuxTFixture(t, tc.fixture)
		if got := c.Host(); got != tc.want {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.fixture, got, tc.want)
		}
	}
}

func TestLinuxCapabilities(t *testing.T) {
	want := map[string]string{
		"linux-intel-hybrid": "cpu memory gpu sensors fans power battery pressure network disk processes system",
		"linux-amd-desktop":  "cpu memory gpu sensors fans power pressure network disk processes system",
		"linux-rpi":          "cpu memory sensors pressure network disk processes system",
		"linux-vm":           "cpu memory network disk processes system",
	}
	for name, w := range want {
		if name == "linux-intel-hybrid" && runtime.GOOS == "windows" {
			continue // its RAPL zones need ':' in their names
		}
		c, _ := linuxTFixture(t, name)
		if got := strings.Join(c.Capabilities(), " "); got != w {
			t.Errorf("%s: capabilities %q, want %q", name, got, w)
		}
	}
}

func TestLinuxCPU(t *testing.T) {
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	s := c.Sample(wire.DetailVitals)
	if !s.Resync || s.CPU == nil || s.CPU.Idle != 1 || s.CPU.Total != 0 {
		t.Fatalf("first sample should be a fresh baseline: %+v", s.CPU)
	}
	if s.CPU.Kinds != "PPPPPPPPEEEEEEEE" || len(s.CPU.PerCore) != 16 {
		t.Errorf("kinds %q, %d cores", s.CPU.Kinds, len(s.CPU.PerCore))
	}
	if linuxTF64(s.CPU.ClockMHz) != 2500 || linuxTF64(s.CPU.PerformanceClockMHz) != 3000 || linuxTF64(s.CPU.EfficiencyClockMHz) != 2000 {
		t.Errorf("clocks %v %v %v", linuxTF64(s.CPU.ClockMHz), linuxTF64(s.CPU.PerformanceClockMHz), linuxTF64(s.CPU.EfficiencyClockMHz))
	}
	if *s.CPU.Load != [3]float64{0.48, 0.95, 0.81} || *s.CPU.Threads != 1234 || *s.CPU.Processes != 6 {
		t.Errorf("load %v threads %d processes %d", *s.CPU.Load, *s.CPU.Threads, *s.CPU.Processes)
	}

	// Baseline: every field at 1000; then 1000 more ticks split
	// user 600, system 100, idle 200, iowait 50, irq 25, softirq 25.
	base := [8]uint64{1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000}
	next := [8]uint64{1600, 1000, 1100, 1200, 1050, 1025, 1025, 1000}
	busy := [8]uint64{1100, 1000, 1000, 1000, 1000, 1000, 1000, 1000} // core 0: all user
	idle := [8]uint64{1000, 1000, 1000, 1100, 1000, 1000, 1000, 1000} // core 1: all idle
	linuxTPut(t, root, "proc/stat", linuxTStatLines(base, [][8]uint64{base, base}))
	c.Sample(wire.DetailVitals)
	linuxTPut(t, root, "proc/stat", linuxTStatLines(next, [][8]uint64{busy, idle}))
	linuxTPause(c, time.Second)
	s = c.Sample(wire.DetailVitals)
	cpu := s.CPU
	linuxTNear(t, "user", cpu.User, 0.6, 1e-9)
	linuxTNear(t, "system", cpu.System, 0.15, 1e-9)
	linuxTNear(t, "idle", cpu.Idle, 0.2, 1e-9)
	linuxTNear(t, "iowait", linuxTF64(cpu.IOWait), 0.05, 1e-9)
	linuxTNear(t, "total", cpu.Total, 0.75, 1e-9)
	if len(cpu.PerCore) != 2 || cpu.PerCore[0] != 1 || cpu.PerCore[1] != 0 {
		t.Errorf("perCore %v", cpu.PerCore)
	}
	if cpu.Kinds != "PP" {
		t.Errorf("kinds after the cpu set changed: %q", cpu.Kinds)
	}

	// A long gap is a resync: rates drop back to a fresh baseline.
	linuxTPut(t, root, "proc/stat", linuxTStatLines([8]uint64{9000, 1000, 1100, 1200, 1050, 1025, 1025, 1000}, [][8]uint64{busy, idle}))
	linuxTPause(c, MaxGap+time.Second)
	s = c.Sample(wire.DetailVitals)
	if !s.Resync || s.CPU.Total != 0 || s.CPU.Idle != 1 || s.CPU.PerCore[0] != 0 {
		t.Errorf("resync sample: resync=%v %+v", s.Resync, s.CPU)
	}
}

func TestLinuxCoreKinds(t *testing.T) {
	ids := func(n int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	}
	tree := func(files map[string]string) string {
		root := t.TempDir()
		for k, v := range files {
			linuxTPut(t, root, k, v)
		}
		return root
	}
	kinds := func(root string, n int) string {
		m, _ := linuxDetectKinds(root, ids(n))
		b := make([]byte, n)
		for i := range b {
			b[i] = '?'
			if k, ok := m[i]; ok {
				b[i] = k
			}
		}
		return string(b)
	}
	cpu := func(i int, file, v string) (string, string) {
		return fmt.Sprintf("sys/devices/system/cpu/cpu%d/%s", i, file), v
	}

	// Arrow Lake on a kernel without the hybrid PMUs (the NUC): max clocks
	// are misreported for the E-cores, base clocks tell the truth.
	files := map[string]string{}
	for i := 0; i < 16; i++ {
		base, max := "2500000", "6400000"
		switch {
		case i >= 14:
			base, max = "700000", "2500000"
		case i >= 6:
			base, max = "2100000", "6200000"
		}
		k, v := cpu(i, "cpufreq/base_frequency", base)
		files[k] = v
		k, v = cpu(i, "cpufreq/cpuinfo_max_freq", max)
		files[k] = v
	}
	if got := kinds(tree(files), 16); got != "PPPPPPEEEEEEEEEE" {
		t.Errorf("base_frequency kinds %q", got)
	}

	// big.LITTLE by capacity (RK3588: 4 × A55 at 414, 4 × A76 at 1024).
	files = map[string]string{}
	for i := 0; i < 8; i++ {
		v := "414"
		if i >= 4 {
			v = "1024"
		}
		k, val := cpu(i, "cpu_capacity", v)
		files[k] = val
	}
	if got := kinds(tree(files), 8); got != "EEEEPPPP" {
		t.Errorf("capacity kinds %q", got)
	}

	// Favoured cores of a homogeneous chip (Turbo Boost Max 3.0) are not
	// P-cores.
	files = map[string]string{}
	for i := 0; i < 8; i++ {
		v := "4800000"
		if i < 2 {
			v = "5100000"
		}
		k, val := cpu(i, "cpufreq/cpuinfo_max_freq", v)
		files[k] = val
	}
	if got := kinds(tree(files), 8); got != "????????" {
		t.Errorf("favoured cores kinds %q", got)
	}

	// A genuine split by maximum clock alone.
	files = map[string]string{}
	for i := 0; i < 4; i++ {
		v := "3000000"
		if i < 2 {
			v = "4400000"
		}
		k, val := cpu(i, "cpufreq/cpuinfo_max_freq", v)
		files[k] = val
	}
	if got := kinds(tree(files), 4); got != "PPEE" {
		t.Errorf("max_freq kinds %q", got)
	}
	if got := kinds(t.TempDir(), 2); got != "??" {
		t.Errorf("no topology kinds %q", got)
	}
}

func TestLinuxMemory(t *testing.T) {
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	s := c.Sample(wire.DetailVitals)
	m := s.Memory
	kb := uint64(1024)
	if m.Total != 32_000_000*kb || m.Used != 12_000_000*kb || *m.Available != 20_000_000*kb || *m.App != m.Used {
		t.Errorf("memory %+v", m)
	}
	if *m.Cached != (12_000_000+1_000_000-800_000)*kb || *m.Buffers != 500_000*kb || *m.Free != 2_000_000*kb {
		t.Errorf("cached %d buffers %d free %d", *m.Cached, *m.Buffers, *m.Free)
	}
	linuxTNear(t, "pressure", linuxTF64(m.Pressure), 0.375, 1e-9)
	if m.PressureLevel != "normal" || m.Swap.Total != 8_388_604*kb || m.Swap.Used != 388_604*kb {
		t.Errorf("level %q swap %+v", m.PressureLevel, m.Swap)
	}
	if m.Swap.InRate != nil {
		t.Errorf("swap rates on the first sample")
	}
	linuxTPut(t, root, "proc/vmstat", "pswpin 110\npswpout 220\n")
	linuxTPause(c, time.Second)
	s = c.Sample(wire.DetailVitals)
	linuxTNear(t, "swap in", linuxTF64(s.Memory.Swap.InRate), 10*4096/s.Interval, 1e-6)
	linuxTNear(t, "swap out", linuxTF64(s.Memory.Swap.OutRate), 20*4096/s.Interval, 1e-6)

	for name, level := range map[string]string{"linux-amd-desktop": "critical", "linux-vm": "warning", "linux-rpi": "normal"} {
		c, _ := linuxTFixture(t, name)
		if got := c.Sample(wire.DetailVitals).Memory.PressureLevel; got != level {
			t.Errorf("%s pressure level %q, want %q", name, got, level)
		}
	}
	psi := &linuxPSI{hasMem: true, hasMemF: true}
	for _, tc := range []struct {
		avail      float64
		some, full float64
		want       string
	}{{0.5, 0, 0, "normal"}, {0.5, 10, 0, "warning"}, {0.5, 1, 5, "critical"}, {0.04, 0, 0, "critical"}, {0.08, 0, 0, "normal"}} {
		psi.memory, psi.memFull = tc.some, tc.full
		if got := linuxPressureLevel(tc.avail, psi); got != tc.want {
			t.Errorf("PSI level(%v, some %v, full %v) = %q, want %q", tc.avail, tc.some, tc.full, got, tc.want)
		}
	}
	if linuxPressureLevel(0.08, nil) != "warning" || linuxPressureLevel(0.2, nil) != "normal" {
		t.Errorf("level without PSI")
	}
}

func TestLinuxPressure(t *testing.T) {
	c, _ := linuxTFixture(t, "linux-intel-hybrid")
	p := c.Sample(wire.DetailVitals).Pressure
	if p == nil || p.CPU != 1.25 || p.Memory != 0.5 || p.IO != 2 || linuxTF64(p.MemoryFull) != 0 || linuxTF64(p.IOFull) != 1 {
		t.Errorf("pressure %+v", p)
	}
	vm, _ := linuxTFixture(t, "linux-vm")
	if p := vm.Sample(wire.DetailVitals).Pressure; p != nil {
		t.Errorf("a kernel without PSI reported %+v", p)
	}
}

func TestLinuxIntelGPU(t *testing.T) {
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	s := c.Sample(wire.DetailVitals)
	if len(s.GPUs) != 1 {
		t.Fatalf("gpus %+v", s.GPUs)
	}
	g := s.GPUs[0]
	if g.Name != "Intel Iris Xe Graphics" || g.Vendor != "intel" || g.Utilization != 0 || linuxTF64(g.ClockMHz) != 700 || linuxTF64(g.MaxClockMHz) != 1400 {
		t.Errorf("first sample %+v", g)
	}
	// 500 ms of RC6 (idle) residency in a one-second window: 50 % busy.
	linuxTPut(t, root, "sys/class/drm/card1/gt/gt0/rc6_residency_ms", "1000500\n")
	linuxTPause(c, time.Second)
	s = c.Sample(wire.DetailVitals)
	linuxTNear(t, "busy", s.GPUs[0].Utilization, 1-0.5/s.Interval, 1e-9)
	linuxTNear(t, "render", s.GPUs[0].Engines["render"], s.GPUs[0].Utilization, 1e-12)

	// Runtime-suspended: idle, and none of its counters are read.
	linuxTPut(t, root, "sys/class/drm/card1/device/power/runtime_status", "suspended\n")
	linuxTPut(t, root, "sys/class/drm/card1/gt/gt0/rc6_residency_ms", "1000500\n")
	s = c.Sample(wire.DetailVitals)
	if g := s.GPUs[0]; g.Utilization != 0 || linuxTF64(g.ClockMHz) != 0 {
		t.Errorf("suspended gpu %+v", g)
	}
}

func TestLinuxAMDGPU(t *testing.T) {
	c, root := linuxTFixture(t, "linux-amd-desktop")
	s := c.Sample(wire.DetailFull)
	if len(s.GPUs) != 1 {
		t.Fatalf("gpus %+v", s.GPUs)
	}
	g := s.GPUs[0]
	if g.Name != "AMD Radeon RX 7900 XT/7900 XTX/7900 GRE/7900M" || g.Vendor != "amd" || g.Utilization != 0.37 ||
		*g.MemoryUsed != 2_147_483_648 || *g.MemoryTotal != 25_753_026_560 || linuxTF64(g.Celsius) != 52 || linuxTF64(g.Watts) != 64 ||
		linuxTF64(g.FanRPM) != 1350 || linuxTF64(g.FanPercent) != 40 || linuxTF64(g.ClockMHz) != 1200 || linuxTF64(g.MaxClockMHz) != 2526 {
		t.Errorf("amd gpu %+v", g)
	}
	if s.Power == nil || linuxTF64(s.Power.GPUWatts) != 64 || linuxTF64(s.Thermal.GPUCelsius) != 52 {
		t.Errorf("gpu power/temperature not propagated: %+v %+v", s.Power, s.Thermal)
	}
	linuxTPut(t, root, "sys/class/drm/card0/device/power/runtime_status", "suspended\n")
	linuxTPut(t, root, "sys/class/hwmon/hwmon7/device/power/runtime_status", "suspended\n")
	s = c.Sample(wire.DetailFull)
	if g := s.GPUs[0]; g.Utilization != 0 || g.MemoryUsed != nil || g.Celsius != nil || g.Watts != nil {
		t.Errorf("a suspended GPU was read: %+v", g)
	}
	for _, sen := range s.Thermal.Sensors {
		if sen.Category == "GPU" {
			t.Errorf("suspended GPU sensor read: %+v", sen)
		}
	}
}

func linuxTSensorKeys(th *wire.Thermal) string {
	var keys []string
	for _, s := range th.Sensors {
		keys = append(keys, s.Key)
	}
	return strings.Join(keys, " ")
}

func TestLinuxThermalIntel(t *testing.T) {
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	th := c.Sample(wire.DetailFull).Thermal
	if got := linuxTSensorKeys(th); got != "pkg c0 c4 c8 c9 nvme0 nvme0s1 acpi1 thinkpad wifi" {
		t.Errorf("sensor keys %q", got)
	}
	pkg := th.Sensors[0]
	if pkg.Label != "CPU package" || pkg.Category != "CPU" || pkg.Celsius != 61 || linuxTF64(pkg.Critical) != 100 {
		t.Errorf("package sensor %+v", pkg)
	}
	for _, s := range th.Sensors {
		if s.Key == "nvme0s1" && s.High != nil {
			t.Errorf("an absurd NVMe limit (65261 °C) was kept: %v", *s.High)
		}
		if s.Key == "nvme0" && (s.Label != "NVMe Composite" || linuxTF64(s.High) != 82.85) {
			t.Errorf("nvme composite %+v", s)
		}
	}
	if linuxTF64(th.CPUCelsius) != 61 || linuxTF64(th.StorageCelsius) != 38.9 || linuxTF64(th.PeakCelsius) != 63 || th.State != "nominal" {
		t.Errorf("headlines cpu %v storage %v peak %v state %q", linuxTF64(th.CPUCelsius), linuxTF64(th.StorageCelsius), linuxTF64(th.PeakCelsius), th.State)
	}
	if len(th.Fans) != 1 || th.Fans[0].Label != "Fan 1" || th.Fans[0].RPM != 2900 || linuxTF64(th.Fans[0].MaxRPM) != 2900 || linuxTF64(th.Fans[0].MinRPM) != 0 {
		t.Errorf("fans %+v", th.Fans)
	}

	// Vitals carry only the headline values.
	v := c.Sample(wire.DetailVitals).Thermal
	if v.Sensors != nil || v.Fans != nil || linuxTF64(v.CPUCelsius) != 61 || linuxTF64(v.PeakCelsius) != 61 {
		t.Errorf("vitals thermal %+v", v)
	}

	for temp, state := range map[string]string{"92000": "serious", "98000": "critical", "89000": "nominal"} {
		linuxTPut(t, root, "sys/class/hwmon/hwmon3/temp1_input", temp+"\n")
		if got := c.Sample(wire.DetailVitals).Thermal.State; got != state {
			t.Errorf("state at %s m°C = %q, want %q", temp, got, state)
		}
	}
}

func TestLinuxThermalAMD(t *testing.T) {
	c, _ := linuxTFixture(t, "linux-amd-desktop")
	th := c.Sample(wire.DetailFull).Thermal
	if got := linuxTSensorKeys(th); got != "tctl ccd1 gpu gpuj gpumem dimm0 dimm1 nvme0 nvme1 nvme1s1 sda systin cputin" {
		t.Errorf("sensor keys %q", got)
	}
	labels := map[string]string{}
	for _, s := range th.Sensors {
		labels[s.Key] = s.Label + "/" + s.Category
	}
	for k, want := range map[string]string{"tctl": "CPU Tctl/CPU", "ccd1": "CPU CCD 1/CPU", "gpuj": "GPU junction/GPU",
		"dimm1": "Memory DIMM 1/Memory", "nvme1": "NVMe 1 Composite/Storage", "sda": "Drive sda/Storage", "systin": "SYSTIN/Other"} {
		if labels[k] != want {
			t.Errorf("%s = %q, want %q", k, labels[k], want)
		}
	}
	if linuxTF64(th.CPUCelsius) != 71.3 || linuxTF64(th.GPUCelsius) != 52 || linuxTF64(th.StorageCelsius) != 51.9 || linuxTF64(th.PeakCelsius) != 71.3 {
		t.Errorf("headlines %+v", th)
	}
	var fans []string
	for _, f := range th.Fans {
		fans = append(fans, fmt.Sprintf("%s %.0f %.0f-%.0f", f.Label, f.RPM, linuxTF64(f.MinRPM), linuxTF64(f.MaxRPM)))
	}
	if got := strings.Join(fans, ", "); got != "Fan 1 1100 0-1100, Rear Fan 650 300-2000, GPU fan 1350 0-3300" {
		t.Errorf("fans %q (the unconnected fan2 must be left out)", got)
	}
}

func TestLinuxThermalZoneFallback(t *testing.T) {
	c, _ := linuxTFixture(t, "linux-rpi")
	th := c.Sample(wire.DetailFull).Thermal
	if th == nil || len(th.Sensors) != 1 {
		t.Fatalf("thermal %+v", th)
	}
	s := th.Sensors[0]
	if s.Key != "cpu" || s.Label != "CPU" || s.Category != "CPU" || s.Celsius != 51.1 || linuxTF64(s.Critical) != 110 {
		t.Errorf("zone sensor %+v", s)
	}
	if linuxTF64(th.CPUCelsius) != 51.1 || th.State != "nominal" || !c.thermal.zones {
		t.Errorf("headline %v state %q", linuxTF64(th.CPUCelsius), th.State)
	}
	// The hybrid laptop has coretemp, so its x86_pkg_temp zone stays out.
	c2, _ := linuxTFixture(t, "linux-intel-hybrid")
	c2.Sample(wire.DetailFull)
	if c2.thermal.zones {
		t.Errorf("thermal zones used although hwmon has a CPU sensor")
	}
	vm, _ := linuxTFixture(t, "linux-vm")
	if th := vm.Sample(wire.DetailFull).Thermal; th != nil {
		t.Errorf("a VM reported thermal %+v", th)
	}
}

func TestLinuxStorageSensorCadence(t *testing.T) {
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	if got := linuxTF64(c.Sample(wire.DetailVitals).Thermal.StorageCelsius); got != 38.9 {
		t.Fatalf("storage %v", got)
	}
	linuxTPut(t, root, "sys/class/hwmon/hwmon2/temp1_input", "50000\n")
	if got := linuxTF64(c.Sample(wire.DetailVitals).Thermal.StorageCelsius); got != 38.9 {
		t.Errorf("NVMe read again within %v: %v", linuxSlowEvery, got)
	}
	for _, s := range c.thermal.sensors {
		s.readAt = s.readAt.Add(-linuxSlowEvery)
	}
	if got := linuxTF64(c.Sample(wire.DetailVitals).Thermal.StorageCelsius); got != 50 {
		t.Errorf("NVMe not refreshed after %v: %v", linuxSlowEvery, got)
	}
}

func TestLinuxRAPL(t *testing.T) {
	linuxTNeedColons(t)
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	if p := c.Sample(wire.DetailVitals).Power; p.PackageWatts != nil || p.CPUWatts != nil {
		t.Errorf("watts on the first sample: %+v", p)
	}
	linuxTPut(t, root, "sys/class/powercap/intel-rapl:0/energy_uj", "55000000\n")
	linuxTPut(t, root, "sys/class/powercap/intel-rapl:0:0/energy_uj", "52000000\n")
	linuxTPut(t, root, "sys/class/powercap/intel-rapl:1/energy_uj", "99000000\n") // psys: not counted
	linuxTPause(c, time.Second)
	s := c.Sample(wire.DetailVitals)
	linuxTNear(t, "package", linuxTF64(s.Power.PackageWatts), 5/s.Interval, 0.006)
	linuxTNear(t, "core", linuxTF64(s.Power.CPUWatts), 2/s.Interval, 0.006)
	if linuxTF64(s.Power.SystemWatts) != 7.25 {
		t.Errorf("battery system watts %v", linuxTF64(s.Power.SystemWatts))
	}
	if n := c.Notices(); len(n) != 0 {
		t.Errorf("notices with readable RAPL: %+v", n)
	}

	// The AMD box's counter wraps at max_energy_range_uj.
	a, aroot := linuxTFixture(t, "linux-amd-desktop")
	a.Sample(wire.DetailVitals)
	linuxTPut(t, aroot, "sys/class/powercap/intel-rapl:0/energy_uj", "4000000\n")
	linuxTPause(a, time.Second)
	s = a.Sample(wire.DetailVitals)
	linuxTNear(t, "wrapped package", linuxTF64(s.Power.PackageWatts), 4.00085/s.Interval, 0.006)
}

func TestLinuxRAPLDenied(t *testing.T) {
	linuxTNeedColons(t)
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	for _, z := range []string{"intel-rapl:0", "intel-rapl:0:0", "intel-rapl:0:1", "intel-rapl:1"} {
		if err := os.Chmod(filepath.Join(root, "sys/class/powercap", z, "energy_uj"), 0); err != nil {
			t.Fatal(err)
		}
	}
	s := c.Sample(wire.DetailVitals)
	if s.Power == nil || s.Power.PackageWatts != nil || s.Power.CPUWatts != nil {
		t.Errorf("power with denied RAPL: %+v", s.Power)
	}
	n := c.Notices()
	if len(n) != 1 || n[0].Code != "rapl-denied" || n[0].Type != "notice" {
		t.Errorf("notices %+v", n)
	}
	var power *Check
	for _, ch := range c.Doctor() {
		if ch.Name == "Power" {
			ch := ch
			power = &ch
		}
	}
	if power == nil || power.OK || !strings.Contains(power.Fix, linuxRAPLRule) || !strings.Contains(power.Fix, linuxRAPLRuleFile) ||
		!strings.Contains(power.Fix, linuxRAPLChmod) {
		t.Errorf("doctor power check %+v", power)
	}
}

func TestLinuxBattery(t *testing.T) {
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	b := c.Sample(wire.DetailFull).Battery
	if b == nil || !b.Present || b.Percentage != 0.81 || b.Charging || b.PluggedIn || linuxTF64(b.SystemWatts) != 7.25 ||
		*b.TimeRemainingMinutes != 380 || *b.CycleCount != 112 || *b.DesignCapacity != 3682 || *b.MaxCapacity != 3669 ||
		linuxTF64(b.Voltage) != 16.8 || b.ChargingWatts != nil {
		t.Errorf("battery %+v", b)
	}
	linuxTPut(t, root, "sys/class/power_supply/BAT0/status", "Charging\n")
	linuxTPut(t, root, "sys/class/power_supply/AC/online", "1\n")
	b = c.Sample(wire.DetailVitals).Battery
	if !b.Charging || !b.PluggedIn || linuxTF64(b.ChargingWatts) != 7.25 || b.SystemWatts != nil {
		t.Errorf("charging battery %+v", b)
	}
	for _, name := range []string{"linux-amd-desktop", "linux-vm"} {
		c, _ := linuxTFixture(t, name)
		if b := c.Sample(wire.DetailFull).Battery; b != nil {
			t.Errorf("%s has no battery, got %+v", name, b)
		}
	}
}

func linuxTNetdevFile(rows ...string) string {
	s := "Inter-|   Receive |  Transmit\n face |bytes packets|bytes packets\n"
	for _, r := range rows {
		f := strings.Fields(r)
		s += fmt.Sprintf("%s: %s 1 0 0 0 0 0 0 %s 1 0 0 0 0 0 0\n", f[0], f[1], f[2])
	}
	return s
}

func TestLinuxNetwork(t *testing.T) {
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	n := c.Sample(wire.DetailFull).Network
	if n.RX != 0 || n.TX != 0 || n.PrimaryInterface != "wlp0s20f3" || len(n.Interfaces) != 2 {
		t.Fatalf("first sample %+v", n)
	}
	if i := n.Interfaces[0]; i.Name != "wlp0s20f3" || !i.Up || i.SpeedMbps != nil {
		t.Errorf("wifi %+v", i)
	}
	if i := n.Interfaces[1]; i.Name != "tailscale0" || !i.Up {
		t.Errorf("tunnel %+v", i)
	}
	linuxTPut(t, root, "proc/net/dev", linuxTNetdevFile("lo 9000 9000", "wlp0s20f3 1001000 200500", "docker0 100300 300", "tailscale0 7100 8000"))
	linuxTPause(c, time.Second)
	s := c.Sample(wire.DetailFull)
	n = s.Network
	linuxTNear(t, "rx", n.RX, 1000/s.Interval, 1e-6)
	linuxTNear(t, "tx", n.TX, 500/s.Interval, 1e-6)
	if n.RXTotal != 1000 || n.TXTotal != 500 {
		t.Errorf("totals %d %d", n.RXTotal, n.TXTotal)
	}
	linuxTNear(t, "tunnel rx", n.Interfaces[1].RX, 100/s.Interval, 1e-6)

	// An interface that disappears is forgotten.
	linuxTPut(t, root, "proc/net/dev", linuxTNetdevFile("wlp0s20f3 1001000 200500"))
	c.Sample(wire.DetailVitals)
	if _, ok := c.net.ifaces["docker0"]; ok {
		t.Errorf("vanished interface kept")
	}

	a, aroot := linuxTFixture(t, "linux-amd-desktop")
	n = a.Sample(wire.DetailFull).Network
	if n.PrimaryInterface != "wg0" || len(n.Interfaces) != 2 || n.Interfaces[0].Name != "wg0" || linuxTF64(n.Interfaces[1].SpeedMbps) != 2500 {
		t.Errorf("amd interfaces %+v", n)
	}
	// Only the physical NIC counts: not its VLAN, the bridge, the veth or the tunnel.
	linuxTPut(t, aroot, "proc/net/dev", linuxTNetdevFile("enp14s0 5000100 6000000", "br-1a2b3c 9100 100", "veth1234 9050 50", "enp14s0.100 9777 777", "wg0 9000 2000"))
	linuxTPause(a, time.Second)
	s = a.Sample(wire.DetailVitals)
	linuxTNear(t, "amd rx", s.Network.RX, 100/s.Interval, 1e-6)
	if s.Network.Interfaces != nil || s.Network.PrimaryInterface != "" {
		t.Errorf("vitals carry the interface list: %+v", s.Network)
	}
}

func TestLinuxDisk(t *testing.T) {
	c, root := linuxTFixture(t, "linux-amd-desktop")
	d := c.Sample(wire.DetailFull).Disk
	var whole []string
	for name, dev := range c.disk.devs {
		if dev.whole {
			whole = append(whole, name)
		}
	}
	if got := strings.Join(linuxSorted(whole), " "); got != "nvme0n1 nvme1n1 sda" {
		t.Errorf("whole disks %q", got)
	}
	var vols []string
	for _, v := range d.Volumes {
		vols = append(vols, v.Name+":"+v.FS)
	}
	if got := strings.Join(vols, " "); got != "/:ext4 /boot/efi:vfat /tank:zfs /mnt/backup:xfs /mnt/nas:cifs /games:ext4" {
		t.Errorf("volumes %q", got)
	}
	if d.Volumes[0].Total != 100<<30 || d.Volumes[0].Available != 40<<30 || d.Volumes[0].Mount != "/" {
		t.Errorf("root volume %+v", d.Volumes[0])
	}
	linuxTPut(t, root, "proc/diskstats", linuxTDiskstatsFile("259 0 nvme0n1 18 20", "8 0 sda 50 76", "8 1 sda1 900 900", "9 0 md0 900 900"))
	linuxTPause(c, time.Second)
	s := c.Sample(wire.DetailVitals)
	linuxTNear(t, "read", s.Disk.Read, 8*512/s.Interval, 1e-6)
	linuxTNear(t, "write", s.Disk.Write, 16*512/s.Interval, 1e-6)
	if s.Disk.ReadTotal != 8*512 || s.Disk.WriteTotal != 16*512 || s.Disk.Volumes != nil {
		t.Errorf("totals %d %d volumes %v", s.Disk.ReadTotal, s.Disk.WriteTotal, s.Disk.Volumes)
	}
	if _, ok := c.disk.devs["nvme1n1"]; ok {
		t.Errorf("vanished disk kept")
	}

	i, _ := linuxTFixture(t, "linux-intel-hybrid")
	vols = nil
	for _, v := range i.Sample(wire.DetailFull).Disk.Volumes {
		vols = append(vols, v.Name)
	}
	if got := strings.Join(vols, "|"); got != "/|/boot/efi|/run/media/alex/My Stick" {
		t.Errorf("laptop volumes %q", got)
	}
	p, _ := linuxTFixture(t, "linux-rpi")
	p.Sample(wire.DetailVitals)
	if dev := p.disk.devs["mmcblk0boot0"]; dev == nil || dev.whole || !p.disk.devs["mmcblk0"].whole {
		t.Errorf("mmc boot partitions must not count as disks")
	}
}

func linuxTDiskstatsFile(rows ...string) string {
	s := ""
	for _, r := range rows {
		f := strings.Fields(r)
		s += fmt.Sprintf(" %s %s %s 1 0 %s 0 1 0 %s 0 0 0 0 0 0 0 0 0 0\n", f[0], f[1], f[2], f[3], f[4])
	}
	return s
}

func TestLinuxSlowNetworkStatfs(t *testing.T) {
	c, _ := linuxTFixture(t, "linux-amd-desktop")
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	c.statfs = func(path string) (uint64, uint64, error) {
		if strings.HasSuffix(filepath.ToSlash(path), "/mnt/nas") {
			mu.Lock()
			calls++
			mu.Unlock()
			<-release // a dead CIFS server
		}
		return 10 << 30, 5 << 30, nil
	}
	start := time.Now()
	vols := c.readVolumes()
	if time.Since(start) > time.Second {
		t.Fatalf("a hung network mount blocked the sample for %v", time.Since(start))
	}
	for _, v := range vols {
		if v.Name == "/mnt/nas" {
			t.Errorf("hung mount reported %+v", v)
		}
	}
	c.readVolumes() // still pending: must not start a second statfs
	mu.Lock()
	if calls != 1 {
		t.Errorf("%d statfs calls for one hung mount", calls)
	}
	mu.Unlock()
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		found := false
		for _, v := range c.readVolumes() {
			found = found || v.Name == "/mnt/nas"
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the mount never came back")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLinuxSystem(t *testing.T) {
	c, _ := linuxTFixture(t, "linux-intel-hybrid")
	units := make(chan []string, 1)
	units <- []string{"nginx.service", "backup.timer"}
	c.failedUnits = func(ctx context.Context) ([]string, error) { return <-units, nil }
	s := c.sampleSystem(time.Now())
	if s.Uptime != 837844.58 || !*s.RebootRequired || s.RebootReason != "kernel 6.10.3-200.fc40.x86_64 installed" ||
		*s.Containers != 2 || s.Updates != nil {
		t.Errorf("laptop system %+v", s)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(s.FailedServices) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		s = c.sampleSystem(time.Now())
	}
	if strings.Join(s.FailedServices, ",") != "nginx.service,backup.timer" {
		t.Errorf("failed units %v", s.FailedServices)
	}

	a, _ := linuxTFixture(t, "linux-amd-desktop")
	s = a.Sample(wire.DetailFull).System
	if !*s.RebootRequired || s.RebootReason != "linux-image-6.8.0-47-generic, linux-base" || *s.Updates != 5 ||
		*s.SecurityUpdates != 2 || *s.Containers != 3 {
		t.Errorf("desktop system %+v", s)
	}
	p, _ := linuxTFixture(t, "linux-rpi")
	s = p.Sample(wire.DetailFull).System
	if *s.RebootRequired || s.Containers != nil {
		t.Errorf("a Pi with its other flavour's kernel installed: %+v", s)
	}
	// Vitals never carry processes, and carry the system section only every
	// half minute, so the fleet list learns about restarts without a dashboard.
	d, _ := linuxTFixture(t, "linux-amd-desktop")
	if v := d.Sample(wire.DetailVitals); v.Processes != nil || v.System == nil {
		t.Errorf("the first vitals sample should carry system and no processes")
	}
	if v := d.Sample(wire.DetailVitals); v.System != nil {
		t.Errorf("the system section should not repeat within half a minute")
	}
}

func TestLinuxProcesses(t *testing.T) {
	c, root := linuxTFixture(t, "linux-intel-hybrid")
	p := c.Sample(wire.DetailFull).Processes
	if p == nil || p.Count != 6 || p.GPUAttribution || len(p.Rank["cpu"]) != 0 || len(p.Rank["memory"]) != 4 {
		t.Fatalf("first scan %+v", p)
	}
	rows := map[int32]wire.ProcessRow{}
	for _, r := range p.Rows {
		rows[r.PID] = r
	}
	if r := rows[1234]; r.Name != "Web Content" || r.User != "alex" || r.Threads != 25 || r.Memory != 100000*4096 ||
		r.Cmd != "/usr/lib64/firefox/firefox -contentproc -childID 1" || r.Start != (1791327353+500)*1e6 {
		t.Errorf("firefox %+v", r)
	}
	if r := rows[1300]; r.Name != "gnome-shell-calendar-server" {
		t.Errorf("truncated comm not expanded: %+v", r)
	}
	if r := rows[1400]; r.User != "27" || r.Cmd != "/usr/sbin/mysqld --user=mysql --password=•••" {
		t.Errorf("mysqld %+v", r)
	}
	if z := c.Sample(wire.DetailVitals).CPU.Zombies; z == nil || *z != 1 {
		t.Errorf("zombies %v", z)
	}

	// 100 more ticks (1 s of CPU) and 1 MB read over two seconds.
	linuxTPut(t, root, "proc/1234/stat", strings.Replace(linuxTReadFile(t, root, "proc/1234/stat"), " 5000 1000 ", " 5100 1000 ", 1))
	linuxTPut(t, root, "proc/1234/io", "read_bytes: 2000000\nwrite_bytes: 2000000\n")
	linuxTPause(c, 2*time.Second)
	p = c.Sample(wire.DetailFull).Processes
	linuxTNear(t, "interval", p.Interval, 2, 0.01)
	rows = map[int32]wire.ProcessRow{}
	for _, r := range p.Rows {
		rows[r.PID] = r
	}
	linuxTNear(t, "firefox cpu", rows[1234].CPU, 50, 0.3)
	linuxTNear(t, "firefox disk read", rows[1234].DiskRead, 500000, 3000)
	if p.Rank["cpu"][0] != 1234 || p.Rank["disk"][0] != 1234 {
		t.Errorf("rank %v", p.Rank)
	}

	// Between scans the last table is repeated.
	if again := c.Sample(wire.DetailFull).Processes; again != p {
		t.Errorf("process table rescanned within %v", linuxProcMinGap)
	}

	// A reused pid is a new process; an exited one is forgotten.
	linuxTPut(t, root, "proc/1234/stat", strings.Replace(linuxTReadFile(t, root, "proc/1234/stat"), " 50000 ", " 90000 ", 1))
	os.RemoveAll(filepath.Join(root, "proc/1300"))
	linuxTPause(c, 2*time.Second)
	p = c.Sample(wire.DetailFull).Processes
	for _, r := range p.Rows {
		if r.PID == 1234 && r.CPU != 0 {
			t.Errorf("reused pid inherited CPU time: %+v", r)
		}
	}
	for k := range c.procs.prev {
		if k.pid == 1300 {
			t.Errorf("exited process kept in state")
		}
	}
	if p.Count != 5 {
		t.Errorf("count %d", p.Count)
	}
}

func linuxTReadFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLinuxDoctor(t *testing.T) {
	vm, _ := linuxTFixture(t, "linux-vm")
	checks := map[string]Check{}
	for _, ch := range vm.Doctor() {
		checks[ch.Name] = ch
	}
	if ch := checks["Pressure"]; ch.OK || !strings.Contains(ch.Fix, "psi=1") {
		t.Errorf("pressure check %+v", ch)
	}
	if ch := checks["Sensors"]; ch.OK || ch.Fix != "" || !strings.Contains(ch.Detail, "Virtual machines") {
		t.Errorf("sensors check %+v", ch)
	}
	if ch := checks["CPU"]; !ch.OK || !strings.Contains(ch.Detail, "no clock readings") {
		t.Errorf("cpu check %+v", ch)
	}
	if ch := checks["Agent"]; !strings.Contains(ch.Detail, "kvm") {
		t.Errorf("agent check %+v", ch)
	}

	// Bare metal without a CPU sensor driver gets the modprobe hint.
	a, aroot := linuxTFixture(t, "linux-amd-desktop")
	os.RemoveAll(filepath.Join(aroot, "sys/class/hwmon/hwmon2"))
	for _, ch := range a.Doctor() {
		if ch.Name == "Sensors" && (ch.OK || !strings.Contains(ch.Fix, "modprobe k10temp")) {
			t.Errorf("sensors check without k10temp %+v", ch)
		}
	}
}

// TestLinuxSamplerPanics checks that a broken section drops only itself.
func TestLinuxSamplerPanics(t *testing.T) {
	c, root := linuxTFixture(t, "linux-vm")
	one := [8]uint64{100, 0, 100, 100, 0, 0, 0, 0}
	two := [8]uint64{200, 0, 200, 200, 0, 0, 0, 0}
	linuxTPut(t, root, "proc/stat", linuxTStatLines(one, [][8]uint64{one, one}))
	c.Sample(wire.DetailVitals)
	c.cpu.prevCores = nil // corrupt state: the next per-core delta indexes past it
	linuxTPut(t, root, "proc/stat", linuxTStatLines(two, [][8]uint64{two, two}))
	s := c.Sample(wire.DetailVitals)
	if s.CPU != nil {
		t.Errorf("a panicking CPU sampler still returned %+v", s.CPU)
	}
	if s.Memory == nil || s.Network == nil {
		t.Errorf("other sections were lost: %+v", s)
	}
	if s = c.Sample(wire.DetailVitals); s.CPU == nil {
		t.Errorf("the CPU section did not recover")
	}
}

func TestLinuxMissingRoot(t *testing.T) {
	c := newLinuxCollector(filepath.Join(t.TempDir(), "nothing"))
	c.statfs = func(string) (uint64, uint64, error) { return 0, 0, errors.New("no") }
	s := c.Sample(wire.DetailFull)
	if s == nil || s.CPU != nil || s.Memory != nil || s.Thermal != nil || len(s.GPUs) != 0 {
		t.Errorf("empty root sample %+v", s)
	}
	if len(c.Doctor()) == 0 {
		t.Errorf("no doctor checks")
	}
	_ = c.Host()
}
