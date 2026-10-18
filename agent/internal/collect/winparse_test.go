package collect

import (
	"encoding/binary"
	"math"
	"testing"
	"unsafe"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestWinCPUUsage(t *testing.T) {
	prev := []winCPUTimes{{Idle: 100, Kernel: 200, User: 100}, {Idle: 0, Kernel: 0, User: 0}}
	// core 0: idle +75, kernel +100 (25 busy kernel), user +100 → 125/200 busy
	// core 1: no time passed
	cur := []winCPUTimes{{Idle: 175, Kernel: 300, User: 200}, {Idle: 0, Kernel: 0, User: 0}}
	total, user, system, idle, per, ok := winCPUUsage(prev, cur)
	if !ok {
		t.Fatal("not ok")
	}
	if !near(user, 0.5) || !near(system, 0.125) || !near(idle, 0.375) || !near(total, 0.625) {
		t.Errorf("got total=%v user=%v system=%v idle=%v", total, user, system, idle)
	}
	if !near(per[0], 0.625) || per[1] != 0 {
		t.Errorf("perCore = %v", per)
	}
	if _, _, _, _, _, ok := winCPUUsage(prev, cur[:1]); ok {
		t.Error("mismatched lengths must not be ok")
	}
	// Counters that go backwards must not produce negative fractions.
	_, u, s, _, _, _ := winCPUUsage(cur, prev)
	if u < 0 || s < 0 {
		t.Error("negative fractions")
	}
}

// coreEntry builds one RelationProcessorCore entry of a 64-bit
// GetLogicalProcessorInformationEx buffer.
func coreEntry(class byte, smt bool, group uint16, mask uint64) []byte {
	b := make([]byte, 48) // 8 header + 24 PROCESSOR_RELATIONSHIP head + 16 GROUP_AFFINITY
	binary.LittleEndian.PutUint32(b[0:], 0)
	binary.LittleEndian.PutUint32(b[4:], 48)
	if smt {
		b[8] = 1
	}
	b[9] = class
	binary.LittleEndian.PutUint16(b[30:], 1)
	binary.LittleEndian.PutUint64(b[32:], mask)
	binary.LittleEndian.PutUint16(b[40:], group)
	return b
}

func TestWinProcessorCoresAndKinds(t *testing.T) {
	var buf []byte
	buf = append(buf, coreEntry(1, true, 0, 0b0011)...) // P core, LP 0+1
	cache := make([]byte, 40)                           // a RelationCache entry to skip
	binary.LittleEndian.PutUint32(cache[0:], 2)
	binary.LittleEndian.PutUint32(cache[4:], 40)
	buf = append(buf, cache...)
	buf = append(buf, coreEntry(0, false, 0, 0b0100)...) // E core, LP 2
	buf = append(buf, coreEntry(0, false, 0, 0b1000)...) // E core, LP 3
	cores := winParseProcessorCores(buf, 8)
	if len(cores) != 3 || !cores[0].SMT || cores[0].Efficiency != 1 || cores[2].Mask != 8 {
		t.Fatalf("cores = %+v", cores)
	}
	kinds, p, e, hetero := winCoreKinds(cores, []int{5})
	if !hetero || p != 1 || e != 2 || kinds != "PPEE?" {
		t.Errorf("kinds=%q p=%d e=%d hetero=%v", kinds, p, e, hetero)
	}
	same := []winCore{{Efficiency: 0, Mask: 1}, {Efficiency: 0, Mask: 2}}
	if k, _, _, h := winCoreKinds(same, []int{2}); h || k != "" {
		t.Errorf("homogeneous: kinds=%q hetero=%v", k, h)
	}
	// A truncated buffer must not panic.
	winParseProcessorCores(buf[:50], 8)
}

func TestWinClocks(t *testing.T) {
	perf := []winPDHValue{{"0,0", 120}, {"0,1", 50}, {"0,_Total", 85}, {"_Total", 85}}
	freq := []winPDHValue{{"0,0", 3000}, {"0,1", 2000}, {"0,_Total", 2500}, {"_Total", 2500}}
	all, p, e := winClocks(perf, freq, "PE", []int{2}, 0)
	if all == nil || *all != 2125 || p == nil || *p != 3600 || e == nil || *e != 1000 {
		t.Errorf("all=%v p=%v e=%v", all, p, e)
	}
	// No frequency counter: fall back to the nominal MHz.
	all, _, _ = winClocks([]winPDHValue{{"0,0", 100}}, nil, "", []int{1}, 2400)
	if all == nil || *all != 2400 {
		t.Errorf("fallback all=%v", all)
	}
	if a, _, _ := winClocks(nil, nil, "", nil, 1000); a != nil {
		t.Error("no counters should give no clock")
	}
}

func TestWinCleanCPUName(t *testing.T) {
	cases := map[string]string{
		"Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz":                      "Intel Core i7-8700",
		"AMD Ryzen 9 7950X 16-Core Processor            ":              "AMD Ryzen 9 7950X",
		"Intel(R) Core(TM) Ultra 7 255H":                               "Intel Core Ultra 7 255H",
		"Snapdragon(R) X Elite - X1E78100 - Qualcomm(R) Oryon(TM) CPU": "Snapdragon X Elite - X1E78100 - Qualcomm Oryon",
		"13th Gen Intel(R) Core(TM) i9-13900K":                         "13th Gen Intel Core i9-13900K",
		"AMD Ryzen 7 5800H with Radeon Graphics         ":              "AMD Ryzen 7 5800H with Radeon Graphics",
	}
	for in, want := range cases {
		if got := winCleanCPUName(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestWinBuildMemory(t *testing.T) {
	pi := &winPerfInfo{CommitLimit: 6000, PhysicalTotal: 4000, SystemCache: 100, KernelNonpaged: 10, PageSize: 4096}
	m := winBuildMemory(16000, 4000, 91, pi, wire.F(25))
	if m.Used != 12000 || *m.Available != 4000 || m.PressureLevel != "warning" || !near(*m.Pressure, 0.75) {
		t.Errorf("memory = %+v", m)
	}
	if m.Swap == nil || m.Swap.Total != 2000*4096 || m.Swap.Used != 500*4096 || m.Swap.Free != 1500*4096 {
		t.Errorf("swap = %+v", m.Swap)
	}
	if *m.Cached != 100*4096 || *m.Wired != 10*4096 {
		t.Errorf("cached/wired wrong")
	}
	if m := winBuildMemory(16000, 4000, 98, pi, nil); m.Swap != nil || m.PressureLevel != "critical" {
		t.Errorf("without %% Usage swap must be absent, got %+v", m.Swap)
	}
	noPage := &winPerfInfo{CommitLimit: 4000, PhysicalTotal: 4000, PageSize: 4096}
	if m := winBuildMemory(16000, 4000, 10, noPage, nil); m.Swap == nil || m.Swap.Total != 0 || m.PressureLevel != "normal" {
		t.Errorf("no page file should report empty swap, got %+v", m.Swap)
	}
	if winBuildMemory(0, 0, 0, nil, nil) != nil {
		t.Error("zero total must give nil")
	}
}

func TestWinFiletime(t *testing.T) {
	// 2024-01-01T00:00:00Z = 1704067200 s
	ft := uint64(1704067200)*10_000_000 + 116444736000000000
	if got := winFiletimeToUnixMicros(ft); got != 1704067200*1_000_000 {
		t.Errorf("got %d", got)
	}
	if winFiletimeToUnixMicros(5) != 0 {
		t.Error("pre-epoch should be 0")
	}
}

func TestWinGPUEngines(t *testing.T) {
	inst, ok := winParseGPUEngineInstance("pid_1234_luid_0x00000000_0x0000D1B6_phys_0_eng_3_engtype_VideoDecode")
	if !ok || inst.PID != 1234 || inst.LUID != 0xD1B6 || inst.Eng != 3 || inst.Type != "videodecode" {
		t.Fatalf("inst = %+v ok=%v", inst, ok)
	}
	if _, ok := winParseGPUEngineInstance("_Total"); ok {
		t.Error("_Total must not parse")
	}
	if winNormalizeEngineType("Compute_1") != "compute" || winNormalizeEngineType("3D") != "3d" || winNormalizeEngineType("Video Encode") != "videoencode" {
		t.Error("normalize")
	}
	vals := []winPDHValue{
		{"pid_10_luid_0x00000000_0x0000D1B6_phys_0_eng_0_engtype_3D", 30},
		{"pid_11_luid_0x00000000_0x0000D1B6_phys_0_eng_0_engtype_3D", 25},  // same engine: sums to 55
		{"pid_11_luid_0x00000000_0x0000D1B6_phys_0_eng_1_engtype_Copy", 5}, // copy engine 0
		{"pid_12_luid_0x00000000_0x0000D1B6_phys_0_eng_2_engtype_Copy", 9}, // copy engine 1: max 9
		{"pid_12_luid_0x00000000_0x0000AAAA_phys_0_eng_0_engtype_3D", 80},  // other adapter
		{"pid_13_luid_0x00000000_0x0000AAAA_phys_0_eng_0_engtype_3D", 70},  // sums past 100: clamp
	}
	per, pids := winAggregateGPUEngines(vals)
	a := per[0xD1B6]
	if a == nil || !near(a.Utilization, 0.55) || !near(a.Engines["3d"], 0.55) || !near(a.Engines["copy"], 0.09) {
		t.Errorf("adapter D1B6 = %+v", a)
	}
	if b := per[0xAAAA]; b == nil || b.Utilization != 1 {
		t.Errorf("adapter AAAA = %+v", b)
	}
	if pids[11] != 25 || pids[12] != 80 || pids[10] != 30 {
		t.Errorf("pids = %v", pids)
	}
	mem := winSumByLUID([]winPDHValue{{"luid_0x00000000_0x0000D1B6_phys_0", 100}, {"luid_0x00000000_0x0000D1B6_phys_1", 50}, {"bogus", 7}})
	if mem[0xD1B6] != 150 || len(mem) != 1 {
		t.Errorf("mem = %v", mem)
	}
}

func TestWinBuildGPUs(t *testing.T) {
	adapters := []winAdapter{
		{Name: "Intel(R) UHD Graphics 770", VendorID: 0x8086, LUIDLow: 0xAAAA, Dedicated: 128 << 20, Shared: 8 << 30},
		{Name: "NVIDIA GeForce RTX 4070", VendorID: 0x10DE, LUIDLow: 0xD1B6, Dedicated: 12 << 30, Shared: 8 << 30},
		{Name: "Microsoft Basic Render Driver", VendorID: 0x1414, LUIDLow: 0xBBBB, Software: true},
		{Name: "Microsoft Remote Display Adapter", VendorID: 0x1414, LUIDLow: 0xCCCC},
	}
	usage := map[uint64]*winGPUUsage{
		0xD1B6: {Engines: map[string]float64{"3d": 0.5}, Utilization: 0.5},
		0xBBBB: {Engines: map[string]float64{"3d": 0.1}, Utilization: 0.1},
	}
	dedicated := map[uint64]uint64{0xD1B6: 3 << 30, 0xAAAA: 10 << 20}
	shared := map[uint64]uint64{0xD1B6: 1 << 20, 0xAAAA: 500 << 20}
	gpus := winBuildGPUs(adapters, usage, dedicated, shared, true)
	if len(gpus) != 2 {
		t.Fatalf("gpus = %+v", gpus)
	}
	nv, ig := gpus[0], gpus[1]
	if nv.Vendor != "nvidia" || nv.Utilization != 0.5 || *nv.MemoryUsed != 3<<30 || *nv.MemoryTotal != 12<<30 {
		t.Errorf("discrete = %+v", nv)
	}
	if ig.Vendor != "intel" || ig.Utilization != 0 || *ig.MemoryUsed != 510<<20 || *ig.MemoryTotal != (128<<20)+(8<<30) {
		t.Errorf("integrated = %+v", ig)
	}
	// Without the engine counter an adapter with no data is left out.
	if g := winBuildGPUs(adapters[:1], nil, nil, nil, false); len(g) != 0 {
		t.Errorf("unmeasured adapter listed: %+v", g)
	}
	// DXGI failed: counters still produce unnamed GPUs.
	if g := winBuildGPUs(nil, usage, nil, nil, true); len(g) != 2 || g[0].Name == "" {
		t.Errorf("orphans = %+v", g)
	}
	// LUID halves in the other order still match.
	swapped := []winAdapter{{Name: "X", VendorID: 0x1002, LUIDHigh: 0xD1B6, Dedicated: 1 << 30}}
	if g := winBuildGPUs(swapped, usage, nil, nil, true); len(g) != 2 || g[0].Name != "X" {
		t.Errorf("swapped = %+v", g)
	}
}

func TestWinMergeNvidia(t *testing.T) {
	gpus := []wire.GPU{
		{Name: "NVIDIA GeForce RTX 4070", Vendor: "nvidia", Utilization: 0.4, Engines: map[string]float64{"3d": 0.4}},
		{Name: "Intel(R) UHD Graphics 770", Vendor: "intel"},
	}
	nv := []wire.GPU{{Name: "NVIDIA GeForce RTX 4070", Vendor: "nvidia", Utilization: 0.9, Celsius: wire.F(61), Watts: wire.F(120), MemoryUsed: wire.U(1), MemoryTotal: wire.U(2)}}
	out := winMergeNvidia(gpus, nv)
	if len(out) != 2 || out[0].Celsius == nil || *out[0].Celsius != 61 || out[0].Utilization != 0.4 || *out[0].MemoryTotal != 2 {
		t.Errorf("merged = %+v", out[0])
	}
	// Different spellings, one on each side: paired by elimination.
	out = winMergeNvidia([]wire.GPU{{Name: "NVIDIA RTX A2000 Laptop GPU", Vendor: "nvidia"}}, []wire.GPU{{Name: "RTX A2000", Celsius: wire.F(50)}})
	if len(out) != 1 || out[0].Celsius == nil {
		t.Errorf("elimination = %+v", out)
	}
	// No DXGI GPU at all: nvidia-smi rows are appended.
	if out := winMergeNvidia(nil, nv); len(out) != 1 {
		t.Errorf("append = %+v", out)
	}
}

func TestWinThermalZones(t *testing.T) {
	s := winThermalZoneSensors([]winPDHValue{{`\_TZ.TZ01`, 320}, {`\_TZ.TZ00`, 300.15}, {`\_TZ.BAD`, 0}, {`\_TZ.HOT`, 600}})
	if len(s) != 2 || s[0].Key != "tz0" || s[0].Celsius != 27 || s[1].Celsius != 46.9 || s[0].Category != "Other" {
		t.Errorf("sensors = %+v", s)
	}
}

const lhmNew = `{"id":0,"Text":"Sensor","Min":"Min","Value":"Value","Max":"Max","ImageURL":"","Children":[
 {"id":1,"Text":"DESKTOP","Min":"","Value":"","Max":"","ImageURL":"images_icon/computer.png","Children":[
  {"id":2,"Text":"Intel Core i7-12700K","HardwareId":"/intelcpu/0","ImageURL":"images_icon/cpu.png","Min":"","Value":"","Max":"","Children":[
   {"id":3,"Text":"Temperatures","ImageURL":"images_icon/temperature.png","Min":"","Value":"","Max":"","Children":[
    {"id":4,"Text":"CPU Core #1","SensorId":"/intelcpu/0/temperature/0","Type":"Temperature","Value":"51.0 °C","RawValue":51,"Children":[]},
    {"id":5,"Text":"CPU Core #1 Distance to TjMax","SensorId":"/intelcpu/0/temperature/1","Type":"Temperature","Value":"49.0 °C","RawValue":49,"Children":[]},
    {"id":6,"Text":"CPU Package","SensorId":"/intelcpu/0/temperature/2","Type":"Temperature","Value":"55.0 °C","RawValue":55,"Children":[]},
    {"id":7,"Text":"Core Max","SensorId":"/intelcpu/0/temperature/3","Type":"Temperature","Value":"-","RawValue":"NaN","Children":[]}]},
   {"id":8,"Text":"Powers","ImageURL":"images_icon/power.png","Min":"","Value":"","Max":"","Children":[
    {"id":9,"Text":"CPU Package","SensorId":"/intelcpu/0/power/0","Type":"Power","Value":"35.2 W","RawValue":35.25,"Children":[]},
    {"id":10,"Text":"CPU Cores","SensorId":"/intelcpu/0/power/1","Type":"Power","Value":"30.0 W","RawValue":30,"Children":[]}]}]},
  {"id":11,"Text":"ASUS PRIME Z690-P","HardwareId":"/motherboard","ImageURL":"images_icon/mainboard.png","Min":"","Value":"","Max":"","Children":[
   {"id":12,"Text":"Nuvoton NCT6798D","HardwareId":"/lpc/nct6798d/0","ImageURL":"images_icon/chip.png","Min":"","Value":"","Max":"","Children":[
    {"id":13,"Text":"Fans","ImageURL":"images_icon/fan.png","Min":"","Value":"","Max":"","Children":[
     {"id":14,"Text":"Fan #2","SensorId":"/lpc/nct6798d/0/fan/1","Type":"Fan","Value":"1180 RPM","RawValue":1180.4,"Children":[]},
     {"id":15,"Text":"Fan #3","SensorId":"/lpc/nct6798d/0/fan/2","Type":"Fan","Value":"","RawValue":null,"Children":[]}]},
    {"id":16,"Text":"Temperatures","ImageURL":"images_icon/temperature.png","Min":"","Value":"","Max":"","Children":[
     {"id":17,"Text":"System","SensorId":"/lpc/nct6798d/0/temperature/0","Type":"Temperature","Value":"36.0 °C","RawValue":36,"Children":[]}]}]}]},
  {"id":18,"Text":"AMD Radeon RX 7800 XT","HardwareId":"/gpu-amd/0","ImageURL":"images_icon/ati.png","Min":"","Value":"","Max":"","Children":[
   {"id":19,"Text":"Temperatures","ImageURL":"images_icon/temperature.png","Min":"","Value":"","Max":"","Children":[
    {"id":20,"Text":"GPU Core","SensorId":"/gpu-amd/0/temperature/0","Type":"Temperature","Value":"44.0 °C","RawValue":44,"Children":[]}]}]}]}]}`

// Older versions: no SensorId/Type/RawValue/HardwareId, localized decimals.
const lhmOld = `{"id":0,"Text":"Sensor","Min":"Min","Value":"Value","Max":"Max","ImageURL":"","Children":[
 {"id":1,"Text":"PC","Min":"","Value":"","Max":"","ImageURL":"images_icon/computer.png","Children":[
  {"id":2,"Text":"AMD Ryzen 7 5800X","Min":"","Value":"","Max":"","ImageURL":"images_icon/cpu.png","Children":[
   {"id":3,"Text":"Temperatures","Min":"","Value":"","Max":"","ImageURL":"images_icon/temperature.png","Children":[
    {"id":4,"Text":"Core (Tctl/Tdie)","Min":"40,0 °C","Value":"47,5 °C","Max":"70,0 °C","ImageURL":"images/transparent.png","Children":[]}]},
   {"id":5,"Text":"Powers","Min":"","Value":"","Max":"","ImageURL":"images_icon/power.png","Children":[
    {"id":6,"Text":"Package","Min":"","Value":"61,3 W","Max":"","ImageURL":"images/transparent.png","Children":[]}]}]}]}]}`

func TestWinParseLHM(t *testing.T) {
	r, err := winParseLHM([]byte(lhmNew))
	if err != nil {
		t.Fatal(err)
	}
	if r.CPUCelsius == nil || *r.CPUCelsius != 55 {
		t.Errorf("cpu = %v", r.CPUCelsius)
	}
	if r.PackageWatts == nil || *r.PackageWatts != 35.25 || r.CoresWatts == nil || *r.CoresWatts != 30 {
		t.Errorf("power = %v %v", r.PackageWatts, r.CoresWatts)
	}
	if len(r.Fans) != 1 || r.Fans[0].RPM != 1180 || r.Fans[0].Label != "Fan #2" {
		t.Errorf("fans = %+v", r.Fans)
	}
	cats := map[string]int{}
	for _, s := range r.Sensors {
		cats[s.Category]++
		if s.Label == "" || s.Key == "" {
			t.Errorf("sensor without key/label: %+v", s)
		}
	}
	if cats["CPU"] != 2 || cats["Other"] != 1 || cats["GPU"] != 1 || len(r.Sensors) != 4 {
		t.Errorf("sensors = %+v", r.Sensors)
	}
	if r.GPUCelsius["AMD Radeon RX 7800 XT"] != 44 {
		t.Errorf("gpu temps = %v", r.GPUCelsius)
	}

	old, err := winParseLHM([]byte(lhmOld))
	if err != nil {
		t.Fatal(err)
	}
	if old.CPUCelsius == nil || *old.CPUCelsius != 47.5 || old.PackageWatts == nil || *old.PackageWatts != 61.3 {
		t.Errorf("old: cpu=%v pkg=%v", old.CPUCelsius, old.PackageWatts)
	}
	if _, err := winParseLHM([]byte("not json")); err == nil {
		t.Error("garbage must fail")
	}
	f := winLHMNode{Value: "113.0 °F"}
	if v, ok := winLHMValue(f); !ok || !near(v, 45) {
		t.Errorf("fahrenheit = %v", v)
	}
}

func TestWinNetwork(t *testing.T) {
	adapters := []winAdapterInfo{
		{Description: "Intel(R) Ethernet Connection (7) I219-V", FriendlyName: "Ethernet", IfType: 6, Up: true, SpeedBps: 1e9, HasGateway: true, Metric: 25, IPv4: []string{"169.254.1.1", "192.168.1.20"}},
		{Description: "Intel(R) Wi-Fi 6 AX201 160MHz", FriendlyName: "Wi-Fi", IfType: 71, Up: true, HasGateway: true, Metric: 50, IPv4: []string{"10.0.0.5"}},
		{Description: "Software Loopback Interface 1", IfType: 24, Up: true, IPv4: []string{"127.0.0.1"}},
	}
	rx := []winPDHValue{
		{"Intel[R] Ethernet Connection [7] I219-V", 1000},
		{"Intel[R] Wi-Fi 6 AX201 160MHz", 10},
		{"isatap.{GUID}", 5},
		{"Hyper-V Virtual Ethernet Adapter _2", 99},
	}
	tx := []winPDHValue{{"Intel[R] Ethernet Connection [7] I219-V", 200}}
	ifaces, sumRX, sumTX := winNetwork(rx, tx, adapters)
	if sumRX != 1010 || sumTX != 200 || len(ifaces) != 2 {
		t.Fatalf("rx=%v tx=%v ifaces=%+v", sumRX, sumTX, ifaces)
	}
	if ifaces[0].Name != "Ethernet" || ifaces[0].SpeedMbps == nil || *ifaces[0].SpeedMbps != 1000 || !ifaces[0].Up {
		t.Errorf("ethernet = %+v", ifaces[0])
	}
	name, addr := winPrimaryAdapter(adapters)
	if name != "Ethernet" || addr != "192.168.1.20" {
		t.Errorf("primary = %q %q", name, addr)
	}
	if winPDHInstanceName("Hyper-V Virtual Ethernet Adapter #2") != "Hyper-V Virtual Ethernet Adapter _2" {
		t.Error("instance name")
	}
	if n, a := winPrimaryAdapter(nil); n != "" || a != "" {
		t.Error("empty")
	}
}

func TestWinHostHelpers(t *testing.T) {
	if winOSName("Windows 10 Pro", 26100) != "Windows 11 Pro" || winOSName("Windows 10 Pro", 19045) != "Windows 10 Pro" {
		t.Error("windows 11 naming")
	}
	if winOSName("Windows Server 2025 Datacenter", 26100) != "Windows Server 2025 Datacenter" {
		t.Error("server naming")
	}
	for _, p := range []string{"To be filled by O.E.M.", "System Product Name", " Default string ", ""} {
		if !winIsPlaceholder(p) {
			t.Errorf("%q should be a placeholder", p)
		}
	}
	if winIsPlaceholder("ROG STRIX Z690-A GAMING WIFI") {
		t.Error("real product flagged")
	}
	virt := map[[3]string]string{
		{"Microsoft Corporation", "Virtual Machine", ""}:      "hyperv",
		{"Microsoft Corporation", "Surface Laptop 5", ""}:     "none",
		{"VMware, Inc.", "VMware7,1", ""}:                     "vmware",
		{"QEMU", "Standard PC (Q35 + ICH9, 2009)", "SeaBIOS"}: "kvm",
		{"innotek GmbH", "VirtualBox", ""}:                    "virtualbox",
		{"Amazon EC2", "t3.micro", "Amazon EC2"}:              "amazon",
		{"Google", "Google Compute Engine", "Google"}:         "google",
		{"Xen", "HVM domU", "Xen"}:                            "xen",
		{"Dell Inc.", "OptiPlex 7090", "Dell Inc."}:           "none",
	}
	for in, want := range virt {
		if got := winVirtualization(in[0], in[1], in[2]); got != want {
			t.Errorf("%v → %q, want %q", in, got, want)
		}
	}
	vols := []wire.Volume{{Name: "D:"}, {Name: "C:"}, {Name: "A:"}}
	winSortVolumes(vols, `C:`)
	if vols[0].Name != "C:" || vols[1].Name != "A:" {
		t.Errorf("volumes = %+v", vols)
	}
}

func TestWinPdhParseItems(t *testing.T) {
	// Three items (72 bytes) followed by two UTF-16 names, as PDH lays the
	// buffer out on 64-bit Windows.
	buf := make([]uint64, 32)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)
	words := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), len(buf)*4)
	putName := func(wordOff int, s string) uintptr {
		for i, r := range s {
			words[wordOff+i] = uint16(r)
		}
		words[wordOff+len(s)] = 0
		return uintptr(unsafe.Pointer(&words[wordOff]))
	}
	item := func(i int, name uintptr, status uint32, v float64) {
		b := raw[i*winPdhItemSize:]
		*(*uintptr)(unsafe.Pointer(&b[0])) = name
		*(*uint32)(unsafe.Pointer(&b[winPdhItemStatusOff])) = status
		*(*float64)(unsafe.Pointer(&b[winPdhItemValueOff])) = v
	}
	item(0, putName(36, "eth0"), 0, 12.5)
	item(1, putName(44, "skip"), 0xC0000BBA, 99) // PDH_CSTATUS_INVALID_DATA
	item(2, 0x10, winPdhCStatusNew, 3)           // name outside the buffer
	got := winPdhParseItems(buf, 3)
	if len(got) != 2 || got[0] != (winPDHValue{"eth0", 12.5}) || got[1] != (winPDHValue{"", 3}) {
		t.Errorf("items = %+v", got)
	}
	if winPdhParseItems(buf, 100) != nil {
		t.Error("a count beyond the buffer must be rejected")
	}
}

func TestWinPeakCelsius(t *testing.T) {
	sensors := []wire.Sensor{
		{Key: "cpu0", Celsius: 61, Category: "CPU"},
		{Key: "ssd0", Celsius: 71, Category: "Storage"},
		{Key: "mb0", Celsius: 84, Category: "Other"}, // a VRM
		{Key: "tz0", Celsius: 27.8, Category: "Other"},
	}
	if p := winPeakCelsius(sensors, wire.F(64), nil); p == nil || *p != 64 {
		t.Errorf("peak %v, want the CPU's 64, not the drive or the VRM", p)
	}
	if p := winPeakCelsius(sensors, nil, []wire.GPU{{Celsius: wire.F(70)}, {}}); p == nil || *p != 70 {
		t.Errorf("peak with a GPU %v", p)
	}
	if p := winPeakCelsius(sensors[1:], nil, nil); p != nil {
		t.Errorf("peak from drives and zones alone: %v", *p)
	}
}

func TestWinYoungProcessCPU(t *testing.T) {
	const s = 10_000_000 // one second in FILETIME units
	base := uint64(133_000_000_000_000_000)
	cases := []struct {
		name                   string
		cpu, created, prev, at uint64
		window, want           float64
		ok                     bool
	}{
		{"existed before", 5 * s, base, base + s, base + 2*s, 1, 0, false},
		{"half a second old, quarter second of CPU", s / 4, base + 3*s/2, base + s, base + 2*s, 1, 50, true},
		{"two threads busy", s, base + 3*s/2, base + s, base + 2*s, 1, 200, true},
		{"created during the scan", s / 100, base + 2*s + 1, base + s, base + 2*s, 1, 1 / 0.0156, true},
	}
	for _, tc := range cases {
		got, ok := winYoungProcessCPU(tc.cpu, tc.created, tc.prev, tc.at, tc.window)
		if ok != tc.ok || math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: %v %v, want %v %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}
