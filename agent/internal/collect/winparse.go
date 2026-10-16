package collect

// OS-independent helpers for the Windows collector (collect_windows*.go).
// They hold no Windows calls, so their logic is unit-tested on every OS;
// every identifier starts with "win" to keep clear of the other collectors.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// winPDHValue is one instance of a formatted PDH counter.
type winPDHValue struct {
	Name  string
	Value float64
}

// PDH_FMT_COUNTERVALUE_ITEM_W is { LPWSTR szName; PDH_FMT_COUNTERVALUE
// FmtValue } and PDH_FMT_COUNTERVALUE is { DWORD CStatus; union { LONG;
// double; LONGLONG; LPCSTR; LPCWSTR } }. The double makes the union, and so
// FmtValue, 8-byte aligned on every Windows architecture (MSVC aligns double
// to 8 even on x86), so an item is 24 bytes with CStatus at 8 and the value
// at 16 on amd64, arm64 and 386 alike. Items are read by these offsets
// rather than through a Go struct, whose layout would differ on 386.
const (
	winPdhItemSize      = 24
	winPdhItemStatusOff = 8
	winPdhItemValueOff  = 16
	winPdhCStatusNew    = 0x00000001 // PDH_CSTATUS_NEW_DATA (PDH_CSTATUS_VALID_DATA is 0)
)

// winPdhParseItems reads count PDH_FMT_COUNTERVALUE_ITEM_W entries from buf.
// Instance names are only read when they point inside buf, so a malformed
// answer can never make the agent read foreign memory.
func winPdhParseItems(buf []uint64, count uint32) []winPDHValue {
	if len(buf) == 0 {
		return nil
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)
	if uint64(count)*winPdhItemSize > uint64(len(raw)) {
		return nil
	}
	base := uintptr(unsafe.Pointer(&raw[0]))
	words := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), len(buf)*4)
	out := make([]winPDHValue, 0, count)
	for i := uint32(0); i < count; i++ {
		item := raw[i*winPdhItemSize : (i+1)*winPdhItemSize]
		status := *(*uint32)(unsafe.Pointer(&item[winPdhItemStatusOff]))
		if status != 0 && status != winPdhCStatusNew {
			continue
		}
		value := *(*float64)(unsafe.Pointer(&item[winPdhItemValueOff]))
		if math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		// szName is read as an integer, never as a Go pointer: it is only
		// used to locate the string inside buf.
		namePtr := *(*uintptr)(unsafe.Pointer(&item[0]))
		name := ""
		if namePtr >= base && namePtr < base+uintptr(len(raw)) && (namePtr-base)%2 == 0 {
			start := int((namePtr - base) / 2)
			end := start
			for end < len(words) && words[end] != 0 {
				end++
			}
			name = string(utf16.Decode(words[start:end]))
		}
		out = append(out, winPDHValue{Name: name, Value: value})
	}
	return out
}

// ---------------------------------------------------------------- CPU

// winCPUTimes is one logical processor's cumulative times in 100 ns units,
// from SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION. Kernel includes Idle.
type winCPUTimes struct {
	Idle, Kernel, User int64
}

// winCPUUsage turns two readings into fractions of all cores and per core.
// ok is false when the readings cannot be compared (different core counts).
func winCPUUsage(prev, cur []winCPUTimes) (total, user, system, idle float64, perCore []float64, ok bool) {
	if len(prev) == 0 || len(prev) != len(cur) {
		return 0, 0, 0, 0, nil, false
	}
	pos := func(v int64) float64 {
		if v < 0 {
			return 0
		}
		return float64(v)
	}
	var sumIdle, sumKernel, sumUser float64
	perCore = make([]float64, len(cur))
	for i := range cur {
		dIdle := pos(cur[i].Idle - prev[i].Idle)
		dKernel := pos(cur[i].Kernel - prev[i].Kernel)
		dUser := pos(cur[i].User - prev[i].User)
		if dIdle > dKernel { // the two are read at slightly different moments
			dIdle = dKernel
		}
		sumIdle += dIdle
		sumKernel += dKernel
		sumUser += dUser
		if all := dKernel + dUser; all > 0 {
			perCore[i] = winClamp01((all - dIdle) / all)
		}
	}
	all := sumKernel + sumUser
	if all <= 0 {
		return 0, 0, 0, 1, perCore, true
	}
	user = winClamp01(sumUser / all)
	system = winClamp01((sumKernel - sumIdle) / all)
	idle = winClamp01(sumIdle / all)
	total = winClamp01(user + system)
	return total, user, system, idle, perCore, true
}

func winClamp01(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// winCore is one RelationProcessorCore entry of
// GetLogicalProcessorInformationEx.
type winCore struct {
	Efficiency byte   // EfficiencyClass: higher is faster and less efficient
	SMT        bool   // LTP_PC_SMT: more than one logical processor
	Group      uint16 // processor group of Mask
	Mask       uint64 // logical processors of the core within Group
}

// winParseProcessorCores walks a GetLogicalProcessorInformationEx buffer.
// The entries are variable length (each starts with Relationship and Size):
//
//	SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
//	  0  DWORD Relationship
//	  4  DWORD Size
//	  8  PROCESSOR_RELATIONSHIP
//	     8  BYTE  Flags
//	     9  BYTE  EfficiencyClass
//	    10  WORD  RelativePerformance, WORD RelativeEfficiency, BYTE Reserved[16]
//	    30  WORD  GroupCount
//	    32  GROUP_AFFINITY GroupMask[GroupCount]
//	          KAFFINITY Mask (pointer sized), WORD Group, WORD Reserved[3]
//
// ptrSize is 8 on amd64/arm64 and 4 on 386.
func winParseProcessorCores(buf []byte, ptrSize int) []winCore {
	const relationProcessorCore = 0
	affinitySize := ptrSize + 8 // Mask + Group + Reserved[3]
	var cores []winCore
	for off := 0; off+8 <= len(buf); {
		rel := binary.LittleEndian.Uint32(buf[off:])
		size := int(binary.LittleEndian.Uint32(buf[off+4:]))
		if size < 8 || off+size > len(buf) {
			break
		}
		entry := buf[off : off+size]
		off += size
		if rel != relationProcessorCore || len(entry) < 32 {
			continue
		}
		flags, class := entry[8], entry[9]
		groups := int(binary.LittleEndian.Uint16(entry[30:]))
		for g := 0; g < groups; g++ {
			base := 32 + g*affinitySize
			if base+affinitySize > len(entry) {
				break
			}
			var mask uint64
			if ptrSize == 8 {
				mask = binary.LittleEndian.Uint64(entry[base:])
			} else {
				mask = uint64(binary.LittleEndian.Uint32(entry[base:]))
			}
			cores = append(cores, winCore{
				Efficiency: class,
				SMT:        flags&1 != 0,
				Group:      binary.LittleEndian.Uint16(entry[base+ptrSize:]),
				Mask:       mask,
			})
			break // a core always lies in exactly one group
		}
	}
	return cores
}

// winCoreKinds derives the per-logical-processor kinds string and the
// performance/efficiency core counts. groupCounts lists the active logical
// processors of each group, in the order the per-core CPU times use.
// Homogeneous machines (one efficiency class) return hetero false and no
// kinds: every core is alike, which "P" or "E" would misstate.
func winCoreKinds(cores []winCore, groupCounts []int) (kinds string, perf, eff int, hetero bool) {
	if len(cores) == 0 {
		return "", 0, 0, false
	}
	lo, hi := cores[0].Efficiency, cores[0].Efficiency
	for _, c := range cores {
		if c.Efficiency < lo {
			lo = c.Efficiency
		}
		if c.Efficiency > hi {
			hi = c.Efficiency
		}
	}
	if lo == hi {
		return "", 0, 0, false
	}
	for _, c := range cores {
		if c.Efficiency == hi {
			perf++
		} else {
			eff++
		}
	}
	var b strings.Builder
	for g, n := range groupCounts {
		for k := 0; k < n; k++ {
			kind := byte('?')
			for _, c := range cores {
				if int(c.Group) == g && k < 64 && c.Mask&(1<<uint(k)) != 0 {
					kind = 'E'
					if c.Efficiency == hi {
						kind = 'P'
					}
					break
				}
			}
			b.WriteByte(kind)
		}
	}
	return b.String(), perf, eff, true
}

// winClocks computes average clocks from `\Processor Information(*)\%
// Processor Performance` (percent of nominal, can exceed 100 with turbo) and
// `\Processor Information(*)\Processor Frequency` (nominal MHz). Instances
// are named "group,index", plus "_Total" and "group,_Total". nominalMHz is
// the fallback when the frequency counter is missing.
func winClocks(perf, freq []winPDHValue, kinds string, groupCounts []int, nominalMHz float64) (all, p, e *float64) {
	if len(perf) == 0 {
		return nil, nil, nil
	}
	freqOf := map[string]float64{}
	for _, f := range freq {
		if f.Value > 0 {
			freqOf[f.Name] = f.Value
		}
	}
	mhz := func(v winPDHValue) (float64, bool) {
		base := freqOf[v.Name]
		if base <= 0 {
			base = nominalMHz
		}
		if base <= 0 || v.Value <= 0 {
			return 0, false
		}
		return v.Value / 100 * base, true
	}
	offsets := make([]int, len(groupCounts))
	for i := 1; i < len(groupCounts); i++ {
		offsets[i] = offsets[i-1] + groupCounts[i-1]
	}
	var sum, sumP, sumE float64
	var n, nP, nE int
	for _, v := range perf {
		if v.Name == "_Total" {
			if m, ok := mhz(v); ok {
				all = wire.F(math.Round(m))
			}
			continue
		}
		gs, ks, found := strings.Cut(v.Name, ",")
		if !found || strings.Contains(ks, "_Total") {
			continue
		}
		g, err1 := strconv.Atoi(gs)
		k, err2 := strconv.Atoi(ks)
		m, ok := mhz(v)
		if err1 != nil || err2 != nil || !ok {
			continue
		}
		sum += m
		n++
		if g >= 0 && g < len(offsets) && k >= 0 && k < groupCounts[g] {
			if idx := offsets[g] + k; idx < len(kinds) {
				switch kinds[idx] {
				case 'P':
					sumP += m
					nP++
				case 'E':
					sumE += m
					nE++
				}
			}
		}
	}
	if all == nil && n > 0 {
		all = wire.F(math.Round(sum / float64(n)))
	}
	if nP > 0 {
		p = wire.F(math.Round(sumP / float64(nP)))
	}
	if nE > 0 {
		e = wire.F(math.Round(sumE / float64(nE)))
	}
	return all, p, e
}

// winCleanCPUName tidies ProcessorNameString: "Intel(R) Core(TM) i7-8700 CPU
// @ 3.20GHz" becomes "Intel Core i7-8700", "AMD Ryzen 9 7950X 16-Core
// Processor" becomes "AMD Ryzen 9 7950X".
func winCleanCPUName(s string) string {
	for _, junk := range []string{"(R)", "(r)", "(TM)", "(tm)", "®", "™"} {
		s = strings.ReplaceAll(s, junk, "")
	}
	if i := strings.Index(s, "@"); i > 0 {
		s = s[:i]
	}
	f := strings.Fields(s)
	// Drop a trailing "CPU", "Processor" and "N-Core".
	for len(f) > 1 {
		last := strings.ToLower(f[len(f)-1])
		if last == "cpu" || last == "processor" || strings.HasSuffix(last, "-core") {
			f = f[:len(f)-1]
			continue
		}
		break
	}
	return strings.Join(f, " ")
}

// ---------------------------------------------------------------- memory

// winPerfInfo is the part of PERFORMANCE_INFORMATION the collector uses,
// in pages except PageSize.
type winPerfInfo struct {
	CommitTotal, CommitLimit, PhysicalTotal, SystemCache, KernelNonpaged uint64
	PageSize                                                             uint64
	ProcessCount, ThreadCount                                            uint32
}

// winBuildMemory assembles the memory section from GlobalMemoryStatusEx
// (total, available, dwMemoryLoad), GetPerformanceInfo and the paging file
// usage percentage. Swap is the page file: its size is the commit limit
// beyond physical memory; its use comes from `\Paging File(_Total)\% Usage`
// and swap is left out when that counter is missing (no zero guess).
func winBuildMemory(total, avail uint64, load uint32, pi *winPerfInfo, pageUsagePct *float64) *wire.Memory {
	if total == 0 {
		return nil
	}
	if avail > total {
		avail = total
	}
	used := total - avail
	m := &wire.Memory{Total: total, Used: used, Available: wire.U(avail)}
	m.Pressure = wire.F(float64(used) / float64(total))
	switch {
	case load >= 97:
		m.PressureLevel = "critical"
	case load >= 90:
		m.PressureLevel = "warning"
	default:
		m.PressureLevel = "normal"
	}
	if pi != nil && pi.PageSize > 0 {
		m.Cached = wire.U(pi.SystemCache * pi.PageSize)
		m.Wired = wire.U(pi.KernelNonpaged * pi.PageSize) // non-paged pool
		limit := pi.CommitLimit * pi.PageSize
		phys := pi.PhysicalTotal * pi.PageSize
		switch {
		case limit <= phys:
			m.Swap = &wire.Swap{} // no page file
		case pageUsagePct != nil:
			swapTotal := limit - phys
			pct := math.Max(0, math.Min(100, *pageUsagePct))
			swapUsed := uint64(float64(swapTotal) * pct / 100)
			m.Swap = &wire.Swap{Total: swapTotal, Used: swapUsed, Free: swapTotal - swapUsed}
		}
	}
	return m
}

// winFiletimeToUnixMicros converts a FILETIME (100 ns since 1601) to
// microseconds since the Unix epoch.
func winFiletimeToUnixMicros(ft uint64) uint64 {
	const epochDelta = 116444736000000000 // 1601-01-01 to 1970-01-01 in 100 ns
	if ft <= epochDelta {
		return 0
	}
	return (ft - epochDelta) / 10
}

// ---------------------------------------------------------------- GPU

// winEngineInstance is a parsed `\GPU Engine(*)` instance name, for example
// "pid_1234_luid_0x00000000_0x0000D1B6_phys_0_eng_0_engtype_3D".
type winEngineInstance struct {
	PID       int32
	LUID      uint64 // first hex field << 32 | second hex field
	Phys, Eng int
	Type      string // normalized: "3d", "copy", "videodecode", "compute", …
}

func winParseLUIDFields(f []string, i int) (uint64, bool) {
	if i+2 >= len(f) {
		return 0, false
	}
	hex := func(s string) (uint64, bool) {
		s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		v, err := strconv.ParseUint(s, 16, 32)
		return v, err == nil
	}
	a, ok1 := hex(f[i+1])
	b, ok2 := hex(f[i+2])
	if !ok1 || !ok2 {
		return 0, false
	}
	return a<<32 | b, true
}

func winParseGPUEngineInstance(name string) (winEngineInstance, bool) {
	var inst winEngineInstance
	head, typ, found := strings.Cut(name, "_engtype_")
	if !found {
		return inst, false
	}
	f := strings.Split(head, "_")
	haveLUID := false
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "pid":
			if i+1 < len(f) {
				if v, err := strconv.ParseInt(f[i+1], 10, 32); err == nil {
					inst.PID = int32(v)
				}
			}
		case "luid":
			inst.LUID, haveLUID = winParseLUIDFields(f, i)
		case "phys":
			if i+1 < len(f) {
				inst.Phys, _ = strconv.Atoi(f[i+1])
			}
		case "eng":
			if i+1 < len(f) {
				inst.Eng, _ = strconv.Atoi(f[i+1])
			}
		}
	}
	if !haveLUID {
		return inst, false
	}
	inst.Type = winNormalizeEngineType(typ)
	return inst, true
}

// winParseLUIDInstance reads the LUID of a `\GPU Adapter Memory(*)`
// instance such as "luid_0x00000000_0x0000D1B6_phys_0".
func winParseLUIDInstance(name string) (uint64, bool) {
	f := strings.Split(name, "_")
	for i := range f {
		if f[i] == "luid" {
			return winParseLUIDFields(f, i)
		}
	}
	return 0, false
}

// winNormalizeEngineType maps "3D" to "3d", "Compute_1" to "compute",
// "Video Decode" to "videodecode".
func winNormalizeEngineType(t string) string {
	s := strings.ToLower(strings.TrimSpace(t))
	if i := strings.LastIndexByte(s, '_'); i > 0 && i < len(s)-1 {
		if _, err := strconv.Atoi(s[i+1:]); err == nil {
			s = s[:i]
		}
	}
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '_' || r == '-' {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "other"
	}
	return s
}

// winGPUUsage is one adapter's engine utilization, as fractions.
type winGPUUsage struct {
	Engines     map[string]float64
	Utilization float64
}

// winAggregateGPUEngines sums `\GPU Engine(*)\Utilization Percentage` over
// processes for every physical engine, then reports each engine type as its
// busiest engine and the adapter as its busiest engine (what Task Manager
// shows). perPID is each process's busiest engine, in percent.
func winAggregateGPUEngines(vals []winPDHValue) (perAdapter map[uint64]*winGPUUsage, perPID map[int32]float64) {
	type engineKey struct {
		luid      uint64
		phys, eng int
	}
	sum := map[engineKey]float64{}
	kind := map[engineKey]string{}
	perPID = map[int32]float64{}
	for _, v := range vals {
		inst, ok := winParseGPUEngineInstance(v.Name)
		if !ok || math.IsNaN(v.Value) || v.Value < 0 {
			continue
		}
		k := engineKey{inst.LUID, inst.Phys, inst.Eng}
		sum[k] += v.Value
		kind[k] = inst.Type
		if inst.PID > 0 && v.Value > perPID[inst.PID] {
			perPID[inst.PID] = math.Min(v.Value, 100)
		}
	}
	perAdapter = map[uint64]*winGPUUsage{}
	for k, pct := range sum {
		u := perAdapter[k.luid]
		if u == nil {
			u = &winGPUUsage{Engines: map[string]float64{}}
			perAdapter[k.luid] = u
		}
		f := winClamp01(pct / 100)
		if cur, seen := u.Engines[kind[k]]; !seen || f > cur {
			u.Engines[kind[k]] = f
		}
		if f > u.Utilization {
			u.Utilization = f
		}
	}
	return perAdapter, perPID
}

// winSumByLUID sums `\GPU Adapter Memory(*)` byte counters per adapter.
func winSumByLUID(vals []winPDHValue) map[uint64]uint64 {
	out := map[uint64]uint64{}
	for _, v := range vals {
		luid, ok := winParseLUIDInstance(v.Name)
		if !ok || math.IsNaN(v.Value) || v.Value < 0 {
			continue
		}
		out[luid] += uint64(v.Value)
	}
	return out
}

// winAdapter describes a DXGI adapter (IDXGIAdapter1::GetDesc1).
type winAdapter struct {
	Name      string
	VendorID  uint32
	LUIDLow   uint32
	LUIDHigh  uint32
	Dedicated uint64 // DedicatedVideoMemory
	Shared    uint64 // SharedSystemMemory
	Software  bool   // DXGI_ADAPTER_FLAG_SOFTWARE (Microsoft Basic Render Driver)
}

// matches compares a LUID parsed from a counter instance with the adapter.
// The instance spells the LUID as two hex fields; which half comes first is
// not documented, so both orders are accepted (one half is almost always 0,
// which keeps this unambiguous).
func (a winAdapter) matches(key uint64) bool {
	hi, lo := uint32(key>>32), uint32(key)
	return (hi == a.LUIDHigh && lo == a.LUIDLow) || (hi == a.LUIDLow && lo == a.LUIDHigh)
}

// winVendorName maps a PCI (or ACPI) vendor id to the protocol's vendor names.
func winVendorName(id uint32) string {
	switch id {
	case 0x10DE:
		return "nvidia"
	case 0x1002, 0x1022:
		return "amd"
	case 0x8086:
		return "intel"
	case 0x5143, 0x4D4F4351: // PCI "Qualcomm", ACPI "QCOM"
		return "qualcomm"
	case 0x1414:
		return "microsoft"
	case 0x106B:
		return "apple"
	case 0x15AD:
		return "vmware"
	case 0x1AF4:
		return "virtio"
	}
	return ""
}

// winDiscreteVRAM separates discrete GPUs (memory = dedicated VRAM) from
// integrated ones (memory = dedicated carve-out plus shared system memory,
// as Task Manager counts it).
const winDiscreteVRAM = 512 << 20

// winBuildGPUs turns adapters and GPU counters into the gpus section, most
// important (largest dedicated memory) first. haveEngines says the GPU
// Engine counter exists, so an adapter without instances is idle, not
// unknown.
func winBuildGPUs(adapters []winAdapter, usage map[uint64]*winGPUUsage, dedicated, shared map[uint64]uint64, haveEngines bool) []wire.GPU {
	type entry struct {
		gpu   wire.GPU
		order int
		vram  uint64
	}
	var out []entry
	claimed := map[uint64]bool{}
	keys := map[uint64]bool{}
	for k := range usage {
		keys[k] = true
	}
	for k := range dedicated {
		keys[k] = true
	}
	for k := range shared {
		keys[k] = true
	}
	sortedKeys := make([]uint64, 0, len(keys))
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Slice(sortedKeys, func(i, j int) bool { return sortedKeys[i] < sortedKeys[j] })

	build := func(a *winAdapter, ks []uint64) wire.GPU {
		g := wire.GPU{}
		var u *winGPUUsage
		var ded, sh uint64
		haveDed, haveSh := false, false
		for _, k := range ks {
			if x := usage[k]; x != nil && u == nil {
				u = x
			}
			if v, ok := dedicated[k]; ok {
				ded, haveDed = ded+v, true
			}
			if v, ok := shared[k]; ok {
				sh, haveSh = sh+v, true
			}
		}
		if u != nil {
			g.Utilization = u.Utilization
			if len(u.Engines) > 0 {
				g.Engines = u.Engines
			}
		}
		discrete := a != nil && a.Dedicated >= winDiscreteVRAM
		switch {
		case discrete && haveDed:
			g.MemoryUsed = wire.U(ded)
		case !discrete && (haveDed || haveSh):
			g.MemoryUsed = wire.U(ded + sh)
		}
		if a != nil {
			g.Name = a.Name
			g.Vendor = winVendorName(a.VendorID)
			if discrete {
				g.MemoryTotal = wire.U(a.Dedicated)
			} else if a.Dedicated+a.Shared > 0 {
				g.MemoryTotal = wire.U(a.Dedicated + a.Shared)
			}
		}
		return g
	}

	for i := range adapters {
		a := &adapters[i]
		var ks []uint64
		for _, k := range sortedKeys {
			if !claimed[k] && a.matches(k) {
				ks = append(ks, k)
				claimed[k] = true
			}
		}
		if a.Software {
			continue
		}
		hasUse := false
		for _, k := range ks {
			if u := usage[k]; u != nil && u.Utilization > 0 {
				hasUse = true
			}
		}
		// Microsoft's display-only adapters (Basic Display, Hyper-V video,
		// Remote Display) are listed only when something actually uses them.
		if a.VendorID == 0x1414 && !hasUse {
			continue
		}
		if len(ks) == 0 && !haveEngines {
			continue // nothing measured: utilization would be a made-up zero
		}
		out = append(out, entry{gpu: build(a, ks), order: i, vram: a.Dedicated})
	}
	// Counter instances whose adapter DXGI did not describe.
	var orphans []uint64
	for _, k := range sortedKeys {
		if !claimed[k] {
			orphans = append(orphans, k)
		}
	}
	for i, k := range orphans {
		if usage[k] == nil && !haveEngines {
			continue
		}
		g := build(nil, []uint64{k})
		g.Name = "GPU"
		if len(orphans) > 1 {
			g.Name = fmt.Sprintf("GPU %d", i+1)
		}
		out = append(out, entry{gpu: g, order: len(adapters) + i})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].vram != out[j].vram {
			return out[i].vram > out[j].vram
		}
		return out[i].order < out[j].order
	})
	gpus := make([]wire.GPU, len(out))
	for i := range out {
		gpus[i] = out[i].gpu
	}
	return gpus
}

func winGPUNameKey(s string) string {
	s = strings.ToLower(s)
	for _, w := range []string{"nvidia", "geforce", "(r)", "(tm)"} {
		s = strings.ReplaceAll(s, w, "")
	}
	return strings.Join(strings.Fields(s), " ")
}

// winMergeNvidia folds nvidia-smi readings (temperature, power, fan, clocks,
// exact VRAM) into the matching DXGI/PDH GPU, by name or, when there is one
// NVIDIA GPU on each side, by elimination. Unmatched ones are appended.
func winMergeNvidia(gpus []wire.GPU, nv []wire.GPU) []wire.GPU {
	if len(nv) == 0 {
		return gpus
	}
	used := make([]bool, len(nv))
	matched := make([]bool, len(gpus))
	isNvidia := func(g wire.GPU) bool {
		return g.Vendor == "nvidia" || strings.Contains(strings.ToLower(g.Name), "nvidia")
	}
	merge := func(dst *wire.GPU, src wire.GPU) {
		if src.Celsius != nil {
			dst.Celsius = src.Celsius
		}
		if src.Watts != nil {
			dst.Watts = src.Watts
		}
		if src.FanPercent != nil {
			dst.FanPercent = src.FanPercent
		}
		if src.FanRPM != nil {
			dst.FanRPM = src.FanRPM
		}
		if src.ClockMHz != nil {
			dst.ClockMHz = src.ClockMHz
		}
		if src.MaxClockMHz != nil {
			dst.MaxClockMHz = src.MaxClockMHz
		}
		if src.MemoryUsed != nil && src.MemoryTotal != nil {
			dst.MemoryUsed, dst.MemoryTotal = src.MemoryUsed, src.MemoryTotal
		}
		if len(dst.Engines) == 0 {
			dst.Engines = src.Engines
			dst.Utilization = src.Utilization
		}
		if dst.Name == "" || dst.Name == "GPU" {
			dst.Name = src.Name
		}
		dst.Vendor = "nvidia"
	}
	for i := range gpus {
		if !isNvidia(gpus[i]) {
			continue
		}
		for j := range nv {
			if used[j] {
				continue
			}
			a, b := winGPUNameKey(gpus[i].Name), winGPUNameKey(nv[j].Name)
			if a != "" && b != "" && (a == b || strings.Contains(a, b) || strings.Contains(b, a)) {
				merge(&gpus[i], nv[j])
				used[j], matched[i] = true, true
				break
			}
		}
	}
	var openG, openN []int
	for i := range gpus {
		if !matched[i] && isNvidia(gpus[i]) {
			openG = append(openG, i)
		}
	}
	for j := range nv {
		if !used[j] {
			openN = append(openN, j)
		}
	}
	if len(openG) == 1 && len(openN) == 1 {
		merge(&gpus[openG[0]], nv[openN[0]])
		used[openN[0]] = true
	}
	for j := range nv {
		if !used[j] {
			gpus = append(gpus, nv[j])
		}
	}
	return gpus
}

// ---------------------------------------------------------------- thermal

// winThermalZoneSensors converts `\Thermal Zone Information(*)\Temperature`
// (Kelvin) into sensors keyed tz0, tz1, … in instance-name order. ACPI zones
// that report nonsense (0 K, above 150 °C) are dropped.
func winThermalZoneSensors(vals []winPDHValue) []wire.Sensor {
	sorted := append([]winPDHValue(nil), vals...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var out []wire.Sensor
	for _, v := range sorted {
		c := v.Value - 273.15
		if math.IsNaN(c) || v.Value <= 0 || c < -40 || c > 150 {
			continue
		}
		out = append(out, wire.Sensor{
			Key:      fmt.Sprintf("tz%d", len(out)),
			Label:    "Thermal zone " + strings.TrimSpace(v.Name),
			Celsius:  math.Round(c*10) / 10,
			Category: "Other",
		})
	}
	return out
}

// winLHMReading is what LibreHardwareMonitor's data.json contributes.
type winLHMReading struct {
	CPUCelsius   *float64
	PackageWatts *float64
	CoresWatts   *float64
	Sensors      []wire.Sensor
	Fans         []wire.Fan
	GPUCelsius   map[string]float64 // hardware name → core temperature
}

type winLHMNode struct {
	Text       string          `json:"Text"`
	Value      string          `json:"Value"`
	ImageURL   string          `json:"ImageURL"`
	SensorID   string          `json:"SensorId"`
	Type       string          `json:"Type"`
	HardwareID string          `json:"HardwareId"`
	RawValue   json.RawMessage `json:"RawValue"`
	Children   []winLHMNode    `json:"Children"`
}

// winLHMCategory classifies a hardware node by its identifier ("/intelcpu/0",
// "/gpu-nvidia/0", "/nvme/1", "/lpc/nct6798d"…) or, for versions without
// identifiers, by its icon.
func winLHMCategory(hardwareID, image string) string {
	id := strings.ToLower(hardwareID)
	img := strings.ToLower(image)
	switch {
	case strings.Contains(id, "cpu"):
		return "CPU"
	case strings.Contains(id, "gpu"):
		return "GPU"
	case strings.Contains(id, "nvme"), strings.Contains(id, "hdd"), strings.Contains(id, "ssd"), strings.Contains(id, "storage"):
		return "Storage"
	case strings.Contains(id, "ram"), strings.Contains(id, "memory"):
		return "Memory"
	case strings.Contains(id, "battery"):
		return "Battery"
	case id != "":
		return "Other"
	case strings.HasSuffix(img, "/cpu.png"):
		return "CPU"
	case strings.HasSuffix(img, "/nvidia.png"), strings.HasSuffix(img, "/ati.png"), strings.HasSuffix(img, "/intel.png"):
		return "GPU"
	case strings.HasSuffix(img, "/hdd.png"):
		return "Storage"
	case strings.HasSuffix(img, "/ram.png"):
		return "Memory"
	case strings.HasSuffix(img, "/battery.png"):
		return "Battery"
	}
	return "Other"
}

// winLHMValue reads a sensor value: the raw number when the version has it,
// else the formatted text ("45.0 °C", "45,0 °C", "113.0 °F", "1200 RPM").
func winLHMValue(n winLHMNode) (float64, bool) {
	if raw := strings.TrimSpace(string(n.RawValue)); raw != "" && raw != "null" {
		var v float64
		if json.Unmarshal(n.RawValue, &v) == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
			return v, true
		}
		var s string
		if json.Unmarshal(n.RawValue, &s) == nil { // NaN is written as the string "NaN"
			return 0, false
		}
	}
	t := strings.TrimSpace(n.Value)
	end := 0
	for end < len(t) && (t[end] == '-' || t[end] == '.' || t[end] == ',' || (t[end] >= '0' && t[end] <= '9')) {
		end++
	}
	num := strings.ReplaceAll(t[:end], ",", ".")
	v, err := strconv.ParseFloat(num, 64)
	if err != nil || math.IsNaN(v) {
		return 0, false
	}
	if strings.Contains(t[end:], "°F") {
		v = (v - 32) * 5 / 9
	}
	return v, true
}

// winLHMSensorType is "Temperature", "Fan", "Power", … from the node, or
// from its group node for versions that do not label sensors.
func winLHMSensorType(n winLHMNode, group winLHMNode) string {
	if n.Type != "" {
		return n.Type
	}
	// A sensor's parent is its type group. power.png doubles as the icon of
	// unknown types, so only the group's text identifies power sensors.
	img := strings.ToLower(group.ImageURL)
	text := strings.ToLower(strings.TrimSpace(group.Text))
	switch {
	case strings.HasSuffix(img, "/temperature.png"), text == "temperatures":
		return "Temperature"
	case strings.HasSuffix(img, "/fan.png"), text == "fans":
		return "Fan"
	case text == "powers":
		return "Power"
	}
	return ""
}

// winParseLHM reads LibreHardwareMonitor's /data.json tree:
// Sensor → computer → hardware (→ sub-hardware) → type group → sensor.
func winParseLHM(data []byte) (*winLHMReading, error) {
	var root winLHMNode
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	r := &winLHMReading{GPUCelsius: map[string]float64{}}
	type cpuTemp struct {
		name string
		c    float64
	}
	var cpuTemps []cpuTemp
	counts := map[string]int{}
	keyPrefix := map[string]string{"CPU": "cpu", "GPU": "gpu", "Storage": "ssd", "Memory": "mem", "Battery": "bat", "Other": "mb"}

	var walk func(n winLHMNode, hw *winLHMNode, parent *winLHMNode, depth int)
	walk = func(n winLHMNode, hw *winLHMNode, parent *winLHMNode, depth int) {
		if depth > 16 {
			return
		}
		if n.HardwareID != "" || (len(n.Children) > 0 && n.SensorID == "" && winLHMIsHardwareIcon(n.ImageURL)) {
			h := n
			hw = &h
		}
		if len(n.Children) == 0 {
			if hw == nil || parent == nil {
				return
			}
			typ := winLHMSensorType(n, *parent)
			v, ok := winLHMValue(n)
			if !ok || typ == "" {
				return
			}
			cat := winLHMCategory(hw.HardwareID, hw.ImageURL)
			name := strings.TrimSpace(n.Text)
			switch typ {
			case "Temperature":
				lower := strings.ToLower(name)
				if strings.Contains(lower, "distance to tjmax") || strings.Contains(lower, "tjmax") || v <= -50 || v > 150 {
					return
				}
				c := math.Round(v*10) / 10
				r.Sensors = append(r.Sensors, wire.Sensor{
					Key:      fmt.Sprintf("%s%d", keyPrefix[cat], counts[cat]),
					Label:    name + " (" + strings.TrimSpace(hw.Text) + ")",
					Celsius:  c,
					Category: cat,
				})
				counts[cat]++
				switch cat {
				case "CPU":
					cpuTemps = append(cpuTemps, cpuTemp{lower, c})
				case "GPU":
					hwName := strings.TrimSpace(hw.Text)
					if _, seen := r.GPUCelsius[hwName]; !seen || strings.Contains(lower, "core") {
						r.GPUCelsius[hwName] = c
					}
				}
			case "Fan":
				if v < 0 || v > 100000 {
					return
				}
				label := name
				if cat != "Other" {
					label += " (" + strings.TrimSpace(hw.Text) + ")"
				}
				r.Fans = append(r.Fans, wire.Fan{Index: len(r.Fans), Label: label, RPM: math.Round(v)})
			case "Power":
				if cat != "CPU" || v < 0 || v > 2000 {
					return
				}
				lower := strings.ToLower(name)
				switch {
				case strings.Contains(lower, "package") && r.PackageWatts == nil:
					r.PackageWatts = wire.F(math.Round(v*100) / 100)
				case lower == "cpu cores" && r.CoresWatts == nil:
					r.CoresWatts = wire.F(math.Round(v*100) / 100)
				}
			}
			return
		}
		for i := range n.Children {
			p := n
			walk(n.Children[i], hw, &p, depth+1)
		}
	}
	walk(root, nil, nil, 0)

	// Headline CPU temperature: the package or Tctl/Tdie reading, else the
	// hottest CPU sensor.
	for _, want := range []string{"cpu package", "core (tctl/tdie)", "tctl/tdie", "tdie", "tctl", "package", "core max", "core average"} {
		for _, t := range cpuTemps {
			if t.name == want {
				r.CPUCelsius = wire.F(t.c)
				break
			}
		}
		if r.CPUCelsius != nil {
			break
		}
	}
	if r.CPUCelsius == nil && len(cpuTemps) > 0 {
		best := cpuTemps[0].c
		for _, t := range cpuTemps {
			best = math.Max(best, t.c)
		}
		r.CPUCelsius = wire.F(best)
	}
	return r, nil
}

func winLHMIsHardwareIcon(image string) bool {
	img := strings.ToLower(image)
	for _, s := range []string{"/cpu.png", "/nvidia.png", "/ati.png", "/intel.png", "/hdd.png", "/mainboard.png", "/chip.png", "/ram.png", "/nic.png", "/battery.png", "/power-supply.png", "/powermonitor.png"} {
		if strings.HasSuffix(img, s) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- network

// winAdapterInfo is the part of IP_ADAPTER_ADDRESSES the collector uses.
type winAdapterInfo struct {
	Description  string
	FriendlyName string
	IfType       uint32
	Up           bool
	SpeedBps     uint64
	HasGateway   bool
	Metric       uint32
	IPv4         []string
}

const (
	winIfTypeLoopback = 24  // IF_TYPE_SOFTWARE_LOOPBACK
	winIfTypeTunnel   = 131 // IF_TYPE_TUNNEL
)

// winPDHInstanceName spells an adapter description the way the Network
// Interface performance object names its instance: "Intel(R) Ethernet
// Connection (7) I219-V #2" becomes "Intel[R] Ethernet Connection [7] I219-V _2".
func winPDHInstanceName(desc string) string {
	return strings.NewReplacer("(", "[", ")", "]", "#", "_", "/", "_", `\`, "_").Replace(desc)
}

// winSkipInterface drops pseudo and virtual adapters from network totals.
func winSkipInterface(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"isatap", "teredo", "loopback", "hyper-v virtual", "vethernet", "wan miniport", "pseudo-interface", "6to4", "ip-https", "kernel debug"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// winNetwork aggregates `\Network Interface(*)\Bytes Received/sec` and
// `Bytes Sent/sec` into per-interface rows and physical totals, naming each
// interface by its adapter's friendly name ("Ethernet", "Wi-Fi") when known.
func winNetwork(rx, tx []winPDHValue, adapters []winAdapterInfo) (ifaces []wire.Interface, sumRX, sumTX float64) {
	byName := map[string]*wire.Interface{}
	var order []string
	add := func(vals []winPDHValue, isRX bool) {
		for _, v := range vals {
			if winSkipInterface(v.Name) || math.IsNaN(v.Value) || v.Value < 0 {
				continue
			}
			var a *winAdapterInfo
			for i := range adapters {
				if strings.EqualFold(winPDHInstanceName(adapters[i].Description), v.Name) {
					a = &adapters[i]
					break
				}
			}
			if a != nil && (a.IfType == winIfTypeLoopback || a.IfType == winIfTypeTunnel) {
				continue
			}
			it := byName[v.Name]
			if it == nil {
				it = &wire.Interface{Name: v.Name, Up: true}
				if a != nil {
					if a.FriendlyName != "" {
						it.Name = a.FriendlyName
					}
					it.Up = a.Up
					if a.SpeedBps > 0 && a.SpeedBps != math.MaxUint64 {
						it.SpeedMbps = wire.F(float64(a.SpeedBps) / 1e6)
					}
				}
				byName[v.Name] = it
				order = append(order, v.Name)
			}
			if isRX {
				it.RX += v.Value
			} else {
				it.TX += v.Value
			}
		}
	}
	add(rx, true)
	add(tx, false)
	sort.Strings(order)
	for _, n := range order {
		it := byName[n]
		sumRX += it.RX
		sumTX += it.TX
		ifaces = append(ifaces, *it)
	}
	return ifaces, sumRX, sumTX
}

// winPrimaryAdapter picks the adapter that carries the default route (up,
// with a gateway, lowest metric), else the first up physical adapter with an
// IPv4 address. It returns the friendly name and IPv4 address.
func winPrimaryAdapter(adapters []winAdapterInfo) (name, addr string) {
	usable := func(a winAdapterInfo) bool {
		return a.Up && a.IfType != winIfTypeLoopback && a.IfType != winIfTypeTunnel && len(a.IPv4) > 0 && !winSkipInterface(a.Description)
	}
	best := -1
	for i, a := range adapters {
		if usable(a) && a.HasGateway && (best < 0 || a.Metric < adapters[best].Metric) {
			best = i
		}
	}
	if best < 0 {
		for i, a := range adapters {
			if usable(a) {
				best = i
				break
			}
		}
	}
	if best < 0 {
		return "", ""
	}
	a := adapters[best]
	addr = a.IPv4[0]
	for _, ip := range a.IPv4 {
		if !strings.HasPrefix(ip, "169.254.") {
			addr = ip
			break
		}
	}
	name = a.FriendlyName
	if name == "" {
		name = a.Description
	}
	return name, addr
}

// ---------------------------------------------------------------- host

// winOSName fixes ProductName, which still says "Windows 10" on Windows 11
// (build 22000 and later).
func winOSName(product string, build int) string {
	product = strings.TrimSpace(product)
	if build >= 22000 && strings.Contains(product, "Windows 10") {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	if product == "" {
		product = "Windows"
	}
	return product
}

// winPlaceholders are the strings OEMs leave in SMBIOS fields.
var winPlaceholders = map[string]bool{
	"to be filled by o.e.m.": true, "to be filled by oem": true, "system product name": true,
	"system manufacturer": true, "system manufacter": true, "default string": true, "o.e.m.": true,
	"oem": true, "not applicable": true, "not specified": true, "none": true, "unknown": true,
	"invalid": true, "type1productconfigid": true, "all series": true, "base board product name": true,
	"x.x": true, "0": true, "1234567890": true, "123456789": true, "system version": true,
	"undefined": true, "n/a": true, "na": true, "empty": true, "sku": true,
}

func winIsPlaceholder(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	return t == "" || winPlaceholders[t] || strings.HasPrefix(t, "to be filled")
}

// winVirtualization recognises hypervisors from the SMBIOS system
// manufacturer, product and BIOS vendor.
func winVirtualization(manufacturer, product, biosVendor string) string {
	m := strings.ToLower(manufacturer)
	p := strings.ToLower(product)
	b := strings.ToLower(biosVendor)
	has := func(s string, subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has(m, "microsoft") && has(p, "virtual"):
		return "hyperv"
	case has(m, "vmware") || has(p, "vmware"):
		return "vmware"
	case has(m, "innotek") || has(p, "virtualbox"):
		return "virtualbox"
	case has(m, "parallels") || has(p, "parallels"):
		return "parallels"
	case has(m, "amazon ec2") || has(p, "amazon ec2") || (has(b, "amazon") && has(m, "amazon")):
		return "amazon"
	case has(m, "google") && has(p, "compute engine"):
		return "google"
	case has(m, "xen") || has(p, "hvm domu") || has(b, "xen"):
		return "xen"
	case has(m, "qemu") || has(p, "qemu", "kvm", "standard pc (q35", "standard pc (i440fx") || has(m, "nutanix", "digitalocean"):
		return "kvm"
	case has(m, "bochs"):
		return "bochs"
	}
	return "none"
}

// winSortVolumes puts the system drive first, then the others by name.
func winSortVolumes(vols []wire.Volume, systemDrive string) {
	sys := strings.ToUpper(strings.TrimRight(systemDrive, `\`))
	sort.SliceStable(vols, func(i, j int) bool {
		si, sj := strings.EqualFold(vols[i].Name, sys), strings.EqualFold(vols[j].Name, sys)
		if si != sj {
			return si
		}
		return vols[i].Name < vols[j].Name
	})
}
