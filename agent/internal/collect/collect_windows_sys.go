//go:build windows

package collect

// Raw Win32 and NT calls the Windows collector needs beyond
// golang.org/x/sys/windows. Every DLL is loaded from System32 only
// (NewLazySystemDLL) and every procedure is looked up before it is called,
// so a missing export degrades to an error instead of a panic.
//
// Struct layouts are written to match the Windows SDK headers on amd64,
// arm64 and 386; sizes that matter are checked at compile time below.
// WINDOWS-NOTES.md lists each layout with its source.

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	winKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	winNtdll    = windows.NewLazySystemDLL("ntdll.dll")
	winPsapi    = windows.NewLazySystemDLL("psapi.dll")
	winPdh      = windows.NewLazySystemDLL("pdh.dll")
	winDxgi     = windows.NewLazySystemDLL("dxgi.dll")

	procGlobalMemoryStatusEx             = winKernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemPowerStatus             = winKernel32.NewProc("GetSystemPowerStatus")
	procGetLogicalProcessorInformationEx = winKernel32.NewProc("GetLogicalProcessorInformationEx")
	procGetActiveProcessorGroupCount     = winKernel32.NewProc("GetActiveProcessorGroupCount")
	procGetActiveProcessorCount          = winKernel32.NewProc("GetActiveProcessorCount")
	procGetProcessIoCounters             = winKernel32.NewProc("GetProcessIoCounters")
	procNtQuerySystemInformationEx       = winNtdll.NewProc("NtQuerySystemInformationEx")
	procGetPerformanceInfo               = winPsapi.NewProc("GetPerformanceInfo")
	procGetProcessMemoryInfo             = winPsapi.NewProc("GetProcessMemoryInfo")
	procCreateDXGIFactory1               = winDxgi.NewProc("CreateDXGIFactory1")
)

var errWinProcMissing = errors.New("function not available on this Windows version")

// winHave reports whether a procedure exists. Callers check it first and
// then call p.Call with every unsafe.Pointer→uintptr conversion written in
// the call expression itself: LazyProc.Call is //go:uintptrescapes, which
// keeps those buffers alive and in place only for conversions made there,
// so no helper may sit between the conversion and the call.
func winHave(p *windows.LazyProc) bool { return p.Find() == nil }

// ---------------------------------------------------------------- CPU

// winSPPI is SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (winternl.h):
// LARGE_INTEGER IdleTime, KernelTime, UserTime, Reserved1[2] (DPC and
// interrupt time), ULONG Reserved2 (interrupt count). The LARGE_INTEGERs
// make the C struct 8-byte aligned, so it is 48 bytes; the explicit pad
// keeps that true for Go on 386 too.
type winSPPI struct {
	IdleTime       int64
	KernelTime     int64
	UserTime       int64
	DpcTime        int64
	InterruptTime  int64
	InterruptCount uint32
	_              uint32
}

var _ = [1]struct{}{}[unsafe.Sizeof(winSPPI{})-48] // compile-time size check

const winSystemProcessorPerformanceInformation = 8

func winActiveGroupCount() int {
	if !winHave(procGetActiveProcessorGroupCount) {
		return 1
	}
	r, _, _ := procGetActiveProcessorGroupCount.Call()
	if uint16(r) == 0 {
		return 1
	}
	return int(uint16(r))
}

func winActiveProcessorCount(group uint16) int {
	if !winHave(procGetActiveProcessorCount) {
		return 0
	}
	return int(windows.GetActiveProcessorCount(group))
}

// winGroupCounts lists the active logical processors of each group.
func winGroupCounts() []int {
	n := winActiveGroupCount()
	counts := make([]int, n)
	for g := 0; g < n; g++ {
		counts[g] = winActiveProcessorCount(uint16(g))
	}
	return counts
}

// winReadCPUTimes returns cumulative times for every logical processor, in
// group order. NtQuerySystemInformation(SystemProcessorPerformanceInformation)
// only covers the calling thread's processor group, so machines with more
// than 64 logical processors are read group by group through
// NtQuerySystemInformationEx with the group number as input (as gopsutil
// does). If that is unavailable only the current group is reported.
func winReadCPUTimes(groupCounts []int) ([]winCPUTimes, error) {
	size := uint32(unsafe.Sizeof(winSPPI{}))
	convert := func(buf []winSPPI) []winCPUTimes {
		out := make([]winCPUTimes, len(buf))
		for i, b := range buf {
			out[i] = winCPUTimes{Idle: b.IdleTime, Kernel: b.KernelTime, User: b.UserTime}
		}
		return out
	}
	if len(groupCounts) > 1 && winHave(procNtQuerySystemInformationEx) {
		var all []winCPUTimes
		ok := true
		for g, n := range groupCounts {
			if n <= 0 {
				continue
			}
			buf := make([]winSPPI, n)
			group := uint16(g)
			var ret uint32
			st, _, _ := procNtQuerySystemInformationEx.Call(
				winSystemProcessorPerformanceInformation,
				uintptr(unsafe.Pointer(&group)), unsafe.Sizeof(group),
				uintptr(unsafe.Pointer(&buf[0])), uintptr(uint32(n)*size),
				uintptr(unsafe.Pointer(&ret)))
			if int32(st) < 0 || ret%size != 0 || ret/size > uint32(n) {
				ok = false
				break
			}
			all = append(all, convert(buf[:ret/size])...)
		}
		if ok && len(all) > 0 {
			return all, nil
		}
	}
	n := 64
	if len(groupCounts) > 0 && groupCounts[0] > 0 {
		n = groupCounts[0]
	}
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]winSPPI, n)
		var ret uint32
		err := windows.NtQuerySystemInformation(winSystemProcessorPerformanceInformation,
			unsafe.Pointer(&buf[0]), uint32(n)*size, &ret)
		if err == nil {
			if ret%size != 0 || ret/size > uint32(n) {
				return nil, fmt.Errorf("unexpected processor information size %d", ret)
			}
			return convert(buf[:ret/size]), nil
		}
		if ret > uint32(n)*size && ret < 1<<20 {
			n = int(ret/size) + 1
			continue
		}
		return nil, err
	}
	return nil, errors.New("processor information keeps growing")
}

// winProcessorCores calls GetLogicalProcessorInformationEx(RelationProcessorCore).
func winProcessorCores() ([]winCore, error) {
	const relationProcessorCore = 0
	if !winHave(procGetLogicalProcessorInformationEx) {
		return nil, errWinProcMissing
	}
	var size uint32
	procGetLogicalProcessorInformationEx.Call(relationProcessorCore, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 || size > 4<<20 {
		return nil, errors.New("no processor information")
	}
	buf := make([]uint64, (size+7)/8) // 8-byte aligned, like the C struct
	r, _, err := procGetLogicalProcessorInformationEx.Call(relationProcessorCore, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return nil, err
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)
	if int(size) < len(b) {
		b = b[:size]
	}
	return winParseProcessorCores(b, int(unsafe.Sizeof(uintptr(0)))), nil
}

// ---------------------------------------------------------------- memory

// winMemoryStatusEx is MEMORYSTATUSEX (sysinfoapi.h), 64 bytes.
type winMemoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var _ = [1]struct{}{}[unsafe.Sizeof(winMemoryStatusEx{})-64]

func winGlobalMemoryStatus() (*winMemoryStatusEx, error) {
	if !winHave(procGlobalMemoryStatusEx) {
		return nil, errWinProcMissing
	}
	m := &winMemoryStatusEx{}
	m.Length = uint32(unsafe.Sizeof(*m))
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(m)))
	if r == 0 {
		return nil, err
	}
	return m, nil
}

// winPerformanceInformation is PERFORMANCE_INFORMATION (psapi.h): DWORD cb,
// ten SIZE_T counts in pages (PageSize in bytes), then three DWORDs. Go lays
// it out exactly like C on every architecture (104 bytes on 64-bit).
type winPerformanceInformation struct {
	CB                uint32
	CommitTotal       uintptr
	CommitLimit       uintptr
	CommitPeak        uintptr
	PhysicalTotal     uintptr
	PhysicalAvailable uintptr
	SystemCache       uintptr
	KernelTotal       uintptr
	KernelPaged       uintptr
	KernelNonpaged    uintptr
	PageSize          uintptr
	HandleCount       uint32
	ProcessCount      uint32
	ThreadCount       uint32
}

func winGetPerformanceInfo() (*winPerfInfo, error) {
	if !winHave(procGetPerformanceInfo) {
		return nil, errWinProcMissing
	}
	var p winPerformanceInformation
	p.CB = uint32(unsafe.Sizeof(p))
	r, _, err := procGetPerformanceInfo.Call(uintptr(unsafe.Pointer(&p)), uintptr(p.CB))
	if r == 0 {
		return nil, err
	}
	return &winPerfInfo{
		CommitTotal: uint64(p.CommitTotal), CommitLimit: uint64(p.CommitLimit),
		PhysicalTotal: uint64(p.PhysicalTotal), SystemCache: uint64(p.SystemCache),
		KernelNonpaged: uint64(p.KernelNonpaged), PageSize: uint64(p.PageSize),
		ProcessCount: p.ProcessCount, ThreadCount: p.ThreadCount,
	}, nil
}

// ---------------------------------------------------------------- battery

// winSystemPowerStatus is SYSTEM_POWER_STATUS (winbase.h), 12 bytes.
type winSystemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

var _ = [1]struct{}{}[unsafe.Sizeof(winSystemPowerStatus{})-12]

func winPowerStatus() (*winSystemPowerStatus, error) {
	if !winHave(procGetSystemPowerStatus) {
		return nil, errWinProcMissing
	}
	var s winSystemPowerStatus
	r, _, err := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&s)))
	if r == 0 {
		return nil, err
	}
	return &s, nil
}

// ---------------------------------------------------------------- processes

// winProcessMemoryCounters is PROCESS_MEMORY_COUNTERS (psapi.h).
type winProcessMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func winProcessWorkingSet(h windows.Handle) (uint64, bool) {
	if !winHave(procGetProcessMemoryInfo) {
		return 0, false
	}
	var m winProcessMemoryCounters
	m.CB = uint32(unsafe.Sizeof(m))
	r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.CB))
	return uint64(m.WorkingSetSize), r != 0
}

func winProcessIO(h windows.Handle) (read, write uint64, ok bool) {
	if !winHave(procGetProcessIoCounters) {
		return 0, 0, false
	}
	var c windows.IO_COUNTERS // six ULONGLONGs, 48 bytes
	r, _, _ := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&c)))
	return c.ReadTransferCount, c.WriteTransferCount, r != 0
}

// ---------------------------------------------------------------- DXGI

// winDXGIAdapterDesc1 is DXGI_ADAPTER_DESC1 (dxgi.h): WCHAR Description[128],
// UINT VendorId, DeviceId, SubSysId, Revision, SIZE_T DedicatedVideoMemory,
// DedicatedSystemMemory, SharedSystemMemory, LUID AdapterLuid {DWORD
// LowPart; LONG HighPart}, UINT Flags. 312 bytes on 64-bit, 296 on 386; Go
// pads it the same way.
type winDXGIAdapterDesc1 struct {
	Description           [128]uint16
	VendorID              uint32
	DeviceID              uint32
	SubSysID              uint32
	Revision              uint32
	DedicatedVideoMemory  uintptr
	DedicatedSystemMemory uintptr
	SharedSystemMemory    uintptr
	LUIDLow               uint32
	LUIDHigh              int32
	Flags                 uint32
}

var winIIDIDXGIFactory1 = windows.GUID{Data1: 0x770aae78, Data2: 0xf26f, Data3: 0x4dba, Data4: [8]byte{0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}}

// COM vtable slots, in dxgi.h declaration order:
// IUnknown 0 QueryInterface, 1 AddRef, 2 Release; IDXGIObject 3–6;
// IDXGIFactory 7 EnumAdapters … 11 CreateSoftwareAdapter; IDXGIFactory1
// 12 EnumAdapters1, 13 IsCurrent. IDXGIAdapter 7 EnumOutputs, 8 GetDesc,
// 9 CheckInterfaceSupport; IDXGIAdapter1 10 GetDesc1.
const (
	winVtblRelease       = 2
	winVtblEnumAdapters1 = 12
	winVtblGetDesc1      = 10
	winDXGIErrorNotFound = 0x887A0002
	winDXGIFlagSoftware  = 2
)

// winComObject is the start of every COM object: a pointer to its vtable.
// Holding COM pointers as typed pointers (not uintptr) keeps go vet's
// unsafeptr check meaningful; the GC ignores pointers outside the Go heap.
type winComObject struct {
	vtbl *[32]uintptr
}

// winComRelease calls IUnknown::Release. Calls with pointer arguments are
// written out at their call sites so the uintptr conversions sit in the
// syscall.SyscallN expression itself (see winHave).
func winComRelease(obj *winComObject) {
	syscall.SyscallN(obj.vtbl[winVtblRelease], uintptr(unsafe.Pointer(obj)))
}

// winDXGIAdapters lists the graphics adapters with their names, vendors,
// memory sizes and LUIDs, which the GPU performance counters are keyed by.
// DXGI needs no COM initialisation and no desktop, so it works in an SSH
// session.
func winDXGIAdapters() ([]winAdapter, error) {
	if !winHave(procCreateDXGIFactory1) {
		return nil, errWinProcMissing
	}
	var factory *winComObject
	hr, _, _ := procCreateDXGIFactory1.Call(uintptr(unsafe.Pointer(&winIIDIDXGIFactory1)), uintptr(unsafe.Pointer(&factory)))
	if int32(hr) < 0 || factory == nil || factory.vtbl == nil {
		return nil, fmt.Errorf("CreateDXGIFactory1: 0x%08X", uint32(hr))
	}
	defer winComRelease(factory)
	var out []winAdapter
	for i := uintptr(0); i < 16; i++ {
		var adapter *winComObject
		hr, _, _ := syscall.SyscallN(factory.vtbl[winVtblEnumAdapters1], uintptr(unsafe.Pointer(factory)), i, uintptr(unsafe.Pointer(&adapter)))
		if uint32(hr) == winDXGIErrorNotFound {
			break
		}
		if int32(hr) < 0 || adapter == nil || adapter.vtbl == nil {
			continue
		}
		var d winDXGIAdapterDesc1
		hr, _, _ = syscall.SyscallN(adapter.vtbl[winVtblGetDesc1], uintptr(unsafe.Pointer(adapter)), uintptr(unsafe.Pointer(&d)))
		winComRelease(adapter)
		if int32(hr) < 0 {
			continue
		}
		out = append(out, winAdapter{
			Name:      windows.UTF16ToString(d.Description[:]),
			VendorID:  d.VendorID,
			LUIDLow:   d.LUIDLow,
			LUIDHigh:  uint32(d.LUIDHigh),
			Dedicated: uint64(d.DedicatedVideoMemory),
			Shared:    uint64(d.SharedSystemMemory),
			Software:  d.Flags&winDXGIFlagSoftware != 0,
		})
	}
	return out, nil
}
