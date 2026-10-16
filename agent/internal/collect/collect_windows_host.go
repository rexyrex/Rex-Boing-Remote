//go:build windows

package collect

// Host description (registry, RtlGetVersion, topology), reboot-pending
// state and the OpenSSH service, for hello, the system section and doctor.

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// winRegString reads a string value under HKLM, or "".
func winRegString(path, name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// winRegInt reads a DWORD/QWORD value under HKLM.
func winRegInt(path, name string) (uint64, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}

// winRegKeyExists reports whether a key exists under HKLM.
func winRegKeyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

const (
	winRegCurrentVersion = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	winRegCPU0           = `HARDWARE\DESCRIPTION\System\CentralProcessor\0`
	winRegBIOS           = `HARDWARE\DESCRIPTION\System\BIOS`
)

// winHostInfo builds hello's host description.
func winHostInfo(groupCounts []int, cores []winCore, perf, eff int) wire.Host {
	h := wire.Host{}
	if name, err := os.Hostname(); err == nil {
		h.Hostname = name
	}
	v := windows.RtlGetVersion() // not subject to manifest version lies
	build := int(v.BuildNumber)
	ubr, _ := winRegInt(winRegCurrentVersion, "UBR")
	h.OSName = winOSName(winRegString(winRegCurrentVersion, "ProductName"), build)
	h.OSVersion = winRegString(winRegCurrentVersion, "DisplayVersion")
	if h.OSVersion == "" {
		h.OSVersion = winRegString(winRegCurrentVersion, "ReleaseId")
	}
	h.Kernel = fmt.Sprintf("%d.%d.%d.%d", v.MajorVersion, v.MinorVersion, build, ubr)

	h.ChipName = winCleanCPUName(winRegString(winRegCPU0, "ProcessorNameString"))
	manufacturer := winRegString(winRegBIOS, "SystemManufacturer")
	product := winRegString(winRegBIOS, "SystemProductName")
	if !winIsPlaceholder(product) {
		h.ModelName = product
	} else if bb := winRegString(winRegBIOS, "BaseBoardProduct"); !winIsPlaceholder(bb) {
		h.ModelName = bb
	}
	if !winIsPlaceholder(manufacturer) {
		h.Vendor = manufacturer
	} else if bb := winRegString(winRegBIOS, "BaseBoardManufacturer"); !winIsPlaceholder(bb) {
		h.Vendor = bb
	}
	h.Virtualization = winVirtualization(manufacturer, product, winRegString(winRegBIOS, "BIOSVendor"))

	for _, n := range groupCounts {
		h.LogicalCores += n
	}
	if len(cores) > 0 {
		h.PhysicalCores = len(cores)
	}
	h.PerformanceCores, h.EfficiencyCores = perf, eff
	if m, err := winGlobalMemoryStatus(); err == nil {
		h.MemoryBytes = m.TotalPhys
	}
	if up := windows.DurationSinceBoot(); up > 0 {
		h.BootTime = time.Now().Add(-up).UnixMilli()
	}
	return h
}

// winNominalMHz is the processor's rated clock from the registry.
func winNominalMHz() float64 {
	if v, ok := winRegInt(winRegCPU0, "~MHz"); ok && v > 0 && v < 20000 {
		return float64(v)
	}
	return 0
}

// winRebootPending reports a pending reboot from Windows Update or
// component servicing. Both are keys whose presence is the signal.
func winRebootPending() (bool, string) {
	switch {
	case winRegKeyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`):
		return true, "Windows Update"
	case winRegKeyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`):
		return true, "Component servicing"
	}
	return false, ""
}

// winServiceState returns "running", "stopped", … or "not installed" for a
// service, or an error text.
func winServiceState(name string) string {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	defer windows.CloseServiceHandle(m)
	n, _ := windows.UTF16PtrFromString(name)
	s, err := windows.OpenService(m, n, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return "not installed"
		}
		return "unknown (" + err.Error() + ")"
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return "unknown (" + err.Error() + ")"
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "starting"
	case windows.SERVICE_STOP_PENDING:
		return "stopping"
	case windows.SERVICE_PAUSED:
		return "paused"
	}
	return fmt.Sprintf("state %d", st.CurrentState)
}

// ---------------------------------------------------------------- volumes

// winVolumes lists fixed and network drives with their sizes. A network
// drive whose server is unreachable can block GetDiskFreeSpaceExW for many
// seconds, which is why the collector only calls this from a background
// goroutine.
func winVolumes() []wire.Volume {
	n, err := windows.GetLogicalDriveStrings(0, nil)
	if err != nil || n == 0 || n > 4096 {
		return nil
	}
	buf := make([]uint16, n+1)
	n, err = windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil || int(n) > len(buf) {
		return nil
	}
	var vols []wire.Volume
	// The buffer is a sequence of NUL-terminated strings ending in an empty
	// one ("C:\\\x00D:\\\x00\x00"); UTF16ToString would stop at the first NUL.
	var roots []string
	start := 0
	for i := 0; i < int(n); i++ {
		if buf[i] == 0 {
			if i > start {
				roots = append(roots, windows.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}
	for _, root := range roots {
		p, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		kind := windows.GetDriveType(p)
		if kind != windows.DRIVE_FIXED && kind != windows.DRIVE_REMOTE {
			continue // removable, optical, RAM disks
		}
		var free, total, totalFree uint64
		if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil || total == 0 {
			continue
		}
		fsName := make([]uint16, windows.MAX_PATH+1)
		fs := ""
		if windows.GetVolumeInformation(p, nil, 0, nil, nil, nil, &fsName[0], uint32(len(fsName))) == nil {
			fs = windows.UTF16ToString(fsName)
		}
		if kind == windows.DRIVE_REMOTE {
			if fs == "" {
				fs = "network"
			} else {
				fs += " (network)"
			}
		}
		vols = append(vols, wire.Volume{
			Name:      strings.TrimRight(root, `\`),
			Mount:     root,
			FS:        fs,
			Total:     total,
			Available: free, // what this user may still write, as statvfs f_bavail
		})
	}
	winSortVolumes(vols, os.Getenv("SystemDrive"))
	return vols
}

// ---------------------------------------------------------------- network

// winReadAdapters reads IP_ADAPTER_ADDRESSES for every adapter, following
// the buffer-growing pattern of Go's net package.
func winReadAdapters() ([]winAdapterInfo, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(15000)
	var buf []byte
	for attempt := 0; ; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			if size == 0 {
				return nil, nil
			}
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(buf)) || attempt > 4 {
			return nil, err
		}
	}
	var out []winAdapterInfo
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		a := winAdapterInfo{
			Description:  windows.UTF16PtrToString(aa.Description),
			FriendlyName: windows.UTF16PtrToString(aa.FriendlyName),
			IfType:       aa.IfType,
			Up:           aa.OperStatus == windows.IfOperStatusUp,
			SpeedBps:     aa.TransmitLinkSpeed,
			HasGateway:   aa.FirstGatewayAddress != nil,
			Metric:       aa.Ipv4Metric,
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := ua.Address.IP(); ip != nil && ip.To4() != nil {
				a.IPv4 = append(a.IPv4, ip.To4().String())
			}
		}
		out = append(out, a)
	}
	return out, nil
}
