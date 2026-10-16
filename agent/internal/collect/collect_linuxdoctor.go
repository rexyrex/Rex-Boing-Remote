package collect

// The Linux doctor report. No build tag: see collect_linuxfs.go.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxGiB formats bytes as GiB.
func linuxGiB(b uint64) string { return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30)) }

// Doctor explains what this machine can and cannot report, and how to fix it.
func (c *linuxCollector) Doctor() []Check {
	h := c.Host()
	c.discover(time.Now())

	// Two samples of each kind: the first sets the baselines, the second
	// shows real values and what a sample costs.
	var full *wire.Sample
	var vitalsCost, fullCost time.Duration
	for i := 0; i < 2; i++ {
		t := time.Now()
		c.Sample(wire.DetailVitals)
		vitalsCost = time.Since(t)
		time.Sleep(100 * time.Millisecond)
	}
	for i := 0; i < 2; i++ {
		t := time.Now()
		full = c.Sample(wire.DetailFull)
		fullCost = time.Since(t)
		if i == 0 {
			time.Sleep(linuxProcMinGap)
		}
	}
	virtual := h.Virtualization != "" && h.Virtualization != "none"

	var checks []Check
	add := func(name string, ok bool, detail, fix string) {
		checks = append(checks, Check{Name: name, OK: ok, Detail: detail, Fix: fix})
	}

	// CPU
	if full.CPU == nil {
		add("CPU", false, "/proc/stat is not readable", "The agent needs /proc mounted with the usual permissions.")
	} else {
		d := fmt.Sprintf("%d logical cores", h.LogicalCores)
		if h.PhysicalCores > 0 && h.PhysicalCores != h.LogicalCores {
			d += fmt.Sprintf(" on %d physical", h.PhysicalCores)
		}
		if h.PerformanceCores+h.EfficiencyCores > 0 {
			d += fmt.Sprintf(", %d performance + %d efficiency (from %s)", h.PerformanceCores, h.EfficiencyCores, c.cpu.kindSource)
		}
		if c.cpu.hasFreq {
			d += "; clocks from cpufreq"
		} else {
			d += "; no clock readings (cpufreq is not exposed, as usual in virtual machines)"
		}
		add("CPU", true, d, "")
	}

	// Memory
	if full.Memory == nil {
		add("Memory", false, "/proc/meminfo is not readable", "")
	} else {
		d := linuxGiB(full.Memory.Total) + " of memory"
		if full.Memory.Swap != nil && full.Memory.Swap.Total > 0 {
			d += ", " + linuxGiB(full.Memory.Swap.Total) + " of swap"
		} else {
			d += ", no swap"
		}
		add("Memory", true, d, "")
	}

	// Pressure
	if full.Pressure != nil {
		add("Pressure", true, "CPU, memory and I/O stall times from /proc/pressure", "")
	} else {
		add("Pressure", false, "Pressure stall information (/proc/pressure) is not available",
			"PSI needs Linux 4.20 or later built with CONFIG_PSI. Some distributions build it but leave it off: add psi=1 to the kernel command line (for example in GRUB_CMDLINE_LINUX in /etc/default/grub, then sudo update-grub) and reboot.")
	}

	// GPU
	{
		var parts []string
		ok := true
		fix := ""
		for _, g := range c.gpu.cards {
			switch g.vendor {
			case "intel":
				if len(g.idle) == 0 {
					ok = false
					parts = append(parts, g.name+" ("+g.driver+"): no RC6 residency counters, so no busy time")
					fix = "Intel GPU busy time comes from RC6 residency in sysfs, which needs a recent i915 or xe driver."
				} else {
					parts = append(parts, g.name+" ("+g.driver+"): busy time from RC6 residency")
				}
			case "amd":
				parts = append(parts, g.name+" (amdgpu): gpu_busy_percent, VRAM, temperature and power")
			}
		}
		if c.nvidia != nil {
			parts = append(parts, "NVIDIA GPUs through nvidia-smi")
		} else if c.hasNVIDIADevice() {
			ok = false
			parts = append(parts, "an NVIDIA GPU, but no nvidia-smi")
			fix = "Install the NVIDIA driver utilities (nvidia-smi ships with the proprietary driver, for example the nvidia-utils package). The open nouveau driver reports no utilisation."
		}
		if len(parts) == 0 {
			add("GPU", true, "No Intel, AMD or NVIDIA GPU found", "")
		} else {
			add("GPU", ok, strings.Join(parts, "; "), fix)
		}
	}

	// Sensors
	{
		ts := &c.thermal
		hasCPU := false
		for _, s := range ts.sensors {
			hasCPU = hasCPU || s.category == "CPU"
		}
		chips := linuxUnique(ts.chips)
		var d string
		switch {
		case ts.zones:
			d = fmt.Sprintf("%d sensors from thermal zones (no hwmon CPU driver)", len(ts.sensors))
		case len(ts.sensors) > 0:
			d = fmt.Sprintf("%d sensors from %s", len(ts.sensors), strings.Join(chips, ", "))
		default:
			d = "No temperature sensors"
		}
		switch {
		case hasCPU:
			add("Sensors", true, d, "")
		case virtual:
			add("Sensors", false, d+". Virtual machines have no temperature sensors of their own.", "")
		default:
			add("Sensors", false, d+"; no CPU temperature", c.sensorFix())
		}
	}

	// Fans
	{
		n := 0
		if full.Thermal != nil {
			n = len(full.Thermal.Fans)
		}
		switch {
		case n > 0:
			var labels []string
			for _, f := range full.Thermal.Fans {
				labels = append(labels, fmt.Sprintf("%s %.0f rpm", f.Label, f.RPM))
			}
			add("Fans", true, strings.Join(labels, ", "), "")
		case virtual:
			add("Fans", false, "No fans (virtual machine)", "")
		case c.isArm():
			add("Fans", false, "No fan readings: this board exposes none (a Raspberry Pi 5 shows its fan once the official cooler is connected)", "")
		default:
			add("Fans", false, "No fan readings",
				"Fan speeds come from a Super I/O or embedded-controller driver. Install lm-sensors, run sudo sensors-detect and load the modules it suggests (for example nct6775 or it87 on desktop boards, dell_smm_hwmon or thinkpad_acpi on laptops). Some machines do not expose their fans to Linux at all.")
		}
	}

	// Power
	{
		ps := &c.power
		switch {
		case ps.packages > 0 && ps.deniedCores > 0:
			add("Power", true, "CPU package power from RAPL; the core subzone is not readable", linuxRAPLFix())
		case ps.packages > 0:
			d := "CPU package power from RAPL"
			if ps.cores > 0 {
				d = "CPU package and core power from RAPL"
			}
			add("Power", true, d, "")
		case ps.deniedPackages > 0:
			add("Power", false, "RAPL energy counters exist but are not readable by "+linuxUserName(), linuxRAPLFix())
		case len(c.battery.batteries) > 0:
			add("Power", true, "No RAPL counters; system power from the battery while it discharges", "")
		case virtual:
			add("Power", false, "No RAPL energy counters (virtual machines do not get them)", "")
		case c.isArm():
			add("Power", false, "No CPU power readings: Arm boards have no RAPL energy counters", "")
		default:
			fix := ""
			if strings.Contains(c.cpuVendor(), "Intel") || strings.Contains(c.cpuVendor(), "AMD") {
				fix = "Load the RAPL driver: sudo modprobe intel_rapl_msr (it serves AMD Zen too, from Linux 5.11)."
			}
			add("Power", false, "No RAPL energy counters (/sys/class/powercap/intel-rapl)", fix)
		}
	}

	// Battery
	if b := full.Battery; b != nil {
		state := "on battery"
		switch {
		case b.Charging:
			state = "charging"
		case b.PluggedIn:
			state = "plugged in"
		}
		add("Battery", true, fmt.Sprintf("%.0f %%, %s", b.Percentage*100, state), "")
	} else {
		add("Battery", true, "No battery", "")
	}

	// Network
	if n := full.Network; n != nil {
		d := fmt.Sprintf("%d interfaces counted", len(n.Interfaces))
		if n.PrimaryInterface != "" {
			d = "primary " + n.PrimaryInterface
			if n.LocalAddress != "" {
				d += " (" + n.LocalAddress + ")"
			}
			d += fmt.Sprintf(", %d listed", len(n.Interfaces))
		}
		add("Network", true, d, "")
	} else {
		add("Network", false, "/proc/net/dev is not readable", "")
	}

	// Disks
	if dk := full.Disk; dk != nil {
		var disks []string
		for name, d := range c.disk.devs {
			if d.whole {
				disks = append(disks, name)
			}
		}
		d := fmt.Sprintf("%d volumes", len(dk.Volumes))
		if len(disks) > 0 {
			d = strings.Join(linuxSorted(disks), ", ") + "; " + d
		}
		add("Disks", true, d, "")
	} else {
		add("Disks", false, "/proc/diskstats is not readable", "")
	}

	// Processes
	if p := full.Processes; p != nil {
		d := fmt.Sprintf("%d processes", p.Count)
		if os.Geteuid() != 0 {
			d += "; disk rates only for processes of " + linuxUserName() + " (the kernel shows other users' I/O to root only)"
		}
		add("Processes", true, d, "")
	} else {
		add("Processes", false, "/proc is not readable", "")
	}

	// System
	if s := full.System; s != nil {
		var parts []string
		if s.RebootRequired != nil && *s.RebootRequired {
			parts = append(parts, "reboot required ("+s.RebootReason+")")
		}
		if s.Updates != nil {
			parts = append(parts, fmt.Sprintf("%d updates", *s.Updates))
		}
		if s.Containers != nil {
			parts = append(parts, fmt.Sprintf("%d containers running", *s.Containers))
		}
		if c.failedUnits != nil {
			parts = append(parts, "failed units from systemctl")
		}
		if len(parts) == 0 {
			parts = append(parts, fmt.Sprintf("up %.0f hours", s.Uptime/3600))
		}
		add("System", true, strings.Join(parts, "; "), "")
	}

	add("Agent", true, fmt.Sprintf("a vitals sample takes %.1f ms, a full one %.1f ms; running in %s",
		float64(vitalsCost.Microseconds())/1000, float64(fullCost.Microseconds())/1000, linuxVirtName(h.Virtualization)), "")
	return checks
}

func linuxVirtName(v string) string {
	if v == "" || v == "none" {
		return "no virtual machine or container"
	}
	return v
}

// sensorFix suggests the hwmon driver for this CPU.
func (c *linuxCollector) sensorFix() string {
	switch v := c.cpuVendor(); {
	case strings.Contains(v, "Intel"):
		return "Load Intel's sensor driver: sudo modprobe coretemp, and keep it across reboots: echo coretemp | sudo tee /etc/modules-load.d/coretemp.conf. If that finds nothing, install lm-sensors and run sudo sensors-detect."
	case strings.Contains(v, "AMD"):
		return "Load AMD's sensor driver: sudo modprobe k10temp, and keep it across reboots: echo k10temp | sudo tee /etc/modules-load.d/k10temp.conf. If that finds nothing, install lm-sensors and run sudo sensors-detect."
	}
	return "Install lm-sensors and run sudo sensors-detect to find and load the sensor drivers for this board."
}

// cpuVendor returns "GenuineIntel", "AuthenticAMD" or "".
func (c *linuxCollector) cpuVendor() string {
	data, err := linuxReadFile(c.path("proc/cpuinfo"))
	if err != nil {
		return ""
	}
	v := linuxParseCPUInfo(data).vendorID
	switch v {
	case "GenuineIntel":
		return "Intel"
	case "AuthenticAMD":
		return "AMD"
	}
	return v
}

// isArm reports an Arm machine (cpuinfo names CPU parts, not a vendor).
func (c *linuxCollector) isArm() bool {
	data, err := linuxReadFile(c.path("proc/cpuinfo"))
	if err != nil {
		return false
	}
	info := linuxParseCPUInfo(data)
	return info.vendorID == "" && len(info.parts) > 0
}

// hasNVIDIADevice looks for an NVIDIA display controller on the PCI bus.
func (c *linuxCollector) hasNVIDIADevice() bool {
	base := c.path("sys/bus/pci/devices")
	for _, d := range linuxDirNames(base) {
		vendor, _ := linuxReadValue(filepath.Join(base, d, "vendor"))
		class, _ := linuxReadValue(filepath.Join(base, d, "class"))
		if vendor == "0x10de" && strings.HasPrefix(class, "0x03") {
			return true
		}
	}
	return false
}

func linuxUserName() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "this user"
}

func linuxUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func linuxSorted(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	return linuxSortedKeys(m)
}
