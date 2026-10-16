package collect

// The hello's host description: names, cores, memory, virtualization. No
// build tag: see collect_linuxfs.go.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxCPUInfo is what the host description needs from /proc/cpuinfo.
type linuxCPUInfo struct {
	modelName string
	vendorID  string
	hardware  string
	model     string // "Model" (Raspberry Pi)
	parts     []string
	flags     string
	cores     map[string]bool // "physical id/core id"
}

func linuxParseCPUInfo(data []byte) linuxCPUInfo {
	info := linuxCPUInfo{cores: map[string]bool{}}
	physical := ""
	seenPart := map[string]bool{}
	implementer := ""
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "model name":
			if info.modelName == "" {
				info.modelName = v
			}
		case "vendor_id":
			info.vendorID = v
		case "Hardware":
			info.hardware = v
		case "Model":
			info.model = v
		case "flags", "Features":
			if info.flags == "" {
				info.flags = " " + v + " "
			}
		case "physical id":
			physical = v
		case "core id":
			info.cores[physical+"/"+v] = true
		case "CPU implementer":
			implementer = v
		case "CPU part":
			key := implementer + "/" + v
			if !seenPart[key] {
				seenPart[key] = true
				info.parts = append(info.parts, key)
			}
		}
	}
	return info
}

// linuxArmParts names common Arm cores by implementer/part.
var linuxArmParts = map[string]string{
	"0x41/0xd03": "Cortex-A53", "0x41/0xd04": "Cortex-A35", "0x41/0xd05": "Cortex-A55", "0x41/0xd07": "Cortex-A57",
	"0x41/0xd08": "Cortex-A72", "0x41/0xd09": "Cortex-A73", "0x41/0xd0a": "Cortex-A75", "0x41/0xd0b": "Cortex-A76",
	"0x41/0xd0c": "Neoverse N1", "0x41/0xd0d": "Cortex-A77", "0x41/0xd40": "Neoverse V1", "0x41/0xd41": "Cortex-A78",
	"0x41/0xd44": "Cortex-X1", "0x41/0xd46": "Cortex-A510", "0x41/0xd47": "Cortex-A710", "0x41/0xd48": "Cortex-X2",
	"0x41/0xd49": "Neoverse N2", "0x41/0xd4f": "Neoverse V2", "0x41/0xd80": "Cortex-A520", "0x41/0xd81": "Cortex-A720",
	"0x41/0xd82": "Cortex-X4", "0x41/0xd87": "Cortex-A725", "0x41/0xd8e": "Neoverse N3", "0x41/0xc07": "Cortex-A7",
	"0x41/0xc09": "Cortex-A9", "0x41/0xc0f": "Cortex-A15", "0x41/0xb76": "ARM1176",
	"0xc0/0xac3": "Ampere-1", "0xc0/0xac4": "Ampere-1a", "0x61/0x022": "Apple M1", "0x61/0x023": "Apple M1",
}

var linuxChipNoise = regexp.MustCompile(`\((?:R|TM|r|tm)\)|®|™| CPU @ .*$| @ .*$| \d+-Core Processor$| Processor$| with Radeon.*$`)

// linuxChipName cleans "Intel(R) Core(TM) Ultra 7 255H" into "Intel Core
// Ultra 7 255H". On Arm, where "model name" is missing or just "ARMv7
// Processor", the cores are named from their part numbers.
func linuxChipName(info linuxCPUInfo, deviceTreeModel string) string {
	name := info.modelName
	if name == "" || strings.HasPrefix(name, "ARMv") {
		var parts []string
		for _, p := range info.parts {
			if n, ok := linuxArmParts[p]; ok {
				parts = append(parts, n)
			}
		}
		switch {
		case len(parts) > 0:
			return strings.Join(parts, " + ")
		case info.hardware != "":
			return info.hardware
		case info.model != "":
			return info.model
		case deviceTreeModel != "":
			return deviceTreeModel
		}
	}
	name = linuxChipNoise.ReplaceAllString(name, "") + " "
	if strings.Contains(name, "Intel") {
		name = strings.ReplaceAll(name, " CPU ", " ") // "Intel Xeon CPU E5-2680 v4"
	}
	name = strings.ReplaceAll(name, " Processor ", " ") // "AMD Opteron Processor 6272"
	return strings.Join(strings.Fields(name), " ")
}

// linuxPlaceholder reports DMI filler text that names nothing.
func linuxPlaceholder(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "to be filled by o.e.m.", "to be filled by o.e.m", "default string", "system product name",
		"system manufacturer", "system version", "o.e.m.", "oem", "not applicable", "none", "unknown",
		"not specified", "type1productconfigid", "all series", "x.x", "0123456789", "123456789",
		"product name", "default", "sku", "invalid", "n/a":
		return true
	}
	return false
}

// linuxCleanVendor shortens "ASUSTeK COMPUTER INC." to "ASUSTeK".
func linuxCleanVendor(v string) string {
	v = strings.TrimSpace(v)
	known := map[string]string{"LENOVO": "Lenovo", "Dell Inc.": "Dell", "Hewlett-Packard": "HP", "HP": "HP",
		"Micro-Star International Co., Ltd.": "MSI", "Micro-Star International Co., Ltd": "MSI",
		"Gigabyte Technology Co., Ltd.": "Gigabyte", "Super Micro Computer, Inc.": "Supermicro", "Supermicro": "Supermicro",
		"TOSHIBA": "Toshiba", "SAMSUNG ELECTRONICS CO., LTD.": "Samsung", "Intel Corporation": "Intel",
		"Apple Inc.": "Apple", "Microsoft Corporation": "Microsoft", "Framework": "Framework"}
	if k, ok := known[v]; ok {
		return k
	}
	for _, suffix := range []string{",", " Inc.", " INC.", " Inc", " Corporation", " CORPORATION", " Co., Ltd.", " CO., LTD.",
		" CO.,LTD.", " Co.,Ltd.", " Co.,Ltd", " CO.,LTD", " Co., Ltd", " Ltd.", " LTD.", " Ltd", " GmbH", " COMPUTER", " Computer", " Technology"} {
		v = strings.TrimSpace(strings.TrimSuffix(v, suffix))
	}
	for _, suffix := range []string{",", " COMPUTER", " Computer"} {
		v = strings.TrimSpace(strings.TrimSuffix(v, suffix))
	}
	return v
}

// buildHost describes the machine. It runs once per collector.
func (c *linuxCollector) buildHost() wire.Host {
	h := wire.Host{}
	if v, err := linuxReadValue(c.path("proc/sys/kernel/hostname")); err == nil && v != "" {
		h.Hostname = v
	} else if c.root == "/" {
		h.Hostname, _ = os.Hostname()
	}
	osr, err := linuxReadFile(c.path("etc/os-release"))
	if err != nil {
		osr, _ = linuxReadFile(c.path("usr/lib/os-release"))
	}
	if osr != nil {
		kv := linuxParseKV(osr)
		h.OSName = kv["NAME"]
		h.OSVersion = kv["VERSION"]
		if i := strings.Index(h.OSVersion, " ("); i > 0 { // "24.04.5 LTS (Noble Numbat)"
			h.OSVersion = h.OSVersion[:i]
		}
		if h.OSVersion == "" {
			h.OSVersion = kv["VERSION_ID"]
		}
		if h.OSVersion == "" {
			h.OSVersion = kv["BUILD_ID"] // Arch: "rolling"
		}
	}
	h.Kernel, _ = linuxReadValue(c.path("proc/sys/kernel/osrelease"))

	cpuinfo, _ := linuxReadFile(c.path("proc/cpuinfo"))
	info := linuxParseCPUInfo(cpuinfo)
	dtModel := ""
	if b, err := linuxReadFile(c.path("proc/device-tree/model")); err == nil {
		dtModel = strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
	}
	h.ChipName = linuxChipName(info, dtModel)

	dmi := func(name string) string {
		v, _ := linuxReadValue(c.path("sys/class/dmi/id", name))
		if linuxPlaceholder(v) {
			return ""
		}
		return v
	}
	vendor, model := dmi("sys_vendor"), dmi("product_name")
	if strings.EqualFold(vendor, "LENOVO") {
		// Lenovo puts the machine type in product_name and the name people
		// know ("ThinkPad X1 Carbon Gen 10") in product_version.
		if v := dmi("product_version"); v != "" {
			model = v
		}
	}
	if model == "" {
		model = dmi("board_name")
		if vendor == "" {
			vendor = dmi("board_vendor")
		}
	}
	if model == "" {
		model = dtModel
	}
	h.ModelName, h.Vendor = model, linuxCleanVendor(vendor)

	// Cores: logical from the online cpus, physical from distinct thread
	// sibling sets (works on Arm, which has no "core id" in cpuinfo).
	var st linuxStat
	if data, err := linuxReadFile(c.path("proc/stat")); err == nil {
		linuxParseStat(data, &st)
		if st.btime > 0 {
			h.BootTime = st.btime * 1000
		}
	}
	h.LogicalCores = len(st.ids)
	if len(st.ids) > 0 && !linuxSameInts(c.cpu.topoIDs, st.ids) {
		c.discoverCPUTopology(st.ids)
	}
	// A physical core is a distinct set of thread siblings; its kind is the
	// kind of its threads. P/E counts are physical cores, as on a Mac (an
	// i7-1260P is 4 P + 8 E with 16 threads).
	siblings := map[string]byte{}
	for i, id := range st.ids {
		dir := c.path("sys/devices/system/cpu", "cpu"+strconv.Itoa(id), "topology")
		s, err := linuxReadValue(filepath.Join(dir, "core_cpus_list"))
		if err != nil {
			s, err = linuxReadValue(filepath.Join(dir, "thread_siblings_list"))
		}
		if err == nil && s != "" {
			kind := byte('?')
			if i < len(c.cpu.kinds) {
				kind = c.cpu.kinds[i]
			}
			siblings[s] = kind
		}
	}
	switch {
	case len(siblings) > 0:
		h.PhysicalCores = len(siblings)
		for _, k := range siblings {
			switch k {
			case 'P':
				h.PerformanceCores++
			case 'E':
				h.EfficiencyCores++
			}
		}
	case len(info.cores) > 0:
		h.PhysicalCores = len(info.cores)
		h.PerformanceCores, h.EfficiencyCores = linuxKindCounts(c.cpu.kinds)
	default:
		h.PhysicalCores = h.LogicalCores
		h.PerformanceCores, h.EfficiencyCores = linuxKindCounts(c.cpu.kinds)
	}
	if data, err := linuxReadFile(c.path("proc/meminfo")); err == nil {
		h.MemoryBytes = linuxParseMeminfo(data).total
	}
	h.Virtualization = c.virtualization(info)
	return h
}

// virtualization names the container or hypervisor the agent runs in.
// Containers come first: a container on a VM is a container to its user.
func (c *linuxCollector) virtualization(info linuxCPUInfo) string {
	if linuxExists(c.path(".dockerenv")) {
		return "docker"
	}
	if linuxExists(c.path("run/.containerenv")) {
		return "podman"
	}
	if v, err := linuxReadValue(c.path("run/systemd/container")); err == nil && v != "" {
		switch {
		case strings.HasPrefix(v, "lxc"):
			return "lxc"
		case v == "systemd-nspawn":
			return "nspawn"
		}
		return v
	}
	if cg, err := linuxReadFile(c.path("proc/1/cgroup")); err == nil {
		s := string(cg)
		switch {
		case strings.Contains(s, "/docker/") || strings.Contains(s, "/docker-"):
			return "docker"
		case strings.Contains(s, "libpod"):
			return "podman"
		case strings.Contains(s, "/lxc/") || strings.Contains(s, "lxc.payload"):
			return "lxc"
		case strings.Contains(s, "kubepods"):
			return "kubernetes"
		}
	}
	if v, err := linuxReadValue(c.path("proc/version")); err == nil && strings.Contains(strings.ToLower(v), "microsoft") {
		return "wsl"
	}
	read := func(name string) string {
		v, _ := linuxReadValue(c.path("sys/class/dmi/id", name))
		return v
	}
	vendor, product := read("sys_vendor"), read("product_name")
	asset, bios := read("chassis_asset_tag"), read("bios_version")
	has := func(s, sub string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(sub)) }
	switch {
	case has(vendor, "Amazon EC2") || has(bios, "amazon"):
		return "aws"
	case has(vendor, "Google") || has(product, "Google Compute Engine"):
		return "gcp"
	case vendor == "Microsoft Corporation" && has(product, "Virtual Machine"):
		if asset == "7783-7084-3265-9085-8269-3286-77" { // Azure's fixed chassis tag
			return "azure"
		}
		return "hyperv"
	case has(asset, "OracleCloud"):
		return "oracle"
	case has(vendor, "DigitalOcean"):
		return "digitalocean"
	case has(vendor, "Hetzner"):
		return "hetzner"
	case has(vendor, "Linode") || has(vendor, "Akamai"):
		return "linode"
	case has(vendor, "Vultr"):
		return "vultr"
	case has(vendor, "Scaleway"):
		return "scaleway"
	case has(vendor, "Alibaba"):
		return "alibaba"
	case has(product, "OpenStack") || has(vendor, "OpenStack"):
		return "openstack"
	case has(vendor, "QEMU") || has(product, "KVM") || has(product, "QEMU"):
		return "kvm"
	case has(vendor, "VMware"):
		return "vmware"
	case has(vendor, "innotek") || has(product, "VirtualBox"):
		return "virtualbox"
	case has(vendor, "Parallels"):
		return "parallels"
	case has(vendor, "Xen"):
		return "xen"
	case has(vendor, "Apple") && has(product, "Virtual"):
		return "apple"
	case has(vendor, "Bochs"):
		return "bochs"
	}
	if strings.Contains(info.flags, " hypervisor ") {
		return "vm"
	}
	return "none"
}
