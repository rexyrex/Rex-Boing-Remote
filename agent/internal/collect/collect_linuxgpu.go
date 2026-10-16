package collect

// GPUs from /sys/class/drm (Intel i915/xe, AMD amdgpu) and nvidia-smi. No
// build tag: see collect_linuxfs.go.

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxGPU is one DRM card the collector can read.
type linuxGPU struct {
	card   string // "card0"
	dir    string // …/sys/class/drm/card0
	vendor string // intel, amd
	driver string
	pciID  string // "8086:7d51"
	name   string

	// runtimeStatus is device/power/runtime_status. Reading busy counters
	// of a runtime-suspended GPU wakes it up (amdgpu and i915 both take a
	// runtime-PM reference in those sysfs handlers), which would keep a
	// laptop's dGPU powered just to report that it is idle.
	runtimeStatus string

	// Intel: idle residency counters, one per GT. busy = 1 - Δidle/Δt.
	idle []*linuxGPUIdle
	// Intel clocks.
	actFreq string
	maxFreq *float64

	// AMD.
	busy, vramUsed, vramTotal             string
	hwTemp, hwPower, hwFan, hwPWM, hwFreq string
	maxClock                              *float64
}

type linuxGPUIdle struct {
	path   string
	engine string // render, media
	prev   uint64
	have   bool
}

// linuxGPUState caches the discovered cards.
type linuxGPUState struct {
	cards     []*linuxGPU
	cardNames string // the card list the cache was built from
	pciNames  map[string]string
}

// discoverGPUs lists /sys/class/drm/cardN and keeps cards already known, so
// their counters survive a rediscovery.
func (c *linuxCollector) discoverGPUs() {
	gs := &c.gpu
	var names []string
	for _, n := range linuxDirNames(c.path("sys/class/drm")) {
		if strings.HasPrefix(n, "card") && linuxNumeric(n[4:]) {
			names = append(names, n)
		}
	}
	key := strings.Join(names, ",")
	if key == gs.cardNames && gs.cards != nil {
		return
	}
	known := map[string]*linuxGPU{}
	for _, g := range gs.cards {
		known[g.card] = g
	}
	cards := []*linuxGPU{}
	for _, n := range names {
		if g, ok := known[n]; ok {
			cards = append(cards, g)
			continue
		}
		if g := c.probeGPU(n); g != nil {
			cards = append(cards, g)
		}
	}
	gs.cards, gs.cardNames = cards, key
}

// probeGPU inspects one card. Cards of drivers we cannot read (vc4, simpledrm,
// nvidia, which nvidia-smi covers) return nil.
func (c *linuxCollector) probeGPU(card string) *linuxGPU {
	dir := c.path("sys/class/drm", card)
	dev := filepath.Join(dir, "device")
	uevent, err := linuxReadFile(filepath.Join(dev, "uevent"))
	if err != nil {
		return nil
	}
	kv := linuxParseKV(uevent)
	g := &linuxGPU{card: card, dir: dir, driver: kv["DRIVER"], pciID: strings.ToLower(kv["PCI_ID"])}
	switch {
	case g.driver == "i915" || g.driver == "xe":
		g.vendor = "intel"
	case g.driver == "amdgpu":
		g.vendor = "amd"
	default:
		return nil
	}
	g.runtimeStatus = filepath.Join(dev, "power/runtime_status")
	if !linuxExists(g.runtimeStatus) {
		g.runtimeStatus = ""
	}
	g.name = c.gpuName(g, dev)

	switch g.vendor {
	case "intel":
		c.probeIntelGPU(g, dev)
	case "amd":
		c.probeAMDGPU(g, dev)
	}
	return g
}

func (c *linuxCollector) probeIntelGPU(g *linuxGPU, dev string) {
	// i915: card/gt/gtN/rc6_residency_ms (gt0 renders, gt1 is the media GT
	// of Meteor Lake and later), or the older card/power/rc6_residency_ms.
	for _, gt := range linuxDirNames(filepath.Join(g.dir, "gt")) {
		p := filepath.Join(g.dir, "gt", gt, "rc6_residency_ms")
		if !strings.HasPrefix(gt, "gt") || !linuxExists(p) {
			continue
		}
		engine := "render"
		if gt != "gt0" {
			engine = "media"
			if gt != "gt1" {
				engine = gt
			}
		}
		g.idle = append(g.idle, &linuxGPUIdle{path: p, engine: engine})
	}
	if len(g.idle) == 0 {
		if p := filepath.Join(g.dir, "power/rc6_residency_ms"); linuxExists(p) {
			g.idle = append(g.idle, &linuxGPUIdle{path: p, engine: "render"})
		}
	}
	// xe: device/tileN/gtM/gtidle/idle_residency_ms, named gtM-rc / gtM-mc.
	if len(g.idle) == 0 {
		for _, tile := range linuxDirNames(dev) {
			if !strings.HasPrefix(tile, "tile") {
				continue
			}
			for _, gt := range linuxDirNames(filepath.Join(dev, tile)) {
				p := filepath.Join(dev, tile, gt, "gtidle/idle_residency_ms")
				if !strings.HasPrefix(gt, "gt") || !linuxExists(p) {
					continue
				}
				engine := "render"
				if name, _ := linuxReadValue(filepath.Join(dev, tile, gt, "gtidle/name")); strings.HasSuffix(name, "-mc") {
					engine = "media"
				}
				g.idle = append(g.idle, &linuxGPUIdle{path: p, engine: engine})
				if g.actFreq == "" {
					if f := filepath.Join(dev, tile, gt, "freq0/act_freq"); linuxExists(f) {
						g.actFreq = f
						if v, ok := linuxReadUint(filepath.Join(dev, tile, gt, "freq0/max_freq")); ok && v > 0 {
							g.maxFreq = wire.F(float64(v))
						}
					}
				}
			}
		}
	}
	if g.actFreq == "" {
		for _, p := range []string{filepath.Join(g.dir, "gt_act_freq_mhz"), filepath.Join(g.dir, "gt/gt0/rps_act_freq_mhz")} {
			if linuxExists(p) {
				g.actFreq = p
				break
			}
		}
		for _, p := range []string{filepath.Join(g.dir, "gt_max_freq_mhz"), filepath.Join(g.dir, "gt/gt0/rps_max_freq_mhz")} {
			if v, ok := linuxReadUint(p); ok && v > 0 {
				g.maxFreq = wire.F(float64(v))
				break
			}
		}
	}
}

func (c *linuxCollector) probeAMDGPU(g *linuxGPU, dev string) {
	set := func(dst *string, p string) {
		if linuxExists(p) {
			*dst = p
		}
	}
	set(&g.busy, filepath.Join(dev, "gpu_busy_percent"))
	set(&g.vramUsed, filepath.Join(dev, "mem_info_vram_used"))
	set(&g.vramTotal, filepath.Join(dev, "mem_info_vram_total"))
	for _, h := range linuxDirNames(filepath.Join(dev, "hwmon")) {
		hw := filepath.Join(dev, "hwmon", h)
		set(&g.hwTemp, filepath.Join(hw, "temp1_input"))
		// Newer kernels report instantaneous power1_input on some ASICs and
		// drop power1_average; prefer the average when both exist.
		set(&g.hwPower, filepath.Join(hw, "power1_input"))
		set(&g.hwPower, filepath.Join(hw, "power1_average"))
		set(&g.hwFan, filepath.Join(hw, "fan1_input"))
		set(&g.hwPWM, filepath.Join(hw, "pwm1"))
		set(&g.hwFreq, filepath.Join(hw, "freq1_input"))
		break
	}
	if !c.gpuSuspended(g) {
		// pp_dpm_sclk lists the shader clock states: "2: 2482Mhz *".
		if data, err := linuxReadFile(filepath.Join(dev, "pp_dpm_sclk")); err == nil {
			var hi float64
			for _, line := range strings.Split(string(data), "\n") {
				f := strings.Fields(line)
				if len(f) < 2 {
					continue
				}
				v := strings.TrimSuffix(strings.TrimSuffix(f[1], "Mhz"), "MHz")
				if mhz, err := strconv.ParseFloat(v, 64); err == nil && mhz > hi {
					hi = mhz
				}
			}
			if hi > 0 {
				g.maxClock = wire.F(hi)
			}
		}
	}
}

// gpuSuspended reports whether the GPU is runtime-suspended (and therefore
// idle, and must not be woken by reading it).
func (c *linuxCollector) gpuSuspended(g *linuxGPU) bool {
	if g.runtimeStatus == "" {
		return false
	}
	s, err := linuxReadValue(g.runtimeStatus)
	return err == nil && s == "suspended"
}

// gpuName names a card from pci.ids, the ACPI label, or the vendor.
func (c *linuxCollector) gpuName(g *linuxGPU, dev string) string {
	if v, d, ok := strings.Cut(g.pciID, ":"); ok {
		if name := c.pciDeviceName(v, d); name != "" {
			return linuxGPUDisplayName(g.vendor, name)
		}
	}
	if label, err := linuxReadValue(filepath.Join(dev, "label")); err == nil && label != "" &&
		!strings.HasPrefix(strings.ToLower(label), "onboard") {
		return label
	}
	if g.vendor == "intel" {
		return "Intel GPU"
	}
	return "AMD GPU"
}

// linuxGPUDisplayName turns a pci.ids device name into a display name:
// "Arrow Lake-P [Intel Graphics]" → "Intel Graphics", "Navi 31 [Radeon RX
// 7900 XT/7900 XTX]" → "AMD Radeon RX 7900 XT/7900 XTX".
func linuxGPUDisplayName(vendor, pci string) string {
	name := pci
	if i := strings.IndexByte(pci, '['); i >= 0 {
		if j := strings.LastIndexByte(pci, ']'); j > i {
			name = strings.TrimSpace(pci[i+1 : j])
		}
	}
	prefix := map[string]string{"intel": "Intel", "amd": "AMD", "nvidia": "NVIDIA"}[vendor]
	if prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
		name = prefix + " " + name
	}
	return name
}

// pciDeviceName looks a vendor:device pair up in pci.ids, the database lspci
// uses, without running lspci. Results are cached; the file is scanned at
// most once per device.
func (c *linuxCollector) pciDeviceName(vendor, device string) string {
	key := vendor + ":" + device
	if name, ok := c.gpu.pciNames[key]; ok {
		return name
	}
	if c.gpu.pciNames == nil {
		c.gpu.pciNames = map[string]string{}
	}
	name := ""
	for _, p := range []string{"usr/share/misc/pci.ids", "usr/share/hwdata/pci.ids", "usr/share/pci.ids"} {
		if name = linuxLookupPCIIDs(c.path(p), vendor, device); name != "" {
			break
		}
	}
	c.gpu.pciNames[key] = name
	return name
}

// linuxLookupPCIIDs scans one pci.ids file. Vendor lines start in column 0
// ("8086  Intel Corporation"), their devices follow indented by one tab.
func linuxLookupPCIIDs(path, vendor, device string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inVendor := false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] != '\t' {
			if inVendor {
				return "" // past our vendor's block
			}
			inVendor = strings.HasPrefix(line, vendor+"  ")
			continue
		}
		if inVendor && len(line) > 1 && line[1] != '\t' && strings.HasPrefix(line[1:], device+"  ") {
			return strings.TrimSpace(line[1+len(device):])
		}
	}
	return ""
}

// sampleGPUs reads every card plus nvidia-smi's latest values.
func (c *linuxCollector) sampleGPUs(interval float64, resync, full bool) []wire.GPU {
	var out []wire.GPU
	for _, g := range c.gpu.cards {
		w := wire.GPU{Name: g.name, Vendor: g.vendor}
		suspended := c.gpuSuspended(g)
		switch g.vendor {
		case "intel":
			c.sampleIntelGPU(g, &w, interval, resync, suspended)
		case "amd":
			c.sampleAMDGPU(g, &w, suspended)
		}
		out = append(out, w)
	}
	if c.nvidia != nil {
		for _, g := range c.nvidia.GPUs() {
			g.Engines = linuxCopyEngines(g.Engines) // never alias the reader's cache
			out = append(out, g)
		}
	}
	// Most important first: discrete vendors before Intel's integrated GPU.
	rank := func(v string) int {
		switch v {
		case "nvidia":
			return 0
		case "amd":
			return 1
		case "intel":
			return 2
		}
		return 3
	}
	sort.SliceStable(out, func(a, b int) bool { return rank(out[a].Vendor) < rank(out[b].Vendor) })
	return out
}

func linuxCopyEngines(m map[string]float64) map[string]float64 {
	if m == nil {
		return nil
	}
	cp := make(map[string]float64, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func (c *linuxCollector) sampleIntelGPU(g *linuxGPU, w *wire.GPU, interval float64, resync, suspended bool) {
	engines := map[string]float64{}
	for _, idle := range g.idle {
		if suspended {
			// Asleep means idle; re-baseline when it wakes.
			idle.have = false
			engines[idle.engine] = 0
			continue
		}
		v, ok := linuxReadUint(idle.path)
		if !ok {
			idle.have = false
			continue
		}
		busy := 0.0
		if idle.have && !resync && interval > 0 && v >= idle.prev {
			busy = linuxClamp01(1 - float64(v-idle.prev)/(interval*1000))
		}
		idle.prev, idle.have = v, true
		engines[idle.engine] = busy
		if busy > w.Utilization {
			w.Utilization = busy
		}
	}
	if len(engines) > 0 {
		w.Engines = engines
	}
	if g.actFreq != "" && !suspended {
		if v, ok := linuxReadUint(g.actFreq); ok {
			w.ClockMHz = wire.F(float64(v))
		}
	} else if suspended {
		w.ClockMHz = wire.F(0)
	}
	w.MaxClockMHz = g.maxFreq
}

func (c *linuxCollector) sampleAMDGPU(g *linuxGPU, w *wire.GPU, suspended bool) {
	w.MaxClockMHz = g.maxClock
	if suspended {
		return // utilization 0; everything else would wake it
	}
	readU := func(p string) (uint64, bool) {
		if p == "" {
			return 0, false
		}
		return linuxReadUint(p)
	}
	if v, ok := readU(g.busy); ok {
		w.Utilization = linuxClamp01(float64(v) / 100)
	}
	if v, ok := readU(g.vramUsed); ok {
		w.MemoryUsed = wire.U(v)
	}
	if v, ok := readU(g.vramTotal); ok {
		w.MemoryTotal = wire.U(v)
	}
	if g.hwTemp != "" {
		if v, ok := linuxReadInt(g.hwTemp); ok {
			if t := float64(v) / 1000; linuxPlausibleTemp(t) {
				w.Celsius = wire.F(t)
			}
		}
	}
	if v, ok := readU(g.hwPower); ok {
		w.Watts = wire.F(float64(v) / 1e6)
	}
	if v, ok := readU(g.hwFan); ok {
		w.FanRPM = wire.F(float64(v))
	}
	if v, ok := readU(g.hwPWM); ok {
		w.FanPercent = wire.F(float64(int(float64(v)/255*1000+0.5)) / 10)
	}
	if v, ok := readU(g.hwFreq); ok {
		w.ClockMHz = wire.F(float64(v) / 1e6)
	}
}
