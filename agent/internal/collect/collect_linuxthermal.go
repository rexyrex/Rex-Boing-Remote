package collect

// Temperatures and fans from /sys/class/hwmon, with /sys/class/thermal as the
// fallback for boards whose CPU sensor has no hwmon device (Raspberry Pi and
// other Arm boards on some kernels). No build tag: see collect_linuxfs.go.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

const (
	// linuxRediscover is how often sensor, battery and RAPL paths are
	// listed again (modules load, USB drives come and go).
	linuxRediscover = 60 * time.Second
	// linuxSlowRead marks a sensor slow: some drivers (dell_smm, i2c chips)
	// take milliseconds per read, and a read blocks the sample.
	linuxSlowRead = 5 * time.Millisecond
	// linuxSlowEvery is how often slow sensors and drive temperatures are
	// read; their last value is repeated in between. An NVMe temperature is
	// an admin command to the drive (about 10 ms on a typical SSD), and
	// drives warm and cool slowly.
	linuxSlowEvery = 10 * time.Second
	// linuxSATAEvery spaces out drivetemp reads further: each is a SMART
	// command to a SATA drive.
	linuxSATAEvery = 30 * time.Second
)

// linuxTempSensor is one temperature input.
type linuxTempSensor struct {
	path     string
	key      string
	label    string
	category string
	headline bool     // feeds cpuCelsius, gpuCelsius, … and is read in vitals mode
	high     *float64 // the hardware's own limits
	crit     *float64
	pm       string        // runtime_status of the owning device (GPUs), "" when none
	every    time.Duration // read at most this often; 0 means every sample

	value  float64
	valid  bool
	readAt time.Time
}

// linuxFan is one fan tachometer.
type linuxFan struct {
	path    string
	label   string
	labeled bool
	pm      string
	minRPM  *float64
	maxRPM  *float64 // fanK_max when the chip reports it
	maxSeen float64
}

// linuxThermalState caches the discovered sensor files.
type linuxThermalState struct {
	discoveredAt time.Time
	sensors      []*linuxTempSensor
	fans         []*linuxFan
	chips        []string // hwmon chip names, for doctor
	zones        bool     // sensors came from thermal zones
	cpuCrit      *float64
}

var linuxCategoryRank = map[string]int{"CPU": 0, "GPU": 1, "SoC": 2, "Memory": 3, "Storage": 4, "Battery": 5, "Power": 6, "Ambient": 7, "Other": 8}

// linuxChipCategory classifies an hwmon chip by its driver name.
func linuxChipCategory(name string) string {
	switch {
	case name == "soc_thermal" || name == "soc-thermal":
		return "SoC"
	case name == "coretemp" || name == "k10temp" || name == "k8temp" || name == "zenpower" ||
		name == "via_cputemp" || strings.HasPrefix(name, "cpu"):
		return "CPU"
	case name == "amdgpu" || name == "nouveau" || name == "i915" || name == "xe" || name == "radeon":
		return "GPU"
	case name == "nvme" || name == "drivetemp":
		return "Storage"
	case strings.HasPrefix(name, "BAT") || name == "battery" || strings.HasSuffix(name, "_battery"):
		return "Battery"
	case name == "jc42" || name == "spd5118":
		return "Memory"
	}
	return "Other"
}

// linuxShortKey makes a grid key: lowercase letters and digits, ≤ 8 chars.
func linuxShortKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			if b.Len() == 8 {
				break
			}
		}
	}
	return b.String()
}

// linuxIndexed returns the K of every "<prefix>K_input" file, in order.
func linuxIndexed(files []string, prefix string) []int {
	var out []int
	for _, f := range files {
		if !strings.HasPrefix(f, prefix) || !strings.HasSuffix(f, "_input") {
			continue
		}
		if k, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(f, prefix), "_input")); err == nil {
			out = append(out, k)
		}
	}
	sort.Ints(out)
	return out
}

// linuxNaturalLess orders "hwmon2" before "hwmon10".
func linuxNaturalLess(a, b string) bool { return linuxCompareVersions(a, b) < 0 }

// linuxPlausibleTemp rejects placeholder readings (-273, 65261, 127 from
// unconnected inputs is not caught, but nothing real is outside this range).
func linuxPlausibleTemp(c float64) bool { return c > -40 && c < 150 }

// linuxLimit reads a millidegree limit, ignoring nonsense such as the
// 65261.85 °C some NVMe drives report as a sensor maximum.
func linuxLimit(path string) *float64 {
	v, ok := linuxReadInt(path)
	if !ok {
		return nil
	}
	c := float64(v) / 1000
	if c <= 0 || c >= 200 {
		return nil
	}
	return &c
}

// linuxHwmonChip is one /sys/class/hwmon/hwmonN during discovery.
type linuxHwmonChip struct {
	name  string
	dir   string
	files []string
}

// discoverThermal lists every hwmon chip (and, without a CPU sensor, the
// thermal zones), keeping per-sensor state of sensors already known.
func (c *linuxCollector) discoverThermal(now time.Time) {
	ts := &c.thermal
	old := map[string]*linuxTempSensor{}
	for _, s := range ts.sensors {
		old[s.path] = s
	}
	oldFans := map[string]*linuxFan{}
	for _, f := range ts.fans {
		oldFans[f.path] = f
	}

	var chips []linuxHwmonChip
	names := linuxDirNames(c.path("sys/class/hwmon"))
	sort.SliceStable(names, func(a, b int) bool { return linuxNaturalLess(names[a], names[b]) })
	for _, h := range names {
		dir := c.path("sys/class/hwmon", h)
		name, err := linuxReadValue(filepath.Join(dir, "name"))
		if err != nil {
			// Kernels before 3.15 kept the attributes on the parent device.
			dir = filepath.Join(dir, "device")
			if name, err = linuxReadValue(filepath.Join(dir, "name")); err != nil {
				continue
			}
		}
		chips = append(chips, linuxHwmonChip{name: name, dir: dir, files: linuxDirNames(dir)})
	}

	nvmeChips, coretempChips := 0, 0
	for _, ch := range chips {
		switch ch.name {
		case "nvme":
			nvmeChips++
		case "coretemp":
			coretempChips++
		}
	}

	var sensors []*linuxTempSensor
	var fans []*linuxFan
	var chipNames []string
	counters := map[string]int{} // running numbers across chips of one kind
	for _, ch := range chips {
		if len(linuxIndexed(ch.files, "temp")) > 0 || len(linuxIndexed(ch.files, "fan")) > 0 {
			chipNames = append(chipNames, ch.name)
		}
		category := linuxChipCategory(ch.name)
		pm := ""
		if category == "GPU" {
			if p := filepath.Join(ch.dir, "device/power/runtime_status"); linuxExists(p) {
				pm = p
			}
		}
		ordinal := counters["chip:"+ch.name]
		counters["chip:"+ch.name]++
		devName := c.hwmonDeviceName(ch, ordinal)

		var chipSensors []*linuxTempSensor
		for _, k := range linuxIndexed(ch.files, "temp") {
			base := filepath.Join(ch.dir, "temp"+strconv.Itoa(k))
			label, _ := linuxReadValue(base + "_label")
			s := &linuxTempSensor{path: base + "_input", category: category, pm: pm}
			s.key, s.label, s.headline = linuxSensorName(ch.name, k, label, devName, ordinal, nvmeChips > 1, coretempChips > 1, counters)
			s.high, s.crit = linuxLimit(base+"_max"), linuxLimit(base+"_crit")
			switch {
			case ch.name == "drivetemp":
				s.every = linuxSATAEvery
			case category == "Storage":
				s.every = linuxSlowEvery
			}
			if prev, ok := old[s.path]; ok {
				s.value, s.valid, s.readAt = prev.value, prev.valid, prev.readAt
				if prev.every > s.every {
					s.every = prev.every
				}
			}
			chipSensors = append(chipSensors, s)
		}
		linuxPickHeadlines(category, chipSensors)
		sensors = append(sensors, chipSensors...)

		for _, k := range linuxIndexed(ch.files, "fan") {
			base := filepath.Join(ch.dir, "fan"+strconv.Itoa(k))
			label, _ := linuxReadValue(base + "_label")
			f := &linuxFan{path: base + "_input", label: linuxFanLabel(ch.name, k, label), labeled: label != "" || category == "GPU", pm: pm}
			if v, ok := linuxReadUint(base + "_min"); ok {
				f.minRPM = wire.F(float64(v))
			}
			if v, ok := linuxReadUint(base + "_max"); ok && v > 0 {
				f.maxRPM = wire.F(float64(v))
			}
			if prev, ok := oldFans[f.path]; ok {
				f.maxSeen = prev.maxSeen
			}
			fans = append(fans, f)
		}
	}

	hasCPU := false
	for _, s := range sensors {
		hasCPU = hasCPU || s.category == "CPU"
	}
	ts.zones = false
	if !hasCPU {
		zs := c.discoverThermalZones(old)
		if len(zs) > 0 {
			ts.zones = true
			sensors = append(sensors, zs...)
		}
	}

	sort.SliceStable(sensors, func(a, b int) bool {
		return linuxCategoryRank[sensors[a].category] < linuxCategoryRank[sensors[b].category]
	})
	linuxDedupeKeys(sensors)

	ts.cpuCrit = nil
	for _, s := range sensors {
		if s.category == "CPU" && s.headline && s.crit != nil && (ts.cpuCrit == nil || *s.crit < *ts.cpuCrit) {
			ts.cpuCrit = s.crit
		}
	}
	ts.sensors, ts.fans, ts.chips, ts.discoveredAt = sensors, fans, chipNames, now
}

// linuxPickHeadlines settles which sensors of one chip are headlines. Tdie,
// when present, replaces Tctl (which carries a fan-control offset on some
// Ryzen parts). A CPU, SoC or GPU chip without any headline (a coretemp of an
// old CPU with only per-core sensors) uses all of its sensors.
func linuxPickHeadlines(category string, sensors []*linuxTempSensor) {
	hasHead, hasTdie := false, false
	for _, s := range sensors {
		hasHead = hasHead || s.headline
		hasTdie = hasTdie || s.key == "tdie"
	}
	if hasTdie {
		for _, s := range sensors {
			if s.key == "tctl" {
				s.headline = false
			}
		}
	}
	if !hasHead && (category == "CPU" || category == "SoC" || category == "GPU") {
		for _, s := range sensors {
			s.headline = true
		}
	}
}

// hwmonDeviceName finds the device behind a storage chip ("nvme0", "sda").
func (c *linuxCollector) hwmonDeviceName(ch linuxHwmonChip, ordinal int) string {
	switch ch.name {
	case "nvme":
		if target, err := os.Readlink(filepath.Join(ch.dir, "device")); err == nil {
			if b := filepath.Base(target); strings.HasPrefix(b, "nvme") {
				return b
			}
		}
		if data, err := linuxReadFile(filepath.Join(ch.dir, "device/uevent")); err == nil {
			if dev := linuxParseKV(data)["DEVNAME"]; dev != "" {
				return filepath.Base(dev)
			}
		}
		return "nvme" + strconv.Itoa(ordinal)
	case "drivetemp":
		if blocks := linuxDirNames(filepath.Join(ch.dir, "device/block")); len(blocks) > 0 {
			return blocks[0]
		}
		return "disk" + strconv.Itoa(ordinal)
	}
	return ""
}

// linuxSensorName gives a sensor its short key, full label and whether it
// is a headline sensor. counters numbers sensors across chips of one kind.
func linuxSensorName(chip string, k int, label, devName string, ordinal int, multiNVMe, multiCPU bool, counters map[string]int) (key, full string, headline bool) {
	idx := strconv.Itoa(k)
	lower := strings.ToLower(label)
	switch chip {
	case "coretemp":
		switch {
		case strings.HasPrefix(label, "Package id ") || strings.HasPrefix(label, "Physical id "):
			if multiCPU {
				n := strings.TrimSpace(label[strings.LastIndexByte(label, ' ')+1:])
				return "pkg" + n, "CPU package " + n, true
			}
			return "pkg", "CPU package", true
		case strings.HasPrefix(label, "Core "):
			n := strings.TrimSpace(strings.TrimPrefix(label, "Core "))
			if multiCPU {
				return "p" + strconv.Itoa(ordinal) + "c" + n, "CPU " + strconv.Itoa(ordinal) + " core " + n, false
			}
			return "c" + n, "Core " + n, false
		}
	case "k10temp", "zenpower", "k8temp":
		switch {
		case label == "Tdie":
			return "tdie", "CPU die", true
		case label == "Tctl":
			return "tctl", "CPU Tctl", true
		case strings.HasPrefix(label, "Tccd"):
			n := strings.TrimPrefix(label, "Tccd")
			return "ccd" + n, "CPU CCD " + n, false
		case label == "":
			return "cpu", "CPU", true
		}
	case "amdgpu":
		switch lower {
		case "edge", "":
			return "gpu", "GPU edge", true
		case "junction":
			return "gpuj", "GPU junction", false
		case "mem":
			return "gpumem", "GPU memory", false
		}
	case "nouveau", "radeon", "i915", "xe":
		if label == "" {
			return "gpu", "GPU", k == 1
		}
		return linuxShortKey("gpu" + label), "GPU " + label, k == 1
	case "nvme":
		drive := ""
		keyBase := devName
		if multiNVMe {
			drive = strings.TrimPrefix(devName, "nvme") + " "
		}
		switch {
		case label == "Composite" || label == "":
			return keyBase, "NVMe " + drive + "Composite", true
		case strings.HasPrefix(label, "Sensor "):
			n := strings.TrimPrefix(label, "Sensor ")
			return linuxShortKey(keyBase + "s" + n), "NVMe " + drive + "Sensor " + n, false
		}
		return linuxShortKey(keyBase + label), "NVMe " + drive + label, false
	case "drivetemp":
		return linuxShortKey(devName), "Drive " + devName, true
	case "acpitz":
		counters["acpitz"]++
		n := strconv.Itoa(counters["acpitz"])
		return "acpi" + n, "ACPI zone " + n, false
	case "jc42", "spd5118":
		counters["dimm"]++
		n := strconv.Itoa(counters["dimm"] - 1)
		return "dimm" + n, "Memory DIMM " + n, false
	}
	switch {
	case strings.HasPrefix(chip, "cpu"):
		if k == 1 && label == "" {
			return "cpu", "CPU", true
		}
		return linuxShortKey("cpu" + label + idx), "CPU " + label, true
	case chip == "soc_thermal" || chip == "soc-thermal":
		return "soc", "SoC", true
	case strings.HasPrefix(chip, "pch_"):
		return "pch", "PCH", false
	case strings.HasPrefix(chip, "iwlwifi"):
		return "wifi", "Wi-Fi", false
	case linuxChipCategory(chip) == "Battery":
		return "bat", "Battery", true
	}
	if label != "" {
		return linuxShortKey(label), label, false
	}
	return linuxShortKey(chip + idx), chip + " " + idx, false
}

// linuxDedupeKeys keeps keys unique within a sample ("c0", "c0-2", …).
func linuxDedupeKeys(sensors []*linuxTempSensor) {
	seen := map[string]int{}
	for _, s := range sensors {
		if s.key == "" {
			s.key = "t"
		}
		n := seen[s.key]
		seen[s.key] = n + 1
		if n == 0 {
			continue
		}
		for {
			n++
			suffix := "-" + strconv.Itoa(n)
			base := s.key
			if len(base)+len(suffix) > 8 {
				base = base[:8-len(suffix)]
			}
			if _, taken := seen[base+suffix]; !taken {
				s.key = base + suffix
				seen[s.key] = 1
				break
			}
		}
	}
}

// linuxFanLabel prettifies "cpu_fan" into "CPU fan".
func linuxFanLabel(chip string, k int, label string) string {
	if label == "" {
		if linuxChipCategory(chip) == "GPU" {
			return "GPU fan"
		}
		return "Fan " + strconv.Itoa(k)
	}
	words := strings.Fields(strings.ReplaceAll(label, "_", " "))
	for i, w := range words {
		switch strings.ToLower(w) {
		case "cpu", "gpu", "psu", "pch", "vrm", "sys":
			words[i] = strings.ToUpper(w)
		default:
			if i == 0 {
				words[i] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
	}
	return strings.Join(words, " ")
}

// discoverThermalZones turns thermal zones without their own hwmon device
// into sensors. Zones that have one are already covered by hwmon.
func (c *linuxCollector) discoverThermalZones(old map[string]*linuxTempSensor) []*linuxTempSensor {
	var out []*linuxTempSensor
	names := linuxDirNames(c.path("sys/class/thermal"))
	sort.SliceStable(names, func(a, b int) bool { return linuxNaturalLess(names[a], names[b]) })
	for _, z := range names {
		if !strings.HasPrefix(z, "thermal_zone") {
			continue
		}
		dir := c.path("sys/class/thermal", z)
		files := linuxDirNames(dir)
		covered := false
		for _, f := range files {
			covered = covered || strings.HasPrefix(f, "hwmon")
		}
		typ, err := linuxReadValue(filepath.Join(dir, "type"))
		if covered || err != nil || typ == "INT3400 Thermal" { // INT3400 is DPTF's manager, not a sensor
			continue
		}
		s := &linuxTempSensor{path: filepath.Join(dir, "temp")}
		s.key, s.label, s.category, s.headline = linuxZoneName(typ)
		for _, f := range files {
			if strings.HasPrefix(f, "trip_point_") && strings.HasSuffix(f, "_type") {
				if t, _ := linuxReadValue(filepath.Join(dir, f)); t == "critical" {
					s.crit = linuxLimit(filepath.Join(dir, strings.TrimSuffix(f, "_type")+"_temp"))
				}
			}
		}
		if prev, ok := old[s.path]; ok {
			s.every, s.value, s.valid, s.readAt = prev.every, prev.value, prev.valid, prev.readAt
		}
		out = append(out, s)
	}
	return out
}

// linuxZoneName classifies a thermal zone by its type.
func linuxZoneName(typ string) (key, label, category string, headline bool) {
	t := strings.ToLower(typ)
	base := t
	for _, suffix := range []string{"-thermal", "_thermal", "_temp", "-temp"} {
		base = strings.TrimSuffix(base, suffix)
	}
	switch {
	case strings.Contains(t, "x86_pkg"):
		return "pkg", "CPU package", "CPU", true
	case base == "cpu" || base == "cpu0" || base == "cpuss":
		return "cpu", "CPU", "CPU", true
	case strings.Contains(t, "cpu") || strings.Contains(t, "core"):
		return linuxShortKey(base), "CPU " + base, "CPU", true
	case strings.Contains(t, "soc"):
		return "soc", "SoC", "SoC", true
	case strings.Contains(t, "gpu"):
		return "gpu", "GPU", "GPU", true
	case strings.Contains(t, "ddr") || strings.Contains(t, "mem"):
		return linuxShortKey(base), "Memory " + base, "Memory", false
	case strings.Contains(t, "batt"):
		return "bat", "Battery", "Battery", true
	case strings.Contains(t, "nvme") || strings.Contains(t, "ssd"):
		return linuxShortKey(base), "Storage " + base, "Storage", false
	case t == "acpitz":
		return "acpi", "ACPI zone", "Other", false
	}
	return linuxShortKey(base), typ, "Other", false
}

// sampleThermal reads the sensors: all of them in full mode, only the
// headline ones in vitals mode. gpus supplies NVIDIA and AMD readings.
func (c *linuxCollector) sampleThermal(full bool, gpus []wire.GPU, now time.Time) *wire.Thermal {
	ts := &c.thermal
	pmState := map[string]bool{} // runtime_status path → suspended, read once per sample
	suspended := func(path string) bool {
		if path == "" {
			return false
		}
		if v, ok := pmState[path]; ok {
			return v
		}
		s, _ := linuxReadValue(path)
		pmState[path] = s == "suspended"
		return pmState[path]
	}

	for _, s := range ts.sensors {
		if !full && !s.headline {
			continue
		}
		if suspended(s.pm) {
			s.valid = false
			continue
		}
		if s.every > 0 && !s.readAt.IsZero() && now.Sub(s.readAt) < s.every {
			continue // repeat the last value
		}
		start := time.Now()
		v, ok := linuxReadInt(s.path)
		if time.Since(start) > linuxSlowRead && s.every < linuxSlowEvery {
			s.every = linuxSlowEvery
		}
		s.readAt = now
		s.value = float64(v) / 1000
		s.valid = ok && linuxPlausibleTemp(s.value)
	}

	out := &wire.Thermal{}
	head := map[string]float64{}
	var peak float64
	havePeak := false
	for _, s := range ts.sensors {
		if !s.valid || (!full && !s.headline) {
			continue
		}
		v := float64(int(s.value*10+0.5)) / 10
		if full {
			out.Sensors = append(out.Sensors, wire.Sensor{Key: s.key, Label: s.label, Celsius: v, Category: s.category, High: s.high, Critical: s.crit})
		}
		if s.headline {
			if cur, ok := head[s.category]; !ok || v > cur {
				head[s.category] = v
			}
		}
		if (s.category == "CPU" || s.category == "GPU" || s.category == "SoC") && (full || s.headline) {
			if !havePeak || v > peak {
				peak, havePeak = v, true
			}
		}
	}
	for _, g := range gpus {
		if g.Celsius == nil {
			continue
		}
		if cur, ok := head["GPU"]; !ok || *g.Celsius > cur {
			head["GPU"] = *g.Celsius
		}
		if !havePeak || *g.Celsius > peak {
			peak, havePeak = *g.Celsius, true
		}
	}
	pick := func(cat string) *float64 {
		if v, ok := head[cat]; ok {
			return wire.F(v)
		}
		return nil
	}
	out.CPUCelsius, out.GPUCelsius, out.SoCCelsius = pick("CPU"), pick("GPU"), pick("SoC")
	out.StorageCelsius, out.BatteryCelsius = pick("Storage"), pick("Battery")
	if havePeak {
		out.PeakCelsius = wire.F(peak)
	}
	if out.CPUCelsius != nil {
		out.State = "nominal"
		if ts.cpuCrit != nil {
			switch margin := *ts.cpuCrit - *out.CPUCelsius; {
			case margin <= 3:
				out.State = "critical"
			case margin <= 10:
				out.State = "serious"
			}
		}
	}

	if full {
		for i, f := range ts.fans {
			if suspended(f.pm) {
				continue
			}
			v, ok := linuxReadUint(f.path)
			if !ok {
				continue
			}
			rpm := float64(v)
			if rpm > f.maxSeen {
				f.maxSeen = rpm
			}
			// Super I/O chips list every header; skip the unconnected ones
			// (no label, never seen spinning).
			if !f.labeled && f.maxSeen == 0 {
				continue
			}
			fan := wire.Fan{Index: i, Label: f.label, RPM: rpm, MinRPM: f.minRPM, MaxRPM: f.maxRPM}
			if fan.MinRPM == nil {
				fan.MinRPM = wire.F(0)
			}
			if fan.MaxRPM == nil && f.maxSeen > 0 {
				fan.MaxRPM = wire.F(f.maxSeen)
			}
			out.Fans = append(out.Fans, fan)
		}
	}
	if out.Sensors == nil && out.Fans == nil && out.CPUCelsius == nil && out.GPUCelsius == nil &&
		out.SoCCelsius == nil && out.StorageCelsius == nil && out.BatteryCelsius == nil {
		return nil
	}
	return out
}
