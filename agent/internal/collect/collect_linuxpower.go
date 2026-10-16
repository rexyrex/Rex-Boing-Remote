package collect

// CPU power from RAPL (/sys/class/powercap) and the battery from
// /sys/class/power_supply. No build tag: see collect_linuxfs.go.

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxRAPLUdevRule makes the energy counters readable again after every
// boot. Linux 5.10 made them root-only (CVE-2020-8694, a power side channel);
// on a server whose users can already see each other's processes the risk
// is small, and the rule is the user's explicit choice.
const (
	linuxRAPLRuleFile = "/etc/udev/rules.d/60-rex-boing-remote-rapl.rules"
	linuxRAPLRule     = `SUBSYSTEM=="powercap", ACTION=="add", RUN+="/bin/chmod a+r /sys%p/energy_uj"`
	linuxRAPLChmod    = "sudo chmod a+r /sys/class/powercap/intel-rapl:*/energy_uj"
)

// linuxRAPLFix is the doctor's fix text for unreadable RAPL counters.
func linuxRAPLFix() string {
	return "Linux makes the RAPL energy counters readable by root only. To let the agent read them, add a udev rule:\n" +
		"  echo '" + linuxRAPLRule + "' | sudo tee " + linuxRAPLRuleFile + "\n" +
		"and apply it now without rebooting:\n" +
		"  " + linuxRAPLChmod
}

// linuxRAPLZone is one readable energy counter.
type linuxRAPLZone struct {
	energy string // …/energy_uj
	kind   string // package, core
	max    uint64 // max_energy_range_uj: where the counter wraps
	prev   uint64
	have   bool
}

// linuxPowerState caches the RAPL zones.
type linuxPowerState struct {
	discoveredAt   time.Time
	zones          []*linuxRAPLZone
	present        bool // any RAPL zone exists
	packages       int  // readable package zones
	cores          int
	deniedPackages int
	deniedCores    int
}

// discoverRAPL finds package zones (intel-rapl:N, named package-N) and their
// core subzones (intel-rapl:N:M, named core). AMD Zen parts use the same
// tree. The MMIO duplicate (intel-rapl-mmio) is skipped.
func (c *linuxCollector) discoverRAPL(now time.Time) {
	ps := &c.power
	old := map[string]*linuxRAPLZone{}
	for _, z := range ps.zones {
		old[z.energy] = z
	}
	*ps = linuxPowerState{discoveredAt: now}
	base := c.path("sys/class/powercap")
	for _, n := range linuxDirNames(base) {
		if !strings.HasPrefix(n, "intel-rapl:") {
			continue
		}
		dir := filepath.Join(base, n)
		name, err := linuxReadValue(filepath.Join(dir, "name"))
		if err != nil {
			continue
		}
		kind := ""
		switch strings.Count(n, ":") {
		case 1:
			if strings.HasPrefix(name, "package") {
				kind = "package"
			}
		case 2:
			if name == "core" {
				kind = "core"
			}
		}
		if kind == "" {
			continue
		}
		ps.present = true
		energy := filepath.Join(dir, "energy_uj")
		if _, err := linuxReadValue(energy); err != nil {
			if linuxDenied(err) {
				if kind == "package" {
					ps.deniedPackages++
				} else {
					ps.deniedCores++
				}
			}
			continue
		}
		z := &linuxRAPLZone{energy: energy, kind: kind}
		z.max, _ = linuxReadUint(filepath.Join(dir, "max_energy_range_uj"))
		if prev, ok := old[energy]; ok {
			z.prev, z.have = prev.prev, prev.have
		}
		ps.zones = append(ps.zones, z)
		if kind == "package" {
			ps.packages++
		} else {
			ps.cores++
		}
	}
}

// sampleRAPL returns package and core watts over the window.
func (c *linuxCollector) sampleRAPL(interval float64, resync bool) (pkg, core *float64) {
	var sums [2]float64
	var have [2]bool
	for _, z := range c.power.zones {
		v, ok := linuxReadUint(z.energy)
		if !ok {
			z.have = false
			continue
		}
		valid := z.have && !resync && interval > 0
		var delta uint64
		switch {
		case !valid:
		case v >= z.prev:
			delta = v - z.prev
		case z.max > 0 && z.prev <= z.max:
			delta = z.max - z.prev + v // the counter wrapped
		default:
			valid = false
		}
		z.prev, z.have = v, true
		if !valid {
			continue
		}
		w := float64(delta) / 1e6 / interval
		if w > 5000 { // a counter reset, not a reading
			continue
		}
		i := 0
		if z.kind == "core" {
			i = 1
		}
		sums[i] += w
		have[i] = true
	}
	round := func(v float64) *float64 { return wire.F(float64(int(v*100+0.5)) / 100) }
	if have[0] {
		pkg = round(sums[0])
	}
	if have[1] {
		core = round(sums[1])
	}
	return pkg, core
}

// linuxBatteryState caches the power supplies.
type linuxBatteryState struct {
	discoveredAt time.Time
	batteries    []string // …/power_supply/BAT0
	adapters     []string // …/power_supply/AC/online
}

// discoverBatteries lists system batteries (not a mouse's: scope Device) and
// the online files of mains and USB-C adapters.
func (c *linuxCollector) discoverBatteries(now time.Time) {
	bs := &c.battery
	*bs = linuxBatteryState{discoveredAt: now}
	base := c.path("sys/class/power_supply")
	for _, n := range linuxDirNames(base) {
		dir := filepath.Join(base, n)
		typ, err := linuxReadValue(filepath.Join(dir, "type"))
		if err != nil {
			continue
		}
		switch {
		case typ == "Battery":
			if scope, _ := linuxReadValue(filepath.Join(dir, "scope")); scope == "Device" {
				continue
			}
			bs.batteries = append(bs.batteries, dir)
		case typ == "Mains" || strings.HasPrefix(typ, "USB"):
			if p := filepath.Join(dir, "online"); linuxExists(p) {
				bs.adapters = append(bs.adapters, p)
			}
		}
	}
}

// sampleBattery reads the batteries; several (ThinkPads with two) are
// combined by energy.
func (c *linuxCollector) sampleBattery(full bool) *wire.Battery {
	bs := &c.battery
	if len(bs.batteries) == 0 {
		return nil
	}
	b := &wire.Battery{Present: true}
	plugged := false
	for _, p := range bs.adapters {
		if v, ok := linuxReadUint(p); ok && v == 1 {
			plugged = true
		}
	}

	var energyNow, energyFull, watts float64
	var haveEnergy, haveWatts = true, false
	var status string
	for i, dir := range bs.batteries {
		get := func(name string) (float64, bool) {
			v, ok := linuxReadInt(filepath.Join(dir, name))
			return float64(v), ok
		}
		st, _ := linuxReadValue(filepath.Join(dir, "status"))
		if i == 0 || st == "Charging" || st == "Discharging" {
			status = st
		}
		if pw, ok := get("power_now"); ok && pw != 0 {
			watts += linuxAbs(pw) / 1e6
			haveWatts = true
		} else if cur, ok := get("current_now"); ok {
			if volt, ok := get("voltage_now"); ok {
				watts += linuxAbs(cur) * volt / 1e12
				haveWatts = true
			}
		}
		en, ok1 := get("energy_now")
		ef, ok2 := get("energy_full")
		if !ok1 || !ok2 {
			en, ok1 = get("charge_now")
			ef, ok2 = get("charge_full")
		}
		if ok1 && ok2 && ef > 0 {
			energyNow += en
			energyFull += ef
		} else {
			haveEnergy = false
		}
		if i == 0 {
			if capacity, ok := get("capacity"); ok {
				b.Percentage = linuxClamp01(capacity / 100)
			}
		}
	}
	if len(bs.batteries) > 1 && haveEnergy && energyFull > 0 {
		b.Percentage = linuxClamp01(energyNow / energyFull)
	} else if b.Percentage == 0 && haveEnergy && energyFull > 0 {
		b.Percentage = linuxClamp01(energyNow / energyFull)
	}
	b.Charging = status == "Charging"
	b.PluggedIn = plugged || status == "Charging" || status == "Full" || status == "Not charging"
	if haveWatts {
		w := wire.F(float64(int(watts*100+0.5)) / 100)
		switch {
		case b.Charging:
			b.ChargingWatts = w
		case status == "Discharging" || !b.PluggedIn:
			b.SystemWatts = w
		}
	}
	if !full {
		return b
	}

	dir := bs.batteries[0]
	get := func(name string) (float64, bool) {
		v, ok := linuxReadInt(filepath.Join(dir, name))
		return float64(v), ok
	}
	volt, haveVolt := get("voltage_now")
	if haveVolt && volt > 0 {
		b.Voltage = wire.F(float64(int(volt/1e4+0.5)) / 100)
	}
	if cur, ok := get("current_now"); ok {
		a := linuxAbs(cur) / 1e6
		if status == "Discharging" {
			a = -a
		}
		b.Amperage = wire.F(float64(int(a*1000+0.5)) / 1000)
	}
	if n, ok := get("cycle_count"); ok && n > 0 {
		b.CycleCount = wire.I(int(n))
	}
	// Capacities in mAh, like macOS reports them. Energy-reporting
	// batteries (µWh) are converted with their design voltage.
	mAh := func(charge, energy string) *int {
		if v, ok := get(charge); ok && v > 0 {
			return wire.I(int(v / 1000))
		}
		if v, ok := get(energy); ok && v > 0 {
			design, ok := get("voltage_min_design")
			if !ok || design <= 0 {
				design, ok = volt, haveVolt
			}
			if ok && design > 0 {
				return wire.I(int(v / design * 1000))
			}
		}
		return nil
	}
	b.DesignCapacity = mAh("charge_full_design", "energy_full_design")
	b.MaxCapacity = mAh("charge_full", "energy_full")
	if t, ok := get("temp"); ok {
		if c := t / 10; linuxPlausibleTemp(c) {
			b.Celsius = wire.F(c)
		}
	}
	if h, err := linuxReadValue(filepath.Join(dir, "health")); err == nil && h != "" && h != "Unknown" {
		b.Condition = h
	}
	switch status {
	case "Discharging":
		if s, ok := get("time_to_empty_now"); ok && s > 0 {
			b.TimeRemainingMinutes = wire.I(int(s / 60))
		} else if haveEnergy && haveWatts && watts > 0 {
			if en, ok := get("energy_now"); ok {
				b.TimeRemainingMinutes = wire.I(int(en / 1e6 / watts * 60))
			}
		}
	case "Charging":
		if s, ok := get("time_to_full_now"); ok && s > 0 {
			b.TimeRemainingMinutes = wire.I(int(s / 60))
		} else if haveWatts && watts > 0 {
			en, ok1 := get("energy_now")
			ef, ok2 := get("energy_full")
			if ok1 && ok2 && ef > en {
				b.TimeRemainingMinutes = wire.I(int((ef - en) / 1e6 / watts * 60))
			}
		}
	}
	return b
}

func linuxAbs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
