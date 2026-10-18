package collect

// Uptime, pending reboot, package updates, failed units and containers. No
// build tag: see collect_linuxfs.go.

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// linuxSystemEvery is how often the slow system facts are refreshed.
const linuxSystemEvery = 30 * time.Second

// linuxSystemState caches the slow system facts.
type linuxSystemState struct {
	refreshedAt time.Time
	cached      wire.System

	mu            sync.Mutex // guards the fields below against the systemctl goroutine
	failed        []string
	failedRunning bool
}

// sampleSystem returns the system section (full mode only).
func (c *linuxCollector) sampleSystem(now time.Time) *wire.System {
	ss := &c.sys
	if ss.refreshedAt.IsZero() || now.Sub(ss.refreshedAt) >= linuxSystemEvery {
		ss.refreshedAt = now
		var s wire.System
		reboot, reason := c.rebootRequired()
		s.RebootRequired, s.RebootReason = wire.B(reboot), reason
		if data, err := linuxReadFile(c.path("var/lib/update-notifier/updates-available")); err == nil {
			s.Updates, s.SecurityUpdates = linuxParseUpdates(string(data))
		}
		if n, ok := c.countContainers(); ok {
			s.Containers = wire.I(n)
		}
		ss.cached = s
		c.refreshFailedUnits()
	}
	out := ss.cached
	if data, err := linuxReadValue(c.path("proc/uptime")); err == nil {
		if f := strings.Fields(data); len(f) > 0 {
			out.Uptime, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	ss.mu.Lock()
	if ss.failed != nil {
		out.FailedServices = append([]string(nil), ss.failed...)
	}
	ss.mu.Unlock()
	return &out
}

// refreshFailedUnits runs systemctl in the background so a slow or hung
// systemd never delays a sample; the next sample after it finishes shows
// the result.
func (c *linuxCollector) refreshFailedUnits() {
	if c.failedUnits == nil {
		return
	}
	ss := &c.sys
	ss.mu.Lock()
	if ss.failedRunning {
		ss.mu.Unlock()
		return
	}
	ss.failedRunning = true
	ss.mu.Unlock()
	run := c.failedUnits
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		units, err := run(ctx)
		ss.mu.Lock()
		defer ss.mu.Unlock()
		ss.failedRunning = false
		if err == nil {
			if units == nil {
				units = []string{}
			}
			ss.failed = units
		}
	}()
}

// linuxSystemctlFailed lists failed units with systemctl.
func linuxSystemctlFailed(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "--failed", "--no-legend", "--plain", "--no-pager").Output()
	if err != nil {
		return nil, err
	}
	return linuxParseFailedUnits(string(out)), nil
}

// linuxParseFailedUnits takes the first column of systemctl --failed.
func linuxParseFailedUnits(out string) []string {
	units := []string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimLeft(strings.TrimSpace(line), "●* "))
		if len(f) > 0 && strings.Contains(f[0], ".") {
			units = append(units, f[0])
		}
	}
	return units
}

// rebootRequired checks Debian's reboot-required flag, then whether a newer
// kernel than the running one is installed.
func (c *linuxCollector) rebootRequired() (bool, string) {
	for _, p := range []string{"run/reboot-required", "var/run/reboot-required"} {
		if !linuxExists(c.path(p)) {
			continue
		}
		var pkgs []string
		seen := map[string]bool{}
		if data, err := linuxReadFile(c.path(p + ".pkgs")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if line = strings.TrimSpace(line); line != "" && !seen[line] {
					seen[line] = true
					pkgs = append(pkgs, line)
				}
			}
		}
		switch {
		case len(pkgs) == 0:
			return true, "updates installed"
		case len(pkgs) > 5:
			return true, strings.Join(pkgs[:5], ", ") + ", …"
		}
		return true, strings.Join(pkgs, ", ")
	}
	running, err := linuxReadValue(c.path("proc/sys/kernel/osrelease"))
	if err != nil || running == "" {
		return false, ""
	}
	if newest := c.newestKernel(running); newest != "" {
		return true, "kernel " + newest + " installed"
	}
	return false, ""
}

// newestKernel returns an installed kernel newer than running, or "". Only
// kernels of the same flavour count (same text once digits are removed), so
// a Raspberry Pi with both its v8 and 2712 kernels, or a box with generic
// and lowlatency kernels, is not told to reboot. A directory in /lib/modules
// only counts when its kernel image is still there: package removal often
// leaves DKMS leftovers behind.
func (c *linuxCollector) newestKernel(running string) string {
	shape := linuxStripDigits(running)
	newest := ""
	for _, v := range linuxDirNames(c.path("lib/modules")) {
		if v == running || linuxStripDigits(v) != shape || linuxCompareVersions(v, running) <= 0 {
			continue
		}
		if newest != "" && linuxCompareVersions(v, newest) <= 0 {
			continue
		}
		image := false
		for _, p := range []string{"boot/vmlinuz-" + v, "boot/vmlinux-" + v, "boot/kernel-" + v, "boot/Image-" + v, "lib/modules/" + v + "/vmlinuz"} {
			image = image || linuxExists(c.path(p))
		}
		if image {
			newest = v
		}
	}
	return newest
}

func linuxStripDigits(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return -1
		}
		return r
	}, s)
}

var (
	linuxUpdatesRE  = regexp.MustCompile(`(?i)^(\d+) (?:updates?|packages?) can be (?:applied|installed|updated)`)
	linuxSecurityRE = regexp.MustCompile(`(?i)^(\d+) (?:of these )?updates? (?:are|is) (?:an? )?(?:standard )?security updates?`)
)

// linuxParseUpdates reads update-notifier's updates-available, the text
// Ubuntu shows at login. It is written in the system's language: English is
// parsed exactly; otherwise the first line that starts with a number and is
// not about ESM is the update count (that line comes first in every
// translation), and the security count is only known when it is zero.
func linuxParseUpdates(text string) (updates, security *int) {
	var firstNumber *int
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if m := linuxUpdatesRE.FindStringSubmatch(line); m != nil && updates == nil {
			n, _ := strconv.Atoi(m[1])
			updates = &n
			continue
		}
		if m := linuxSecurityRE.FindStringSubmatch(line); m != nil && security == nil {
			n, _ := strconv.Atoi(m[1])
			security = &n
			continue
		}
		if firstNumber == nil && line != "" && line[0] >= '0' && line[0] <= '9' && !strings.Contains(strings.ToLower(line), "esm") {
			digits := line
			if i := strings.IndexFunc(line, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
				digits = line[:i]
			}
			if n, err := strconv.Atoi(digits); err == nil {
				firstNumber = &n
			}
		}
	}
	if updates == nil {
		updates = firstNumber
	}
	if updates != nil && security == nil && *updates == 0 {
		security = wire.I(0)
	}
	return updates, security
}

// countContainers counts running containers from their cgroups: Docker and
// Podman scopes under the systemd driver, Docker's cgroupfs driver on cgroup
// v2 and v1, systemd-nspawn/libvirt machines and LXC, LXD, Incus and Proxmox
// containers. ok is false when no container runtime is installed, so hosts
// without one report no count rather than zero.
func (c *linuxCollector) countContainers() (n int, ok bool) {
	cg := c.path("sys/fs/cgroup")
	// The systemd driver's scopes sit at the top of cgroup v2, and in the
	// name=systemd hierarchy on v1 and hybrid hosts.
	for _, base := range []string{cg, cg + "/systemd"} {
		found := false
		for _, slice := range []string{"system.slice", "machine.slice"} {
			names := linuxDirNames(base + "/" + slice)
			found = found || names != nil
			for _, name := range names {
				if !strings.HasSuffix(name, ".scope") {
					continue
				}
				switch {
				case strings.HasPrefix(name, "docker-"),
					strings.HasPrefix(name, "libpod-") && !strings.HasPrefix(name, "libpod-conmon-"),
					strings.HasPrefix(name, "crio-") && !strings.HasPrefix(name, "crio-conmon-"),
					slice == "machine.slice" && strings.HasPrefix(name, "machine-"):
					n++
				}
			}
		}
		if found {
			break
		}
	}
	for _, dir := range []string{"docker", "cpu/docker", "cpu,cpuacct/docker", "memory/docker", "pids/docker"} {
		names := linuxDirNames(cg + "/" + dir)
		if names == nil {
			continue
		}
		for _, name := range names {
			if len(name) == 64 && strings.Trim(name, "0123456789abcdef") == "" {
				n++
			}
		}
		break
	}
	// LXC 4 and later (and LXD, Incus) name a container's cgroup
	// lxc.payload.<name>; Proxmox uses lxc/<vmid>, as older LXC did with
	// lxc/<name>. They sit at the top of cgroup v2 and under every
	// controller of v1, where one controller is counted. lxc.monitor.* and
	// lxc.pivot hold LXC's own processes, not containers.
	for _, base := range []string{cg, cg + "/memory", cg + "/pids", cg + "/cpu,cpuacct", cg + "/cpu"} {
		found := len(linuxSubdirs(base + "/lxc"))
		for _, name := range linuxDirNames(base) {
			if strings.HasPrefix(name, "lxc.payload.") {
				found++
			}
		}
		if found > 0 {
			n += found
			break
		}
	}
	if n > 0 {
		return n, true
	}
	for _, p := range []string{"var/lib/docker", "var/lib/containers", "var/lib/lxc", "var/lib/lxd", "var/lib/incus", "run/docker.sock", "run/podman"} {
		if linuxExists(c.path(p)) {
			return 0, true
		}
	}
	return 0, false
}
