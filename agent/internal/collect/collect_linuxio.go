package collect

// Network (/proc/net/dev), disks (/proc/diskstats) and volumes
// (/proc/self/mountinfo + statfs). No build tag: see collect_linuxfs.go.

import (
	"bytes"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// Interface classes.
const (
	linuxIfaceSkip = iota
	linuxIfacePhysical
	linuxIfaceWireless
	linuxIfaceTunnel // listed, but not summed: its traffic also crosses a physical NIC
	// linuxIfaceVirtual is a software interface that is nobody's port: a
	// container's veth eth0, which has no device link. It is summed only on
	// machines with no physical or wireless interface at all (inside Docker,
	// LXC, a Proxmox CT, nspawn), where it is the machine's network.
	linuxIfaceVirtual
)

// linuxFields splits line on spaces and tabs into dst without allocating.
func linuxFields(line []byte, dst [][]byte) [][]byte {
	dst = dst[:0]
	for len(line) > 0 {
		for len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			line = line[1:]
		}
		if len(line) == 0 {
			break
		}
		i := 0
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		dst = append(dst, line[:i])
		line = line[i:]
	}
	return dst
}

// linuxIface is one network interface's baseline.
type linuxIface struct {
	class        int
	classifiedAt time.Time
	prevRX       uint64
	prevTX       uint64
	have         bool
	rx, tx       float64
	drx, dtx     uint64 // bytes since the previous sample, for the totals
	seen         bool
}

// linuxNetState keeps interface baselines and session totals.
type linuxNetState struct {
	ifaces    map[string]*linuxIface
	rxTotal   uint64
	txTotal   uint64
	primary   string
	local     string
	primaryAt time.Time
	fields    [][]byte
}

// classifyIface decides whether an interface is hardware. Physical NICs have
// a device link in sysfs; Wi-Fi also has wireless or phy80211. Bridges, veths,
// bonds and VLANs have neither, so their traffic (already counted on the
// physical NIC beneath them) is not counted twice.
func (c *linuxCollector) classifyIface(name string) int {
	if name == "lo" {
		return linuxIfaceSkip
	}
	dir := c.path("sys/class/net", name)
	if linuxExists(filepath.Join(dir, "wireless")) || linuxExists(filepath.Join(dir, "phy80211")) {
		return linuxIfaceWireless
	}
	if linuxExists(filepath.Join(dir, "device")) {
		// A VF enslaved to another NIC (Azure accelerated networking,
		// net_failover) carries traffic the master's counters already
		// include. Bridges, bonds and OVS have no device link, so their
		// ports still count.
		if linuxExists(filepath.Join(dir, "master", "device")) {
			return linuxIfaceSkip
		}
		return linuxIfacePhysical
	}
	for _, p := range []string{"tailscale", "wg", "tun", "zt", "ppp", "nordlynx"} {
		if strings.HasPrefix(name, p) {
			return linuxIfaceTunnel
		}
	}
	// Bridges, their ports (the host side of every veth), interfaces
	// enslaved to another and those stacked on one (VLANs, macvlans) are
	// never summed; what is left is a container's own interface.
	for _, f := range linuxDirNames(dir) {
		if f == "bridge" || f == "brport" || f == "master" || strings.HasPrefix(f, "lower_") {
			return linuxIfaceSkip
		}
	}
	return linuxIfaceVirtual
}

// linuxIfaceCounted reports whether an interface's traffic goes into the
// machine's totals. hardware says whether the machine has any physical or
// wireless interface.
func linuxIfaceCounted(class int, hardware bool) bool {
	return class == linuxIfacePhysical || class == linuxIfaceWireless || (class == linuxIfaceVirtual && !hardware)
}

// sampleNetwork reads /proc/net/dev; the per-interface list, speeds and the
// primary interface are added in full mode.
func (c *linuxCollector) sampleNetwork(interval float64, resync, full bool, now time.Time) *wire.Network {
	data, err := linuxReadInto(c.path("proc/net/dev"), &c.buf)
	if err != nil {
		return nil
	}
	ns := &c.net
	if ns.ifaces == nil {
		ns.ifaces = map[string]*linuxIface{}
	}
	for _, e := range ns.ifaces {
		e.seen = false
	}
	out := &wire.Network{}
	for len(data) > 0 {
		var line []byte
		line, data = linuxNextLine(data)
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue // the two header lines
		}
		name := string(bytes.TrimSpace(line[:colon]))
		ns.fields = linuxFields(line[colon+1:], ns.fields)
		if len(ns.fields) < 9 || name == "" {
			continue
		}
		rx, ok1 := linuxAtou(ns.fields[0])
		tx, ok2 := linuxAtou(ns.fields[8])
		if !ok1 || !ok2 {
			continue
		}
		e := ns.ifaces[name]
		if e == nil {
			e = &linuxIface{}
			ns.ifaces[name] = e
		}
		if e.classifiedAt.IsZero() || now.Sub(e.classifiedAt) > linuxRediscover {
			e.class, e.classifiedAt = c.classifyIface(name), now
		}
		e.seen = true
		e.rx, e.tx, e.drx, e.dtx = 0, 0, 0, 0
		if e.have {
			e.drx, _ = counterDelta(e.prevRX, rx)
			e.dtx, _ = counterDelta(e.prevTX, tx)
			if !resync {
				e.rx, e.tx = Rate(e.prevRX, rx, interval), Rate(e.prevTX, tx, interval)
			}
		}
		e.prevRX, e.prevTX, e.have = rx, tx, true
	}
	hardware := false
	for name, e := range ns.ifaces {
		if !e.seen {
			delete(ns.ifaces, name) // veths come and go with containers
			continue
		}
		hardware = hardware || e.class == linuxIfacePhysical || e.class == linuxIfaceWireless
	}
	for _, e := range ns.ifaces {
		if linuxIfaceCounted(e.class, hardware) {
			ns.rxTotal += e.drx
			ns.txTotal += e.dtx
			out.RX += e.rx
			out.TX += e.tx
		}
	}
	out.RXTotal, out.TXTotal = ns.rxTotal, ns.txTotal
	if !full {
		return out
	}

	if ns.primaryAt.IsZero() || now.Sub(ns.primaryAt) > 30*time.Second {
		ns.primary = linuxDefaultRoute(c.path("proc/net/route"))
		ns.local = ""
		if ns.primary != "" && c.ifaceIPv4 != nil {
			ns.local = c.ifaceIPv4(ns.primary)
		}
		ns.primaryAt = now
	}
	out.PrimaryInterface, out.LocalAddress = ns.primary, ns.local
	names := make([]string, 0, len(ns.ifaces))
	for name, e := range ns.ifaces {
		if e.class != linuxIfaceSkip && (e.class != linuxIfaceVirtual || !hardware) {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(a, b int) bool {
		if (names[a] == ns.primary) != (names[b] == ns.primary) {
			return names[a] == ns.primary
		}
		return names[a] < names[b]
	})
	for _, name := range names {
		e := ns.ifaces[name]
		dir := c.path("sys/class/net", name)
		iface := wire.Interface{Name: name, RX: e.rx, TX: e.tx}
		if v, ok := linuxReadInt(filepath.Join(dir, "speed")); ok && v > 0 {
			iface.SpeedMbps = wire.F(float64(v))
		}
		switch state, _ := linuxReadValue(filepath.Join(dir, "operstate")); state {
		case "up":
			iface.Up = true
		case "unknown":
			// Tunnels report "unknown"; trust the administrative flag.
			if s, err := linuxReadValue(filepath.Join(dir, "flags")); err == nil {
				if v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64); err == nil {
					iface.Up = v&1 == 1
				}
			}
		}
		out.Interfaces = append(out.Interfaces, iface)
	}
	return out
}

// linuxDefaultRoute returns the interface of the IPv4 default route with the
// lowest metric.
func linuxDefaultRoute(path string) string {
	data, err := linuxReadFile(path)
	if err != nil {
		return ""
	}
	best, bestMetric := "", int64(-1)
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&1 == 0 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		metric, err := strconv.ParseInt(f[6], 10, 64)
		if err != nil {
			continue
		}
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = f[0], metric
		}
	}
	return best
}

// linuxInterfaceIPv4 returns the first IPv4 address of an interface.
func linuxInterfaceIPv4(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return ""
}

// linuxDiskDev is one block device's baseline.
type linuxDiskDev struct {
	whole        bool
	classifiedAt time.Time
	prevR, prevW uint64 // sectors
	have         bool
	seen         bool
}

// linuxVolStat is the last statfs result for one mount.
type linuxVolStat struct {
	total, avail uint64
	ok           bool
	pending      bool
}

// linuxDiskState keeps disk baselines, session totals and the volume cache.
type linuxDiskState struct {
	devs       map[string]*linuxDiskDev
	readTotal  uint64
	writeTotal uint64
	fields     [][]byte

	volumes   []wire.Volume
	volumesAt time.Time

	mu    sync.Mutex // guards stats against statfs goroutines
	stats map[string]*linuxVolStat
}

// linuxWholeDisk reports whether a /proc/diskstats name is a whole physical
// disk: present in /sys/block (partitions are not) with a device link
// (virtual devices have none), and not one of the virtual families.
func (c *linuxCollector) linuxWholeDisk(name string) bool {
	for _, p := range []string{"loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd", "drbd", "zd"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	if strings.HasPrefix(name, "mmcblk") && (strings.Contains(name, "boot") || strings.Contains(name, "rpmb")) {
		return false
	}
	// nvme0c0n1 is the hidden per-controller path of a multipath namespace.
	if strings.HasPrefix(name, "nvme") && strings.Contains(name, "c") && strings.Contains(name[strings.Index(name, "c"):], "n") {
		return false
	}
	return linuxExists(c.path("sys/block", name, "device"))
}

// sampleDisk reads /proc/diskstats; volumes are added in full mode.
func (c *linuxCollector) sampleDisk(interval float64, resync, full bool, now time.Time) *wire.Disk {
	data, err := linuxReadInto(c.path("proc/diskstats"), &c.buf)
	if err != nil {
		return nil
	}
	ds := &c.disk
	if ds.devs == nil {
		ds.devs = map[string]*linuxDiskDev{}
	}
	for _, d := range ds.devs {
		d.seen = false
	}
	out := &wire.Disk{}
	for len(data) > 0 {
		var line []byte
		line, data = linuxNextLine(data)
		ds.fields = linuxFields(line, ds.fields)
		if len(ds.fields) < 10 {
			continue
		}
		d := ds.devs[string(ds.fields[2])]
		if d == nil {
			name := string(ds.fields[2])
			d = &linuxDiskDev{}
			ds.devs[name] = d
		}
		if d.classifiedAt.IsZero() || now.Sub(d.classifiedAt) > linuxRediscover {
			d.whole, d.classifiedAt = c.linuxWholeDisk(string(ds.fields[2])), now
		}
		d.seen = true
		if !d.whole {
			continue
		}
		// Sectors here are always 512 bytes, whatever the device's block size.
		r, ok1 := linuxAtou(ds.fields[5])
		w, ok2 := linuxAtou(ds.fields[9])
		if !ok1 || !ok2 {
			continue
		}
		if d.have {
			dr, _ := counterDelta(d.prevR, r)
			dw, _ := counterDelta(d.prevW, w)
			ds.readTotal += dr * 512
			ds.writeTotal += dw * 512
			if !resync {
				out.Read += Rate(d.prevR, r, interval) * 512
				out.Write += Rate(d.prevW, w, interval) * 512
			}
		}
		d.prevR, d.prevW, d.have = r, w, true
	}
	for name, d := range ds.devs {
		if !d.seen {
			delete(ds.devs, name)
		}
	}
	out.ReadTotal, out.WriteTotal = ds.readTotal, ds.writeTotal
	if full {
		if ds.volumesAt.IsZero() || now.Sub(ds.volumesAt) >= 5*time.Second {
			ds.volumes, ds.volumesAt = c.readVolumes(), now
		}
		out.Volumes = ds.volumes
	}
	return out
}

// linuxMount is one /proc/self/mountinfo line.
type linuxMount struct {
	majmin, root, point, fs, source string
}

// linuxUnescapeMount decodes the octal escapes mountinfo uses for spaces,
// tabs, newlines and backslashes in paths.
func linuxUnescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// linuxParseMountinfo parses "29 1 259:2 / / rw,relatime shared:1 - ext4
// /dev/nvme0n1p2 rw". The optional fields end at the lone "-".
func linuxParseMountinfo(data []byte) []linuxMount {
	var out []linuxMount
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 10 || sep < 0 || sep+2 >= len(f) {
			continue
		}
		out = append(out, linuxMount{
			majmin: f[2],
			root:   linuxUnescapeMount(f[3]),
			point:  linuxUnescapeMount(f[4]),
			fs:     f[sep+1],
			source: linuxUnescapeMount(f[sep+2]),
		})
	}
	return out
}

var (
	linuxRealFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
		"f2fs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true, "jfs": true,
		"reiserfs": true, "bcachefs": true, "nfs": true, "nfs4": true, "cifs": true, "smb3": true}
	// statfs on these can block for minutes when the server (or the FUSE
	// daemon) is gone, so they are asked from a goroutine with a deadline.
	linuxSlowFS = map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "fuseblk": true}
	// Mounts under these belong to container runtimes and snaps, not users.
	// A filesystem mounted at one of them (a disk for /var/lib/docker, often
	// the one that fills up) is the user's and stays.
	linuxHiddenMounts = []string{"/snap/", "/var/snap/", "/var/lib/docker/", "/var/lib/containers/", "/var/lib/kubelet/",
		"/var/lib/lxd/", "/var/lib/incus/", "/var/lib/rancher/", "/var/lib/snapd/", "/run/containerd/", "/run/docker/",
		"/run/k3s/", "/proc/", "/sys/", "/dev/"}
)

// linuxVolumeMounts picks the user-visible filesystems: real filesystem
// types, no snap/container mounts, no bind mounts of subdirectories, one
// entry per device (btrfs subvolumes and binds share one).
func linuxVolumeMounts(mounts []linuxMount) []linuxMount {
	var out []linuxMount
	seen := map[string]bool{}
	for _, m := range mounts {
		if !linuxRealFS[m.fs] {
			continue
		}
		hidden := false
		for _, p := range linuxHiddenMounts {
			hidden = hidden || strings.HasPrefix(m.point, p)
		}
		if hidden {
			continue
		}
		if m.root != "/" && m.fs != "btrfs" && m.fs != "zfs" && !linuxSlowFS[m.fs] {
			continue // a bind mount of a subdirectory
		}
		key := m.majmin
		switch {
		case m.fs == "zfs":
			pool, _, _ := strings.Cut(m.source, "/")
			key = "zfs:" + pool // datasets of a pool share its free space
		case linuxSlowFS[m.fs] && m.fs != "fuseblk":
			key = "net:" + m.source
		case strings.HasPrefix(m.source, "/dev/"):
			key = m.source
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].point == "/" && out[b].point != "/" })
	return out
}

// readVolumes lists the volumes with their sizes.
func (c *linuxCollector) readVolumes() []wire.Volume {
	data, err := linuxReadFile(c.path("proc/self/mountinfo"))
	if err != nil || c.statfs == nil {
		return nil
	}
	mounts := linuxVolumeMounts(linuxParseMountinfo(data))
	var out []wire.Volume
	live := map[string]bool{}
	for _, m := range mounts {
		point := m.point
		live[point] = true
		total, avail, ok := c.volumeStat(point, linuxSlowFS[m.fs])
		if !ok || total == 0 {
			continue
		}
		if avail > total {
			avail = total
		}
		out = append(out, wire.Volume{Name: point, Mount: point, FS: m.fs, Total: total, Available: avail})
	}
	ds := &c.disk
	ds.mu.Lock()
	for p, st := range ds.stats {
		if !live[p] && !st.pending {
			delete(ds.stats, p)
		}
	}
	ds.mu.Unlock()
	return out
}

// volumeStat runs statfs, from a goroutine with a 100 ms deadline for
// network filesystems. A call that does not return keeps the mount marked
// pending, so a dead server costs one stuck goroutine, never one per sample.
func (c *linuxCollector) volumeStat(point string, slow bool) (total, avail uint64, ok bool) {
	statfs := c.statfs
	if !slow {
		t, a, err := statfs(c.path(point))
		return t, a, err == nil
	}
	ds := &c.disk
	ds.mu.Lock()
	if ds.stats == nil {
		ds.stats = map[string]*linuxVolStat{}
	}
	st := ds.stats[point]
	if st == nil {
		st = &linuxVolStat{}
		ds.stats[point] = st
	}
	if st.pending {
		t, a, ok := st.total, st.avail, st.ok
		ds.mu.Unlock()
		return t, a, ok
	}
	st.pending = true
	ds.mu.Unlock()

	done := make(chan struct{})
	path := c.path(point)
	go func() {
		t, a, err := statfs(path)
		ds.mu.Lock()
		if err == nil {
			st.total, st.avail, st.ok = t, a, true
		}
		st.pending = false
		ds.mu.Unlock()
		close(done)
	}()
	timer := time.NewTimer(100 * time.Millisecond)
	select {
	case <-done:
	case <-timer.C:
	}
	timer.Stop()
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return st.total, st.avail, st.ok
}
