package collect

// Unit tests for the Linux text-format parsers.

import (
	"strings"
	"testing"
)

func TestLinuxParseUpdates(t *testing.T) {
	cases := []struct {
		name, text      string
		updates, secure int // -1: unknown
	}{
		{"english", "\nExpanded Security Maintenance for Applications is not enabled.\n\n12 updates can be applied immediately.\n3 of these updates are standard security updates.\nTo see these additional updates run: apt list --upgradable\n\n18 additional security updates can be applied with ESM Apps.\n", 12, 3},
		{"english one", "1 update can be applied immediately.\n1 of these updates is a standard security update.\n", 1, 1},
		{"english none", "0 updates can be applied immediately.\n\n18 additional security updates can be applied with ESM Apps.\n", 0, 0},
		{"focal", "7 packages can be updated.\n2 updates are security updates.\n", 7, 2},
		{"korean", "\nApplications를 위한 확장된 보안 유지보수 비활성화됨.\n\n0개의 업데이트가 즉시 적용 가능합니다.\n\n18 추가 보안 업데이트는 ESM Apps에 적용될 수 있습니다.\nESM Apps 서비스 at https://ubuntu.com/esm 활성화에 대해 자세히 알아보십시오\n", 0, 0},
		{"german", "4 Aktualisierungen können sofort angewendet werden.\n2 dieser Aktualisierungen sind Standard-Sicherheitsaktualisierungen.\n", 4, -1},
		{"empty", "", -1, -1},
	}
	for _, tc := range cases {
		u, s := linuxParseUpdates(tc.text)
		got := func(p *int) int {
			if p == nil {
				return -1
			}
			return *p
		}
		if got(u) != tc.updates || got(s) != tc.secure {
			t.Errorf("%s: updates %d security %d, want %d %d", tc.name, got(u), got(s), tc.updates, tc.secure)
		}
	}
}

func TestLinuxCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.8.0-147-generic", "6.8.0-146-generic", 1},
		{"6.8.0-88-generic", "6.8.0-146-generic", -1},
		{"6.11.0-29-generic", "6.8.0-146-generic", 1},
		{"6.10.3-200.fc40.x86_64", "6.9.7-200.fc40.x86_64", 1},
		{"5.15.0-010", "5.15.0-10", 0},
		{"6.1.0", "6.1.0-1", -1},
	}
	for _, tc := range cases {
		if got := linuxCompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if linuxStripDigits("6.6.51+rpt-rpi-v8") == linuxStripDigits("6.6.51+rpt-rpi-2712") {
		t.Errorf("the Pi's two kernel flavours must not compare")
	}
}

func TestLinuxSmallParsers(t *testing.T) {
	if got := linuxParseCPUList("0-3,8,10-11\n"); len(got) != 7 || got[4] != 8 || got[6] != 11 {
		t.Errorf("cpu list %v", got)
	}
	if got := linuxParseCPUList("garbage,5-2"); len(got) != 0 {
		t.Errorf("bad cpu list %v", got)
	}
	if got := linuxUnescapeMount(`/media/My\040Disk\134x`); got != `/media/My Disk\x` {
		t.Errorf("unescape %q", got)
	}
	if got := strings.Join(linuxParseFailedUnits("nginx.service loaded failed failed A web server\n● backup.timer loaded failed failed Backup\n\n"), ","); got != "nginx.service,backup.timer" {
		t.Errorf("failed units %q", got)
	}
	kv := linuxParseKV([]byte("NAME=\"Arch Linux\"\nBUILD_ID=rolling\n# comment\nPRETTY_NAME='Arch'\nX=\"a \\\"b\\\"\"\n"))
	if kv["NAME"] != "Arch Linux" || kv["BUILD_ID"] != "rolling" || kv["PRETTY_NAME"] != "Arch" || kv["X"] != `a "b"` {
		t.Errorf("kv %v", kv)
	}
	if got := linuxDefaultRoute("testdata/linux-vm/proc/net/route"); got != "ens3" {
		t.Errorf("default route %q", got)
	}
	if !linuxNumeric("123") || linuxNumeric("12a") || linuxNumeric("") {
		t.Errorf("numeric")
	}
}

func TestLinuxStatFields(t *testing.T) {
	line := "4242 (tmux: server (1)) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 3 0 12345 9000000 777 18446744073709551615 1 1\n"
	comm, state, ticks, threads, start, rss, ok := linuxStatFields([]byte(line))
	if !ok || comm != "tmux: server (1)" || state != 'S' || ticks != 300 || threads != 3 || start != 12345 || rss != 777 {
		t.Errorf("stat fields %q %c %d %d %d %d %v", comm, state, ticks, threads, start, rss, ok)
	}
	if _, _, _, _, _, _, ok := linuxStatFields([]byte("12 (short) S 1 2")); ok {
		t.Errorf("a truncated stat line parsed")
	}
}

func TestLinuxProcessName(t *testing.T) {
	cases := []struct{ comm, exe, argv0, title, want string }{
		{"gnome-shell-cal", "", "/usr/libexec/gnome-shell-calendar-server", "", "gnome-shell-calendar-server"},
		{"2.1.295-8b2928c", "/home/u/.claude/remote/2.1.295-8b2928c330c4", "", "", "2.1.295-8b2928c330c4"},
		{"node /home/alex", "/usr/bin/node", "", "node /home/alex/app/server.js", "node"},
		{"gunicorn: worke", "/usr/bin/python3.12", "", "gunicorn: worker [authentik.root.asgi:application]", "gunicorn"},
		{"Web Content", "/usr/lib64/firefox/firefox", "/usr/lib64/firefox/firefox", "", "Web Content"},
		{"kworker/u32:1-e", "", "", "", "kworker/u32:1-e"},
	}
	for _, tc := range cases {
		if got := linuxProcessName(tc.comm, tc.exe, tc.argv0, tc.title); got != tc.want {
			t.Errorf("name(%q) = %q, want %q", tc.comm, got, tc.want)
		}
	}
}

func TestLinuxNames(t *testing.T) {
	chips := map[string]string{
		"Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz":         "Intel Core i7-8700",
		"Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz":       "Intel Xeon E5-2680 v4",
		"Intel(R) Core(TM) Ultra 7 255H":                  "Intel Core Ultra 7 255H",
		"12th Gen Intel(R) Core(TM) i5-1235U":             "12th Gen Intel Core i5-1235U",
		"Intel(R) Celeron(R) N5105 @ 2.00GHz":             "Intel Celeron N5105",
		"Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz": "Intel Core2 Duo E8400",
		"Intel(R) Atom(TM) CPU  C3758 @ 2.20GHz":          "Intel Atom C3758",
		"AMD Ryzen 9 7950X 16-Core Processor":             "AMD Ryzen 9 7950X",
		"AMD Ryzen 7 5800U with Radeon Graphics":          "AMD Ryzen 7 5800U",
		"AMD Ryzen AI 9 HX 370 w/ Radeon 890M":            "AMD Ryzen AI 9 HX 370 w/ Radeon 890M",
		"AMD EPYC 7763 64-Core Processor":                 "AMD EPYC 7763",
		"AMD Ryzen 5 2600 Six-Core Processor":             "AMD Ryzen 5 2600 Six-Core",
		"AMD FX(tm)-8350 Eight-Core Processor":            "AMD FX-8350 Eight-Core",
		"AMD Opteron(tm) Processor 6272":                  "AMD Opteron 6272",
		"QEMU Virtual CPU version 2.5+":                   "QEMU Virtual CPU version 2.5+",
		"Common KVM processor":                            "Common KVM processor",
	}
	for in, want := range chips {
		if got := linuxChipName(linuxCPUInfo{modelName: in}, ""); got != want {
			t.Errorf("chip %q → %q, want %q", in, got, want)
		}
	}
	arm := linuxCPUInfo{modelName: "ARMv7 Processor rev 3 (v7l)", parts: []string{"0x41/0xd03"}}
	if got := linuxChipName(arm, ""); got != "Cortex-A53" {
		t.Errorf("armv7 chip %q", got)
	}
	if got := linuxChipName(linuxCPUInfo{parts: []string{"0x41/0xd05", "0x41/0xd0b"}}, ""); got != "Cortex-A55 + Cortex-A76" {
		t.Errorf("big.LITTLE chip %q", got)
	}
	if got := linuxChipName(linuxCPUInfo{parts: []string{"0x99/0x001"}}, "Some Board"); got != "Some Board" {
		t.Errorf("unknown arm chip %q", got)
	}

	vendors := map[string]string{"ASUSTeK COMPUTER INC.": "ASUSTeK", "LENOVO": "Lenovo", "Dell Inc.": "Dell",
		"Micro-Star International Co., Ltd.": "MSI", "Gigabyte Technology Co., Ltd.": "Gigabyte", "ASRock": "ASRock",
		"Framework": "Framework", "Beelink": "Beelink", "Shenzhen Meigao Electronic Equipment Co.,Ltd": "Shenzhen Meigao Electronic Equipment"}
	for in, want := range vendors {
		if got := linuxCleanVendor(in); got != want {
			t.Errorf("vendor %q → %q, want %q", in, got, want)
		}
	}
	for _, p := range []string{"To Be Filled By O.E.M.", "Default string", "System Product Name", " none "} {
		if !linuxPlaceholder(p) {
			t.Errorf("%q is a placeholder", p)
		}
	}

	if got := linuxGPUDisplayName("intel", "Arrow Lake-P [Intel Graphics]"); got != "Intel Graphics" {
		t.Errorf("gpu name %q", got)
	}
	if got := linuxGPUDisplayName("intel", "HD Graphics 620"); got != "Intel HD Graphics 620" {
		t.Errorf("gpu name %q", got)
	}
	if got := linuxFanLabel("asus", 1, "cpu_fan"); got != "CPU fan" {
		t.Errorf("fan label %q", got)
	}
	if got := linuxFanLabel("nct6775", 2, ""); got != "Fan 2" {
		t.Errorf("fan label %q", got)
	}
	if k := linuxShortKey("PECI Agent 0 Calibration"); k != "peciagen" {
		t.Errorf("short key %q", k)
	}
	sensors := []*linuxTempSensor{{key: "c0"}, {key: "c0"}, {key: "abcdefgh"}, {key: "abcdefgh"}, {key: ""}}
	linuxDedupeKeys(sensors)
	var keys []string
	for _, s := range sensors {
		keys = append(keys, s.key)
	}
	if got := strings.Join(keys, " "); got != "c0 c0-2 abcdefgh abcdef-2 t" {
		t.Errorf("deduped keys %q", got)
	}
	if k, l, c, h := linuxZoneName("bigcore0-thermal"); k != "bigcore0" || c != "CPU" || !h || l != "CPU bigcore0" {
		t.Errorf("zone %q %q %q %v", k, l, c, h)
	}
	if got := linuxLookupPCIIDs("testdata/linux-intel-hybrid/usr/share/misc/pci.ids", "10de", "2684"); got != "AD102 [GeForce RTX 4090]" {
		t.Errorf("pci.ids %q", got)
	}
	if got := linuxLookupPCIIDs("testdata/linux-intel-hybrid/usr/share/misc/pci.ids", "8086", "ffff"); got != "" {
		t.Errorf("pci.ids miss %q", got)
	}
}

func TestLinuxVirtualization(t *testing.T) {
	cases := []struct {
		files map[string]string
		want  string
	}{
		{map[string]string{".dockerenv": ""}, "docker"},
		{map[string]string{"run/.containerenv": ""}, "podman"},
		{map[string]string{"run/systemd/container": "lxc\n"}, "lxc"},
		{map[string]string{"proc/1/cgroup": "0::/system.slice/docker-abc.scope\n"}, "docker"},
		{map[string]string{"proc/version": "Linux version 5.15.153.1-microsoft-standard-WSL2"}, "wsl"},
		{map[string]string{"sys/class/dmi/id/sys_vendor": "Microsoft Corporation", "sys/class/dmi/id/product_name": "Virtual Machine",
			"sys/class/dmi/id/chassis_asset_tag": "7783-7084-3265-9085-8269-3286-77"}, "azure"},
		{map[string]string{"sys/class/dmi/id/sys_vendor": "Microsoft Corporation", "sys/class/dmi/id/product_name": "Virtual Machine"}, "hyperv"},
		{map[string]string{"sys/class/dmi/id/sys_vendor": "Amazon EC2", "sys/class/dmi/id/product_name": "t3.medium"}, "aws"},
		{map[string]string{"sys/class/dmi/id/sys_vendor": "Google", "sys/class/dmi/id/product_name": "Google Compute Engine"}, "gcp"},
		{map[string]string{"sys/class/dmi/id/sys_vendor": "VMware, Inc."}, "vmware"},
		{map[string]string{"sys/class/dmi/id/sys_vendor": "innotek GmbH", "sys/class/dmi/id/product_name": "VirtualBox"}, "virtualbox"},
		{map[string]string{"sys/class/dmi/id/sys_vendor": "Hetzner", "sys/class/dmi/id/product_name": "vServer"}, "hetzner"},
		{map[string]string{}, "none"},
	}
	for _, tc := range cases {
		root := t.TempDir()
		for k, v := range tc.files {
			linuxTPut(t, root, k, v)
		}
		c := newLinuxCollector(root)
		if got := c.virtualization(linuxCPUInfo{}); got != tc.want {
			t.Errorf("%v → %q, want %q", tc.files, got, tc.want)
		}
	}
	c := newLinuxCollector(t.TempDir())
	if got := c.virtualization(linuxCPUInfo{flags: " fpu hypervisor sse "}); got != "vm" {
		t.Errorf("hypervisor flag → %q", got)
	}
}
