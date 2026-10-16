package manage

// Pairing codes (PROTOCOL.md, "Pairing code") and the OS-independent facts
// that go into one: sshd's port, the host keys, and this machine's
// addresses in the order the app should try them. No build tag: nothing
// here calls into the OS beyond the standard library, so every agent can
// use it.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// pairCodePrefix starts every version-1 pairing code.
const pairCodePrefix = "rbr1:"

// encodePairCode returns "rbr1:" + base64url (no padding) of the JSON.
func encodePairCode(p wire.PairCode) (string, error) {
	if p.V == 0 {
		p.V = 1
	}
	if p.Addresses == nil {
		p.Addresses = []string{}
	}
	if p.HostKeys == nil {
		p.HostKeys = []string{}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return pairCodePrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// decodePairCode parses a pairing code (tests, and anything that needs to
// read one back).
func decodePairCode(code string) (wire.PairCode, error) {
	var p wire.PairCode
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, pairCodePrefix) {
		return p, errors.New("not a Rex Boing Remote pairing code (it must start with " + pairCodePrefix + ")")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(code[len(pairCodePrefix):], "="))
	if err != nil {
		return p, errors.New("the pairing code is damaged: " + err.Error())
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, errors.New("the pairing code is damaged: " + err.Error())
	}
	if p.V != 1 {
		return p, errors.New("unsupported pairing code version " + strconv.Itoa(p.V))
	}
	return p, nil
}

// pairAddresses lists the IPv4 addresses of interfaces that are up, best
// first (see orderPairAddresses), then "<host>.local" for mDNS. Container
// and VM bridges are skipped: their addresses are unreachable from a Mac.
func pairAddresses(hostname string) []string {
	var ips []net.IP
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || pairVirtualInterface(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLinkLocalUnicast() {
					ips = append(ips, ip4)
				}
			}
		}
	}
	out := orderPairAddresses(ips)
	if short, _, _ := strings.Cut(hostname, "."); short != "" {
		out = append(out, short+".local")
	}
	return out
}

// pairVirtualInterface names interfaces that belong to container runtimes
// and hypervisors on this machine.
func pairVirtualInterface(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "virbr", "lxcbr", "lxdbr", "incusbr", "cni", "flannel",
		"cali", "vxlan", "kube", "podman", "vmnet", "vboxnet", "tap"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// orderPairAddresses sorts addresses: private LAN ranges (RFC 1918) first,
// then CGNAT/Tailscale (100.64.0.0/10), then everything else, keeping the
// interface order within each group and dropping duplicates.
func orderPairAddresses(ips []net.IP) []string {
	tier := func(ip net.IP) int {
		ip4 := ip.To4()
		switch {
		case ip4 == nil:
			return 3
		case ip4.IsPrivate():
			return 0
		case ip4[0] == 100 && ip4[1]&0xc0 == 64:
			return 1
		}
		return 2
	}
	sorted := append([]net.IP(nil), ips...)
	sort.SliceStable(sorted, func(a, b int) bool { return tier(sorted[a]) < tier(sorted[b]) })
	out := []string{}
	seen := map[string]bool{}
	for _, ip := range sorted {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// sshdPort returns the first Port directive of an sshd_config, following
// Include lines where they appear (OpenSSH keeps the first value it reads,
// and Debian and Ubuntu include sshd_config.d/*.conf at the very top), or
// 22.
func sshdPort(configPath string) int {
	if p := sshdPortIn(configPath, filepath.Dir(configPath), 0); p > 0 {
		return p
	}
	return 22
}

func sshdPortIn(path, base string, depth int) int {
	if depth > 8 {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		key, rest, _ := strings.Cut(line, " ")
		if k, v, ok := strings.Cut(key, "="); ok { // "Port=2222"
			key, rest = k, v+" "+rest
		}
		args := strings.Fields(strings.TrimLeft(rest, "= \t"))
		switch strings.ToLower(key) {
		case "match":
			return 0 // Port is not allowed in Match blocks; nothing below counts
		case "include":
			for _, pattern := range args {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(base, pattern)
				}
				matches, _ := filepath.Glob(pattern)
				sort.Strings(matches)
				for _, m := range matches {
					if p := sshdPortIn(m, base, depth+1); p > 0 {
						return p
					}
				}
			}
		case "port":
			if len(args) > 0 {
				if n, err := strconv.Atoi(args[0]); err == nil && n > 0 && n < 65536 {
					return n
				}
			}
		}
	}
	return 0
}

// readHostKeys returns the server's public host keys ("type base64"),
// Ed25519 first, from dir (/etc/ssh on Unix).
func readHostKeys(dir string) []string {
	keys := []string{}
	for _, name := range []string{"ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub", "ssh_host_rsa_key.pub"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		f := strings.Fields(string(data))
		if len(f) < 2 {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(f[1]); err != nil {
			continue
		}
		keys = append(keys, f[0]+" "+f[1])
	}
	return keys
}
