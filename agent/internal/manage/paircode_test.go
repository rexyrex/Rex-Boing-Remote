package manage

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

func TestPairCodeEncoding(t *testing.T) {
	in := wire.PairCode{V: 1, Name: "homelab", User: "alex", Port: 2222, OS: "linux",
		Addresses: []string{"192.168.1.20", "100.101.102.103", "homelab.local"}, HostKeys: []string{"ssh-ed25519 AAAAC3Nza"}}
	code, err := encodePairCode(in)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(code, pairCodePrefix)
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || !strings.HasPrefix(code, "rbr1:") || strings.Contains(code, "=") {
		t.Fatalf("code %q: %v", code, err)
	}
	if want := `{"v":1,"n":"homelab","u":"alex","p":2222,"o":"linux","a":["192.168.1.20","100.101.102.103","homelab.local"],"k":["ssh-ed25519 AAAAC3Nza"]}`; string(raw) != want {
		t.Errorf("json %s", raw)
	}
	out, err := decodePairCode(" " + code + "\n")
	if err != nil || !reflect.DeepEqual(out, in) {
		t.Errorf("round trip %+v %v", out, err)
	}
	empty, _ := encodePairCode(wire.PairCode{Name: "x"})
	if p, err := decodePairCode(empty); err != nil || p.V != 1 || p.Addresses == nil || p.HostKeys == nil {
		t.Errorf("empty lists must be [] not null: %+v %v", p, err)
	}
	for _, bad := range []string{"", "rbr2:abc", "rbr1:***", "rbr1:" + base64.RawURLEncoding.EncodeToString([]byte(`{"v":2}`))} {
		if _, err := decodePairCode(bad); err == nil {
			t.Errorf("decoded %q", bad)
		}
	}
}

func TestOrderPairAddresses(t *testing.T) {
	var ips []net.IP
	for _, s := range []string{"203.0.113.9", "100.101.102.103", "192.168.1.20", "10.0.0.5", "192.168.1.20", "172.20.0.1", "100.128.0.1"} {
		ips = append(ips, net.ParseIP(s))
	}
	got := orderPairAddresses(ips)
	want := []string{"192.168.1.20", "10.0.0.5", "172.20.0.1", "100.101.102.103", "203.0.113.9", "100.128.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}
	for name, virtual := range map[string]bool{"docker0": true, "br-1a2b": true, "veth12": true, "virbr0": true, "eth0": false, "tailscale0": false, "wlan0": false} {
		if pairVirtualInterface(name) != virtual {
			t.Errorf("pairVirtualInterface(%q) != %v", name, virtual)
		}
	}
	if a := pairAddresses("box.example.com"); len(a) == 0 || a[len(a)-1] != "box.local" {
		t.Errorf("addresses %v", a)
	}
}

func TestSSHDPortAndHostKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
	}
	write("sshd_config", "# Port 1\nInclude sshd_config.d/*.conf\nPort 22\n")
	write("sshd_config.d/10-a.conf", "PasswordAuthentication no\n")
	write("sshd_config.d/20-b.conf", "port=2222\nPort 3333\n")
	if p := sshdPort(filepath.Join(dir, "sshd_config")); p != 2222 {
		t.Errorf("port %d, want the first one sshd reads (2222)", p)
	}
	write("plain", "  Port   2200 # comment\n")
	if p := sshdPort(filepath.Join(dir, "plain")); p != 2200 {
		t.Errorf("plain port %d", p)
	}
	write("match", "Match User git\n  Port 9999\n")
	if p := sshdPort(filepath.Join(dir, "match")); p != 22 {
		t.Errorf("port inside Match %d", p)
	}
	if p := sshdPort(filepath.Join(dir, "missing")); p != 22 {
		t.Errorf("missing config port %d", p)
	}
	write("loop", "Include loop\n")
	if p := sshdPort(filepath.Join(dir, "loop")); p != 22 {
		t.Errorf("include loop port %d", p)
	}

	write("ssh_host_rsa_key.pub", "ssh-rsa AAAAB3NzaC1yc2E= root@box\n")
	write("ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 root@box\n")
	write("ssh_host_ecdsa_key.pub", "garbage\n")
	if got := readHostKeys(dir); !reflect.DeepEqual(got, []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", "ssh-rsa AAAAB3NzaC1yc2E="}) {
		t.Errorf("host keys %v", got)
	}
	if got := readHostKeys(filepath.Join(dir, "none")); got == nil || len(got) != 0 {
		t.Errorf("no host keys must be an empty list: %v", got)
	}
}
