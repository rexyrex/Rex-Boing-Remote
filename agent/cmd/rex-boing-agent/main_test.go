package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/collect"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

func TestSSHCommand(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	allowed := []string{"stream", "version", "doctor", "doctor --json", "uninstall", "pair-code", "install-service", "uninstall-service",
		"upgrade --sha256 " + sha + " --size 123", "upgrade --size=123 --sha256=" + sha, "  stream  "}
	for _, cmd := range allowed {
		if _, err := sshCommand(cmd); err != nil {
			t.Errorf("%q refused: %v", cmd, err)
		}
	}
	refused := []string{"", "   ", "bash", "stream --count 1", "doctor --verbose", "install --key x", "ssh", "version; rm -rf ~",
		"upgrade", "upgrade --sha256 " + sha, "upgrade --sha256 " + sha + " --size 0", "upgrade --sha256 x --size 5 extra",
		"scp -t /tmp", "rsync --server", "sftp-server", "serve", "serve --interval 0.5", "install-service --now", "uninstall-service x"}
	for _, cmd := range refused {
		_, err := sshCommand(cmd)
		if err == nil {
			t.Errorf("%q allowed", cmd)
			continue
		}
		if msg := err.Error(); strings.Contains(msg, "\n") || !strings.Contains(msg, "Rex Boing Remote") {
			t.Errorf("%q: explanation %q is not one helpful line", cmd, msg)
		}
	}
	var out, errOut bytes.Buffer
	if code := cmdSSH("cat /etc/passwd", nil, &out, &errOut); code != 1 || out.Len() != 0 || strings.Count(errOut.String(), "\n") != 1 {
		t.Errorf("refusal: code %d stdout %q stderr %q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := cmdSSH("version", nil, &out, &errOut); code != 0 || !strings.Contains(out.String(), `"protocol":1`) {
		t.Errorf("ssh version: %d %q", code, out.String())
	}
}

func TestVersionAndUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, nil, &out, &errOut); code != 0 {
		t.Fatalf("version exit %d", code)
	}
	want := `{"name":"rex-boing-agent","version":"dev","protocol":1,"os":"` + runtime.GOOS + `","arch":"` + runtime.GOARCH + `"}` + "\n"
	if out.String() != want {
		t.Errorf("version %q, want %q", out.String(), want)
	}
	out.Reset()
	if code := run(nil, nil, &out, &errOut); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "Usage:") {
		t.Errorf("no command: %d %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"frobnicate"}, nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "unknown command") {
		t.Errorf("unknown command: %d %q", code, errOut.String())
	}
	if code := run([]string{"stream", "--detail", "most"}, nil, &out, &errOut); code != 2 {
		t.Errorf("bad detail accepted")
	}
	out.Reset()
	if code := run([]string{"upgrade"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Errorf("upgrade without flags: %d", code)
	}
	var r wire.Result
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.OK || r.Error != "usage" {
		t.Errorf("upgrade usage result %q", out.String())
	}
}

func TestStreamCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"stream", "--count", "2", "--interval", "0.5", "--detail", "full"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("stream exit %d: %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var hello wire.Hello
	if err := json.Unmarshal([]byte(lines[0]), &hello); err != nil || hello.Type != "hello" || hello.Agent.Name != "rex-boing-agent" {
		t.Errorf("hello %q", lines[0])
	}
	samples := 0
	for _, l := range lines[1:] {
		var m struct{ Type string }
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Errorf("non-JSON line %q", l)
		}
		if m.Type == "sample" {
			samples++
		}
	}
	if samples != 2 {
		t.Errorf("%d samples in %q", samples, out.String())
	}
}

func TestFormatDoctor(t *testing.T) {
	text := formatDoctor(wire.AgentInfo{Name: "rex-boing-agent", Version: "1.0", OS: "linux", Arch: "amd64"},
		wire.Host{Hostname: "box", Vendor: "ASUSTeK", ModelName: "NUC", Kernel: "6.8"},
		[]collect.Check{{Name: "CPU", OK: true, Detail: "fine"}, {Name: "Power", OK: false, Detail: "denied", Fix: "line one\n  line two"}})
	for _, want := range []string{"rex-boing-agent 1.0 (protocol 1, linux/amd64)", "box: ASUSTeK NUC, kernel 6.8", "[ok] CPU    fine",
		"[!!] Power  denied", "Fix: line one", "       line two"} {
		if !strings.Contains(text, want) {
			t.Errorf("doctor output lacks %q:\n%s", want, text)
		}
	}
}
