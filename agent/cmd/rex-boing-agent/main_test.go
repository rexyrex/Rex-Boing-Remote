package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/collect"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

func TestSSHCommand(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	allowed := []string{"stream", "version", "doctor", "doctor --json", "uninstall", "pair-code", "install-service", "uninstall-service",
		"upgrade --sha256 " + sha + " --size 123", "upgrade --size=123 --sha256=" + sha, "  stream  ",
		"retention", "retention --days 7", "retention --days 30"}
	for _, cmd := range allowed {
		if _, err := sshCommand(cmd); err != nil {
			t.Errorf("%q refused: %v", cmd, err)
		}
	}
	refused := []string{"", "   ", "bash", "stream --count 1", "doctor --verbose", "install --key x", "ssh", "version; rm -rf ~",
		"upgrade", "upgrade --sha256 " + sha, "upgrade --sha256 " + sha + " --size 0", "upgrade --sha256 x --size 5 extra",
		"scp -t /tmp", "rsync --server", "sftp-server", "serve", "serve --interval 0.5", "install-service --now", "uninstall-service x",
		"retention --days", "retention --days 07", "retention --days -1", "retention --days 7 x", "retention --days=7",
		"retention --days 1e3", "history", "history --json"}
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

func TestParseMoment(t *testing.T) {
	loc := time.FixedZone("KST", 9*3600)
	now := time.Date(2026, 11, 17, 10, 30, 0, 0, loc)
	for in, want := range map[string]time.Time{
		"now":                       now,
		"90m":                       now.Add(-90 * time.Minute),
		"6h":                        now.Add(-6 * time.Hour),
		"3d":                        now.Add(-72 * time.Hour),
		"2w":                        now.Add(-14 * 24 * time.Hour),
		"1h30m":                     now.Add(-90 * time.Minute),
		"2026-11-16 03:00":          time.Date(2026, 11, 16, 3, 0, 0, 0, loc),
		"2026-11-16T03:00:05":       time.Date(2026, 11, 16, 3, 0, 5, 0, loc),
		"2026-11-16":                time.Date(2026, 11, 16, 0, 0, 0, 0, loc),
		"2026-11-16T03:00:00Z":      time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC),
		"03:00":                     time.Date(2026, 11, 17, 3, 0, 0, 0, loc),
		"23:15":                     time.Date(2026, 11, 16, 23, 15, 0, 0, loc), // still to come today: yesterday's
		"1792200000000":             time.UnixMilli(1792200000000),
		"1792200000":                time.Unix(1792200000, 0),
		"2026-11-16T03:00:00+09:00": time.Date(2026, 11, 16, 3, 0, 0, 0, loc),
	} {
		got, err := parseMoment(in, now, loc)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"yesterday", "3 days ago", "25:00", "-1h"} {
		if _, err := parseMoment(in, now, loc); err == nil {
			t.Errorf("%q parsed", in)
		}
	}
}

// TestRetentionAndHistoryCommands runs both against a home of its own,
// with no background agent running: the setting is saved for later, and
// history comes from the saved file.
func TestRetentionAndHistoryCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the install directory is under LOCALAPPDATA")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".local", "share", "rex-boing-remote")
	var out, errOut bytes.Buffer
	run([]string{"retention", "--days", "7"}, nil, &out, &errOut)
	if !strings.Contains(out.String(), `"error":"not-installed"`) {
		t.Errorf("without an install directory: %s", out.String())
	}
	os.MkdirAll(dir, 0o700)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"retention"}, `"keepDays":"2"`},
		{[]string{"retention", "--days", "1"}, `"error":"usage"`},
		{[]string{"retention", "--days", "31"}, `"error":"usage"`},
		{[]string{"retention", "--days", "14"}, `"running":"no"`},
		{[]string{"retention"}, `"keepDays":"14"`},
		{[]string{"retention", "--days", "2"}, `"keepDays":"2"`},
	} {
		out.Reset()
		run(c.args, nil, &out, &errOut)
		if !strings.Contains(out.String(), c.want) {
			t.Errorf("%v: %s, want %s", c.args, out.String(), c.want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "history-settings.json")); err == nil {
		t.Errorf("the default left a settings file behind")
	}

	out.Reset()
	errOut.Reset()
	if code := run([]string{"history"}, nil, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "no history is kept") {
		t.Errorf("without history: %d %q", code, errOut.String())
	}
	saved, err := os.ReadFile(filepath.Join("..", "..", "internal", "history", "testdata", "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "history.json"), saved, 0o600)
	at := time.Unix(1_792_206_000, 0).Add(3 * time.Minute)
	out.Reset()
	errOut.Reset()
	code := cmdHistory([]string{"--from", "2026-10-17T03:00:00Z", "--to", "2026-10-17T03:05:00Z", "--utc"}, at, &out, &errOut)
	if code != 0 || !strings.Contains(errOut.String(), "not running") || !strings.Contains(out.String(), "Vitals") {
		t.Errorf("history from the saved file: %d\n%s\n%s", code, errOut.String(), out.String())
	}
	out.Reset()
	if code := cmdHistory([]string{"--at", "2026-10-17T03:01:00Z", "--json"}, at, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), `"from":1792206000000,"to":1792206900000`) {
		t.Errorf("history --at --json: %d %s", code, out.String())
	}
	if code := cmdHistory([]string{"--at", "03:00", "--from", "1h"}, at, &out, &errOut); code != 2 {
		t.Errorf("--at with --from: %d", code)
	}
}
