//go:build !windows

package manage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unixTestKey builds a structurally valid OpenSSH public key line.
func unixTestKey(typ string, seed byte, comment string) string {
	var blob bytes.Buffer
	binary.Write(&blob, binary.BigEndian, uint32(len(typ)))
	blob.WriteString(typ)
	binary.Write(&blob, binary.BigEndian, uint32(32))
	blob.Write(bytes.Repeat([]byte{seed}, 32))
	line := typ + " " + base64.StdEncoding.EncodeToString(blob.Bytes())
	if comment != "" {
		line += " " + comment
	}
	return line
}

func unixTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func unixRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallCreatesAndIsIdempotent(t *testing.T) {
	home := unixTestHome(t)
	key := unixTestKey("ssh-ed25519", 1, "alex@Alexs-MacBook-Pro.local")
	r := Install(InstallOptions{Key: key})
	if !r.OK {
		t.Fatalf("install: %+v", r)
	}
	agent := filepath.Join(home, ".local/share/rex-boing-remote/rex-boing-agent")
	keyFile := filepath.Join(home, ".ssh/authorized_keys")
	if r.Details["agentPath"] != agent || r.Details["keyFile"] != keyFile {
		t.Errorf("details %v", r.Details)
	}
	if fi, err := os.Stat(agent); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("agent not installed executable: %v %v", fi, err)
	}
	if fi, _ := os.Stat(filepath.Join(home, ".ssh")); fi.Mode().Perm() != 0o700 {
		t.Errorf("~/.ssh mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(keyFile); fi.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode %v", fi.Mode().Perm())
	}
	fields := strings.Fields(key)
	want := `restrict,command="'` + agent + `' ssh" ssh-ed25519 ` + fields[1] + " rex-boing-remote:alex-Alexs-MacBook-Pro.local\n"
	if got := unixRead(t, keyFile); got != want {
		t.Errorf("authorized_keys\n got %q\nwant %q", got, want)
	}

	// Again, and again with a new label: still one line, label updated.
	if r := Install(InstallOptions{Key: key}); !r.OK {
		t.Fatalf("second install: %+v", r)
	}
	if got := unixRead(t, keyFile); got != want {
		t.Errorf("second install changed the file: %q", got)
	}
	if r := Install(InstallOptions{Key: key, Label: "Work Mac (2024)"}); !r.OK || !strings.HasPrefix(r.Message, "Updated") {
		t.Fatalf("relabel: %+v", r)
	}
	got := unixRead(t, keyFile)
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, " rex-boing-remote:Work-Mac-2024\n") {
		t.Errorf("relabelled file %q", got)
	}
}

func TestInstallKeepsForeignLines(t *testing.T) {
	home := unixTestHome(t)
	ssh := filepath.Join(home, ".ssh")
	os.Mkdir(ssh, 0o755)
	keyFile := filepath.Join(ssh, "authorized_keys")
	mine := unixTestKey("ssh-ed25519", 2, "")
	other := unixTestKey("ssh-rsa", 3, "bob@laptop")
	foreign := "# my keys\n" +
		`command="/usr/bin/backup --dir \"a b\"",no-pty ` + other + "\r\n" +
		"\n" +
		unixTestKey("ecdsa-sha2-nistp256", 4, "phone")
	os.WriteFile(keyFile, []byte(foreign), 0o644)

	if r := Install(InstallOptions{Key: mine, Label: "mac"}); !r.OK {
		t.Fatalf("install: %+v", r)
	}
	got := unixRead(t, keyFile)
	if !strings.HasPrefix(got, foreign) {
		t.Errorf("foreign lines changed:\n%q", got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Errorf("a file without a trailing newline gained one: %q", got)
	}
	if fi, _ := os.Stat(keyFile); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode not preserved: %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(ssh); fi.Mode().Perm() != 0o755 {
		t.Errorf("existing ~/.ssh mode changed: %v", fi.Mode().Perm())
	}
	// The same blob already present under another comment is replaced in
	// place, not duplicated.
	os.WriteFile(keyFile, []byte(other+"\n"+unixTestKey("ssh-ed25519", 2, "old")+"\n"+unixTestKey("ssh-ed25519", 2, "dup")+"\n"), 0o600)
	Install(InstallOptions{Key: mine, Label: "mac"})
	lines := strings.Split(strings.TrimSuffix(unixRead(t, keyFile), "\n"), "\n")
	if len(lines) != 2 || lines[0] != other || !strings.HasPrefix(lines[1], "restrict,command=") {
		t.Errorf("replace in place: %q", lines)
	}

	r := Uninstall()
	if !r.OK || r.Details["removedKeys"] != "1" {
		t.Fatalf("uninstall: %+v", r)
	}
	if got := unixRead(t, keyFile); got != other+"\n" {
		t.Errorf("after uninstall %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".local/share/rex-boing-remote")); !os.IsNotExist(err) {
		t.Errorf("install directory left behind: %v", err)
	}
	if r := Uninstall(); !r.OK || r.Details["removedKeys"] != "0" {
		t.Errorf("second uninstall: %+v", r)
	}
}

func TestInstallFollowsSymlinkedKeys(t *testing.T) {
	home := unixTestHome(t)
	real := filepath.Join(home, "managed_keys")
	os.WriteFile(real, []byte(unixTestKey("ssh-rsa", 5, "x")+"\n"), 0o600)
	os.Mkdir(filepath.Join(home, ".ssh"), 0o700)
	link := filepath.Join(home, ".ssh/authorized_keys")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	if r := Install(InstallOptions{Key: unixTestKey("ssh-ed25519", 6, "")}); !r.OK {
		t.Fatalf("install: %+v", r)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symlink was replaced by a file")
	}
	if !strings.Contains(unixRead(t, real), "rex-boing-remote:mac") {
		t.Errorf("the link target was not edited")
	}
}

func TestInstallRejectsBadKeys(t *testing.T) {
	unixTestHome(t)
	good := strings.Fields(unixTestKey("ssh-ed25519", 7, ""))[1]
	for _, key := range []string{
		"",
		"ssh-dss " + good,
		"ssh-ed25519 not-base64!!",
		"ssh-rsa " + good, // the blob says ssh-ed25519
		"ssh-ed25519 " + good + "\nssh-ed25519 " + good,
		"-----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		r := Install(InstallOptions{Key: key})
		if r.OK || r.Error != "bad-key" || r.Message == "" {
			t.Errorf("Install(%.30q) = %+v", key, r)
		}
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".ssh")); !os.IsNotExist(err) {
		t.Errorf("a rejected key still created ~/.ssh")
	}
	for in, want := range map[string]string{"Alex's MacBook Pro": "Alex-s-MacBook-Pro", "--x--": "x", "ünïcode": "n-code", "a/b\\c": "a-b-c"} {
		if got := unixSanitizeLabel(in); got != want {
			t.Errorf("label %q → %q, want %q", in, got, want)
		}
	}
	if got := unixKeyLine(`/home/o'neil/"x"/agent`, unixKey{typ: "ssh-ed25519", blob: "AAAA"}, "m"); got != `restrict,command="'/home/o'\''neil/\"x\"/agent' ssh" ssh-ed25519 AAAA rex-boing-remote:m` {
		t.Errorf("quoting %s", got)
	}
}

// Root on someone else's home (sudo keeping HOME) is refused; anyone on
// their own home, root included, is not.
func TestRootRefusesSomeoneElsesHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a directory that root does not own")
	}
	home := t.TempDir()
	if _, foreign := unixForeignHome(home, os.Geteuid()); foreign {
		t.Errorf("a user's own home was taken for someone else's")
	}
	if owner, foreign := unixForeignHome(home, 0); !foreign || owner != os.Getuid() {
		t.Errorf("root on uid %d's home: owner %d, foreign %v", os.Getuid(), owner, foreign)
	}
	if _, foreign := unixForeignHome("/", 0); foreign {
		t.Errorf("root on a root-owned directory was refused")
	}
}

// CleanupOld removes the temporary files of killed runs once they are an
// hour old, and nothing else.
func TestCleanupOldRemovesStaleTemporaries(t *testing.T) {
	home := unixTestHome(t)
	dir := filepath.Join(home, ".local/share/rex-boing-remote")
	os.MkdirAll(dir, 0o755)
	old := time.Now().Add(-2 * time.Hour)
	files := map[string]bool{ // name: should go
		".rex-boing-agent-upgrade-123": true, ".rex-boing-agent.rbr-456": true, ".history.json.789": true,
		"rex-boing-agent": false, "history.json": false, ".other-123": false,
	}
	for name := range files {
		path := filepath.Join(dir, name)
		os.WriteFile(path, []byte("x"), 0o600)
		os.Chtimes(path, old, old)
	}
	fresh := filepath.Join(dir, ".rex-boing-agent-upgrade-999") // an upgrade in progress
	os.WriteFile(fresh, []byte("x"), 0o600)
	CleanupOld()
	for name, gone := range files {
		if _, err := os.Stat(filepath.Join(dir, name)); os.IsNotExist(err) != gone {
			t.Errorf("%s: removed %v, want %v", name, os.IsNotExist(err), gone)
		}
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("removed a temporary file still being written: %v", err)
	}
}

func unixFakeAgent(t *testing.T, protocol string) []byte {
	t.Helper()
	return []byte("#!/bin/sh\necho '{\"name\":\"rex-boing-agent\",\"version\":\"9.9.9\",\"protocol\":" + protocol + ",\"os\":\"linux\",\"arch\":\"amd64\"}'\n")
}

func TestUpgrade(t *testing.T) {
	home := unixTestHome(t)
	dir := filepath.Join(home, ".local/share/rex-boing-remote")
	agent := filepath.Join(dir, "rex-boing-agent")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(agent, []byte("old"), 0o755)
	leftovers := func() []string {
		m, _ := filepath.Glob(filepath.Join(dir, ".rex-boing-agent-upgrade-*"))
		return m
	}

	bin := unixFakeAgent(t, "1")
	sum := sha256.Sum256(bin)
	wrong := sha256.Sum256([]byte("something else"))
	r := Upgrade(bytes.NewReader(bin), hex.EncodeToString(wrong[:]), int64(len(bin)))
	if r.OK || r.Error != "hash-mismatch" {
		t.Errorf("hash mismatch accepted: %+v", r)
	}
	if unixRead(t, agent) != "old" || len(leftovers()) != 0 {
		t.Errorf("a rejected upgrade touched the agent or left files")
	}
	if r := Upgrade(bytes.NewReader(bin[:10]), hex.EncodeToString(sum[:]), int64(len(bin))); r.OK || r.Error != "short-read" {
		t.Errorf("short upload accepted: %+v", r)
	}
	if r := Upgrade(bytes.NewReader(bin), "abc", int64(len(bin))); r.OK || r.Error != "usage" {
		t.Errorf("bad hash accepted: %+v", r)
	}
	bad := unixFakeAgent(t, "2")
	badSum := sha256.Sum256(bad)
	if r := Upgrade(bytes.NewReader(bad), hex.EncodeToString(badSum[:]), int64(len(bad))); r.OK || r.Error != "verify-failed" {
		t.Errorf("protocol 2 agent accepted: %+v", r)
	}
	if unixRead(t, agent) != "old" || len(leftovers()) != 0 {
		t.Errorf("a failed verification touched the agent or left files")
	}

	// Exactly size bytes are read: what follows on stdin is not consumed.
	in := bytes.NewReader(append(append([]byte{}, bin...), "trailing"...))
	r = Upgrade(in, strings.ToUpper(hex.EncodeToString(sum[:])), int64(len(bin)))
	if !r.OK || r.Details["version"] != "9.9.9" {
		t.Fatalf("upgrade: %+v", r)
	}
	if unixRead(t, agent) != string(bin) || in.Len() != len("trailing") {
		t.Errorf("agent not replaced, or stdin over-read (%d left)", in.Len())
	}
	if fi, _ := os.Stat(agent); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
}

func TestPairCodeRoundTrip(t *testing.T) {
	code, err := PairCode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, "rbr1:") || strings.ContainsAny(code, "=+/\n") {
		t.Fatalf("code %q", code)
	}
	p, err := decodePairCode(code)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	if p.V != 1 || p.Name != host || p.Port <= 0 || p.User == "" || p.Addresses == nil || p.HostKeys == nil {
		t.Errorf("decoded %+v", p)
	}
	if last := p.Addresses[len(p.Addresses)-1]; !strings.HasSuffix(last, ".local") {
		t.Errorf("mDNS name not last: %v", p.Addresses)
	}
}
