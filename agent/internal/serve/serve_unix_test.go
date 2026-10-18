//go:build !windows

package serve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndpointIsPrivate(t *testing.T) {
	dir := shortDir(t)
	stop := start(t, dir)
	defer stop()
	sock := socketPath(dir)
	for path, want := range map[string]os.FileMode{filepath.Dir(sock): 0o700, sock: 0o600} {
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
	// A directory others can enter is refused by clients.
	os.Chmod(filepath.Dir(sock), 0o755)
	if _, err := Query(dir, time.Second); err == nil || !strings.Contains(err.Error(), "other users") {
		t.Errorf("a client used an endpoint in an open directory: %v", err)
	}
	os.Chmod(filepath.Dir(sock), 0o700)
}

func TestSocketPathFallsBack(t *testing.T) {
	long := "/home/" + strings.Repeat("a", 120)
	// Fixed, not $TMPDIR, which a service and an SSH session may not share.
	t.Setenv("TMPDIR", "/somewhere/else")
	p := socketPath(long)
	if want := fmt.Sprintf("/tmp/rex-boing-remote-%d/serve.sock", os.Getuid()); p != want {
		t.Errorf("long home: %s, want %s", p, want)
	}
	if p := socketPath("/home/alex/.local/share/rex-boing-remote"); p != "/home/alex/.local/share/rex-boing-remote/run/serve.sock" {
		t.Errorf("short home: %s", p)
	}
}

// The fallback directory outside the install directory is removed once
// the serve has stopped, and left alone while it runs.
func TestFallbackEndpointRemoved(t *testing.T) {
	saved := fallbackBase
	fallbackBase = shortDir(t)
	t.Cleanup(func() { fallbackBase = saved })
	dir := filepath.Join(shortDir(t), strings.Repeat("a", 100))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := filepath.Dir(socketPath(dir))
	if !strings.HasPrefix(run, fallbackBase) {
		t.Fatalf("endpoint %s is not in the fallback directory", run)
	}
	stop := start(t, dir)
	if err := RemoveEndpoint(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Query(dir, time.Second); err != nil {
		t.Fatalf("removed the endpoint of a running serve: %v", err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEndpoint(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(run); !os.IsNotExist(err) {
		t.Errorf("%s left behind: %v", run, err)
	}
	// The directory inside a short install directory goes with it, not here.
	short := shortDir(t)
	stop = start(t, short)
	stop()
	RemoveEndpoint(short)
	if _, err := os.Stat(filepath.Join(short, "run")); err != nil {
		t.Errorf("removed %s/run: %v", short, err)
	}
}
