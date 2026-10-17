//go:build !windows

package serve

import (
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
	p := socketPath(long)
	if len(p) > maxSocketPath || !strings.HasPrefix(p, os.TempDir()) {
		t.Errorf("long home: %s", p)
	}
	if p := socketPath("/home/alex/.local/share/rex-boing-remote"); p != "/home/alex/.local/share/rex-boing-remote/run/serve.sock" {
		t.Errorf("short home: %s", p)
	}
}
