//go:build !windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/collect"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/manage"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/serve"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

type quietCollector struct{}

func (quietCollector) Host() wire.Host         { return wire.Host{Hostname: "test"} }
func (quietCollector) Capabilities() []string  { return nil }
func (quietCollector) Doctor() []collect.Check { return nil }
func (quietCollector) Notices() []wire.Notice  { return nil }
func (quietCollector) Close()                  {}
func (quietCollector) Sample(wire.Detail) *wire.Sample {
	return &wire.Sample{Interval: 0.5, CPU: &wire.CPU{Total: 0.1}}
}

// fakeService stands in for the service manager: a restart stops the serve
// that runs and starts another a moment later, as systemd does once the old
// process has saved and gone.
func fakeService(t *testing.T, installed bool) (restarts *int) {
	t.Helper()
	restarts = new(int)
	var cancel context.CancelFunc
	done := make(chan struct{})
	close(done)
	saved := restartService
	restartService = func(dir string) (bool, error) {
		if !installed {
			return false, nil
		}
		*restarts++
		if cancel != nil {
			cancel()
			<-done
		}
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		done = make(chan struct{})
		go func(done chan struct{}) {
			defer close(done)
			time.Sleep(300 * time.Millisecond)
			serve.Run(ctx, quietCollector{}, serve.Options{Interval: 0.5, Dir: dir})
		}(done)
		return true, nil
	}
	t.Cleanup(func() {
		restartService = saved
		if cancel != nil {
			cancel()
			<-done
		}
	})
	return restarts
}

// shortHome is a home directory short enough for the serve socket inside
// it (t.TempDir on macOS is not).
func shortHome(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "rbr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	return home
}

func testKey() string {
	var blob bytes.Buffer
	binary.Write(&blob, binary.BigEndian, uint32(len("ssh-ed25519")))
	blob.WriteString("ssh-ed25519")
	binary.Write(&blob, binary.BigEndian, uint32(32))
	blob.Write(bytes.Repeat([]byte{9}, 32))
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " rex-boing-remote:test"
}

func result(t *testing.T, out *bytes.Buffer) wire.Result {
	t.Helper()
	var r wire.Result
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("not a result: %q", out.String())
	}
	return r
}

// Installing again replaces the binary, so a background agent is restarted
// on it; upgrading too. Either returns only once the new serve answers, so
// the app's next session finds its history.
func TestInstallAndUpgradeRestartTheService(t *testing.T) {
	shortHome(t)
	restarts := fakeService(t, true)
	dir := manage.InstallDir()

	var out, errOut bytes.Buffer
	if code := run([]string{"install", "--key", testKey()}, nil, &out, &errOut); code != 0 {
		t.Fatalf("install: %d %s %s", code, out.String(), errOut.String())
	}
	r := result(t, &out)
	if r.Details["agentCopied"] != "true" || r.Details["service"] != "restarted" || *restarts != 1 {
		t.Errorf("install over a running service: %+v, %d restarts", r, *restarts)
	}
	if _, err := serve.Query(dir, 200*time.Millisecond); err != nil {
		t.Errorf("install returned before the restarted serve answered: %v", err)
	}

	agent := []byte("#!/bin/sh\necho '{\"name\":\"rex-boing-agent\",\"version\":\"9.9.9\",\"protocol\":1}'\n")
	sum := sha256.Sum256(agent)
	out.Reset()
	code := run([]string{"upgrade", "--sha256", hex.EncodeToString(sum[:]), "--size", strconv.Itoa(len(agent))},
		bytes.NewReader(agent), &out, &errOut)
	if r := result(t, &out); code != 0 || r.Details["service"] != "restarted" || *restarts != 2 {
		t.Fatalf("upgrade: %d %+v, %d restarts", code, r, *restarts)
	}
	if _, err := serve.Query(dir, 200*time.Millisecond); err != nil {
		t.Errorf("upgrade returned before the restarted serve answered: %v", err)
	}
}

// A serve run by hand stops cleanly, saving its history, when the terminal
// it runs in closes.
func TestServeStopsOnHangup(t *testing.T) {
	if signal.Ignored(syscall.SIGHUP) {
		t.Skip("SIGHUP is ignored here (nohup), as serve then leaves it")
	}
	shortHome(t)
	dir := manage.InstallDir()
	done := make(chan int, 1)
	go func() { done <- run([]string{"serve", "--interval", "0.5"}, nil, io.Discard, io.Discard) }()
	if _, ok := serve.WaitRunning(dir, 5*time.Second); !ok {
		t.Fatal("serve never answered")
	}
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("serve exited %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve ignored SIGHUP")
	}
	if _, err := os.Stat(filepath.Join(dir, serve.HistoryFile)); err != nil {
		t.Errorf("history not saved on SIGHUP: %v", err)
	}
}

func TestInstallWithoutServiceRestartsNothing(t *testing.T) {
	shortHome(t)
	restarts := fakeService(t, false)
	var out, errOut bytes.Buffer
	if code := run([]string{"install", "--key", testKey()}, nil, &out, &errOut); code != 0 {
		t.Fatalf("install: %d %s", code, out.String())
	}
	if r := result(t, &out); r.Details["service"] != "" || *restarts != 0 {
		t.Errorf("no service, yet %+v", r)
	}
}
