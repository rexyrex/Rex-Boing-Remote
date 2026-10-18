//go:build linux

package service

// Linux: a systemd user unit, ~/.config/systemd/user/rex-boing-agent.service.
//
// A user's services only outlive their last login session when lingering is
// on for them. Without it, systemd stops the unit a few seconds after the
// app's SSH session ends, which is exactly when history matters, so
// install-service turns lingering on where logind lets the user do that
// themselves, and otherwise says how.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/serve"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

const unitName = Name + ".service"

func fail(code, format string, args ...any) wire.Result {
	return wire.Result{OK: false, Error: code, Message: fmt.Sprintf(format, args...)}
}

func unitFile() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user", unitName)
}

// command runs a short system command and returns its combined output.
func command(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	env := os.Environ()
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		// Some SSH setups leave it out; systemctl --user needs it to find
		// the user manager.
		if dir := fmt.Sprintf("/run/user/%d", os.Getuid()); isDir(dir) {
			env = append(env, "XDG_RUNTIME_DIR="+dir)
		}
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func systemctl(args ...string) (string, error) {
	return command("systemctl", append([]string{"--user", "--no-ask-password"}, args...)...)
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func userName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// linger reports whether name's services keep running after logout: "yes",
// "no", or "" when it cannot tell.
func linger(name string) string {
	if out, err := command("loginctl", "show-user", name, "--property=Linger"); err == nil {
		switch strings.TrimSpace(strings.TrimPrefix(out, "Linger=")) {
		case "yes":
			return "yes"
		case "no":
			return "no"
		}
	}
	// logind keeps one file per lingering user.
	if _, err := os.Stat(filepath.Join("/var/lib/systemd/linger", name)); err == nil {
		return "yes"
	} else if isDir("/var/lib/systemd/linger") {
		return "no"
	}
	return ""
}

// Installed reports whether the unit file exists.
func Installed() bool {
	_, err := os.Stat(unitFile())
	return err == nil
}

// Install writes the unit, enables and (re)starts it, and makes sure it
// outlives the login session.
func Install(agentPath, dir string) wire.Result {
	if strings.ContainsAny(agentPath, "\r\n") {
		return fail("bad-path", "The agent's path contains a line break.")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fail("no-systemd", "This server doesn't use systemd, so the agent can't install itself as a service. "+
			"To keep history anyway, have your init system run %q.", agentPath+" serve")
	}
	if out, err := systemctl("show", "--property=Version"); err != nil {
		return fail("no-user-manager", "systemd's per-user service manager isn't available for %s (%s). "+
			"It usually is on desktop and server distributions; in a container it often is not.", userName(), firstLine(out, err))
	}
	path := unitFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fail("install-failed", "Cannot create %s: %v", filepath.Dir(path), err)
	}
	if err := writeAtomic(path, []byte(unitText(agentPath)), 0o644); err != nil {
		return fail("install-failed", "Cannot write %s: %v", path, err)
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", unitName}, {"restart", unitName}} {
		if out, err := systemctl(args...); err != nil {
			return fail("install-failed", "systemctl --user %s failed: %s", strings.Join(args, " "), firstLine(out, err))
		}
	}
	st, running := serve.WaitRunning(dir, 8*time.Second)
	if !running {
		out, _ := systemctl("status", "--no-pager", "--lines=5", unitName)
		return fail("not-running", "The service is installed but did not start. See: journalctl --user -u %s\n%s", unitName, out)
	}

	name := userName()
	details := map[string]string{"manager": "systemd", "unit": path, "interval": strconv.FormatFloat(st.Interval, 'f', -1, 64)}
	state := linger(name)
	if state == "no" {
		// logind lets a user turn this on for themselves on many systems;
		// where its policy asks for an administrator, this fails quietly.
		if _, err := command("loginctl", "--no-ask-password", "enable-linger", name); err == nil {
			if state = linger(name); state == "yes" {
				details["lingerEnabled"] = "true"
			}
		}
	}
	details["linger"] = state
	msg := fmt.Sprintf("Keeping history: the agent samples every %g s in the background and keeps 48 hours, "+
		"as the systemd user service %s.", st.Interval, Name)
	if state == "no" {
		fix := lingerFix(name)
		details["fix"] = fix
		msg += fmt.Sprintf(" But lingering is off for %s, so systemd stops the service a few seconds after the last "+
			"session ends, which is when history matters. Turn it on once, as an administrator: %s", name, fix)
	}
	return wire.Result{OK: true, Message: msg, Details: details}
}

// Uninstall stops and removes the unit, and deletes the history it kept.
func Uninstall(dir string) wire.Result {
	path := unitFile()
	removed := false
	if _, err := os.Stat(path); err == nil {
		systemctl("disable", "--now", unitName) // the manager may be gone; the file still goes
		if err := os.Remove(path); err != nil {
			return fail("uninstall-failed", "Cannot remove %s: %v", path, err)
		}
		systemctl("daemon-reload")
		systemctl("reset-failed", unitName)
		removed = true
	}
	stopped := stopRunning(dir)
	os.Remove(filepath.Join(dir, serve.HistoryFile))
	serve.RemoveEndpoint(dir)
	switch {
	case removed:
		return wire.Result{OK: true, Message: "History is off: the background service and the history it kept were removed.",
			Details: map[string]string{"removed": path}}
	case stopped:
		return wire.Result{OK: true, Message: "History is off: the background agent was stopped and its history removed."}
	}
	return wire.Result{OK: true, Message: "History was already off."}
}

// stopRunning asks a serve that is still running (started by hand, or by
// something other than the unit) to stop.
func stopRunning(dir string) bool {
	if err := serve.Stop(dir, 2*time.Second); err != nil {
		return false
	}
	serve.WaitStopped(dir, 5*time.Second)
	return true
}

// Restart restarts the installed service, so it runs a freshly upgraded
// agent. It reports whether there was one to restart.
func Restart(dir string) (bool, error) {
	if !Installed() {
		return false, nil
	}
	if out, err := systemctl("restart", unitName); err != nil {
		return true, errors.New(firstLine(out, err))
	}
	return true, nil
}

// Describe explains the service's state for doctor: the hint when it is
// installed but not answering.
func Describe(dir string) (installed bool, hint string) {
	if !Installed() {
		return false, ""
	}
	hint = "systemctl --user status " + Name + "; journalctl --user -u " + Name
	if linger(userName()) == "no" {
		hint = lingerFix(userName()) + " (lingering is off, so the service stops when you log out)"
	}
	return true, hint
}

func firstLine(out string, err error) string {
	out = strings.TrimSpace(out)
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	if out == "" && err != nil {
		return err.Error()
	}
	return out
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
