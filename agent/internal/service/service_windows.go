//go:build windows

package service

// Windows: a Scheduled Task, "\Rex Boing Remote agent", that starts serve
// when this user signs in. It runs as the user, without elevation, so a
// standard account can create it. Windows only runs such a task while the
// user has a desktop session (at the console or over Remote Desktop); on a
// PC no one signs in to, it waits for the next sign-in.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/serve"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

func fail(code, format string, args ...any) wire.Result {
	return wire.Result{OK: false, Error: code, Message: fmt.Sprintf(format, args...)}
}

func schtasks(args ...string) (string, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		sys = `C:\Windows\System32`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(sys, "schtasks.exe"), args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// account returns DOMAIN\user and the SID of the user running the agent.
func account() (string, string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", "", err
	}
	sid := u.User.Sid
	name, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return "", "", err
	}
	if domain != "" {
		name = domain + `\` + name
	}
	return name, sid.String(), nil
}

// Installed reports whether the scheduled task exists.
func Installed() bool {
	_, err := schtasks("/Query", "/TN", TaskName)
	return err == nil
}

// Install registers the task and starts it now if this user is signed in.
func Install(agentPath, dir string) wire.Result {
	userID, sid, err := account()
	if err != nil {
		return fail("install-failed", "Cannot tell which account this is: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fail("install-failed", "Cannot create %s: %v", dir, err)
	}
	file := filepath.Join(dir, "rex-boing-agent-task.xml")
	if err := os.WriteFile(file, utf16File(taskXML(agentPath, userID, sid)), 0o600); err != nil {
		return fail("install-failed", "Cannot write %s: %v", file, err)
	}
	out, err := schtasks("/Create", "/TN", TaskName, "/XML", file, "/F")
	os.Remove(file)
	if err != nil {
		return fail("install-failed", "Windows did not accept the scheduled task: %s", firstLine(out, err))
	}
	// A serve that is already running would keep the old settings and
	// binary: replace it.
	if serve.Stop(dir, time.Second) == nil {
		serve.WaitStopped(dir, 5*time.Second)
	}
	schtasks("/Run", "/TN", TaskName) // fails when no one is signed in; the trigger starts it later
	details := map[string]string{"manager": "task", "task": TaskName}
	if st, ok := serve.WaitRunning(dir, 8*time.Second); ok {
		details["running"] = "yes"
		return wire.Result{OK: true, Details: details, Message: fmt.Sprintf(
			"Keeping history: the agent samples every %g s in the background and keeps 48 hours, as the scheduled task %q. "+
				"Windows runs it while %s is signed in, and starts it again at every sign-in.", st.Interval, strings.TrimPrefix(TaskName, `\`), userID)}
	}
	details["running"] = "no"
	return wire.Result{OK: true, Details: details, Message: fmt.Sprintf(
		"Installed as the scheduled task %q, which Windows starts when %s signs in. No one is signed in to this PC "+
			"right now, so it starts at the next sign-in (at the console or over Remote Desktop).", strings.TrimPrefix(TaskName, `\`), userID)}
}

// Uninstall stops the background agent, deletes the task, and deletes the
// history it kept.
func Uninstall(dir string) wire.Result {
	stopped := false
	if serve.Stop(dir, 2*time.Second) == nil {
		stopped = serve.WaitStopped(dir, 5*time.Second)
	}
	removed := false
	if Installed() {
		schtasks("/End", "/TN", TaskName)
		if out, err := schtasks("/Delete", "/TN", TaskName, "/F"); err != nil {
			return fail("uninstall-failed", "Could not delete the scheduled task: %s", firstLine(out, err))
		}
		removed = true
	}
	os.Remove(filepath.Join(dir, serve.HistoryFile))
	switch {
	case removed:
		return wire.Result{OK: true, Message: "History is off: the scheduled task and the history it kept were removed."}
	case stopped:
		return wire.Result{OK: true, Message: "History is off: the background agent was stopped and its history removed."}
	}
	return wire.Result{OK: true, Message: "History was already off."}
}

// Restart starts the task again, so it runs a freshly upgraded agent.
func Restart(dir string) (bool, error) {
	if !Installed() {
		return false, nil
	}
	if serve.Stop(dir, 2*time.Second) == nil {
		serve.WaitStopped(dir, 5*time.Second)
	}
	schtasks("/Run", "/TN", TaskName) // no one signed in: the next sign-in starts it
	return true, nil
}

// Describe explains the service's state for doctor.
func Describe(dir string) (installed bool, hint string) {
	if !Installed() {
		return false, ""
	}
	return true, `it starts when you sign in to Windows; check it with: schtasks /Query /TN "` +
		strings.TrimPrefix(TaskName, `\`) + `" /V /FO LIST`
}

func firstLine(out string, err error) string {
	out = strings.TrimSpace(out)
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = strings.TrimSpace(out[:i])
	}
	if out == "" && err != nil {
		return err.Error()
	}
	return out
}
