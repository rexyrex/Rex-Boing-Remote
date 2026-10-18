// Command rex-boing-agent reports a machine to Rex Boing Remote over SSH.
// PROTOCOL.md at the repository root describes every command and message.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/collect"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/manage"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/serve"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/service"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/stream"
	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// version is set at build time: -ldflags "-X main.version=0.1.0".
var version = "dev"

const agentName = "rex-boing-agent"

const usageText = `rex-boing-agent reports this machine to Rex Boing Remote over SSH.

Usage:
  rex-boing-agent stream [--interval S] [--detail vitals|full] [--count N]
  rex-boing-agent version
  rex-boing-agent doctor [--json]
  rex-boing-agent install [--key "ssh-ed25519 AAAA…"] [--label NAME]   (key on stdin without --key)
  rex-boing-agent pair-code
  rex-boing-agent upgrade --sha256 HEX --size N                       (new binary on stdin)
  rex-boing-agent uninstall
  rex-boing-agent serve [--interval S]          keep history in the background (optional)
  rex-boing-agent install-service               run serve as this user's service, now and after reboots
  rex-boing-agent uninstall-service             stop it and delete the history it kept
  rex-boing-agent ssh                                                 (used by the installed key)
`

func main() {
	// Windows leaves the previous executable behind after an upgrade (a
	// running .exe can be renamed but not deleted); clear it on every run.
	// A no-op on other systems.
	manage.CleanupOld()
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func agentInfo() wire.AgentInfo {
	return wire.AgentInfo{Name: agentName, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH}
}

// run dispatches a command line and returns the exit status.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "stream":
		return cmdStream(rest, stdin, stdout, stderr)
	case "version":
		return cmdVersion(stdout)
	case "doctor":
		return cmdDoctor(rest, stdout, stderr)
	case "install":
		return cmdInstall(rest, stdin, stdout, stderr)
	case "pair-code":
		return cmdPairCode(stdout, stderr)
	case "upgrade":
		return cmdUpgrade(rest, stdin, stdout, stderr)
	case "uninstall":
		return cmdUninstall(stdout)
	case "serve":
		return cmdServe(rest, stderr)
	case "install-service":
		return cmdInstallService(rest, stdout, stderr)
	case "uninstall-service":
		return printResult(stdout, service.Uninstall(manage.InstallDir()))
	case "ssh":
		return cmdSSH(os.Getenv("SSH_ORIGINAL_COMMAND"), stdin, stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	}
	fmt.Fprintf(stderr, "rex-boing-agent: unknown command %q\n\n%s", cmd, usageText)
	return 2
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(agentName+" "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func cmdStream(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlags("stream", stderr)
	count := fs.Int("count", 0, "exit after `N` samples (0: until stdin closes)")
	interval := fs.Float64("interval", stream.DefaultInterval, "seconds between samples, 0.5–10")
	detail := fs.String("detail", "vitals", "starting detail: vitals or full")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	if *detail != string(wire.DetailVitals) && *detail != string(wire.DetailFull) {
		fmt.Fprintf(stderr, "rex-boing-agent: --detail must be vitals or full\n")
		return 2
	}
	c := collect.New()
	defer c.Close()
	dir := manage.InstallDir()
	err := stream.Run(c, stdin, stdout, stream.Options{
		Agent:    agentInfo(),
		Interval: *interval,
		Detail:   wire.Detail(*detail),
		Count:    *count,
		Log:      stderr,
		// A background agent, when one runs, has what happened while the
		// app was away. Without one this costs one failed local connect.
		History: func() []byte { return serve.History(dir, 2*time.Second) },
	})
	if err != nil {
		// stdout is gone (the session dropped): nothing left to tell anyone.
		return 1
	}
	return 0
}

func cmdVersion(stdout io.Writer) int {
	v := struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Protocol int    `json:"protocol"`
		OS       string `json:"os"`
		Arch     string `json:"arch"`
	}{agentName, version, wire.ProtocolVersion, runtime.GOOS, runtime.GOARCH}
	return printJSON(stdout, v)
}

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("doctor", stderr)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	c := collect.New()
	defer c.Close()
	host := c.Host()
	caps := c.Capabilities()
	checks := append(c.Doctor(), backgroundCheck(manage.InstallDir()))
	if *asJSON {
		return printJSON(stdout, struct {
			Agent        wire.AgentInfo  `json:"agent"`
			Host         wire.Host       `json:"host"`
			Capabilities []string        `json:"capabilities"`
			Checks       []collect.Check `json:"checks"`
		}{agentInfo(), host, caps, checks})
	}
	fmt.Fprint(stdout, formatDoctor(agentInfo(), host, checks))
	return 0
}

// formatDoctor renders the human-readable doctor report.
func formatDoctor(a wire.AgentInfo, h wire.Host, checks []collect.Check) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s (protocol %d, %s/%s)\n", a.Name, a.Version, wire.ProtocolVersion, a.OS, a.Arch)
	var about []string
	for _, s := range []string{strings.TrimSpace(h.Vendor + " " + h.ModelName), h.ChipName,
		strings.TrimSpace(h.OSName + " " + h.OSVersion), kernelText(h.Kernel)} {
		if s != "" {
			about = append(about, s)
		}
	}
	fmt.Fprintf(&b, "%s: %s\n\n", h.Hostname, strings.Join(about, ", "))
	width := 0
	for _, c := range checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}
	for _, c := range checks {
		mark := "ok"
		if !c.OK {
			mark = "!!"
		}
		fmt.Fprintf(&b, "[%s] %-*s  %s\n", mark, width, c.Name, c.Detail)
		if c.Fix != "" {
			indent := strings.Repeat(" ", width+7)
			lines := strings.Split(c.Fix, "\n")
			fmt.Fprintf(&b, "%sFix: %s\n", indent, lines[0])
			for _, l := range lines[1:] {
				fmt.Fprintf(&b, "%s     %s\n", indent, l)
			}
		}
	}
	return b.String()
}

func kernelText(k string) string {
	if k == "" {
		return ""
	}
	return "kernel " + k
}

func cmdInstall(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlags("install", stderr)
	key := fs.String("key", "", "the OpenSSH public key line (default: read from stdin)")
	label := fs.String("label", "", "a name for the Mac the key belongs to")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	k := *key
	if k == "" {
		k = firstLine(stdin)
	}
	r := manage.Install(manage.InstallOptions{Key: k, Label: *label})
	if r.OK && r.Details["agentCopied"] == "true" {
		// Installing again (the installer, or Repair) replaced the binary
		// a background agent may still be running.
		restartBackground(&r, manage.InstallDir())
	}
	return printResult(stdout, r)
}

// firstLine returns the first non-empty line of r, reading at most 16 KiB.
func firstLine(r io.Reader) string {
	sc := bufio.NewScanner(io.LimitReader(r, 16<<10))
	sc.Buffer(make([]byte, 0, 4096), 16<<10)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			return line
		}
	}
	return ""
}

func cmdPairCode(stdout, stderr io.Writer) int {
	code, err := manage.PairCode()
	if err != nil {
		fmt.Fprintf(stderr, "rex-boing-agent: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, code)
	return 0
}

// upgradeFlags parses the upgrade arguments.
func upgradeFlags(args []string, stderr io.Writer) (sha string, size int64, err error) {
	fs := newFlags("upgrade", stderr)
	shaFlag := fs.String("sha256", "", "SHA-256 of the new binary, hex")
	sizeFlag := fs.Int64("size", 0, "size of the new binary in bytes")
	if err := fs.Parse(args); err != nil {
		return "", 0, err
	}
	if fs.NArg() > 0 || *shaFlag == "" || *sizeFlag <= 0 {
		return "", 0, errors.New("upgrade needs --sha256 HEX --size N")
	}
	return *shaFlag, *sizeFlag, nil
}

func cmdUpgrade(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	sha, size, err := upgradeFlags(args, stderr)
	if err != nil {
		return printResult(stdout, wire.Result{OK: false, Error: "usage", Message: err.Error()})
	}
	r := manage.Upgrade(stdin, sha, size)
	if r.OK {
		restartBackground(&r, manage.InstallDir())
	}
	return printResult(stdout, r)
}

// restartService is service.Restart; tests replace it.
var restartService = service.Restart

// restartBackground restarts the background agent, when one is installed,
// so it runs the binary now in place; its history is saved and reloaded on
// the way. It returns once the new serve answers, or after 8 seconds: the
// app asks for history once, right after its next session's hello, and
// would otherwise find the serve still starting and go without it for that
// whole session.
func restartBackground(r *wire.Result, dir string) {
	restarted, err := restartService(dir)
	switch {
	case err != nil:
		r.Message += " The background agent could not be restarted: " + err.Error()
	case restarted:
		if r.Details == nil {
			r.Details = map[string]string{}
		}
		r.Details["service"] = "restarted"
		serve.WaitRunning(dir, 8*time.Second)
	}
}

// cmdUninstall removes the background service first, while the agent that
// runs it still exists, then the keys and the agent.
func cmdUninstall(stdout io.Writer) int {
	bg := service.Uninstall(manage.InstallDir())
	r := manage.Uninstall()
	if r.Details == nil {
		r.Details = map[string]string{}
	}
	if !bg.OK {
		r.Message += " The background service was not removed: " + bg.Message
	} else if bg.Message != "History was already off." {
		r.Details["service"] = "removed"
	}
	return printResult(stdout, r)
}

func cmdServe(args []string, stderr io.Writer) int {
	fs := newFlags("serve", stderr)
	interval := fs.Float64("interval", serve.DefaultInterval, "seconds between samples, 0.5–10")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	signals := []os.Signal{os.Interrupt, syscall.SIGTERM}
	// A serve run by hand in a terminal that closes gets SIGHUP: save the
	// history and stop, as for SIGTERM. Under nohup, which ignores it, it
	// stays ignored (handling it would undo nohup).
	if !signal.Ignored(syscall.SIGHUP) {
		signals = append(signals, syscall.SIGHUP)
	}
	ctx, stop := signal.NotifyContext(context.Background(), signals...)
	defer stop()
	c := collect.New()
	defer c.Close()
	err := serve.Run(ctx, c, serve.Options{Agent: agentInfo(), Interval: *interval, Dir: manage.InstallDir(), Log: stderr})
	switch {
	case errors.Is(err, serve.ErrRunning):
		fmt.Fprintln(stderr, "rex-boing-agent: already keeping history in the background; nothing to do")
		return 0
	case err != nil:
		fmt.Fprintf(stderr, "rex-boing-agent: serve: %v\n", err)
		return 1
	}
	return 0
}

// cmdInstallService registers the installed agent (not a copy running from
// elsewhere) with the service manager.
func cmdInstallService(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("install-service", stderr)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	dir := manage.InstallDir()
	path := filepath.Join(dir, manage.ExecutableName())
	if _, err := os.Stat(path); err != nil {
		return printResult(stdout, wire.Result{OK: false, Error: "not-installed",
			Message: "The agent is not installed at " + path + " yet. Add this server in Rex Boing Remote first."})
	}
	return printResult(stdout, service.Install(path, dir))
}

// backgroundCheck is doctor's line about background history.
func backgroundCheck(dir string) collect.Check {
	c := collect.Check{Name: "Background history"}
	if st, err := serve.Query(dir, 2*time.Second); err == nil {
		c.OK = true
		c.Detail = fmt.Sprintf("running (pid %d, since %s, sampling every %g s)", st.PID,
			time.UnixMilli(st.Started).Format("Jan 2 15:04"), st.Interval)
		if st.Oldest > 0 {
			c.Detail += fmt.Sprintf("; history back to %s", time.UnixMilli(st.Oldest).Format("Jan 2 15:04"))
		}
		return c
	}
	if installed, hint := service.Describe(dir); installed {
		c.Detail = "installed as a service, but not running"
		c.Fix = hint
		return c
	}
	c.OK = true
	c.Detail = "off (optional: Rex Boing Remote › Settings › Servers › Keep history while this Mac is away)"
	return c
}

// sshCommand checks the command a restricted key's client asked for
// (SSH_ORIGINAL_COMMAND) against the commands that key may run.
func sshCommand(original string) ([]string, error) {
	const allowed = "stream, version, doctor, doctor --json, upgrade, uninstall, pair-code, install-service, uninstall-service"
	f := strings.Fields(original)
	if len(f) == 0 {
		return nil, fmt.Errorf("this key only runs the Rex Boing Remote agent and no command was given (allowed: %s)", allowed)
	}
	ok := false
	switch f[0] {
	case "stream", "version", "uninstall", "pair-code", "install-service", "uninstall-service":
		ok = len(f) == 1
	case "doctor":
		ok = len(f) == 1 || (len(f) == 2 && f[1] == "--json")
	case "upgrade":
		_, _, err := upgradeFlags(f[1:], io.Discard)
		ok = err == nil
	}
	if !ok {
		shown := original
		if len(shown) > 80 {
			shown = shown[:80] + "…"
		}
		return nil, fmt.Errorf("refused %q: this key only runs the Rex Boing Remote agent (allowed: %s)", shown, allowed)
	}
	return f, nil
}

func cmdSSH(original string, stdin io.Reader, stdout, stderr io.Writer) int {
	args, err := sshCommand(original)
	if err != nil {
		fmt.Fprintf(stderr, "rex-boing-agent: %v\n", err)
		return 1
	}
	return run(args, stdin, stdout, stderr)
}

func printResult(stdout io.Writer, r wire.Result) int {
	printJSON(stdout, r)
	if !r.OK {
		return 1
	}
	return 0
}

func printJSON(stdout io.Writer, v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 1
	}
	b = append(b, '\n')
	if _, err := stdout.Write(b); err != nil {
		return 1
	}
	return 0
}
