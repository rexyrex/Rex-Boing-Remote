// Package service registers the agent's background mode (serve) with the
// operating system's own per-user service manager, so it runs without the
// app: a systemd user unit on Linux, a Scheduled Task at logon on Windows.
// (The macOS agent, which is Swift, installs a LaunchAgent itself.)
//
// Nothing here needs root, opens a port, or touches anything outside the
// user's own service definitions and the agent's install directory. This
// file holds the OS-independent parts, so they are tested everywhere.
package service

import (
	"encoding/xml"
	"strings"
	"unicode/utf16"
)

// Name is the service's name: the systemd unit (with .service) and the
// scheduled task.
const Name = "rex-boing-agent"

// TaskName is the Windows scheduled task's path.
const TaskName = `\Rex Boing Remote agent`

const description = "Rex Boing Remote agent: keeps this machine's history while the Mac that watches it is away"

// systemdQuote quotes one ExecStart argument for systemd: inside double
// quotes, backslash and double quote are escaped; % starts a specifier and
// $ a variable everywhere, so both are doubled.
func systemdQuote(arg string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`)
	return `"` + r.Replace(arg) + `"`
}

// systemdSpecifiers escapes a value systemd takes as it is, such as a
// condition's path: only % is special there, where it starts a specifier.
func systemdSpecifiers(s string) string { return strings.ReplaceAll(s, "%", "%%") }

// unitText is the systemd user unit that runs serve.
//
// Restart only on failure: a serve that finds another one running exits
// cleanly and stays stopped. The condition keeps a unit whose agent was
// deleted by hand from failing every 30 seconds for good: it is skipped
// instead. Nice and the idle I/O class keep it out of the way of whatever
// the machine is for.
func unitText(agentPath string) string {
	return "# Written by rex-boing-agent install-service; removed by uninstall-service.\n" +
		"[Unit]\n" +
		"Description=" + description + "\n" +
		"Documentation=https://github.com/rexyrex/Rex-Boing-Remote\n" +
		"ConditionPathIsExecutable=" + systemdSpecifiers(agentPath) + "\n" +
		"\n" +
		"[Service]\n" +
		"Type=simple\n" +
		"ExecStart=" + systemdQuote(agentPath) + " serve\n" +
		"Restart=on-failure\n" +
		"RestartSec=30\n" +
		"Nice=10\n" +
		"IOSchedulingClass=idle\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=default.target\n"
}

// xmlText escapes s for XML character data.
func xmlText(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// taskXML is the Windows scheduled task: started when this user signs in,
// as this user, without elevation, never stopped for running long, and
// restarted if it fails.
func taskXML(agentPath, userID, sid string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>` + xmlText(description) + `</Description>
    <URI>` + xmlText(TaskName) + `</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlText(userID) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlText(sid) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlText(agentPath) + `</Command>
      <Arguments>serve</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// utf16File encodes s as UTF-16 little-endian with a byte order mark,
// which is what schtasks /XML reads reliably on every Windows version.
func utf16File(s string) []byte {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2, 2+2*len(units))
	out[0], out[1] = 0xFF, 0xFE
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// lingerFix is the command that keeps a user's services running after
// they log out.
func lingerFix(user string) string { return "sudo loginctl enable-linger " + user }
