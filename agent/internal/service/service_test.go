package service

import (
	"encoding/xml"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestSystemdQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/home/alex/.local/share/rex-boing-remote/rex-boing-agent": `"/home/alex/.local/share/rex-boing-remote/rex-boing-agent"`,
		`/home/o'neil "x"/agent`:                                   `"/home/o'neil \"x\"/agent"`,
		`/home/100%/$HOME\agent`:                                   `"/home/100%%/$$HOME\\agent"`,
		"/srv/with space/agent":                                    `"/srv/with space/agent"`,
	} {
		if got := systemdQuote(in); got != want {
			t.Errorf("systemdQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestUnitText(t *testing.T) {
	unit := unitText("/home/alex/.local/share/rex-boing-remote/rex-boing-agent")
	for _, want := range []string{
		"\n[Service]\n",
		"\nExecStart=\"/home/alex/.local/share/rex-boing-remote/rex-boing-agent\" serve\n",
		"\nRestart=on-failure\n",
		"\n[Install]\nWantedBy=default.target\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") && strings.Count(line, "serve") != 1 {
			t.Errorf("ExecStart runs more than serve: %s", line)
		}
	}
}

func TestTaskXML(t *testing.T) {
	text := taskXML(`C:\Users\Zoë & Co\AppData\Local\RexBoingRemote\rex-boing-agent.exe`, `PC\Zoë & Co`, "S-1-5-21-1-2-3-1001")
	// It must be well-formed XML with the values where Task Scheduler
	// expects them.
	var task struct {
		Triggers struct {
			Logon struct {
				UserID string `xml:"UserId"`
			} `xml:"LogonTrigger"`
		}
		Principals struct {
			Principal struct {
				UserID    string `xml:"UserId"`
				LogonType string
				RunLevel  string
			}
		}
		Settings struct {
			ExecutionTimeLimit string
			MultipleInstances  string `xml:"MultipleInstancesPolicy"`
		}
		Actions struct {
			Exec struct {
				Command   string
				Arguments string
			}
		}
	}
	// encoding/xml refuses the UTF-16 declaration; the file itself is
	// UTF-16 (TestUTF16File).
	if err := xml.Unmarshal([]byte(strings.Replace(text, `encoding="UTF-16"`, "", 1)), &task); err != nil {
		t.Fatalf("not XML: %v\n%s", err, text)
	}
	if task.Actions.Exec.Command != `C:\Users\Zoë & Co\AppData\Local\RexBoingRemote\rex-boing-agent.exe` || task.Actions.Exec.Arguments != "serve" {
		t.Errorf("action %+v", task.Actions.Exec)
	}
	if task.Triggers.Logon.UserID != `PC\Zoë & Co` || task.Principals.Principal.UserID != "S-1-5-21-1-2-3-1001" {
		t.Errorf("users %q, %q", task.Triggers.Logon.UserID, task.Principals.Principal.UserID)
	}
	if task.Principals.Principal.RunLevel != "LeastPrivilege" || task.Principals.Principal.LogonType != "InteractiveToken" {
		t.Errorf("principal %+v: the task must run unelevated as the signed-in user", task.Principals.Principal)
	}
	if task.Settings.ExecutionTimeLimit != "PT0S" || task.Settings.MultipleInstances != "IgnoreNew" {
		t.Errorf("settings %+v", task.Settings)
	}
}

func TestUTF16File(t *testing.T) {
	b := utf16File("a\nZoë")
	if b[0] != 0xFF || b[1] != 0xFE {
		t.Fatalf("no byte order mark: % x", b[:2])
	}
	units := make([]uint16, 0, (len(b)-2)/2)
	for i := 2; i+1 < len(b); i += 2 {
		units = append(units, uint16(b[i])|uint16(b[i+1])<<8)
	}
	if got := string(utf16.Decode(units)); got != "a\r\nZoë" {
		t.Errorf("decoded %q", got)
	}
}
