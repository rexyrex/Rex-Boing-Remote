// Package redact removes secrets from process command lines before they
// leave the machine.
package redact

import (
	"regexp"
	"strings"
)

var patterns = []*regexp.Regexp{
	// --password=x, --token x, -p x style flags whose value is a secret.
	regexp.MustCompile(`(?i)((?:--?|/)(?:pass(?:word|wd)?|pwd|token|secret|api[-_]?key|access[-_]?key|auth|credentials?|private[-_]?key|client[-_]?secret)(?:=|\s+))("[^"]*"|'[^']*'|\S+)`),
	// KEY=value environment-style assignments with a secret-sounding name.
	regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[A-Z0-9_]*=)("[^"]*"|'[^']*'|\S+)`),
	// user:password@host in URLs.
	regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^:/\s@]+:)([^@\s]+)(@)`),
	// Bearer tokens.
	regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{8,})`),
	// Well-known token shapes.
	regexp.MustCompile(`()(gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
}

const mask = "•••"

// MaxLength caps a command line on the wire.
const MaxLength = 512

// CommandLine returns cmd with secrets masked and its length capped.
func CommandLine(cmd string) string {
	out := strings.TrimSpace(cmd)
	for i, p := range patterns {
		switch i {
		case 2:
			out = p.ReplaceAllString(out, "${1}"+mask+"${3}")
		default:
			out = p.ReplaceAllString(out, "${1}"+mask)
		}
	}
	if len(out) > MaxLength {
		out = out[:MaxLength] + "…"
	}
	return out
}
