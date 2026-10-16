package manage

// OS-independent helpers for manage_windows.go: authorized_keys line
// building and rewriting, key validation, OpenSSH-for-Windows shell quoting,
// sshd_config parsing and address ordering. No Windows calls, so they are
// unit-tested on every OS; every identifier starts with "win".

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// winKeyTypes are the public key algorithms install accepts (the same set
// as manage_unix.go).
var winKeyTypes = map[string]bool{
	"ssh-ed25519":         true,
	"ssh-rsa":             true,
	"ecdsa-sha2-nistp256": true,
	"ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true,
}

// winParsedKey is one validated public key.
type winParsedKey struct {
	Type    string
	Blob    string // base64, exactly as given
	Comment string
}

// winParseKey validates one OpenSSH public key line ("type base64
// [comment]"). Options in front of the key, control characters and blobs
// whose embedded type disagrees with the stated one are rejected.
func winParseKey(line string) (winParsedKey, error) {
	var k winParsedKey
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if line == "" {
		return k, errors.New("no key given")
	}
	for _, r := range line {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return k, errors.New("the key contains control characters; pass exactly one key line")
		}
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return k, errors.New("not an OpenSSH public key line")
	}
	if !winKeyTypes[f[0]] {
		return k, fmt.Errorf("unsupported key type %q", f[0])
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return k, errors.New("the key's base64 data is damaged")
	}
	if len(raw) < 4 {
		return k, errors.New("the key data is too short")
	}
	n := binary.BigEndian.Uint32(raw)
	if uint64(n)+4 > uint64(len(raw)) || string(raw[4:4+n]) != f[0] {
		return k, errors.New("the key data does not match its type")
	}
	k.Type, k.Blob = f[0], f[1]
	if len(f) > 2 {
		k.Comment = strings.Join(f[2:], " ")
	}
	return k, nil
}

// winSanitizeLabel makes the comment suffix safe for one authorized_keys
// field, by the same rule as manage_unix.go: letters, digits and ._- only,
// runs of anything else become one "-", at most 64 characters, "mac" if
// nothing is left.
func winSanitizeLabel(label string) string {
	label = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(label), KeyCommentPrefix))
	var b strings.Builder
	dash := false
	for _, r := range label {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_'
		if !ok {
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
			continue
		}
		b.WriteRune(r)
		dash = false
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 64 {
		out = strings.TrimRight(out[:64], "-.")
	}
	if out == "" {
		out = "mac"
	}
	return out
}

// winShellKind classifies OpenSSH's DefaultShell (registry
// HKLM\SOFTWARE\OpenSSH, value DefaultShell); empty means cmd.exe.
func winShellKind(defaultShell string) string {
	s := strings.ToLower(strings.TrimSpace(strings.Trim(defaultShell, `"`)))
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		s = s[i+1:]
	}
	switch s {
	case "powershell.exe", "pwsh.exe", "powershell", "pwsh":
		return "powershell"
	}
	return "cmd"
}

// winForcedCommand is the command OpenSSH's default shell runs for the
// restricted key. PowerShell needs the call operator and single quotes
// (a ' inside is doubled); cmd.exe takes a double-quoted path (Windows paths
// cannot contain ").
func winForcedCommand(defaultShell, exePath string) string {
	if winShellKind(defaultShell) == "powershell" {
		return "& '" + strings.ReplaceAll(exePath, "'", "''") + "' ssh"
	}
	return `"` + exePath + `" ssh`
}

// winKeyLine builds the authorized_keys line. Inside an option value
// OpenSSH only unescapes \" (a lone backslash stays literal), so Windows
// paths need no further escaping.
func winKeyLine(command string, k winParsedKey, label string) string {
	return `restrict,command="` + strings.ReplaceAll(command, `"`, `\"`) + `" ` +
		k.Type + " " + k.Blob + " " + KeyCommentPrefix + winSanitizeLabel(label)
}

// winLineFields splits an authorized_keys line into options, type, blob and
// comment. Options may contain quoted strings with spaces.
func winLineFields(line string) (options, typ, blob, comment string, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", "", "", false
	}
	first := func(s string) (tok, rest string) {
		inQuote := false
		for i := 0; i < len(s); i++ {
			switch c := s[i]; {
			case c == '\\' && inQuote && i+1 < len(s):
				i++
			case c == '"':
				inQuote = !inQuote
			case (c == ' ' || c == '\t') && !inQuote:
				return s[:i], strings.TrimLeft(s[i:], " \t")
			}
		}
		return s, ""
	}
	tok, rest := first(s)
	if !winKeyTypes[tok] && !strings.Contains(tok, "-cert-") && !strings.HasPrefix(tok, "ssh-") && !strings.HasPrefix(tok, "ecdsa-") && !strings.HasPrefix(tok, "sk-") {
		options = tok
		tok, rest = first(rest)
	}
	typ = tok
	blob, comment = first(rest)
	if typ == "" || blob == "" {
		return "", "", "", "", false
	}
	return options, typ, blob, comment, true
}

// winIsOurLine reports whether an authorized_keys line was installed by
// this agent: its comment starts with KeyCommentPrefix.
func winIsOurLine(line string) bool {
	_, _, _, comment, ok := winLineFields(line)
	return ok && strings.HasPrefix(comment, KeyCommentPrefix)
}

// winSplitLines splits file content into lines and reports the line ending
// the file uses (CRLF when its first line ends in CRLF).
func winSplitLines(content string) (lines []string, eol string) {
	eol = "\n"
	if i := strings.IndexByte(content, '\n'); i > 0 && content[i-1] == '\r' {
		eol = "\r\n"
	}
	content = strings.TrimRight(content, "\r\n")
	if content == "" {
		return nil, eol
	}
	for _, l := range strings.Split(content, "\n") {
		lines = append(lines, strings.TrimSuffix(l, "\r"))
	}
	return lines, eol
}

func winJoinLines(lines []string, eol string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, eol) + eol
}

// winUpsertKey puts line into content: the first line holding the same key
// blob is replaced, later duplicates are dropped, every other line is kept
// verbatim, and the file's line ending is preserved. It reports whether an
// existing line was replaced.
func winUpsertKey(content, line, blob string) (out string, replaced bool) {
	lines, eol := winSplitLines(content)
	var kept []string
	for _, l := range lines {
		if _, _, b, _, ok := winLineFields(l); ok && b == blob {
			if !replaced {
				kept = append(kept, line)
				replaced = true
			}
			continue
		}
		kept = append(kept, l)
	}
	if !replaced {
		kept = append(kept, line)
	}
	return winJoinLines(kept, eol), replaced
}

// winRemoveOurKeys drops every line this agent installed.
func winRemoveOurKeys(content string) (out string, removed int) {
	lines, eol := winSplitLines(content)
	var kept []string
	for _, l := range lines {
		if winIsOurLine(l) {
			removed++
			continue
		}
		kept = append(kept, l)
	}
	if removed == 0 {
		return content, 0
	}
	return winJoinLines(kept, eol), removed
}

// winDecodeKeyFile reads an authorized_keys file as text. A UTF-8 byte
// order mark is dropped and UTF-16 (what PowerShell 5's ">" writes, which
// sshd cannot read) is converted; changed reports either, so the file is
// written back as plain UTF-8.
func winDecodeKeyFile(b []byte) (text string, changed bool) {
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		return string(b[3:]), true
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}), bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		big := b[0] == 0xFE
		b = b[2:]
		u := make([]uint16, len(b)/2)
		for i := range u {
			if big {
				u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
			} else {
				u[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
			}
		}
		return string(utf16.Decode(u)), true
	}
	return string(b), false
}

// winAdminKeyFileInUse reports whether sshd_config still sends
// administrators to administrators_authorized_keys (the stock "Match Group
// administrators" block). An empty config means the built-in default,
// which does.
func winAdminKeyFileInUse(config string) bool {
	if strings.TrimSpace(config) == "" {
		return true
	}
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && strings.Contains(strings.ToLower(line), "administrators_authorized_keys") {
			return true
		}
	}
	return false
}

// winVirtualAdapter recognises adapters of local virtual networks by their
// friendly name or description.
func winVirtualAdapter(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"vethernet", "hyper-v virtual", "virtualbox host-only", "vmware network adapter", "vmnet", "wsl", "docker", "loopback"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// winSSHUser is the name to log in with: the plain user for local and
// Microsoft accounts, DOMAIN\user for domain accounts (the NameSamCompatible
// form OpenSSH for Windows resolves domain users to).
func winSSHUser(user, domain, computer string) string {
	user = strings.TrimSpace(user)
	domain = strings.TrimSpace(domain)
	if domain == "" || strings.EqualFold(domain, computer) || strings.EqualFold(domain, "WORKGROUP") {
		return user
	}
	return domain + `\` + user
}

// winVersionInfo is what "rex-boing-agent version" prints.
type winVersionInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Protocol int    `json:"protocol"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

// winCheckVersionOutput accepts the output of a new binary's "version"
// command only if it is this agent speaking this protocol.
func winCheckVersionOutput(out []byte) (winVersionInfo, error) {
	var v winVersionInfo
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		return v, errors.New("the new binary did not print a version line")
	}
	if v.Name != "rex-boing-agent" {
		return v, fmt.Errorf("the new binary calls itself %q", v.Name)
	}
	if v.Protocol != wire.ProtocolVersion {
		return v, fmt.Errorf("the new binary speaks protocol %d, this agent %d", v.Protocol, wire.ProtocolVersion)
	}
	if v.OS != "" && v.OS != "windows" {
		return v, fmt.Errorf("the new binary is built for %s", v.OS)
	}
	return v, nil
}

// winValidSHA256 reports whether s is 64 hex digits.
func winValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
