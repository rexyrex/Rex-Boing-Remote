//go:build !windows

package manage

// Install, upgrade and uninstall on Linux, macOS and the BSDs: the agent
// lives in ~/.local/share/rex-boing-remote and its key in
// ~/.ssh/authorized_keys.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rexyrex/Rex-Boing-Remote/agent/internal/wire"
)

// unixMaxUpgrade caps the size of an uploaded agent.
const unixMaxUpgrade = 256 << 20

func installDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "share", "rex-boing-remote")
}

func executableName() string { return "rex-boing-agent" }

func unixFail(code, format string, args ...any) wire.Result {
	return wire.Result{OK: false, Error: code, Message: fmt.Sprintf(format, args...)}
}

// unixKeyTypes are the key types install accepts.
var unixKeyTypes = map[string]bool{
	"ssh-ed25519": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true, "ssh-rsa": true,
}

// unixKey is a parsed OpenSSH public key line.
type unixKey struct {
	typ, blob, comment string
}

// unixParseKey validates "type base64 [comment]": a supported type whose
// base64 blob decodes and names the same type inside.
func unixParseKey(line string) (unixKey, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return unixKey{}, errors.New("no public key was given")
	}
	if strings.ContainsAny(line, "\r\n\x00") {
		return unixKey{}, errors.New("the public key must be a single line")
	}
	f := strings.Fields(line)
	if len(f) < 2 || !unixKeyTypes[f[0]] {
		return unixKey{}, errors.New("that is not an OpenSSH public key of a supported type (ssh-ed25519, ecdsa-sha2-nistp256/384/521 or ssh-rsa)")
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(raw) < 4 {
		return unixKey{}, errors.New("the public key's base64 data is damaged")
	}
	n := binary.BigEndian.Uint32(raw)
	if uint64(n) > uint64(len(raw)-4) || string(raw[4:4+n]) != f[0] {
		return unixKey{}, errors.New("the public key's data does not match its type " + f[0])
	}
	return unixKey{typ: f[0], blob: f[1], comment: strings.Join(f[2:], " ")}, nil
}

// unixSanitizeLabel keeps [A-Za-z0-9._-], turning anything else into "-".
func unixSanitizeLabel(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		if !ok || r == '-' {
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = true
			continue
		}
		b.WriteRune(r)
		dash = false
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 64 {
		out = strings.TrimRight(out[:64], "-.")
	}
	return out
}

// unixKeyLine builds the restricted authorized_keys line.
func unixKeyLine(agentPath string, k unixKey, label string) string {
	// The command is run by the user's shell: single-quote the path. Inside
	// the option's double quotes only \" is special to sshd.
	shell := "'" + strings.ReplaceAll(agentPath, "'", `'\''`) + "' ssh"
	return `restrict,command="` + strings.ReplaceAll(shell, `"`, `\"`) + `" ` + k.typ + " " + k.blob + " " + KeyCommentPrefix + label
}

// unixTokens splits an authorized_keys line on whitespace outside double
// quotes (options such as command="a b" contain spaces).
func unixTokens(line string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case ch == '\\' && quoted && i+1 < len(line) && line[i+1] == '"':
			cur.WriteString(`\"`)
			i++
		case ch == '"':
			quoted = !quoted
			cur.WriteByte(ch)
		case (ch == ' ' || ch == '\t') && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// unixLineKey finds the key type, blob and comment of an authorized_keys
// line, past any options. Comments and blank lines yield ok == false.
func unixLineKey(line string) (typ, blob, comment string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", "", "", false
	}
	tok := unixTokens(line)
	for i := 0; i+1 < len(tok) && i < 2; i++ { // the type is the first or the second token
		t := tok[i]
		if strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-sha2-") || strings.HasPrefix(t, "sk-") {
			if _, err := base64.StdEncoding.DecodeString(tok[i+1]); err == nil {
				return t, tok[i+1], strings.Join(tok[i+2:], " "), true
			}
		}
	}
	return "", "", "", false
}

// unixEOL is the line ending the file already uses.
func unixEOL(content string) string {
	if i := strings.IndexByte(content, '\n'); i > 0 && content[i-1] == '\r' {
		return "\r\n"
	}
	return "\n"
}

// unixUpsertKey replaces the line(s) carrying blob with line, or appends it.
// Every other line is kept byte for byte, as is the file's trailing newline
// (or its absence).
func unixUpsertKey(content, line, blob string) (string, bool) {
	var b strings.Builder
	replaced := false
	for _, l := range strings.SplitAfter(content, "\n") {
		if l == "" {
			continue
		}
		body := strings.TrimRight(l, "\r\n")
		if _, kb, _, ok := unixLineKey(body); ok && kb == blob {
			if !replaced {
				b.WriteString(line + l[len(body):])
				replaced = true
			}
			continue // a second copy of the same key would shadow nothing; drop it
		}
		b.WriteString(l)
	}
	if !replaced {
		eol := unixEOL(content)
		switch {
		case content == "" || strings.HasSuffix(content, "\n"):
			b.WriteString(line + eol)
		default:
			b.WriteString(eol + line)
		}
	}
	return b.String(), replaced
}

// unixRemoveOurKeys drops every line whose key comment starts with
// KeyCommentPrefix.
func unixRemoveOurKeys(content string) (string, int) {
	var b strings.Builder
	removed := 0
	for _, l := range strings.SplitAfter(content, "\n") {
		if l == "" {
			continue
		}
		if _, _, comment, ok := unixLineKey(strings.TrimRight(l, "\r\n")); ok && strings.HasPrefix(comment, KeyCommentPrefix) {
			removed++
			continue
		}
		b.WriteString(l)
	}
	out := b.String()
	// Removing the last line must not glue the file's new last line to
	// nothing: keep a trailing newline if the original had one.
	if strings.HasSuffix(content, "\n") && out != "" && !strings.HasSuffix(out, "\n") {
		out += unixEOL(content)
	}
	return out, removed
}

// unixWriteAtomic writes data to path through a temporary file in the same
// directory (fsynced, then renamed), so a crash never leaves a half-written
// authorized_keys or agent behind.
func unixWriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".rbr-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	unixSyncDir(dir)
	return nil
}

func unixSyncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// unixAuthorizedKeys returns the authorized_keys path to edit (through a
// symlink, if the file is one), creating ~/.ssh (0700) when it is missing.
func unixAuthorizedKeys(create bool) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot find the home directory")
	}
	dir := filepath.Join(home, ".ssh")
	if create {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				return "", err
			}
		}
	}
	path := filepath.Join(dir, "authorized_keys")
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	return path, nil
}

// unixForeignHome reports, when euid is root's, whether home belongs to
// someone else, and who. A sudo that keeps HOME runs the agent as root on
// another user's home: everything it wrote there (the install directory,
// ~/.ssh, authorized_keys) would be root's, which the user could not change
// and sshd, reading their keys as them, could not read.
func unixForeignHome(home string, euid int) (owner int, foreign bool) {
	if euid != 0 {
		return 0, false
	}
	fi, err := os.Stat(home)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return 0, false
	}
	return int(st.Uid), true
}

// unixRefuseForeignHome is the error result for unixForeignHome, or ok.
func unixRefuseForeignHome() (wire.Result, bool) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return wire.Result{}, true
	}
	if owner, foreign := unixForeignHome(home, os.Geteuid()); foreign {
		return unixFail("wrong-user", "This runs as root, but the home directory %s belongs to user %d (sudo kept HOME). "+
			"Run it as that user, without sudo.", home, owner), false
	}
	return wire.Result{}, true
}

// unixCopyExecutable puts the running executable at dest unless it already
// runs from there, and reports whether it did.
func unixCopyExecutable(dest string) (bool, error) {
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if a, err := os.Stat(exe); err == nil {
		if b, err := os.Stat(dest); err == nil && os.SameFile(a, b) {
			return false, nil
		}
	}
	src, err := os.Open(exe)
	if err != nil {
		return false, err
	}
	defer src.Close()
	data, err := io.ReadAll(io.LimitReader(src, unixMaxUpgrade+1))
	if err != nil {
		return false, err
	}
	if len(data) > unixMaxUpgrade {
		return false, errors.New("the running executable is unexpectedly large")
	}
	return true, unixWriteAtomic(dest, data, 0o755)
}

func install(o InstallOptions) wire.Result {
	key, err := unixParseKey(o.Key)
	if err != nil {
		return unixFail("bad-key", "%s.", strings.TrimSuffix(err.Error(), "."))
	}
	label := o.Label
	if label == "" {
		label = strings.TrimPrefix(key.comment, KeyCommentPrefix)
	}
	label = unixSanitizeLabel(label)
	if label == "" {
		label = "mac"
	}
	if r, ok := unixRefuseForeignHome(); !ok {
		return r
	}

	dir := installDir()
	if dir == "" {
		return unixFail("no-home", "Cannot find the home directory.")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return unixFail("install-failed", "Cannot create %s: %v", dir, err)
	}
	agentPath := filepath.Join(dir, executableName())
	copied, err := unixCopyExecutable(agentPath)
	if err != nil {
		return unixFail("install-failed", "Cannot copy the agent to %s: %v", agentPath, err)
	}

	keyFile, err := unixAuthorizedKeys(true)
	if err != nil {
		return unixFail("install-failed", "Cannot prepare ~/.ssh: %v", err)
	}
	mode := os.FileMode(0o600)
	var content []byte
	if fi, err := os.Stat(keyFile); err == nil {
		mode = fi.Mode().Perm()
		if content, err = os.ReadFile(keyFile); err != nil {
			return unixFail("install-failed", "Cannot read %s: %v", keyFile, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return unixFail("install-failed", "Cannot read %s: %v", keyFile, err)
	}
	updated, replaced := unixUpsertKey(string(content), unixKeyLine(agentPath, key, label), key.blob)
	if updated != string(content) {
		if err := unixWriteAtomic(keyFile, []byte(updated), mode); err != nil {
			return unixFail("install-failed", "Cannot write %s: %v", keyFile, err)
		}
	}
	msg := "Installed. The key " + KeyCommentPrefix + label + " can now run the agent, and nothing else."
	if replaced {
		msg = "Updated. The key " + KeyCommentPrefix + label + " can now run the agent, and nothing else."
	}
	details := map[string]string{"agentPath": agentPath, "keyFile": keyFile}
	if copied {
		details["agentCopied"] = "true"
	}
	return wire.Result{OK: true, Message: msg, Details: details}
}

func uninstall() wire.Result {
	if r, ok := unixRefuseForeignHome(); !ok {
		return r
	}
	details := map[string]string{}
	keyFile, err := unixAuthorizedKeys(false)
	if err != nil {
		return unixFail("uninstall-failed", "%v", err)
	}
	details["keyFile"] = keyFile
	removed := 0
	if fi, err := os.Stat(keyFile); err == nil {
		content, err := os.ReadFile(keyFile)
		if err != nil {
			return unixFail("uninstall-failed", "Cannot read %s: %v", keyFile, err)
		}
		var updated string
		updated, removed = unixRemoveOurKeys(string(content))
		if removed > 0 {
			if err := unixWriteAtomic(keyFile, []byte(updated), fi.Mode().Perm()); err != nil {
				return unixFail("uninstall-failed", "Cannot write %s: %v", keyFile, err)
			}
		}
	}
	details["removedKeys"] = strconv.Itoa(removed)
	if dir := installDir(); dir != "" && filepath.Base(dir) == "rex-boing-remote" {
		if err := os.RemoveAll(dir); err != nil {
			return unixFail("uninstall-failed", "Removed %d key(s) but not %s: %v", removed, dir, err)
		}
		details["removedDir"] = dir
	}
	return wire.Result{OK: true, Message: fmt.Sprintf("Uninstalled: removed %d key(s) and the agent.", removed), Details: details}
}

func upgrade(r io.Reader, sha256Hex string, size int64) wire.Result {
	want, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(sha256Hex)))
	if err != nil || len(want) != sha256.Size {
		return unixFail("usage", "--sha256 must be 64 hexadecimal characters.")
	}
	if size <= 0 || size > unixMaxUpgrade {
		return unixFail("usage", "--size must be between 1 and %d bytes.", unixMaxUpgrade)
	}
	dir := installDir()
	if dir == "" {
		return unixFail("no-home", "Cannot find the home directory.")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return unixFail("upgrade-failed", "Cannot create %s: %v", dir, err)
	}
	f, err := os.CreateTemp(dir, ".rex-boing-agent-upgrade-*")
	if err != nil {
		return unixFail("upgrade-failed", "Cannot write to %s: %v", dir, err)
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			f.Close()
			os.Remove(tmp)
		}
	}()
	h := sha256.New()
	n, err := io.CopyN(io.MultiWriter(f, h), r, size)
	if err != nil || n != size {
		return unixFail("short-read", "Received %d of %d bytes.", n, size)
	}
	if got := h.Sum(nil); !unixEqualBytes(got, want) {
		return unixFail("hash-mismatch", "The upload's SHA-256 is %s, not the expected %s.", hex.EncodeToString(got), hex.EncodeToString(want))
	}
	if err := f.Chmod(0o755); err != nil {
		return unixFail("upgrade-failed", "%v", err)
	}
	if err := f.Sync(); err != nil {
		return unixFail("upgrade-failed", "%v", err)
	}
	if err := f.Close(); err != nil {
		return unixFail("upgrade-failed", "%v", err)
	}

	// Run it before trusting it: a binary for the wrong architecture, or
	// one that speaks another protocol, must not replace a working agent.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tmp, "version").Output()
	if err != nil {
		return unixFail("verify-failed", "The new agent does not run on this machine (%s/%s): %v", runtime.GOOS, runtime.GOARCH, err)
	}
	var v struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Protocol int    `json:"protocol"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &v); err != nil || v.Name != "rex-boing-agent" || v.Protocol != wire.ProtocolVersion {
		return unixFail("verify-failed", "The new agent did not report protocol %d.", wire.ProtocolVersion)
	}
	dest := filepath.Join(dir, executableName())
	if err := os.Rename(tmp, dest); err != nil {
		return unixFail("upgrade-failed", "Cannot replace %s: %v", dest, err)
	}
	keep = true
	unixSyncDir(dir)
	return wire.Result{OK: true, Message: "Upgraded to " + v.Version + ".", Details: map[string]string{"version": v.Version, "agentPath": dest}}
}

func unixEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

func pairCode() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	name := os.Getenv("USER")
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	return encodePairCode(wire.PairCode{
		V:         1,
		Name:      host,
		User:      name,
		Port:      sshdPort("/etc/ssh/sshd_config"),
		OS:        runtime.GOOS,
		Addresses: pairAddresses(host),
		HostKeys:  readHostKeys("/etc/ssh"),
	})
}
